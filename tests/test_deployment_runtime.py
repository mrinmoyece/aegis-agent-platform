"""Production process dispatch contracts."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import psycopg
import pytest

from aegis_agent_platform.config import ConfigurationError, ProcessRole, Settings
from aegis_agent_platform.event_store.fencing import (
    ReloadingTenantWriterFenceResolver,
    TenantWriterFenceResolver,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.operations import WriterFence
from aegis_agent_platform.runtime import deployment
from aegis_agent_platform.runtime.deployment import (
    ManagedControlPlane,
    active_process_roles,
    create_application,
    run_background_role,
)


class FenceCursor:
    def __init__(self, row: tuple[str, int, str] | None = None) -> None:
        self._row = row

    async def fetchone(self) -> tuple[str, int, str] | None:
        return self._row


class FenceTransaction:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_: object) -> None:
        return None


class FenceConnection:
    def __init__(self, row: tuple[str, int, str] | None) -> None:
        self._row = row

    def transaction(self) -> FenceTransaction:
        return FenceTransaction()

    async def execute(
        self,
        query: str,
        _parameters: tuple[str, ...],
    ) -> FenceCursor:
        return FenceCursor(self._row if "FROM tenant_writer_fences" in query else None)


def test_only_implemented_roles_are_advertised_active() -> None:
    assert active_process_roles() == frozenset(
        {
            ProcessRole.API,
            ProcessRole.OUTBOX_PUBLISHER,
            ProcessRole.RECONCILER,
        }
    )


def test_api_factory_rejects_non_api_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_PROCESS_ROLE", "worker-general")

    with pytest.raises(ConfigurationError, match="only supports the api role"):
        create_application()


def test_api_factory_defers_connections_to_asgi_lifespan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_PROCESS_ROLE", "api")

    assert isinstance(create_application(), ManagedControlPlane)


@pytest.mark.asyncio
async def test_unimplemented_background_role_fails_closed() -> None:
    settings = Settings(process_role=ProcessRole.PROTOCOL_GATEWAY)

    with pytest.raises(ConfigurationError, match="disabled"):
        await run_background_role(settings)


@pytest.mark.asyncio
async def test_managed_app_is_unavailable_before_lifespan() -> None:
    app = ManagedControlPlane(Settings())
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await app({"type": "http"}, receive, send)

    assert messages[0]["status"] == 503
    assert messages[1]["body"] == (
        b'{"status":"not-ready","reason":"managed_dependencies_uninitialized"}'
    )


@pytest.mark.asyncio
async def test_lifespan_reports_dependency_bootstrap_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = ManagedControlPlane(Settings())
    start = AsyncMock(side_effect=RuntimeError("database unavailable"))
    close = AsyncMock()
    monkeypatch.setattr(app, "_start", start)
    monkeypatch.setattr(app, "_close", close)
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "lifespan.startup"}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await app({"type": "lifespan"}, receive, send)

    assert messages == [
        {
            "type": "lifespan.startup.failed",
            "message": "managed dependency bootstrap failed: RuntimeError",
        }
    ]
    close.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_rejects_invalid_startup_message() -> None:
    app = ManagedControlPlane(Settings())

    async def receive() -> dict[str, object]:
        return {"type": "http.request"}

    async def send(_: dict[str, object]) -> None:
        raise AssertionError("invalid lifespan startup must not send a response")

    with pytest.raises(RuntimeError, match="did not initiate lifespan startup"):
        await app({"type": "lifespan"}, receive, send)


@pytest.mark.asyncio
async def test_lifespan_starts_and_closes_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = ManagedControlPlane(Settings())
    start = AsyncMock()
    close = AsyncMock()
    monkeypatch.setattr(app, "_start", start)
    monkeypatch.setattr(app, "_close", close)
    request_messages: tuple[dict[str, object], ...] = (
        {"type": "lifespan.startup"},
        {"type": "lifespan.shutdown"},
    )
    requests: Iterator[dict[str, object]] = iter(request_messages)
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return next(requests)

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await app({"type": "lifespan"}, receive, send)

    assert messages == [
        {"type": "lifespan.startup.complete"},
        {"type": "lifespan.shutdown.complete"},
    ]
    close.assert_awaited_once()


@pytest.mark.asyncio
async def test_managed_close_releases_every_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = ManagedControlPlane(Settings())
    redis = SimpleNamespace(aclose=AsyncMock())
    async_connection = SimpleNamespace(close=AsyncMock())
    sync_connection = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(app, "_delegate", object())
    monkeypatch.setattr(app, "_redis", redis)
    monkeypatch.setattr(app, "_async_connection", async_connection)
    monkeypatch.setattr(app, "_sync_connection", sync_connection)

    await app._close()

    assert app._delegate is None
    assert app._redis is None
    assert app._async_connection is None
    assert app._sync_connection is None
    redis.aclose.assert_awaited_once()
    async_connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_managed_start_closes_postgres_when_sync_connect_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = ManagedControlPlane(Settings())
    async_connection = SimpleNamespace(close=AsyncMock())
    monkeypatch.setattr(deployment, "_writer_fences", lambda _: _resolver())
    monkeypatch.setattr(
        psycopg.AsyncConnection,
        "connect",
        AsyncMock(return_value=async_connection),
    )
    monkeypatch.setattr(
        asyncio,
        "to_thread",
        AsyncMock(side_effect=RuntimeError("sync connection failed")),
    )

    with pytest.raises(RuntimeError, match="sync connection failed"):
        await app._start()

    async_connection.close.assert_awaited_once()
    assert app._async_connection is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "runner_name"),
    [
        (ProcessRole.OUTBOX_PUBLISHER, "_run_outbox_publisher"),
        (ProcessRole.RECONCILER, "_run_reconciler"),
    ],
)
async def test_background_dispatch_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    role: ProcessRole,
    runner_name: str,
) -> None:
    ready_file = tmp_path / "ready"
    ready_file.touch()
    runner = AsyncMock()
    loop = SimpleNamespace(
        add_signal_handler=lambda *_: None,
        remove_signal_handler=lambda *_: None,
    )
    monkeypatch.setattr(deployment, "_READY_FILE", ready_file)
    monkeypatch.setattr(deployment, runner_name, runner)
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)

    await run_background_role(Settings(process_role=role))

    runner.assert_awaited_once()
    assert not ready_file.exists()


def test_runtime_helpers_are_tenant_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = TenantId("tenant-b")
    second = TenantId("tenant-a")
    resolver = TenantWriterFenceResolver(
        fences={
            first: WriterFence(home_region="eu-west-1", generation=1),
            second: WriterFence(home_region="eu-west-1", generation=1),
        }
    )
    monkeypatch.setenv("HOSTNAME", "aegis-pod-1")

    assert [context.tenant_id for context in deployment._tenant_contexts(resolver)] == [
        second,
        first,
    ]
    assert deployment._process_identity() == "aegis-pod-1"
    monkeypatch.delenv("HOSTNAME")
    assert deployment._process_identity() == "aegis-local"


@pytest.mark.asyncio
async def test_wait_returns_when_stopped() -> None:
    stop = asyncio.Event()
    stop.set()

    await deployment._wait(stop, 60.0)
    await deployment._wait(asyncio.Event(), 0.0)


def _resolver() -> TenantWriterFenceResolver:
    return TenantWriterFenceResolver(
        fences={
            TenantId("tenant-a"): WriterFence(
                home_region="eu-west-1",
                generation=1,
            )
        }
    )


@pytest.mark.asyncio
async def test_outbox_publisher_processes_tenant_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stop = asyncio.Event()
    connection = SimpleNamespace(close=AsyncMock(), rollback=AsyncMock())
    redis = SimpleNamespace(aclose=AsyncMock())
    queue = SimpleNamespace(health=AsyncMock(return_value=True))

    async def publish_batch(*_: object, **kwargs: object) -> None:
        assert kwargs["cancelled"] is stop
        stop.set()

    publisher = SimpleNamespace(publish_batch=AsyncMock(side_effect=publish_batch))
    connect = AsyncMock(return_value=connection)
    monkeypatch.setattr(deployment, "_READY_FILE", tmp_path / "ready")
    monkeypatch.setattr(deployment, "_writer_fences", lambda _: _resolver())
    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)
    monkeypatch.setattr(
        deployment,
        "postgres_connection_lock",
        lambda _: asyncio.Lock(),
    )
    monkeypatch.setattr(deployment, "create_redis_client", lambda _: redis)
    monkeypatch.setattr(deployment, "RedisStreamQueue", lambda _: queue)
    monkeypatch.setattr(
        deployment, "PostgresEventStore", lambda *_args, **_kwargs: object()
    )
    monkeypatch.setattr(
        deployment, "OutboxPublisher", lambda *_args, **_kwargs: publisher
    )
    monkeypatch.setattr(
        deployment,
        "_writer_fences_match_database",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        deployment,
        "PostgresSchemaVersionProbe",
        lambda _: AsyncMock(return_value=1),
    )
    monkeypatch.setattr(deployment, "_wait", AsyncMock())

    await deployment._run_outbox_publisher(Settings(), stop)

    queue.health.assert_awaited_once()
    publisher.publish_batch.assert_awaited_once()
    redis.aclose.assert_awaited_once()
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_outbox_publisher_fails_closed_without_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SimpleNamespace(close=AsyncMock())
    redis = SimpleNamespace(aclose=AsyncMock())
    queue = SimpleNamespace(health=AsyncMock(return_value=False))
    monkeypatch.setattr(deployment, "_writer_fences", lambda _: _resolver())
    monkeypatch.setattr(
        psycopg.AsyncConnection,
        "connect",
        AsyncMock(return_value=connection),
    )
    monkeypatch.setattr(
        deployment,
        "postgres_connection_lock",
        lambda _: asyncio.Lock(),
    )
    monkeypatch.setattr(deployment, "create_redis_client", lambda _: redis)
    monkeypatch.setattr(deployment, "RedisStreamQueue", lambda _: queue)

    with pytest.raises(RuntimeError, match="Redis transport"):
        await deployment._run_outbox_publisher(Settings(), asyncio.Event())

    redis.aclose.assert_awaited_once()
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_reconciler_processes_tenant_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stop = asyncio.Event()
    connection = SimpleNamespace(close=AsyncMock(), rollback=AsyncMock())

    async def reconcile(*_: object, **_kwargs: object) -> None:
        stop.set()

    repository = SimpleNamespace(reconcile_expired=AsyncMock(side_effect=reconcile))
    monkeypatch.setattr(deployment, "_READY_FILE", tmp_path / "ready")
    monkeypatch.setattr(deployment, "_writer_fences", lambda _: _resolver())
    monkeypatch.setattr(
        psycopg.AsyncConnection,
        "connect",
        AsyncMock(return_value=connection),
    )
    monkeypatch.setattr(
        deployment,
        "postgres_connection_lock",
        lambda _: asyncio.Lock(),
    )
    monkeypatch.setattr(
        deployment, "PostgresEventStore", lambda *_args, **_kwargs: object()
    )
    monkeypatch.setattr(
        deployment,
        "PostgresWorkRepository",
        lambda *_args: repository,
    )
    monkeypatch.setattr(
        deployment,
        "_writer_fences_match_database",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        deployment,
        "PostgresSchemaVersionProbe",
        lambda _: AsyncMock(return_value=1),
    )
    monkeypatch.setattr(deployment, "_wait", AsyncMock())

    await deployment._run_reconciler(Settings(), stop)

    repository.reconcile_expired.assert_awaited_once()
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("row", "expected"),
    [
        (("eu-west-1", 1, "active"), True),
        (("eu-west-1", 1, "disabled"), False),
        (None, False),
    ],
)
async def test_writer_fence_readiness_uses_authoritative_database_state(
    row: tuple[str, int, str] | None,
    expected: bool,
) -> None:
    connection = cast(psycopg.AsyncConnection[Any], FenceConnection(row))

    assert (
        await deployment._writer_fences_match_database(
            connection,
            asyncio.Lock(),
            _resolver(),
        )
        is expected
    )


@pytest.mark.asyncio
async def test_writer_fence_readiness_fails_closed_on_invalid_secret(
    tmp_path: Path,
) -> None:
    resolver = ReloadingTenantWriterFenceResolver(tmp_path / "missing.json")
    connection = cast(
        psycopg.AsyncConnection[Any],
        FenceConnection(("eu-west-1", 1, "active")),
    )

    assert not await deployment._writer_fences_match_database(
        connection,
        asyncio.Lock(),
        resolver,
    )
