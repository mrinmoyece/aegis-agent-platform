"""Managed deployment composition and explicit process-role entry points."""

from __future__ import annotations

import asyncio
import os
import signal
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg

from aegis_agent_platform.config import (
    ConfigurationError,
    Environment,
    ProcessRole,
    Settings,
)
from aegis_agent_platform.control_plane.api import (
    AsgiMessage,
    ControlPlaneApp,
    Receive,
    Send,
)
from aegis_agent_platform.event_store.fencing import (
    ReloadingTenantWriterFenceResolver,
    TenantWriterFenceResolver,
)
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    PostgresProjectionRepository,
    postgres_connection_lock,
)
from aegis_agent_platform.identity import (
    AuthenticationError,
    AuthenticationService,
    JwtValidationConfig,
    JwtVerifier,
    RemoteJwksProvider,
)
from aegis_agent_platform.observability.health import (
    ComponentProbe,
    DependencyCriticality,
    HealthRegistry,
    HealthStatus,
    ProbeResult,
)
from aegis_agent_platform.operations import (
    PostgresSchemaVersionProbe,
    SchemaCompatibilityWindow,
)
from aegis_agent_platform.persistence.postgres import (
    PostgresAuditStore,
    PostgresIdentityDirectory,
    PostgresPolicyRepository,
    PostgresTenantRepository,
)
from aegis_agent_platform.queueing.publisher import OutboxPublisher
from aegis_agent_platform.queueing.redis_streams import (
    RedisStreamQueue,
    create_redis_client,
)
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext

_READY_FILE = Path("/tmp/aegis-ready")  # noqa: S108 - writable container tmpfs
_ACTIVE_ROLES = frozenset(
    {
        ProcessRole.API,
        ProcessRole.OUTBOX_PUBLISHER,
        ProcessRole.RECONCILER,
    }
)


def _connect_sync(database_url: str) -> psycopg.Connection[Any]:
    return psycopg.connect(database_url)


class ManagedControlPlane:
    """Own production adapters for the complete ASGI lifespan."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._delegate: ControlPlaneApp | None = None
        self._async_connection: psycopg.AsyncConnection[Any] | None = None
        self._sync_connection: psycopg.Connection[Any] | None = None
        self._redis: Any | None = None

    async def __call__(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        if self._delegate is None:
            await _unavailable(send)
            return
        await self._delegate(scope, receive, send)

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        startup = await receive()
        if startup.get("type") != "lifespan.startup":
            raise RuntimeError("ASGI server did not initiate lifespan startup")
        try:
            await self._start()
        except Exception as error:
            await self._close()
            await send(
                {
                    "type": "lifespan.startup.failed",
                    "message": (
                        f"managed dependency bootstrap failed: {type(error).__name__}"
                    ),
                }
            )
            return
        await send({"type": "lifespan.startup.complete"})
        shutdown = await receive()
        if shutdown.get("type") != "lifespan.shutdown":
            raise RuntimeError("ASGI server did not initiate lifespan shutdown")
        await self._close()
        await send({"type": "lifespan.shutdown.complete"})

    async def _start(self) -> None:
        settings = self._settings
        resolver = _writer_fences(settings)
        async_connection = await psycopg.AsyncConnection.connect(settings.database_url)
        self._async_connection = async_connection
        try:
            sync_connection = await asyncio.to_thread(
                _connect_sync,
                settings.database_url,
            )
            self._sync_connection = sync_connection
            redis_client = create_redis_client(settings)
            self._redis = redis_client
        except Exception:
            await self._close()
            raise
        jwks = RemoteJwksProvider(
            settings.oidc_jwks_url,
            allow_http=settings.environment is Environment.DEVELOPMENT,
        )
        event_store = PostgresEventStore(
            async_connection,
            writer_fence_resolver=resolver,
        )
        queue = RedisStreamQueue(redis_client)
        connection_lock = postgres_connection_lock(async_connection)
        schema_probe = PostgresSchemaVersionProbe(async_connection)

        async def storage_ready() -> bool:
            async with connection_lock, async_connection.transaction():
                cursor = await async_connection.execute("SELECT 1")
                row = await cursor.fetchone()
            return row == (1,)

        async def schema_version() -> int | None:
            async with connection_lock:
                version = await schema_probe()
                await async_connection.rollback()
                return version

        async def oidc_ready() -> ProbeResult:
            try:
                available = await asyncio.to_thread(jwks.ready)
            except AuthenticationError:
                available = False
            return ProbeResult(
                HealthStatus.HEALTHY if available else HealthStatus.UNAVAILABLE,
                "oidc_jwks_available" if available else "oidc_jwks_unavailable",
            )

        async def postgres_ready() -> ProbeResult:
            available = await storage_ready()
            return ProbeResult(
                HealthStatus.HEALTHY if available else HealthStatus.UNAVAILABLE,
                "postgresql_available" if available else "postgresql_unavailable",
            )

        async def redis_ready() -> ProbeResult:
            available = await queue.health()
            return ProbeResult(
                HealthStatus.HEALTHY if available else HealthStatus.DEGRADED,
                "redis_available" if available else "redis_unavailable",
            )

        async def writer_fences_ready() -> ProbeResult:
            available = await _writer_fences_match_database(
                async_connection,
                connection_lock,
                resolver,
            )
            return ProbeResult(
                HealthStatus.HEALTHY if available else HealthStatus.UNAVAILABLE,
                ("writer_fences_current" if available else "writer_fences_unavailable"),
            )

        self._delegate = ControlPlaneApp(
            authentication=AuthenticationService(
                JwtVerifier(
                    JwtValidationConfig(
                        issuer=settings.oidc_issuer,
                        audience=settings.oidc_audience,
                        clock_skew=timedelta(seconds=settings.oidc_clock_skew_seconds),
                    ),
                    jwks,
                ),
                PostgresIdentityDirectory(sync_connection),
            ),
            tenants=PostgresTenantRepository(sync_connection),
            policies=PostgresPolicyRepository(sync_connection),
            audit=PostgresAuditStore(sync_connection),
            event_store=event_store,
            projections=PostgresProjectionRepository(async_connection),
            storage_ready=storage_ready,
            schema_version=schema_version,
            health_registry=HealthRegistry(
                (
                    ComponentProbe(
                        "postgresql",
                        DependencyCriticality.CORRECTNESS,
                        postgres_ready,
                    ),
                    ComponentProbe(
                        "oidc-jwks",
                        DependencyCriticality.CORRECTNESS,
                        oidc_ready,
                    ),
                    ComponentProbe(
                        "writer-fences",
                        DependencyCriticality.CORRECTNESS,
                        writer_fences_ready,
                    ),
                    ComponentProbe(
                        "redis",
                        DependencyCriticality.OPTIONAL,
                        redis_ready,
                    ),
                ),
                transition_threshold=1,
            ),
            settings=settings,
        )

    async def _close(self) -> None:
        self._delegate = None
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
        if self._async_connection is not None:
            await self._async_connection.close()
            self._async_connection = None
        if self._sync_connection is not None:
            await asyncio.to_thread(self._sync_connection.close)
            self._sync_connection = None


def create_application() -> ManagedControlPlane:
    """Create the fail-closed managed API application for Uvicorn."""
    settings = Settings.from_env()
    if settings.process_role is not ProcessRole.API:
        raise ConfigurationError("ASGI application factory only supports the api role")
    return ManagedControlPlane(settings)


def active_process_roles() -> frozenset[ProcessRole]:
    """Return roles implemented by this release, for tests and deployment gates."""
    return _ACTIVE_ROLES


async def run_background_role(settings: Settings) -> None:
    """Run an implemented non-HTTP role until graceful termination."""
    if settings.process_role not in _ACTIVE_ROLES - {ProcessRole.API}:
        raise ConfigurationError(
            f"{settings.process_role.value} is disabled until its production "
            "adapter prerequisites are implemented"
        )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    _READY_FILE.unlink(missing_ok=True)
    try:
        if settings.process_role is ProcessRole.OUTBOX_PUBLISHER:
            await _run_outbox_publisher(settings, stop)
        else:
            await _run_reconciler(settings, stop)
    finally:
        _READY_FILE.unlink(missing_ok=True)
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(signum)


async def _run_outbox_publisher(settings: Settings, stop: asyncio.Event) -> None:
    resolver = _writer_fences(settings)
    connection = await psycopg.AsyncConnection.connect(settings.database_url)
    connection_lock = postgres_connection_lock(connection)
    schema_probe = PostgresSchemaVersionProbe(connection)
    schema_window = SchemaCompatibilityWindow(
        settings.schema_min_version, settings.schema_max_version
    )
    redis_client = create_redis_client(settings)
    try:
        queue = RedisStreamQueue(redis_client)
        if not await queue.health():
            raise RuntimeError("Redis transport is unavailable")
        repository = PostgresEventStore(
            connection,
            writer_fence_resolver=resolver,
        )
        publisher = OutboxPublisher(
            repository,
            queue,
            publisher_id=_process_identity(),
        )
        while not stop.is_set():
            if not await _writer_fences_match_database(
                connection,
                connection_lock,
                resolver,
            ):
                _READY_FILE.unlink(missing_ok=True)
                await _wait(stop, 1.0)
                continue
            async with connection_lock:
                schema_version = await schema_probe()
                await connection.rollback()
            if schema_version is None or not schema_window.accepts(schema_version):
                _READY_FILE.unlink(missing_ok=True)
                await _wait(stop, 1.0)
                continue
            _READY_FILE.touch(mode=0o600)
            contexts = _tenant_contexts(resolver)
            now = datetime.now(UTC)
            for context in contexts:
                if stop.is_set():
                    break
                await publisher.publish_batch(context, now=now, cancelled=stop)
            await _wait(stop, 1.0)
    finally:
        await redis_client.aclose()
        await connection.close()


async def _run_reconciler(settings: Settings, stop: asyncio.Event) -> None:
    resolver = _writer_fences(settings)
    connection = await psycopg.AsyncConnection.connect(settings.database_url)
    connection_lock = postgres_connection_lock(connection)
    schema_probe = PostgresSchemaVersionProbe(connection)
    schema_window = SchemaCompatibilityWindow(
        settings.schema_min_version, settings.schema_max_version
    )
    try:
        event_store = PostgresEventStore(
            connection,
            writer_fence_resolver=resolver,
        )
        repository = PostgresWorkRepository(connection, event_store)
        while not stop.is_set():
            if not await _writer_fences_match_database(
                connection,
                connection_lock,
                resolver,
            ):
                _READY_FILE.unlink(missing_ok=True)
                await _wait(stop, 5.0)
                continue
            async with connection_lock:
                schema_version = await schema_probe()
                await connection.rollback()
            if schema_version is None or not schema_window.accepts(schema_version):
                _READY_FILE.unlink(missing_ok=True)
                await _wait(stop, 5.0)
                continue
            _READY_FILE.touch(mode=0o600)
            contexts = _tenant_contexts(resolver)
            now = datetime.now(UTC)
            for context in contexts:
                if stop.is_set():
                    break
                await repository.reconcile_expired(context, now=now)
            await _wait(stop, 5.0)
    finally:
        await connection.close()


def _writer_fences(settings: Settings) -> ReloadingTenantWriterFenceResolver:
    return ReloadingTenantWriterFenceResolver(Path(settings.writer_fences_file))


def _tenant_contexts(
    resolver: TenantWriterFenceResolver | ReloadingTenantWriterFenceResolver,
) -> tuple[TenantContext, ...]:
    return tuple(
        TenantContext(tenant_id) for tenant_id in sorted(resolver.fences, key=str)
    )


async def _writer_fences_match_database(
    connection: psycopg.AsyncConnection[Any],
    connection_lock: asyncio.Lock,
    resolver: TenantWriterFenceResolver | ReloadingTenantWriterFenceResolver,
) -> bool:
    try:
        fences = dict(resolver.fences)
    except (OSError, ValueError):
        return False
    async with connection_lock, connection.transaction():
        for tenant_id, fence in fences.items():
            await connection.execute(
                "SELECT set_config('aegis.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            cursor = await connection.execute(
                """
                SELECT home_region, generation, state
                FROM tenant_writer_fences
                WHERE tenant_id = %s
                """,
                (str(tenant_id),),
            )
            row = await cursor.fetchone()
            if row != (fence.home_region, fence.generation, "active"):
                return False
    return True


def _process_identity() -> str:
    return os.environ.get("HOSTNAME", "aegis-local")


async def _wait(stop: asyncio.Event, seconds: float) -> None:
    with suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


async def _unavailable(send: Send) -> None:
    body = b'{"status":"not-ready","reason":"managed_dependencies_uninitialized"}'
    await send(
        {
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


__all__ = [
    "ManagedControlPlane",
    "active_process_roles",
    "create_application",
    "run_background_role",
]
