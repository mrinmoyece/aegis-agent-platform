"""Fast tests for storage contracts that do not require PostgreSQL."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest

import aegis_agent_platform.event_store.postgres as postgres_module
from aegis_agent_platform.domain import DomainEventType, EventEnvelope
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    EventPage,
    OutboxMessage,
    PermanentStorageError,
    ReplayCorruptionError,
    TransientStorageError,
)
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    _required_decimal,
    _required_uuid,
    classify_storage_error,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.projections import (
    ProjectionCheckpoint,
    ProjectionEngine,
)
from aegis_agent_platform.tenancy import TenantContext


def stored_event(
    position: int,
    sequence: int = 1,
    *,
    aggregate_id: str = "run-a",
    previous_aggregate_sequence: int | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-a",
        aggregate_id=aggregate_id,
        event_type=DomainEventType.RUN_STARTED,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        recorded_at=datetime(2025, 1, 1, tzinfo=UTC),
        aggregate_sequence=sequence,
        global_position=position,
        previous_aggregate_sequence=previous_aggregate_sequence,
        payload={},
    )


def pending_event() -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-a",
        aggregate_id="run-a",
        event_type=DomainEventType.RUN_STARTED,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        payload={},
    )


class FakeEventStore:
    def __init__(self, events: Sequence[EventEnvelope]) -> None:
        self.events = tuple(events)

    async def append(self, *args: object, **kwargs: object) -> int:
        del args, kwargs
        raise NotImplementedError

    async def append_from_inbox(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise NotImplementedError

    async def read_stream(
        self, *args: object, **kwargs: object
    ) -> AsyncIterator[EventEnvelope]:
        del args, kwargs
        for event in self.events:
            yield event

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        del context
        remaining = tuple(
            event
            for event in self.events
            if event.global_position is None or event.global_position > after_position
        )[:limit]
        next_cursor = remaining[-1].global_position if len(remaining) == limit else None
        return EventPage(remaining, next_cursor)


class FakeProjectionRepository:
    def __init__(self) -> None:
        self.position = 0
        self.applied: list[int] = []
        self.reset_count = 0

    async def checkpoint(
        self, context: TenantContext, projection_name: str
    ) -> ProjectionCheckpoint:
        del context
        return ProjectionCheckpoint(projection_name, self.position)

    async def apply(
        self,
        context: TenantContext,
        projection_name: str,
        events: Sequence[EventEnvelope],
        *,
        expected_checkpoint: int,
    ) -> int:
        del context, projection_name
        assert expected_checkpoint == self.position
        for event in events:
            position = event.global_position
            assert position is not None
            if position > self.position:
                self.applied.append(position)
                self.position = position
        return self.position

    async def reset(self, context: TenantContext, projection_name: str) -> None:
        del context, projection_name
        self.position = 0
        self.applied.clear()
        self.reset_count += 1

    async def begin_rebuild(
        self, context: TenantContext, projection_name: str
    ) -> None:
        del context, projection_name

    async def end_rebuild(
        self, context: TenantContext, projection_name: str
    ) -> None:
        del context, projection_name


def test_projection_catch_up_is_idempotent_and_rebuildable() -> None:
    events = (stored_event(3), stored_event(7, sequence=2))
    repository = FakeProjectionRepository()
    engine = ProjectionEngine(
        FakeEventStore(events),  # type: ignore[arg-type]
        repository,
        page_size=1,
    )
    context = TenantContext(TenantId("tenant-a"))

    first = asyncio.run(engine.catch_up(context, "run-status"))
    second = asyncio.run(engine.catch_up(context, "run-status"))
    rebuilt = asyncio.run(engine.rebuild(context, "run-status"))

    assert first.last_global_position == second.last_global_position == 7
    assert rebuilt.last_global_position == 7
    assert repository.applied == [3, 7]
    assert repository.reset_count == 1


def test_projection_detects_sequence_corruption() -> None:
    engine = ProjectionEngine(
        FakeEventStore((stored_event(1), stored_event(2, sequence=3))),  # type: ignore[arg-type]
        FakeProjectionRepository(),
        page_size=1,
    )

    with pytest.raises(ReplayCorruptionError, match="sequence gap"):
        asyncio.run(engine.catch_up(TenantContext(TenantId("tenant-a")), "run-status"))


def test_projection_detects_checkpoint_resume_sequence_gaps() -> None:
    repository = FakeProjectionRepository()
    repository.position = 6
    engine = ProjectionEngine(
        FakeEventStore((stored_event(7, 4, previous_aggregate_sequence=2),)),  # type: ignore[arg-type]
        repository,
    )

    with pytest.raises(ReplayCorruptionError, match="sequence gap"):
        asyncio.run(engine.catch_up(TenantContext(TenantId("tenant-a")), "run-status"))


def test_append_from_inbox_ignores_telemetry_failures_on_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RaisingTelemetry:
        def append_completed(self, event_count: int, elapsed_seconds: float) -> None:
            del event_count, elapsed_seconds

        def append_conflicted(self) -> None:
            raise RuntimeError("telemetry down")

        def outbox_lag_observed(self, lag_seconds: float) -> None:
            del lag_seconds

        def projection_lag_observed(self, lag_events: int) -> None:
            del lag_events

    class DummyAsyncConnection:
        def __init__(self) -> None:
            self.calls = 0

        async def execute(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            self.calls += 1

            class InsertedCursor:
                async def fetchone(self) -> tuple[str]:
                    return ("message-1",)

            if self.calls == 1:
                return InsertedCursor()
            raise AssertionError("execute should not run after conflict")

    @asynccontextmanager
    async def noop_transaction(
        connection: object, lock: object, context: TenantContext
    ) -> AsyncIterator[None]:
        del connection, lock, context
        yield

    async def conflicted_append(
        self: PostgresEventStore,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[object],
    ) -> int:
        del self, events, expected_version, outbox
        raise ConcurrencyError(0, 1)

    monkeypatch.setattr(postgres_module, "_tenant_transaction", noop_transaction)
    store = PostgresEventStore(
        DummyAsyncConnection(),  # type: ignore[arg-type]
        telemetry=RaisingTelemetry(),
    )
    monkeypatch.setattr(
        store,
        "_append_in_transaction",
        conflicted_append.__get__(store, PostgresEventStore),
    )

    with pytest.raises(ConcurrencyError):
        asyncio.run(
            store.append_from_inbox(
                TenantContext(TenantId("tenant-a")),
                source="worker",
                message_id="message-1",
                events=[pending_event()],
                expected_version=0,
            )
        )


def test_outbox_contract_rejects_ambiguous_delivery_metadata() -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        OutboxMessage(
            message_id=uuid4(),
            destination="work",
            payload={},
            headers={},
            available_at=datetime(2025, 1, 1, tzinfo=UTC),
            max_attempts=0,
        )


def test_postgres_failures_have_stable_retry_classification() -> None:
    assert isinstance(
        classify_storage_error(psycopg.OperationalError("offline")),
        TransientStorageError,
    )
    assert isinstance(
        classify_storage_error(psycopg.ProgrammingError("bad schema")),
        PermanentStorageError,
    )


def test_projection_helpers_classify_invalid_uuid_and_decimal_values() -> None:
    with pytest.raises(PermanentStorageError, match="uuid artifact_id"):
        _required_uuid({"artifact_id": "not-a-uuid"}, "artifact_id")
    with pytest.raises(PermanentStorageError, match="finite non-negative cost_usd"):
        _required_decimal({"cost_usd": "NaN"}, "cost_usd")


def test_append_ignores_telemetry_failures_after_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RaisingTelemetry:
        def append_completed(self, event_count: int, elapsed_seconds: float) -> None:
            del event_count, elapsed_seconds
            raise RuntimeError("telemetry down")

        def append_conflicted(self) -> None:
            raise RuntimeError("telemetry down")

        def outbox_lag_observed(self, lag_seconds: float) -> None:
            del lag_seconds

        def projection_lag_observed(self, lag_events: int) -> None:
            del lag_events

    class DummyAsyncConnection:
        pass

    @asynccontextmanager
    async def noop_transaction(
        connection: object, lock: object, context: TenantContext
    ) -> AsyncIterator[None]:
        del connection, lock, context
        yield

    async def fake_append(
        self: PostgresEventStore,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[object],
    ) -> int:
        del self, outbox
        return expected_version + len(events)

    monkeypatch.setattr(postgres_module, "_tenant_transaction", noop_transaction)
    store = PostgresEventStore(
        DummyAsyncConnection(),  # type: ignore[arg-type]
        telemetry=RaisingTelemetry(),
    )
    monkeypatch.setattr(
        store,
        "_append_in_transaction",
        fake_append.__get__(store, PostgresEventStore),
    )

    version = asyncio.run(
        store.append(
            TenantContext(TenantId("tenant-a")),
            [pending_event()],
            expected_version=0,
        )
    )

    assert version == 1


def test_projection_rejects_invalid_page_size_and_positions() -> None:
    with pytest.raises(ValueError, match="page_size"):
        ProjectionEngine(FakeEventStore(()), FakeProjectionRepository(), page_size=0)  # type: ignore[arg-type]

    missing_position = EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-a",
        aggregate_id="run-a",
        event_type=DomainEventType.RUN_STARTED,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        aggregate_sequence=1,
        payload={},
    )
    engine = ProjectionEngine(
        FakeEventStore((missing_position,)),  # type: ignore[arg-type]
        FakeProjectionRepository(),
    )
    with pytest.raises(ReplayCorruptionError, match="global positions"):
        asyncio.run(engine.catch_up(TenantContext(TenantId("tenant-a")), "run-status"))


def test_concurrency_error_exposes_expected_and_actual_versions() -> None:
    error = ConcurrencyError(2, 3)

    assert error.expected == 2
    assert error.actual == 3
    assert "expected 2, actual 3" in str(error)
