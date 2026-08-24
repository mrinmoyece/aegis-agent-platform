"""Fast tests for storage contracts that do not require PostgreSQL."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest

from aegis_agent_platform.domain import DomainEventType, EventEnvelope
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    EventPage,
    OutboxMessage,
    PermanentStorageError,
    ReplayCorruptionError,
    TransientStorageError,
)
from aegis_agent_platform.event_store.postgres import classify_storage_error
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.projections import (
    ProjectionCheckpoint,
    ProjectionEngine,
)
from aegis_agent_platform.tenancy import TenantContext


def stored_event(position: int, sequence: int = 1) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-a",
        aggregate_id="run-a",
        event_type=DomainEventType.RUN_STARTED,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        recorded_at=datetime(2025, 1, 1, tzinfo=UTC),
        aggregate_sequence=sequence,
        global_position=position,
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
