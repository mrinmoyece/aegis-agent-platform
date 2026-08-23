"""PostgreSQL event, inbox/outbox, and projection adapters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from threading import Lock
from time import monotonic
from typing import Any, ClassVar, Protocol
from uuid import UUID
from weakref import WeakKeyDictionary

import psycopg
from psycopg import errors, sql
from psycopg.types.json import Jsonb

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EventEnvelope,
    JsonValue,
    TraceContext,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import (
    AppendResult,
    ClaimedOutboxMessage,
    ConcurrencyError,
    EventPage,
    FencingError,
    OutboxMessage,
    PermanentStorageError,
    ReplayCorruptionError,
    TransientStorageError,
)
from aegis_agent_platform.projections import ProjectionCheckpoint
from aegis_agent_platform.tenancy import TenantContext

_READ_STREAM = """
SELECT event_id, tenant_id, aggregate_id, aggregate_sequence, global_position,
    event_type, schema_version, occurred_at, recorded_at, payload, metadata,
    correlation_id, causation_id, actor_id, actor_kind, identity_reference,
    policy_reference, audit_reference, idempotency_key, traceparent, tracestate
FROM events
WHERE tenant_id = %s AND aggregate_id = %s
  AND aggregate_sequence > %s
ORDER BY aggregate_sequence
LIMIT %s
"""
_CLAIM_OUTBOX_ALL_DESTINATIONS = """
WITH candidates AS (
    SELECT tenant_id, message_id
    FROM outbox_messages
    WHERE tenant_id = %s
      AND status IN ('pending', 'leased')
      AND (
          attempt_count < max_attempts
          OR (
              status = 'leased'
              AND last_error_code IS NULL
          )
      )
      AND available_at <= clock_timestamp()
      AND (
          lease_expires_at IS NULL
          OR lease_expires_at <= clock_timestamp()
      )
    ORDER BY available_at, message_id
    FOR UPDATE SKIP LOCKED
    LIMIT %s
)
UPDATE outbox_messages AS outbox
SET status = 'leased',
    lease_owner = %s,
    lease_expires_at = clock_timestamp()
        + (%s * interval '1 second'),
    attempt_count = attempt_count + 1,
    last_error_code = NULL
FROM candidates
WHERE outbox.tenant_id = candidates.tenant_id
  AND outbox.message_id = candidates.message_id
RETURNING outbox.message_id, outbox.event_id,
    outbox.destination, outbox.payload, outbox.headers,
    outbox.available_at, outbox.max_attempts,
    outbox.attempt_count, outbox.lease_owner,
    outbox.lease_expires_at
"""
_CLAIM_OUTBOX_ONE_DESTINATION = """
WITH candidates AS (
    SELECT tenant_id, message_id
    FROM outbox_messages
    WHERE tenant_id = %s
      AND destination = %s
      AND status IN ('pending', 'leased')
      AND (
          attempt_count < max_attempts
          OR (
              status = 'leased'
              AND last_error_code IS NULL
          )
      )
      AND available_at <= clock_timestamp()
      AND (
          lease_expires_at IS NULL
          OR lease_expires_at <= clock_timestamp()
      )
    ORDER BY available_at, message_id
    FOR UPDATE SKIP LOCKED
    LIMIT %s
)
UPDATE outbox_messages AS outbox
SET status = 'leased',
    lease_owner = %s,
    lease_expires_at = clock_timestamp()
        + (%s * interval '1 second'),
    attempt_count = attempt_count + 1,
    last_error_code = NULL
FROM candidates
WHERE outbox.tenant_id = candidates.tenant_id
  AND outbox.message_id = candidates.message_id
RETURNING outbox.message_id, outbox.event_id,
    outbox.destination, outbox.payload, outbox.headers,
    outbox.available_at, outbox.max_attempts,
    outbox.attempt_count, outbox.lease_owner,
    outbox.lease_expires_at
"""
_CONNECTION_LOCKS: WeakKeyDictionary[psycopg.AsyncConnection[Any], asyncio.Lock] = (
    WeakKeyDictionary()
)
_CONNECTION_LOCKS_GUARD = Lock()
_READ_ALL = """
SELECT event_id, tenant_id, aggregate_id, aggregate_sequence, global_position,
    event_type, schema_version, occurred_at, recorded_at, payload, metadata,
    correlation_id, causation_id, actor_id, actor_kind, identity_reference,
    policy_reference, audit_reference, idempotency_key, traceparent, tracestate,
    previous_aggregate_sequence
FROM (
    SELECT event_id, tenant_id, aggregate_id, aggregate_sequence,
        global_position, event_type, schema_version, occurred_at, recorded_at,
        payload, metadata, correlation_id, causation_id, actor_id, actor_kind,
        identity_reference, policy_reference, audit_reference, idempotency_key,
        traceparent, tracestate,
        lag(aggregate_sequence) OVER (
            PARTITION BY tenant_id, aggregate_id
            ORDER BY aggregate_sequence
        ) AS previous_aggregate_sequence
    FROM events
    WHERE tenant_id = %s
) AS ordered_events
WHERE global_position > %s
ORDER BY global_position
LIMIT %s
"""


class StorageTelemetry(Protocol):
    """Bounded-cardinality storage signals with no payload or tenant labels."""

    def append_completed(self, event_count: int, elapsed_seconds: float) -> None:
        """Observe successful append latency and batch size."""
        ...

    def append_conflicted(self) -> None:
        """Count an optimistic concurrency conflict."""
        ...

    def outbox_lag_observed(self, lag_seconds: float) -> None:
        """Observe age of publishable work."""
        ...

    def projection_lag_observed(self, lag_events: int) -> None:
        """Observe a bounded projection cursor lag."""
        ...


class NullStorageTelemetry:
    """Default telemetry sink; it deliberately invents no metric values."""

    def append_completed(self, event_count: int, elapsed_seconds: float) -> None:
        del event_count, elapsed_seconds

    def append_conflicted(self) -> None:
        pass

    def outbox_lag_observed(self, lag_seconds: float) -> None:
        del lag_seconds

    def projection_lag_observed(self, lag_events: int) -> None:
        del lag_events


def _observe_telemetry(callback: Callable[..., None], *args: object) -> None:
    with suppress(Exception):
        callback(*args)


class PostgresEventStore:
    """Tenant-isolated append-only ledger using PostgreSQL transactions."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        *,
        telemetry: StorageTelemetry | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._connection = connection
        self._telemetry = telemetry or NullStorageTelemetry()
        self._monotonic = monotonic_clock
        self._lock = postgres_connection_lock(connection)

    async def append(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> int:
        """Atomically append a gapless aggregate batch and outgoing messages."""
        _validate_append(context, events, expected_version)
        started_at = self._monotonic()
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                version = await self._append_in_transaction(
                    events,
                    expected_version=expected_version,
                    outbox=outbox,
                )
            _observe_telemetry(
                self._telemetry.append_completed,
                len(events),
                self._monotonic() - started_at,
            )
            return version
        except ConcurrencyError:
            _observe_telemetry(self._telemetry.append_conflicted)
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def append_atomic(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        mutation: Callable[
            [psycopg.AsyncConnection[Any]],
            Awaitable[None],
        ],
        outbox: Sequence[OutboxMessage] = (),
    ) -> int:
        """Append ledger truth and one adapter projection mutation atomically."""
        _validate_append(context, events, expected_version)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                version = await self._append_in_transaction(
                    events,
                    expected_version=expected_version,
                    outbox=outbox,
                )
                await mutation(self._connection)
                return version
        except ConcurrencyError:
            self._telemetry.append_conflicted()
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def append_from_inbox(
        self,
        context: TenantContext,
        *,
        source: str,
        message_id: str,
        events: Sequence[EventEnvelope],
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
        mutation: (
            Callable[[psycopg.AsyncConnection[Any]], Awaitable[None]] | None
        ) = None,
    ) -> AppendResult:
        """Deduplicate delivery and append all consequences in one transaction."""
        if not source or not message_id:
            raise ValueError("inbox source and message_id are required")
        _validate_append(context, events, expected_version)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                inserted = await self._connection.execute(
                    """
                    INSERT INTO inbox_messages (
                        tenant_id, source, message_id, received_at
                    ) VALUES (%s, %s, %s, clock_timestamp())
                    ON CONFLICT (tenant_id, source, message_id) DO NOTHING
                    RETURNING message_id
                    """,
                    (str(context.tenant_id), source, message_id),
                )
                if await inserted.fetchone() is None:
                    existing = await self._connection.execute(
                        """
                        SELECT aggregate_version
                        FROM inbox_messages
                        WHERE tenant_id = %s AND source = %s AND message_id = %s
                        """,
                        (str(context.tenant_id), source, message_id),
                    )
                    row = await existing.fetchone()
                    if row is None or row[0] is None:
                        raise PermanentStorageError(
                            "duplicate inbox record has no committed result"
                        )
                    return AppendResult(aggregate_version=int(row[0]), duplicate=True)
                version = await self._append_in_transaction(
                    events,
                    expected_version=expected_version,
                    outbox=outbox,
                )
                await self._connection.execute(
                    """
                    UPDATE inbox_messages
                    SET processed_at = clock_timestamp(), aggregate_version = %s
                    WHERE tenant_id = %s AND source = %s AND message_id = %s
                    """,
                    (version, str(context.tenant_id), source, message_id),
                )
                if mutation is not None:
                    await mutation(self._connection)
                return AppendResult(aggregate_version=version)
        except ConcurrencyError:
            _observe_telemetry(self._telemetry.append_conflicted)
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def append_fenced(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        work_id: UUID,
        lease_token: UUID,
        lease_generation: int,
        at: datetime,
        outbox: Sequence[OutboxMessage] = (),
        mutation: (
            Callable[[psycopg.AsyncConnection[Any]], Awaitable[None]] | None
        ) = None,
    ) -> int:
        """Append worker effects only while its PostgreSQL fence is current."""
        _validate_append(context, events, expected_version)
        if at.tzinfo is None or lease_generation < 1:
            raise ValueError("valid fence generation and timestamp are required")
        if any(event.aggregate_id != str(work_id) for event in events):
            raise ValueError("fenced events must belong to the leased work")
        for event in events:
            if (
                event.payload.get("lease_token") != str(lease_token)
                or event.payload.get("lease_generation") != lease_generation
            ):
                raise ValueError("fenced event payload does not match lease")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT generation
                    FROM work_leases
                    WHERE tenant_id = %s AND work_id = %s
                      AND lease_token = %s AND generation = %s
                      AND released_at IS NULL
                      AND expires_at > clock_timestamp()
                    FOR UPDATE
                    """,
                    (
                        str(context.tenant_id),
                        work_id,
                        lease_token,
                        lease_generation,
                    ),
                )
                if await cursor.fetchone() is None:
                    raise FencingError(lease_generation, 0)
                version = await self._append_in_transaction(
                    events,
                    expected_version=expected_version,
                    outbox=outbox,
                )
                if mutation is not None:
                    await mutation(self._connection)
                return version
        except FencingError:
            raise
        except ConcurrencyError:
            self._telemetry.append_conflicted()
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def _append_in_transaction(
        self,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[OutboxMessage],
    ) -> int:
        first = events[0]
        await self._connection.execute(
            """
            INSERT INTO tenant_event_commit_locks (tenant_id)
            VALUES (%s)
            ON CONFLICT (tenant_id) DO NOTHING
            """,
            (first.tenant_id,),
        )
        await self._connection.execute(
            """
            SELECT tenant_id
            FROM tenant_event_commit_locks
            WHERE tenant_id = %s
            FOR UPDATE
            """,
            (first.tenant_id,),
        )
        await self._connection.execute(
            """
            INSERT INTO event_stream_heads (
                tenant_id, aggregate_id, current_version
            ) VALUES (%s, %s, 0)
            ON CONFLICT (tenant_id, aggregate_id) DO NOTHING
            """,
            (first.tenant_id, first.aggregate_id),
        )
        head = await self._connection.execute(
            """
            SELECT current_version
            FROM event_stream_heads
            WHERE tenant_id = %s AND aggregate_id = %s
            FOR UPDATE
            """,
            (first.tenant_id, first.aggregate_id),
        )
        row = await head.fetchone()
        if row is None:
            raise PermanentStorageError("aggregate head could not be established")
        actual_version = int(row[0])
        if actual_version != expected_version:
            raise ConcurrencyError(expected_version, actual_version)

        version = expected_version
        for event in events:
            version += 1
            await self._connection.execute(
                """
                INSERT INTO events (
                    event_id, tenant_id, aggregate_id, aggregate_sequence,
                    event_type, schema_version, occurred_at, payload, metadata,
                    correlation_id, causation_id, actor_id, actor_kind,
                    identity_reference, policy_reference, audit_reference,
                    idempotency_key, traceparent, tracestate
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                _event_insert_values(event, version),
            )
        await self._connection.execute(
            """
            UPDATE event_stream_heads
            SET current_version = %s
            WHERE tenant_id = %s AND aggregate_id = %s
            """,
            (version, first.tenant_id, first.aggregate_id),
        )
        for message in outbox:
            await self._connection.execute(
                """
                INSERT INTO outbox_messages (
                    tenant_id, message_id, event_id, destination, payload,
                    headers, available_at, max_attempts
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    first.tenant_id,
                    message.message_id,
                    message.event_id,
                    message.destination,
                    Jsonb(thaw_json(message.payload)),
                    Jsonb(thaw_json(message.headers)),
                    message.available_at,
                    message.max_attempts,
                ),
            )
        return version

    async def read_stream(
        self,
        context: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
        limit: int = 100,
    ) -> AsyncIterator[EventEnvelope]:
        """Read and validate a bounded aggregate stream."""
        _validate_page_arguments(after_version, limit)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    _READ_STREAM,
                    (
                        str(context.tenant_id),
                        aggregate_id,
                        after_version,
                        limit,
                    ),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        expected = after_version
        for row in rows:
            event = _event_from_row(row)
            expected += 1
            if event.aggregate_sequence != expected:
                raise ReplayCorruptionError(
                    f"aggregate sequence gap: expected {expected}, "
                    f"found {event.aggregate_sequence}"
                )
            yield event

    async def current_version(
        self,
        context: TenantContext,
        aggregate_id: str,
    ) -> int:
        """Read the current aggregate head for a subsequent guarded append."""
        if not aggregate_id:
            raise ValueError("aggregate_id is required")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT current_version
                    FROM event_stream_heads
                    WHERE tenant_id = %s AND aggregate_id = %s
                    """,
                    (str(context.tenant_id), aggregate_id),
                )
                row = await cursor.fetchone()
                return int(row[0]) if row is not None else 0
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        """Read a deterministic bounded tenant page by global position."""
        _validate_page_arguments(after_position, limit)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    _READ_ALL,
                    (str(context.tenant_id), after_position, limit),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        events = tuple(_event_from_row(row) for row in rows)
        for row, event in zip(rows, events, strict=True):
            previous = row[21]
            expected = 1 if previous is None else int(previous) + 1
            if event.aggregate_sequence != expected:
                raise ReplayCorruptionError(
                    f"aggregate sequence gap: expected {expected}, "
                    f"found {event.aggregate_sequence}"
                )
        return EventPage(
            events=events,
            next_cursor=(events[-1].global_position if len(events) == limit else None),
        )

    async def claim_outbox(
        self,
        context: TenantContext,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        now: datetime,
        limit: int,
        destination: str | None = None,
    ) -> tuple[ClaimedOutboxMessage, ...]:
        """Lease publishable work using skip-locked race-safe claiming.

        Pass ``destination`` to restrict claiming to a specific outbox queue
        (e.g. ``"aegis.work"`` for the worker publisher). Omit it to claim
        from all destinations, which is useful for integration tests and
        general-purpose outbox consumers.
        """
        lease_duration = lease_expires_at - now
        if (
            not lease_owner
            or now.tzinfo is None
            or not timedelta(seconds=1) <= lease_duration <= timedelta(hours=1)
        ):
            raise ValueError("valid lease owner and future expiry are required")
        if not 1 <= limit <= 100:
            raise ValueError("outbox claim limit must be between 1 and 100")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                if destination is not None:
                    statement = _CLAIM_OUTBOX_ONE_DESTINATION
                    params: tuple[object, ...] = (
                        str(context.tenant_id),
                        destination,
                        limit,
                        lease_owner,
                        lease_duration.total_seconds(),
                    )
                else:
                    statement = _CLAIM_OUTBOX_ALL_DESTINATIONS
                    params = (
                        str(context.tenant_id),
                        limit,
                        lease_owner,
                        lease_duration.total_seconds(),
                    )
                cursor = await self._connection.execute(statement, params)
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return tuple(
            ClaimedOutboxMessage(
                message=OutboxMessage(
                    message_id=row[0],
                    event_id=row[1],
                    destination=row[2],
                    payload=row[3],
                    headers=row[4],
                    available_at=row[5],
                    max_attempts=row[6],
                ),
                attempt_count=row[7],
                lease_owner=row[8],
                lease_expires_at=row[9],
            )
            for row in rows
        )

    async def mark_outbox_published(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        published_at: datetime,
    ) -> None:
        """Mark only the exact current lease as delivered.

        ``lease_expires_at`` acts as a fencing token: if the lease has expired
        and been reclaimed by another attempt (even with the same owner name),
        the expiry timestamp will differ and the stale completion will be a
        no-op that raises ``ConcurrencyError`` instead of silently succeeding.
        """
        await self._update_outbox_state(
            context,
            """
            UPDATE outbox_messages
            SET status = 'published', published_at = %s,
                lease_owner = NULL, lease_expires_at = NULL
            WHERE tenant_id = %s AND message_id = %s
              AND status = 'leased' AND lease_owner = %s
              AND lease_expires_at = %s
            """,
            (
                published_at,
                str(context.tenant_id),
                message_id,
                lease_owner,
                lease_expires_at,
            ),
        )

    async def mark_outbox_failed(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        retry_at: datetime,
        error_code: str,
    ) -> None:
        """Release the exact current lease or dead-letter exhausted work.

        ``lease_expires_at`` acts as a fencing token — see ``mark_outbox_published``.
        """
        if not error_code or len(error_code) > 128:
            raise ValueError("bounded error_code is required")
        await self._update_outbox_state(
            context,
            """
            UPDATE outbox_messages
            SET status = CASE
                    WHEN attempt_count >= max_attempts
                    THEN 'dead_letter' ELSE 'pending' END,
                available_at = %s, last_error_code = %s,
                lease_owner = NULL, lease_expires_at = NULL
            WHERE tenant_id = %s AND message_id = %s
              AND status = 'leased' AND lease_owner = %s
              AND lease_expires_at = %s
            """,
            (
                retry_at,
                error_code,
                str(context.tenant_id),
                message_id,
                lease_owner,
                lease_expires_at,
            ),
        )

    async def mark_outbox_dead_lettered(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        error_code: str,
    ) -> None:
        """Immediately quarantine a permanently invalid envelope.

        Unlike ``mark_outbox_failed``, this method sets ``status =
        'dead_letter'`` unconditionally — the attempt count does not matter.
        Use for ``PermanentQueueError`` where retrying can never succeed.
        """
        if not error_code or len(error_code) > 128:
            raise ValueError("bounded error_code is required")
        await self._update_outbox_state(
            context,
            """
            UPDATE outbox_messages
            SET status = 'dead_letter',
                last_error_code = %s,
                lease_owner = NULL, lease_expires_at = NULL
            WHERE tenant_id = %s AND message_id = %s
              AND status = 'leased' AND lease_owner = %s
              AND lease_expires_at = %s
            """,
            (
                error_code,
                str(context.tenant_id),
                message_id,
                lease_owner,
                lease_expires_at,
            ),
        )

    async def _update_outbox_state(
        self,
        context: TenantContext,
        statement: str,
        parameters: tuple[object, ...],
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(statement, parameters)
                if cursor.rowcount != 1:
                    raise ConcurrencyError(1, 0)
        except ConcurrencyError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error


class PostgresProjectionRepository:
    """Transactional disposable read models with monotonic checkpoints."""

    _TABLES: ClassVar[Mapping[str, str]] = {
        "run-status": "run_status_projection",
        "artifact-index": "artifact_index_projection",
        "model-usage": "model_usage_projection",
        "pending-approvals": "pending_approvals_projection",
        "tenant-listing": "tenant_listing_projection",
        "usage-quota": "usage_quota_projection",
    }

    def __init__(self, connection: psycopg.AsyncConnection[Any]) -> None:
        self._connection = connection
        self._lock = postgres_connection_lock(connection)

    async def checkpoint(
        self, context: TenantContext, projection_name: str
    ) -> ProjectionCheckpoint:
        _projection_table(projection_name, self._TABLES)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT last_global_position
                    FROM projection_checkpoints
                    WHERE tenant_id = %s AND projection_name = %s
                    """,
                    (str(context.tenant_id), projection_name),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return ProjectionCheckpoint(projection_name, int(row[0]) if row else 0)

    async def apply(
        self,
        context: TenantContext,
        projection_name: str,
        events: Sequence[EventEnvelope],
        *,
        expected_checkpoint: int,
    ) -> int:
        _projection_table(projection_name, self._TABLES)
        if not events:
            return expected_checkpoint
        positions = [event.global_position for event in events]
        if any(position is None for position in positions):
            raise ReplayCorruptionError("projection events require global positions")
        final_position = int(positions[-1] or 0)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                await self._connection.execute(
                    """
                    INSERT INTO projection_checkpoints (
                        tenant_id, projection_name, last_global_position,
                        updated_at
                    ) VALUES (%s, %s, 0, clock_timestamp())
                    ON CONFLICT (tenant_id, projection_name) DO NOTHING
                    """,
                    (str(context.tenant_id), projection_name),
                )
                cursor = await self._connection.execute(
                    """
                    SELECT last_global_position
                    FROM projection_checkpoints
                    WHERE tenant_id = %s AND projection_name = %s
                    FOR UPDATE
                    """,
                    (str(context.tenant_id), projection_name),
                )
                row = await cursor.fetchone()
                actual = int(row[0]) if row else 0
                if actual >= final_position:
                    return actual
                if actual != expected_checkpoint:
                    raise ConcurrencyError(expected_checkpoint, actual)
                for event in events:
                    if event.tenant_id != str(context.tenant_id):
                        raise PermanentStorageError(
                            "projection event tenant does not match context"
                        )
                    await self._apply_event(projection_name, event)
                await self._connection.execute(
                    """
                    UPDATE projection_checkpoints
                    SET last_global_position = %s, updated_at = clock_timestamp()
                    WHERE tenant_id = %s AND projection_name = %s
                    """,
                    (final_position, str(context.tenant_id), projection_name),
                )
                return final_position
        except InvalidOperation as error:
            raise PermanentStorageError(
                "projection event payload is invalid"
            ) from error
        except ValueError as error:
            raise PermanentStorageError(
                "projection event payload is invalid"
            ) from error
        except ConcurrencyError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def reset(self, context: TenantContext, projection_name: str) -> None:
        table = _projection_table(projection_name, self._TABLES)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                await self._connection.execute(
                    sql.SQL("DELETE FROM {} WHERE tenant_id = %s").format(
                        sql.Identifier(table)
                    ),
                    (str(context.tenant_id),),
                )
                await self._connection.execute(
                    """
                    DELETE FROM projection_checkpoints
                    WHERE tenant_id = %s AND projection_name = %s
                    """,
                    (str(context.tenant_id), projection_name),
                )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def begin_rebuild(self, context: TenantContext, projection_name: str) -> None:
        """Acquire a session-level advisory lock that blocks concurrent admission.

        Budget admission in ``PostgresGatewayRepository.reserve()`` uses
        ``pg_try_advisory_lock`` with the same key and fails closed when this
        lock is held.  The lock is automatically released when the database
        session ends, so a crashed worker cannot permanently block admission.
        """
        try:
            await self._connection.execute(
                """
                SELECT pg_advisory_lock(
                    hashtext('aegis:rebuild:' || %s || ':' || %s)::bigint
                )
                """,
                (projection_name, str(context.tenant_id)),
            )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def end_rebuild(self, context: TenantContext, projection_name: str) -> None:
        """Release the advisory lock acquired by ``begin_rebuild``."""
        try:
            await self._connection.execute(
                """
                SELECT pg_advisory_unlock(
                    hashtext('aegis:rebuild:' || %s || ':' || %s)::bigint
                )
                """,
                (projection_name, str(context.tenant_id)),
            )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def _apply_event(self, projection_name: str, event: EventEnvelope) -> None:
        if projection_name == "run-status":
            await self._apply_run_status(event)
        elif projection_name == "artifact-index":
            await self._apply_artifact(event)
        elif projection_name == "pending-approvals":
            await self._apply_approval(event)
        elif projection_name == "model-usage":
            await self._apply_model_usage(event)
        elif projection_name == "usage-quota":
            await self._apply_usage(event)
        elif projection_name == "tenant-listing":
            await self._apply_tenant(event)

    async def _apply_run_status(self, event: EventEnvelope) -> None:
        statuses: dict[DomainEventType, str] = {
            DomainEventType.RUN_STARTED: "running",
            DomainEventType.RUN_COMPLETED: "completed",
            DomainEventType.RUN_FAILED: "failed",
        }
        event_type = _domain_event_type(event.event_type)
        status: str | None
        if event_type is DomainEventType.RUN_STATUS_CHANGED:
            status = _required_string(event.payload, "status")
        else:
            status = statuses.get(event_type) if event_type is not None else None
        if status is None:
            return
        await self._connection.execute(
            """
            INSERT INTO run_status_projection (
                tenant_id, run_id, status, aggregate_sequence,
                last_global_position, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, run_id) DO UPDATE
            SET status = EXCLUDED.status,
                aggregate_sequence = EXCLUDED.aggregate_sequence,
                last_global_position = EXCLUDED.last_global_position,
                updated_at = EXCLUDED.updated_at
            WHERE run_status_projection.aggregate_sequence
                < EXCLUDED.aggregate_sequence
            """,
            (
                event.tenant_id,
                event.aggregate_id,
                status,
                event.aggregate_sequence,
                event.global_position,
                event.recorded_at,
            ),
        )

    async def _apply_artifact(self, event: EventEnvelope) -> None:
        if (
            _domain_event_type(event.event_type)
            is not DomainEventType.ARTIFACT_RECORDED
        ):
            return
        await self._connection.execute(
            """
            INSERT INTO artifact_index_projection (
                tenant_id, artifact_id, run_id, artifact_kind,
                source_reference, summary, event_id, global_position
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, artifact_id) DO NOTHING
            """,
            (
                event.tenant_id,
                _required_uuid(event.payload, "artifact_id"),
                event.aggregate_id,
                _required_string(event.payload, "artifact_kind"),
                _required_string(event.payload, "source_reference"),
                _required_string(event.payload, "summary"),
                event.event_id,
                event.global_position,
            ),
        )

    async def _apply_approval(self, event: EventEnvelope) -> None:
        event_type = _domain_event_type(event.event_type)
        if event_type is DomainEventType.APPROVAL_REQUESTED:
            await self._connection.execute(
                """
                INSERT INTO pending_approvals_projection (
                    tenant_id, approval_id, run_id, proposal_reference,
                    requested_at, event_id, global_position
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, approval_id) DO NOTHING
                """,
                (
                    event.tenant_id,
                    _required_uuid(event.payload, "approval_id"),
                    event.aggregate_id,
                    _required_string(event.payload, "proposal_reference"),
                    event.occurred_at,
                    event.event_id,
                    event.global_position,
                ),
            )

        elif event_type is DomainEventType.APPROVAL_DECIDED:
            await self._connection.execute(
                """
                DELETE FROM pending_approvals_projection
                WHERE tenant_id = %s AND approval_id = %s
                """,
                (
                    event.tenant_id,
                    _required_uuid(event.payload, "approval_id"),
                ),
            )

    async def _apply_model_usage(self, event: EventEnvelope) -> None:
        if (
            _domain_event_type(event.event_type)
            is not DomainEventType.MODEL_USAGE_RECORDED
        ):
            return
        recorded_at = event.recorded_at or event.occurred_at
        input_tokens = _required_int(event.payload, "input_tokens")
        output_tokens = _required_int(event.payload, "output_tokens")
        cache_read_tokens = _required_int(event.payload, "cache_read_tokens")
        cache_write_tokens = _required_int(event.payload, "cache_write_tokens")
        reasoning_tokens = _required_int(event.payload, "reasoning_tokens")
        await self._connection.execute(
            """
            INSERT INTO model_usage_projection (
                tenant_id, request_id, run_id, provider, model, price_version,
                input_tokens, output_tokens, cache_read_tokens,
                cache_write_tokens, reasoning_tokens, total_tokens, cost_usd,
                recorded_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (tenant_id, request_id) DO UPDATE
            SET run_id = EXCLUDED.run_id,
                provider = EXCLUDED.provider,
                model = EXCLUDED.model,
                price_version = EXCLUDED.price_version,
                input_tokens = EXCLUDED.input_tokens,
                output_tokens = EXCLUDED.output_tokens,
                cache_read_tokens = EXCLUDED.cache_read_tokens,
                cache_write_tokens = EXCLUDED.cache_write_tokens,
                reasoning_tokens = EXCLUDED.reasoning_tokens,
                total_tokens = EXCLUDED.total_tokens,
                cost_usd = EXCLUDED.cost_usd,
                recorded_at = EXCLUDED.recorded_at
            """,
            (
                event.tenant_id,
                UUID(_required_string(event.payload, "request_id")),
                UUID(_required_string(event.payload, "run_id")),
                _required_string(event.payload, "provider"),
                _required_string(event.payload, "model"),
                _required_string(event.payload, "price_version"),
                input_tokens,
                output_tokens,
                cache_read_tokens,
                cache_write_tokens,
                reasoning_tokens,
                (
                    input_tokens
                    + output_tokens
                    + cache_read_tokens
                    + cache_write_tokens
                    + reasoning_tokens
                ),
                Decimal(_required_string(event.payload, "cost_usd")),
                recorded_at,
            ),
        )

    async def _apply_usage(self, event: EventEnvelope) -> None:
        if _domain_event_type(event.event_type) is not DomainEventType.USAGE_RECORDED:
            return
        period = _required_string(event.payload, "period")
        tokens = _required_int(event.payload, "tokens")
        cost = _required_decimal(event.payload, "cost_usd")
        await self._connection.execute(
            """
            INSERT INTO usage_quota_projection (
                tenant_id, usage_period, tokens_used, cost_usd,
                last_global_position
            ) VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, usage_period) DO UPDATE
            SET tokens_used = usage_quota_projection.tokens_used
                    + EXCLUDED.tokens_used,
                cost_usd = usage_quota_projection.cost_usd
                    + EXCLUDED.cost_usd,
                last_global_position = EXCLUDED.last_global_position
            WHERE usage_quota_projection.last_global_position
                < EXCLUDED.last_global_position
            """,
            (event.tenant_id, period, tokens, cost, event.global_position),
        )

    async def _apply_tenant(self, event: EventEnvelope) -> None:
        if (
            _domain_event_type(event.event_type)
            is not DomainEventType.TENANT_REGISTERED
        ):
            return
        display_name = _required_string(event.payload, "display_name")
        enabled = event.payload.get("enabled", True)
        if not isinstance(enabled, bool):
            raise PermanentStorageError(
                "tenant projection event requires boolean enabled"
            )
        await self._connection.execute(
            """
            INSERT INTO tenant_listing_projection (
                tenant_id, display_name, enabled, last_global_position
            ) VALUES (%s, %s, %s, %s)
            ON CONFLICT (tenant_id) DO UPDATE
            SET display_name = EXCLUDED.display_name,
                enabled = EXCLUDED.enabled,
                last_global_position = EXCLUDED.last_global_position
            WHERE tenant_listing_projection.last_global_position
                < EXCLUDED.last_global_position
            """,
            (event.tenant_id, display_name, enabled, event.global_position),
        )

    async def run_status(
        self,
        context: TenantContext,
        *,
        limit: int = 100,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        """Return a bounded tenant run-status listing."""
        if not 1 <= limit <= 1_000:
            raise ValueError("projection query limit must be between 1 and 1000")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT run_id, status, aggregate_sequence,
                        last_global_position, updated_at
                    FROM run_status_projection
                    WHERE tenant_id = %s
                    ORDER BY last_global_position DESC
                    LIMIT %s
                    """,
                    (str(context.tenant_id), limit),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return tuple(
            {
                "run_id": row[0],
                "status": row[1],
                "aggregate_sequence": row[2],
                "global_position": row[3],
                "updated_at": row[4].isoformat(),
            }
            for row in rows
        )


def postgres_connection_lock(
    connection: psycopg.AsyncConnection[Any],
) -> asyncio.Lock:
    """Return the process-local lock shared by adapters using one connection."""
    with _CONNECTION_LOCKS_GUARD:
        lock = _CONNECTION_LOCKS.get(connection)
        if lock is None:
            lock = asyncio.Lock()
            _CONNECTION_LOCKS[connection] = lock
        return lock


@asynccontextmanager
async def _tenant_transaction(
    connection: psycopg.AsyncConnection[Any],
    lock: asyncio.Lock,
    context: TenantContext,
) -> AsyncIterator[None]:
    async with lock, connection.transaction():
        await _set_tenant(connection, context)
        yield


async def _set_tenant(
    connection: psycopg.AsyncConnection[Any], context: TenantContext
) -> None:
    await connection.execute(
        "SELECT set_config('aegis.tenant_id', %s, true)",
        (str(context.tenant_id),),
    )


def _event_insert_values(
    event: EventEnvelope, aggregate_sequence: int
) -> tuple[object, ...]:
    return (
        event.event_id,
        event.tenant_id,
        event.aggregate_id,
        aggregate_sequence,
        event.event_type,
        event.schema_version,
        event.occurred_at,
        Jsonb(thaw_json(event.payload)),
        Jsonb(thaw_json(event.metadata)),
        event.correlation_id,
        event.causation_id,
        event.actor.actor_id if event.actor else None,
        str(event.actor.kind) if event.actor else None,
        event.identity_reference,
        event.policy_reference,
        event.audit_reference,
        event.idempotency_key,
        event.trace_context.traceparent if event.trace_context else None,
        event.trace_context.tracestate if event.trace_context else None,
    )


def _event_from_row(row: Sequence[Any]) -> EventEnvelope:
    actor = (
        ActorReference(actor_id=row[13], kind=ActorKind(row[14]))
        if row[13] is not None
        else None
    )
    trace_context = (
        TraceContext(traceparent=row[19], tracestate=row[20])
        if row[19] is not None
        else None
    )
    return EventEnvelope(
        event_id=row[0],
        tenant_id=row[1],
        aggregate_id=row[2],
        aggregate_sequence=row[3],
        global_position=row[4],
        event_type=row[5],
        schema_version=row[6],
        occurred_at=row[7],
        recorded_at=row[8],
        payload=row[9],
        metadata=row[10],
        correlation_id=row[11],
        causation_id=row[12],
        actor=actor,
        identity_reference=row[15],
        policy_reference=row[16],
        audit_reference=row[17],
        idempotency_key=row[18],
        trace_context=trace_context,
        previous_aggregate_sequence=(
            int(row[21]) if len(row) > 21 and row[21] is not None else None
        ),
    )


def _validate_append(
    context: TenantContext,
    events: Sequence[EventEnvelope],
    expected_version: int,
) -> None:
    if expected_version < 0:
        raise ValueError("expected_version cannot be negative")
    if not events:
        raise ValueError("at least one event is required")
    tenant_id = str(context.tenant_id)
    aggregate_id = events[0].aggregate_id
    if any(event.tenant_id != tenant_id for event in events):
        raise ValueError("event tenant does not match trusted tenant context")
    if any(event.aggregate_id != aggregate_id for event in events):
        raise ValueError("an append batch must target one aggregate")
    if any(event.aggregate_sequence != 0 for event in events):
        raise ValueError("new events cannot preassign aggregate sequences")
    if any(event.global_position is not None for event in events):
        raise ValueError("new events cannot preassign global positions")


def _validate_page_arguments(cursor: int, limit: int) -> None:
    if cursor < 0:
        raise ValueError("cursor cannot be negative")
    if not 1 <= limit <= 1_000:
        raise ValueError("page limit must be between 1 and 1000")


def classify_storage_error(error: psycopg.Error) -> Exception:
    if isinstance(
        error,
        (
            psycopg.OperationalError,
            psycopg.InterfaceError,
            errors.SerializationFailure,
            errors.DeadlockDetected,
            errors.ConnectionException,
        ),
    ):
        return TransientStorageError("transient PostgreSQL storage failure")
    return PermanentStorageError("permanent PostgreSQL storage failure")


def _projection_table(name: str, tables: Mapping[str, str]) -> str:
    try:
        return tables[name]
    except KeyError as error:
        raise ValueError(f"unknown projection: {name}") from error


def _domain_event_type(value: str) -> DomainEventType | None:
    try:
        return DomainEventType(value)
    except ValueError:
        return None


def _required_string(payload: Mapping[str, JsonValue], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise PermanentStorageError(f"projection event requires string {field}")
    return value


def _required_int(payload: Mapping[str, JsonValue], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PermanentStorageError(f"projection event requires non-negative {field}")
    return value


def _required_uuid(payload: Mapping[str, JsonValue], field: str) -> UUID:
    value = _required_string(payload, field)
    try:
        return UUID(value)
    except ValueError as error:
        raise PermanentStorageError(
            f"projection event requires uuid {field}"
        ) from error


def _required_decimal(payload: Mapping[str, JsonValue], field: str) -> Decimal:
    value = _required_string(payload, field)
    try:
        decimal_value = Decimal(value)
    except InvalidOperation as error:
        raise PermanentStorageError(
            f"projection event requires finite non-negative {field}"
        ) from error
    if not decimal_value.is_finite() or decimal_value < 0:
        raise PermanentStorageError(
            f"projection event requires finite non-negative {field}"
        )
    return decimal_value


__all__ = [
    "NullStorageTelemetry",
    "PostgresEventStore",
    "PostgresProjectionRepository",
    "StorageTelemetry",
    "classify_storage_error",
]
