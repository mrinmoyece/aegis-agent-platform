"""PostgreSQL-authoritative work claims, leases, fencing, and reconciliation."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from aegis_agent_platform.domain import (
    DomainEventType,
    FailureClass,
    JsonValue,
    WorkLease,
    WorkRequest,
    WorkStatus,
    WorkTransition,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    FencingError,
    OutboxMessage,
)
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    classify_storage_error,
    postgres_connection_lock,
)
from aegis_agent_platform.queueing import QueueDelivery
from aegis_agent_platform.runtime.operations import RequeueApproval
from aegis_agent_platform.tenancy import TenantContext

_MAX_UUID = UUID(int=(1 << 128) - 1)
_KeysetCursor = tuple[datetime, UUID]
_RedriveRow = tuple[UUID, UUID]
_ExpiredLeaseRow = tuple[
    UUID,
    UUID,
    int,
    str,
    int,
    datetime,
    datetime,
    datetime,
    datetime | None,
    int,
]


class _ClaimUnavailableError(Exception):
    pass


def _descending_cursor(cursor: _KeysetCursor | datetime | None) -> _KeysetCursor:
    if cursor is None:
        return (datetime.max.replace(tzinfo=UTC), _MAX_UUID)
    if isinstance(cursor, tuple):
        requested_at, work_id = cursor
        if requested_at.tzinfo is None:
            raise ValueError("cursor timestamps must be timezone-aware")
        return (requested_at, work_id)
    if cursor.tzinfo is None:
        raise ValueError("cursor timestamps must be timezone-aware")
    return (cursor, _MAX_UUID)


class PostgresWorkRepository:
    """Lease projection backed by fenced event appends to the Layer 3 ledger."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
        *,
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._connection = connection
        self._events = event_store
        self._uuid_factory = uuid_factory
        self._lock = postgres_connection_lock(connection)

    async def register(
        self,
        context: TenantContext,
        request: WorkRequest,
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> int:
        """Persist request intent and publication outbox before any execution."""
        _validate_request_context(context, request)
        event = WorkTransition(
            DomainEventType.WORK_REQUESTED,
            request.requested_at,
            {
                "max_attempts": request.max_attempts,
                "timeout_seconds": request.timeout_seconds,
                "idempotency_key": request.idempotency_key,
                "request_payload": request.payload,
            },
        ).to_event(
            request,
            event_id=requested_event_id,
            causation_id=request.causation_id,
        )
        outbox = OutboxMessage(
            message_id=outbox_message_id,
            event_id=requested_event_id,
            destination="aegis.work",
            available_at=request.requested_at,
            max_attempts=request.max_attempts,
            payload=_request_payload(request),
            headers={"tenant_id": request.tenant_id, "schema_version": 1},
        )

        async def insert_work(connection: psycopg.AsyncConnection[Any]) -> None:
            await connection.execute(
                """
                INSERT INTO work_items (
                    tenant_id, work_id, work_kind, idempotency_key, status,
                    requested_at, available_at, max_attempts, timeout_seconds,
                    request_event_id, correlation_id, causation_id,
                    request_payload
                ) VALUES (
                    %s, %s, %s, %s, 'requested', %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    request.tenant_id,
                    request.work_id,
                    request.work_kind,
                    request.idempotency_key,
                    request.requested_at,
                    request.requested_at,
                    request.max_attempts,
                    request.timeout_seconds,
                    requested_event_id,
                    request.correlation_id,
                    request.causation_id,
                    Jsonb(thaw_json(request.payload)),
                ),
            )

        return await self._events.append_atomic(
            context,
            (event,),
            expected_version=0,
            mutation=insert_work,
            outbox=(outbox,),
        )

    async def mark_published(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        *,
        at: datetime,
    ) -> None:
        request = await self._verify_delivery(context, delivery)
        version = await self._current_version(context, request.work_id)
        event = WorkTransition(
            DomainEventType.WORK_PUBLISHED,
            at,
        ).to_event(
            request,
            event_id=self._uuid_factory(),
            causation_id=delivery.envelope.event_id,
        )

        async def mark_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            cursor = await connection.execute(
                """
                UPDATE work_items SET status = 'published'
                WHERE tenant_id = %s AND work_id = %s
                  AND status IN ('requested', 'retry_wait')
                """,
                (request.tenant_id, request.work_id),
            )
            if cursor.rowcount != 1:
                raise ConcurrencyError(1, 0)

        await self._events.append_from_inbox(
            context,
            source="redis-stream:aegis:work:v1",
            message_id=str(delivery.envelope.message_id),
            events=(event,),
            expected_version=version,
            mutation=mark_projection,
        )

    async def claim(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        *,
        owner: str,
        now: datetime,
        expires_at: datetime,
        tenant_concurrency_limit: int,
    ) -> WorkLease | None:
        """CAS claim one exact work item while enforcing the tenant quota."""
        if (
            not owner
            or now.tzinfo is None
            or expires_at <= now
            or tenant_concurrency_limit < 0
        ):
            raise ValueError("invalid work claim")
        lease_duration = expires_at - now
        if not timedelta(seconds=5) <= lease_duration <= timedelta(hours=1):
            raise ValueError("lease duration must be between 5 and 3600 seconds")
        request = await self._verify_delivery(context, delivery)
        _validate_request_context(context, request)
        if tenant_concurrency_limit == 0:
            return None
        token = self._uuid_factory()
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT attempt_count, max_attempts
                    FROM work_items
                    WHERE tenant_id = %s AND work_id = %s
                      AND status IN ('published', 'retry_wait')
                      AND cancel_requested_at IS NULL
                    """,
                    (request.tenant_id, request.work_id),
                )
                row = await cursor.fetchone()
                if row is None or int(row[0]) >= int(row[1]):
                    return None
                generation_cursor = await self._connection.execute(
                    """
                    SELECT generation
                    FROM work_leases
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                    (request.tenant_id, request.work_id),
                )
                generation_row = await generation_cursor.fetchone()
                generation = int(generation_row[0]) + 1 if generation_row else 1
                attempt = int(row[0]) + 1
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        lease = WorkLease(
            work_id=request.work_id,
            tenant_id=request.tenant_id,
            token=token,
            generation=generation,
            owner=owner,
            attempt=attempt,
            acquired_at=now,
            heartbeat_at=now,
            expires_at=expires_at,
        )
        authoritative_times: list[tuple[datetime, datetime]] = []

        async def claim_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            await connection.execute(
                """
                INSERT INTO tenant_event_commit_locks (tenant_id)
                VALUES (%s)
                ON CONFLICT (tenant_id) DO NOTHING
                """,
                (request.tenant_id,),
            )
            await connection.execute(
                """
                SELECT tenant_id FROM tenant_event_commit_locks
                WHERE tenant_id = %s FOR UPDATE
                """,
                (request.tenant_id,),
            )
            active = await connection.execute(
                """
                SELECT count(*) FROM work_items
                WHERE tenant_id = %s AND status IN ('claimed', 'running')
                """,
                (request.tenant_id,),
            )
            active_row = await active.fetchone()
            if active_row is None or int(active_row[0]) >= tenant_concurrency_limit:
                raise _ClaimUnavailableError
            clock_row = await (
                await connection.execute("SELECT clock_timestamp()")
            ).fetchone()
            if clock_row is None:
                raise _ClaimUnavailableError
            acquired_at = clock_row[0]
            database_expiry = acquired_at + lease_duration
            authoritative_times.append((acquired_at, database_expiry))
            cursor = await connection.execute(
                """
                UPDATE work_items
                SET status = 'claimed', attempt_count = %s
                WHERE tenant_id = %s AND work_id = %s
                  AND attempt_count = %s
                  AND status IN ('published', 'retry_wait')
                  AND available_at <= clock_timestamp()
                  AND cancel_requested_at IS NULL
                """,
                (
                    attempt,
                    request.tenant_id,
                    request.work_id,
                    attempt - 1,
                ),
            )
            if cursor.rowcount != 1:
                raise _ClaimUnavailableError
            lease_cursor = await connection.execute(
                """
                INSERT INTO work_leases (
                    tenant_id, work_id, lease_token, generation, owner,
                    acquired_at, heartbeat_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, work_id) DO UPDATE
                SET lease_token = EXCLUDED.lease_token,
                    generation = EXCLUDED.generation,
                    owner = EXCLUDED.owner,
                    acquired_at = EXCLUDED.acquired_at,
                    heartbeat_at = EXCLUDED.heartbeat_at,
                    expires_at = EXCLUDED.expires_at,
                    released_at = NULL,
                    release_reason = NULL
                WHERE work_leases.generation = %s
                """,
                (
                    request.tenant_id,
                    request.work_id,
                    token,
                    generation,
                    owner,
                    acquired_at,
                    acquired_at,
                    database_expiry,
                    generation - 1,
                ),
            )
            if lease_cursor.rowcount != 1:
                raise _ClaimUnavailableError

        version = await self._current_version(context, request.work_id)
        event = WorkTransition(
            DomainEventType.WORK_CLAIMED,
            now,
            lease=lease,
        ).to_event(request, event_id=self._uuid_factory(), causation_id=None)
        try:
            await self._events.append_atomic(
                context,
                (event,),
                expected_version=version,
                mutation=claim_projection,
            )
        except (_ClaimUnavailableError, ConcurrencyError):
            return None
        acquired_at, database_expiry = authoritative_times[0]
        return WorkLease(
            work_id=lease.work_id,
            tenant_id=lease.tenant_id,
            token=lease.token,
            generation=lease.generation,
            owner=lease.owner,
            attempt=lease.attempt,
            acquired_at=acquired_at,
            heartbeat_at=acquired_at,
            expires_at=database_expiry,
        )

    async def start(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        request = _request_from_delivery(delivery)

        async def mark_started(connection: psycopg.AsyncConnection[Any]) -> None:
            cursor = await connection.execute(
                """
                UPDATE work_items SET status = 'running'
                WHERE tenant_id = %s AND work_id = %s AND status = 'claimed'
                """,
                (request.tenant_id, request.work_id),
            )
            if cursor.rowcount != 1:
                raise FencingError(lease.generation, 0)

        await self._append_fenced(
            context,
            request,
            WorkTransition(DomainEventType.WORK_STARTED, at, lease=lease),
            lease,
            mutation=mark_started,
        )

    async def heartbeat(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
        expires_at: datetime,
    ) -> WorkLease:
        if expires_at <= at:
            raise ValueError("heartbeat expiry must be in the future")
        extension = expires_at - at
        if not timedelta(seconds=5) <= extension <= timedelta(hours=1):
            raise ValueError("heartbeat extension must be between 5 and 3600 seconds")
        heartbeat_times: list[tuple[datetime, datetime]] = []

        async def renew_lease(connection: psycopg.AsyncConnection[Any]) -> None:
            cursor = await connection.execute(
                """
                UPDATE work_leases
                SET heartbeat_at = clock_timestamp(),
                    expires_at = clock_timestamp() + (%s * interval '1 second')
                WHERE tenant_id = %s AND work_id = %s
                  AND lease_token = %s AND generation = %s AND owner = %s
                  AND released_at IS NULL
                  AND expires_at > clock_timestamp()
                RETURNING heartbeat_at, expires_at
                """,
                (
                    extension.total_seconds(),
                    lease.tenant_id,
                    lease.work_id,
                    lease.token,
                    lease.generation,
                    lease.owner,
                ),
            )
            row = await cursor.fetchone()
            if row is None:
                raise FencingError(lease.generation, 0)
            heartbeat_times.append((row[0], row[1]))

        renewed = WorkLease(
            work_id=lease.work_id,
            tenant_id=lease.tenant_id,
            token=lease.token,
            generation=lease.generation,
            owner=lease.owner,
            attempt=lease.attempt,
            acquired_at=lease.acquired_at,
            heartbeat_at=at,
            expires_at=expires_at,
        )
        await self._append_fenced(
            context,
            _request_from_delivery(delivery),
            WorkTransition(DomainEventType.WORK_HEARTBEAT, at, lease=renewed),
            renewed,
            mutation=renew_lease,
        )
        heartbeat_at, database_expiry = heartbeat_times[0]
        return WorkLease(
            work_id=renewed.work_id,
            tenant_id=renewed.tenant_id,
            token=renewed.token,
            generation=renewed.generation,
            owner=renewed.owner,
            attempt=renewed.attempt,
            acquired_at=renewed.acquired_at,
            heartbeat_at=heartbeat_at,
            expires_at=database_expiry,
        )

    async def cancellation_requested(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> bool:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT cancel_requested_at
                    FROM work_items
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                    (str(context.tenant_id), work_id),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return bool(row and row[0] is not None)

    async def delivery_complete(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> bool:
        """Return whether a duplicate transport entry can be safely acknowledged."""
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT status
                    FROM work_items
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                    (str(context.tenant_id), work_id),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return bool(
            row
            and WorkStatus(str(row[0]))
            in {
                WorkStatus.SUCCEEDED,
                WorkStatus.FAILED,
                WorkStatus.CANCELLED,
                WorkStatus.DEAD_LETTER,
            }
        )

    async def request_cancel(
        self,
        context: TenantContext,
        request: WorkRequest,
        *,
        at: datetime,
        actor_id: str | None = None,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT status FROM work_items
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                    (request.tenant_id, request.work_id),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        if row is None:
            raise ValueError("work request not found")
        status = WorkStatus(str(row[0]))
        terminal = {
            WorkStatus.SUCCEEDED,
            WorkStatus.FAILED,
            WorkStatus.CANCELLED,
            WorkStatus.DEAD_LETTER,
        }
        if status in terminal:
            raise ConcurrencyError(1, 0)
        queued = status in {
            WorkStatus.REQUESTED,
            WorkStatus.PUBLISHED,
            WorkStatus.RETRY_WAIT,
        }
        requested = WorkTransition(
            DomainEventType.WORK_CANCEL_REQUESTED,
            at,
            {"requested_by": actor_id} if actor_id is not None else {},
        ).to_event(request, event_id=self._uuid_factory(), causation_id=None)
        events = [requested]
        if queued:
            events.append(
                WorkTransition(DomainEventType.WORK_CANCELLED, at).to_event(
                    request,
                    event_id=self._uuid_factory(),
                    causation_id=requested.event_id,
                )
            )

        async def cancel_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            cursor = await connection.execute(
                """
                UPDATE work_items
                SET cancel_requested_at = COALESCE(cancel_requested_at, %s),
                    status = CASE WHEN %s THEN 'cancelled' ELSE status END,
                    completed_at = CASE WHEN %s THEN %s ELSE completed_at END
                WHERE tenant_id = %s AND work_id = %s
                  AND status = %s
                """,
                (
                    at,
                    queued,
                    queued,
                    at,
                    request.tenant_id,
                    request.work_id,
                    status.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrencyError(1, 0)

        version = await self._current_version(context, request.work_id)
        await self._events.append_atomic(
            context,
            tuple(events),
            expected_version=version,
            mutation=cancel_projection,
        )

    async def succeed(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
        result_reference: str,
    ) -> None:
        request = _request_from_delivery(delivery)

        async def complete(connection: psycopg.AsyncConnection[Any]) -> None:
            await self._complete_in_transaction(
                connection,
                lease,
                at=at,
                status=WorkStatus.SUCCEEDED,
                reason="succeeded",
            )

        await self._append_fenced(
            context,
            request,
            WorkTransition(
                DomainEventType.WORK_SUCCEEDED,
                at,
                {"result_reference": result_reference},
                lease,
            ),
            lease,
            mutation=complete,
        )

    async def cancel(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        request = _request_from_delivery(delivery)

        async def complete(connection: psycopg.AsyncConnection[Any]) -> None:
            await self._cancel_in_transaction(
                connection,
                lease,
                at=at,
            )

        await self._append_fenced(
            context,
            request,
            WorkTransition(DomainEventType.WORK_CANCELLED, at, lease=lease),
            lease,
            mutation=complete,
        )

    async def fail(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
        failure_class: FailureClass,
        error_code: str,
        retry_at: datetime | None,
    ) -> bool:
        """Record failure and return whether the work became terminal."""
        if not error_code or len(error_code) > 128:
            raise ValueError("bounded error_code is required")
        request = _request_from_delivery(delivery)
        terminal = (
            failure_class not in {FailureClass.RETRYABLE, FailureClass.TIMEOUT}
            or retry_at is None
            or lease.attempt >= request.max_attempts
        )
        failed = WorkTransition(
            DomainEventType.WORK_FAILED,
            at,
            {"failure_class": failure_class.value, "error_code": error_code},
            lease,
        ).to_event(request, event_id=self._uuid_factory(), causation_id=None)
        second_type = (
            DomainEventType.WORK_DEAD_LETTERED
            if terminal
            else DomainEventType.WORK_RETRY_SCHEDULED
        )
        second = WorkTransition(
            second_type,
            at,
            (
                {"reason_code": error_code}
                if terminal
                else {"retry_at": cast(datetime, retry_at).isoformat()}
            ),
            lease,
        ).to_event(
            request,
            event_id=self._uuid_factory(),
            causation_id=failed.event_id,
        )
        outbox: Sequence[OutboxMessage] = ()
        if not terminal:
            assert retry_at is not None
            outbox = (
                OutboxMessage(
                    message_id=self._uuid_factory(),
                    event_id=second.event_id,
                    destination="aegis.work",
                    available_at=retry_at,
                    max_attempts=request.max_attempts,
                    payload=_request_payload(request),
                    headers={"tenant_id": request.tenant_id},
                ),
            )
        version = await self._current_version(context, request.work_id)

        async def update_projection(
            connection: psycopg.AsyncConnection[Any],
        ) -> None:
            if terminal:
                await self._dead_letter_in_transaction(
                    connection,
                    lease,
                    at=at,
                    reason=error_code,
                )
                return
            assert retry_at is not None
            await self._release_in_transaction(
                connection,
                lease,
                at=at,
                reason="retry_scheduled",
                retry_at=retry_at,
                running_only=True,
            )

        await self._events.append_fenced(
            context,
            (failed, second),
            expected_version=version,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=at,
            outbox=outbox,
            mutation=update_projection,
        )
        return terminal

    async def release(
        self,
        context: TenantContext,
        lease: WorkLease,
        *,
        at: datetime,
        reason: str,
        retry_at: datetime,
    ) -> None:
        if not reason or len(reason) > 128:
            raise ValueError("bounded release reason is required")
        request = await self._load_request(context, lease.work_id)

        async def release_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            await self._release_in_transaction(
                connection,
                lease,
                at=at,
                reason=reason,
                retry_at=retry_at,
            )

        await self._append_fenced(
            context,
            request,
            WorkTransition(
                DomainEventType.WORK_RETRY_SCHEDULED,
                at,
                {"retry_at": retry_at.isoformat(), "reason_code": reason},
                lease,
            ),
            lease,
            mutation=release_projection,
        )

    async def reconcile_expired(
        self,
        context: TenantContext,
        *,
        now: datetime,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        """Release a bounded page of expired leases for safe redelivery."""
        if not 1 <= limit <= 1_000:
            raise ValueError("reconciliation limit must be between 1 and 1000")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                redrive_cursor = await self._connection.execute(
                    """
                    SELECT w.work_id, latest.message_id
                    FROM work_items AS w
                    JOIN LATERAL (
                        SELECT o.message_id, o.published_at
                        FROM outbox_messages AS o
                        WHERE o.tenant_id = w.tenant_id
                          AND o.payload->>'work_id' = w.work_id::text
                          AND o.status = 'published'
                        ORDER BY o.published_at DESC, o.message_id DESC
                        LIMIT 1
                    ) AS latest ON true
                    LEFT JOIN work_leases AS l
                      ON l.tenant_id = w.tenant_id
                     AND l.work_id = w.work_id
                     AND l.released_at IS NULL
                    WHERE w.tenant_id = %s
                      AND w.status IN ('requested', 'published', 'retry_wait')
                      AND l.work_id IS NULL
                      AND latest.published_at <=
                          clock_timestamp() - interval '5 minutes'
                    ORDER BY latest.published_at, latest.message_id
                    LIMIT %s
                    """,
                    (str(context.tenant_id), limit),
                )
                redrive_rows = cast(list[_RedriveRow], await redrive_cursor.fetchall())
                remaining = max(limit - len(redrive_rows), 0)
                rows: list[_ExpiredLeaseRow] = []
                if remaining > 0:
                    cursor = await self._connection.execute(
                        """
                        SELECT l.work_id, l.lease_token, l.generation, l.owner,
                            w.attempt_count, l.acquired_at, l.heartbeat_at,
                            l.expires_at, w.cancel_requested_at, w.max_attempts
                        FROM work_leases AS l
                        JOIN work_items AS w
                          ON w.tenant_id = l.tenant_id
                         AND w.work_id = l.work_id
                        WHERE l.tenant_id = %s AND l.released_at IS NULL
                          AND l.expires_at <= %s
                        ORDER BY l.expires_at, l.work_id
                        LIMIT %s
                        """,
                        (str(context.tenant_id), now, remaining),
                    )
                    rows = cast(list[_ExpiredLeaseRow], await cursor.fetchall())
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

        reconciled: list[UUID] = []
        for redrive_row in redrive_rows:
            work_id = UUID(str(redrive_row[0]))
            message_id = UUID(str(redrive_row[1]))
            request = await self._load_request(context, work_id)
            event = WorkTransition(
                DomainEventType.WORK_RECONCILED,
                now,
                {"outcome": "published_transport_redrive"},
            ).to_event(request, event_id=self._uuid_factory(), causation_id=None)

            async def redrive_projection(
                connection: psycopg.AsyncConnection[Any],
                *,
                current_message_id: UUID = message_id,
                current_work_id: UUID = work_id,
            ) -> None:
                cursor = await connection.execute(
                    """
                    UPDATE outbox_messages AS o
                    SET status = 'pending', available_at = clock_timestamp(),
                        published_at = NULL, lease_owner = NULL,
                        lease_expires_at = NULL, attempt_count = 0,
                        last_error_code = NULL
                    FROM work_items AS w
                    WHERE o.tenant_id = %s AND o.message_id = %s
                      AND o.status = 'published'
                      AND o.published_at <=
                          clock_timestamp() - interval '5 minutes'
                      AND w.tenant_id = o.tenant_id
                      AND w.work_id = %s
                      AND w.status IN ('requested', 'published', 'retry_wait')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM outbox_messages AS newer
                          WHERE newer.tenant_id = o.tenant_id
                            AND newer.payload->>'work_id' = w.work_id::text
                            AND newer.status = 'published'
                            AND (
                                newer.published_at > o.published_at
                                OR (
                                    newer.published_at = o.published_at
                                    AND newer.message_id > o.message_id
                                )
                            )
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM work_leases AS l
                          WHERE l.tenant_id = w.tenant_id
                            AND l.work_id = w.work_id
                            AND l.released_at IS NULL
                      )
                    """,
                    (
                        str(context.tenant_id),
                        current_message_id,
                        current_work_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ConcurrencyError(1, 0)

            version = await self._current_version(context, work_id)
            try:
                await self._events.append_atomic(
                    context,
                    (event,),
                    expected_version=version,
                    mutation=redrive_projection,
                )
            except ConcurrencyError:
                continue
            reconciled.append(work_id)

        for expired_row in rows:
            work_id = UUID(str(expired_row[0]))
            lease = WorkLease(
                work_id=work_id,
                tenant_id=str(context.tenant_id),
                token=expired_row[1],
                generation=int(expired_row[2]),
                owner=str(expired_row[3]),
                attempt=int(expired_row[4]),
                acquired_at=expired_row[5],
                heartbeat_at=expired_row[6],
                expires_at=expired_row[7],
            )
            cancel_requested_at = expired_row[8]
            cancel_requested = cancel_requested_at is not None
            exhausted = int(expired_row[4]) >= int(expired_row[9])
            request = await self._load_request(context, work_id)
            expired = WorkTransition(
                DomainEventType.WORK_LEASE_EXPIRED,
                now,
                {"reason_code": "heartbeat_timeout"},
                lease,
            ).to_event(request, event_id=self._uuid_factory(), causation_id=None)
            outcome_type = DomainEventType.WORK_RECONCILED
            if cancel_requested:
                outcome_type = DomainEventType.WORK_CANCELLED
            elif exhausted:
                outcome_type = DomainEventType.WORK_DEAD_LETTERED
            outcome_name = "retry_wait"
            if cancel_requested:
                outcome_name = "cancelled"
            elif exhausted:
                outcome_name = "dead_letter"
            outcome = WorkTransition(
                outcome_type,
                now,
                {
                    "outcome": outcome_name,
                    **(
                        {"reason_code": "lease_expired_after_max_attempts"}
                        if exhausted and not cancel_requested
                        else {}
                    ),
                },
                lease,
            ).to_event(
                request,
                event_id=self._uuid_factory(),
                causation_id=expired.event_id,
            )

            async def expire_projection(
                connection: psycopg.AsyncConnection[Any],
                *,
                current_lease: WorkLease = lease,
                cancelled: bool = cancel_requested,
                attempts_exhausted: bool = exhausted,
                expected_cancel_requested_at: datetime | None = cancel_requested_at,
            ) -> None:
                cancellation_cursor = await connection.execute(
                    """
                    SELECT work_id
                    FROM work_items
                    WHERE tenant_id = %s AND work_id = %s
                      AND cancel_requested_at IS NOT DISTINCT FROM %s
                    FOR UPDATE
                    """,
                    (
                        current_lease.tenant_id,
                        current_lease.work_id,
                        expected_cancel_requested_at,
                    ),
                )
                if await cancellation_cursor.fetchone() is None:
                    raise ConcurrencyError(1, 0)
                if attempts_exhausted and not cancelled:
                    await self._dead_letter_expired_in_transaction(
                        connection,
                        current_lease,
                        at=now,
                        reason="lease_expired_after_max_attempts",
                    )
                    return
                cursor = await connection.execute(
                    """
                    UPDATE work_leases
                    SET released_at = %s, release_reason = 'lease_expired'
                    WHERE tenant_id = %s AND work_id = %s
                      AND lease_token = %s AND generation = %s
                      AND released_at IS NULL
                      AND expires_at <= clock_timestamp()
                    """,
                    (
                        now,
                        current_lease.tenant_id,
                        current_lease.work_id,
                        current_lease.token,
                        current_lease.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise FencingError(current_lease.generation, 0)
                cursor = await connection.execute(
                    """
                    UPDATE work_items
                    SET status = %s, available_at = %s,
                        completed_at = CASE WHEN %s THEN %s ELSE NULL END
                    WHERE tenant_id = %s AND work_id = %s
                      AND status IN ('claimed', 'running')
                    """,
                    (
                        (
                            WorkStatus.CANCELLED.value
                            if cancelled
                            else WorkStatus.RETRY_WAIT.value
                        ),
                        now,
                        cancelled,
                        now,
                        current_lease.tenant_id,
                        current_lease.work_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise FencingError(current_lease.generation, 0)

            version = await self._current_version(context, work_id)
            try:
                await self._events.append_atomic(
                    context,
                    (expired, outcome),
                    expected_version=version,
                    mutation=expire_projection,
                )
            except (ConcurrencyError, FencingError):
                continue
            reconciled.append(work_id)
        return tuple(reconciled)

    async def cancel_by_id(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        at: datetime,
        actor_id: str,
    ) -> None:
        """Record a cooperative cancellation request without exposing payload."""
        if not actor_id:
            raise ValueError("actor_id is required")
        request = await self._load_request(context, work_id)
        await self.request_cancel(
            context,
            request,
            at=at,
            actor_id=actor_id,
        )

    async def requeue_dead_letter(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        at: datetime,
        approval: RequeueApproval,
        actor_id: str,
    ) -> None:
        """Requeue a DLQ record only with explicit scoped approval evidence."""
        request = await self._load_request(context, work_id)
        reconciled = WorkTransition(
            DomainEventType.WORK_RETRY_SCHEDULED,
            at,
            {
                "retry_at": at.isoformat(),
                "reason_code": "approved_dlq_requeue",
                "approval_id": str(approval.approval_id),
            },
        ).to_event(
            request,
            event_id=self._uuid_factory(),
            causation_id=None,
        )
        outbox = OutboxMessage(
            message_id=self._uuid_factory(),
            event_id=reconciled.event_id,
            destination="aegis.work",
            available_at=at,
            max_attempts=request.max_attempts,
            payload=_request_payload(request),
            headers={"tenant_id": request.tenant_id, "schema_version": 1},
        )
        version = await self._current_version(context, work_id)

        async def requeue_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            approval_cursor = await connection.execute(
                """
                SELECT approval_id
                FROM work_requeue_approvals
                WHERE tenant_id = %s AND approval_id = %s AND work_id = %s
                  AND approved_by = %s AND approved_at = %s
                  AND consumed_at IS NULL
                  AND expires_at > clock_timestamp()
                  AND approved_by <> %s
                FOR UPDATE
                """,
                (
                    request.tenant_id,
                    approval.approval_id,
                    work_id,
                    approval.approved_by,
                    approval.approved_at,
                    actor_id,
                ),
            )
            if await approval_cursor.fetchone() is None:
                raise ConcurrencyError(1, 0)
            cursor = await connection.execute(
                """
                    UPDATE work_items
                    SET status = 'retry_wait', available_at = %s,
                        attempt_count = 0, completed_at = NULL,
                        last_error_code = NULL, cancel_requested_at = NULL
                    WHERE tenant_id = %s AND work_id = %s
                      AND status = 'dead_letter'
                    """,
                (at, request.tenant_id, work_id),
            )
            if cursor.rowcount != 1:
                raise ConcurrencyError(1, 0)
            await connection.execute(
                """
                UPDATE work_requeue_approvals
                SET consumed_at = clock_timestamp(), consumed_by = %s
                WHERE tenant_id = %s AND approval_id = %s
                """,
                (actor_id, request.tenant_id, approval.approval_id),
            )
            await connection.execute(
                """
                    UPDATE work_dead_letters
                    SET requeue_count = requeue_count + 1,
                        last_requeued_at = %s
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                (at, request.tenant_id, work_id),
            )

        await self._events.append_atomic(
            context,
            (reconciled,),
            expected_version=version,
            mutation=requeue_projection,
            outbox=(outbox,),
        )

    async def approve_dead_letter_requeue(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        approval: RequeueApproval,
        expires_at: datetime,
    ) -> None:
        """Persist tenant/work-bound approval before a separate actor requeues."""
        if expires_at <= approval.approved_at:
            raise ValueError("approval expiry must be after approval time")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    INSERT INTO work_requeue_approvals (
                        tenant_id, approval_id, work_id, approved_by,
                        approved_at, expires_at
                    )
                    SELECT %s, %s, %s, %s, %s, %s
                    FROM work_dead_letters
                    WHERE tenant_id = %s AND work_id = %s
                    ON CONFLICT (tenant_id, approval_id) DO NOTHING
                    """,
                    (
                        str(context.tenant_id),
                        approval.approval_id,
                        work_id,
                        approval.approved_by,
                        approval.approved_at,
                        expires_at,
                        str(context.tenant_id),
                        work_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ConcurrencyError(1, 0)
        except ConcurrencyError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def status(
        self,
        context: TenantContext,
        *,
        status: WorkStatus | None = None,
        limit: int = 100,
        cursor: _KeysetCursor | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        """Return a bounded payload-free tenant status page."""
        if not 1 <= limit <= 200:
            raise ValueError("status limit must be between 1 and 200")
        before_requested_at, before_work_id = _descending_cursor(cursor)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                query = """
                    SELECT work_id, work_kind, status, requested_at, available_at,
                        attempt_count, max_attempts, cancel_requested_at,
                        last_error_code
                    FROM work_items
                    WHERE tenant_id = %s
                      AND (requested_at, work_id) < (%s, %s)
                """
                parameters: list[object] = [
                    str(context.tenant_id),
                    before_requested_at,
                    before_work_id,
                ]
                if status is not None:
                    query += " AND status = %s"
                    parameters.append(status.value)
                query += " ORDER BY requested_at DESC, work_id DESC LIMIT %s"
                parameters.append(limit)
                rows = await (
                    await self._connection.execute(query, tuple(parameters))
                ).fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return tuple(
            {
                "work_id": str(row[0]),
                "work_kind": str(row[1]),
                "status": str(row[2]),
                "requested_at": row[3].isoformat(),
                "available_at": row[4].isoformat(),
                "attempt_count": int(row[5]),
                "max_attempts": int(row[6]),
                "cancel_requested": row[7] is not None,
                "last_error_code": str(row[8]) if row[8] else None,
            }
            for row in rows
        )

    async def pending_status(
        self,
        context: TenantContext,
        *,
        limit: int = 100,
        cursor: _KeysetCursor | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        """Return tenant-scoped pending state from PostgreSQL, never the global PEL."""
        if not 1 <= limit <= 200:
            raise ValueError("pending limit must be between 1 and 200")
        before_available_at, before_work_id = _descending_cursor(cursor)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                rows = await (
                    await self._connection.execute(
                        """
                        SELECT w.work_id, w.work_kind, w.status, w.available_at,
                            w.attempt_count, w.max_attempts, l.owner,
                            l.heartbeat_at, l.expires_at
                        FROM work_items AS w
                        LEFT JOIN work_leases AS l
                          ON l.tenant_id = w.tenant_id
                         AND l.work_id = w.work_id
                         AND l.released_at IS NULL
                        WHERE w.tenant_id = %s
                          AND w.status IN (
                              'requested', 'published', 'claimed',
                              'running', 'retry_wait'
                          )
                          AND (w.available_at, w.work_id) < (%s, %s)
                        ORDER BY w.available_at DESC, w.work_id DESC
                        LIMIT %s
                        """,
                        (
                            str(context.tenant_id),
                            before_available_at,
                            before_work_id,
                            limit,
                        ),
                    )
                ).fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return tuple(
            {
                "work_id": str(row[0]),
                "work_kind": str(row[1]),
                "status": str(row[2]),
                "available_at": row[3].isoformat(),
                "attempt_count": int(row[4]),
                "max_attempts": int(row[5]),
                "lease_owner": str(row[6]) if row[6] is not None else None,
                "heartbeat_at": row[7].isoformat() if row[7] is not None else None,
                "expires_at": row[8].isoformat() if row[8] is not None else None,
            }
            for row in rows
        )

    async def _append_unfenced(
        self,
        context: TenantContext,
        request: WorkRequest,
        transition: WorkTransition,
    ) -> None:
        version = await self._current_version(context, request.work_id)
        event = transition.to_event(
            request,
            event_id=self._uuid_factory(),
            causation_id=None,
        )
        await self._events.append(
            context,
            (event,),
            expected_version=version,
        )

    async def _append_fenced(
        self,
        context: TenantContext,
        request: WorkRequest,
        transition: WorkTransition,
        lease: WorkLease,
        *,
        mutation: (
            Callable[[psycopg.AsyncConnection[Any]], Awaitable[None]] | None
        ) = None,
        outbox: tuple[OutboxMessage, ...] = (),
    ) -> None:
        version = await self._current_version(context, request.work_id)
        event = transition.to_event(
            request,
            event_id=self._uuid_factory(),
            causation_id=None,
        )
        await self._events.append_fenced(
            context,
            (event,),
            expected_version=version,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=transition.occurred_at,
            mutation=mutation,
            outbox=outbox,
        )

    async def _current_version(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> int:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT current_version
                    FROM event_stream_heads
                    WHERE tenant_id = %s AND aggregate_id = %s
                    """,
                    (str(context.tenant_id), str(work_id)),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return int(row[0]) if row else 0

    async def _load_request(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> WorkRequest:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT w.work_kind, w.idempotency_key, w.requested_at,
                        w.max_attempts, w.timeout_seconds,
                        w.correlation_id, w.causation_id, w.request_payload
                    FROM work_items AS w
                    WHERE w.tenant_id = %s AND w.work_id = %s
                    """,
                    (str(context.tenant_id), work_id),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        if row is None or row[5] is None:
            raise ValueError("work request not found or lacks correlation metadata")
        return WorkRequest(
            work_id=work_id,
            tenant_id=str(context.tenant_id),
            work_kind=str(row[0]),
            idempotency_key=str(row[1]),
            requested_at=row[2],
            max_attempts=int(row[3]),
            timeout_seconds=int(row[4]),
            correlation_id=row[5],
            causation_id=row[6],
            payload=row[7],
        )

    async def _verify_delivery(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
    ) -> WorkRequest:
        """Bind untrusted Redis data to the authoritative outbox and work row."""
        supplied = _request_from_delivery(delivery)
        _validate_request_context(context, supplied)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT w.work_kind, w.idempotency_key, w.requested_at,
                        w.max_attempts, w.timeout_seconds, w.correlation_id,
                        w.causation_id, w.request_payload,
                        o.destination, o.event_id, o.payload, o.headers
                    FROM work_items AS w
                    JOIN outbox_messages AS o
                      ON o.tenant_id = w.tenant_id
                     AND o.message_id = %s
                     AND o.status IN ('leased', 'published')
                     AND o.payload->>'work_id' = w.work_id::text
                    WHERE w.tenant_id = %s AND w.work_id = %s
                    """,
                    (
                        delivery.envelope.message_id,
                        str(context.tenant_id),
                        delivery.envelope.work_id,
                    ),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        if row is None:
            raise ValueError("delivery has no authoritative published outbox row")
        authoritative = WorkRequest(
            work_id=delivery.envelope.work_id,
            tenant_id=str(context.tenant_id),
            work_kind=str(row[0]),
            idempotency_key=str(row[1]),
            requested_at=row[2],
            max_attempts=int(row[3]),
            timeout_seconds=int(row[4]),
            correlation_id=row[5],
            causation_id=row[6],
            payload=row[7],
        )
        envelope_matches = (
            supplied == authoritative
            and str(row[8]) == delivery.envelope.destination
            and row[9] == delivery.envelope.event_id
            and row[10] == thaw_json(delivery.envelope.payload)
            and row[11] == thaw_json(delivery.envelope.headers)
        )
        if not envelope_matches:
            raise ValueError("delivery does not match authoritative work")
        return authoritative

    async def _set_status(
        self,
        context: TenantContext,
        work_id: UUID,
        status: WorkStatus,
        from_statuses: tuple[WorkStatus, ...] | None = None,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                query = """
                    UPDATE work_items SET status = %s
                    WHERE tenant_id = %s AND work_id = %s
                """
                parameters: list[object] = [
                    status.value,
                    str(context.tenant_id),
                    work_id,
                ]
                if from_statuses:
                    query += " AND status = ANY(%s)"
                    parameters.append([item.value for item in from_statuses])
                await self._connection.execute(
                    query,
                    tuple(parameters),
                )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def _complete(
        self,
        context: TenantContext,
        lease: WorkLease,
        *,
        at: datetime,
        status: WorkStatus,
        reason: str,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    UPDATE work_leases
                    SET released_at = %s, release_reason = %s
                    WHERE tenant_id = %s AND work_id = %s
                      AND lease_token = %s AND generation = %s
                      AND released_at IS NULL
                    """,
                    (
                        at,
                        reason,
                        lease.tenant_id,
                        lease.work_id,
                        lease.token,
                        lease.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise FencingError(lease.generation, 0)
                await self._connection.execute(
                    """
                    UPDATE work_items
                    SET status = %s, completed_at = %s
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                    (status.value, at, lease.tenant_id, lease.work_id),
                )
        except FencingError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def _dead_letter(
        self,
        context: TenantContext,
        lease: WorkLease,
        *,
        at: datetime,
        reason: str,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    UPDATE work_leases
                    SET released_at = %s, release_reason = 'dead_letter'
                    WHERE tenant_id = %s AND work_id = %s
                      AND lease_token = %s AND generation = %s
                      AND released_at IS NULL
                    """,
                    (
                        at,
                        lease.tenant_id,
                        lease.work_id,
                        lease.token,
                        lease.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise FencingError(lease.generation, 0)
                await self._connection.execute(
                    """
                    UPDATE work_items
                    SET status = 'dead_letter', completed_at = %s,
                        last_error_code = %s
                    WHERE tenant_id = %s AND work_id = %s
                    """,
                    (at, reason, lease.tenant_id, lease.work_id),
                )
                await self._connection.execute(
                    """
                    INSERT INTO work_dead_letters (
                        tenant_id, work_id, dead_lettered_at, reason_code, attempts
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, work_id) DO UPDATE
                    SET dead_lettered_at = EXCLUDED.dead_lettered_at,
                        reason_code = EXCLUDED.reason_code,
                        attempts = EXCLUDED.attempts
                    """,
                    (
                        lease.tenant_id,
                        lease.work_id,
                        at,
                        reason,
                        lease.attempt,
                    ),
                )
        except FencingError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    @staticmethod
    async def _complete_in_transaction(
        connection: psycopg.AsyncConnection[Any],
        lease: WorkLease,
        *,
        at: datetime,
        status: WorkStatus,
        reason: str,
    ) -> None:
        cursor = await connection.execute(
            """
            UPDATE work_leases
            SET released_at = %s, release_reason = %s
            WHERE tenant_id = %s AND work_id = %s
              AND lease_token = %s AND generation = %s
              AND released_at IS NULL
            """,
            (
                at,
                reason,
                lease.tenant_id,
                lease.work_id,
                lease.token,
                lease.generation,
            ),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)
        cursor = await connection.execute(
            """
            UPDATE work_items
            SET status = %s, completed_at = %s
            WHERE tenant_id = %s AND work_id = %s
              AND status IN ('claimed', 'running')
              AND cancel_requested_at IS NULL
            """,
            (status.value, at, lease.tenant_id, lease.work_id),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)

    @staticmethod
    async def _release_in_transaction(
        connection: psycopg.AsyncConnection[Any],
        lease: WorkLease,
        *,
        at: datetime,
        reason: str,
        retry_at: datetime,
        running_only: bool = False,
    ) -> None:
        """Release a lease back to retry_wait.

        Set ``running_only=True`` when called from ``fail()`` to restrict the
        eligible status to ``running``, preventing an invalid ``CLAIMED →
        RETRY_WAIT`` transition that ``next_status()`` would reject on replay.
        """
        cursor = await connection.execute(
            """
            UPDATE work_leases
            SET released_at = %s, release_reason = %s
            WHERE tenant_id = %s AND work_id = %s
              AND lease_token = %s AND generation = %s
              AND released_at IS NULL
            """,
            (
                at,
                reason,
                lease.tenant_id,
                lease.work_id,
                lease.token,
                lease.generation,
            ),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)
        if running_only:
            status_sql = """
            UPDATE work_items
            SET status = 'retry_wait', available_at = %s
            WHERE tenant_id = %s AND work_id = %s
              AND status = 'running'
              AND cancel_requested_at IS NULL
            """
        else:
            status_sql = """
            UPDATE work_items
            SET status = 'retry_wait', available_at = %s
            WHERE tenant_id = %s AND work_id = %s
              AND status IN ('claimed', 'running')
              AND cancel_requested_at IS NULL
            """
        cursor = await connection.execute(
            status_sql,
            (retry_at, lease.tenant_id, lease.work_id),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)

    @staticmethod
    async def _cancel_in_transaction(
        connection: psycopg.AsyncConnection[Any],
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        cursor = await connection.execute(
            """
            UPDATE work_leases
            SET released_at = %s, release_reason = 'cancelled'
            WHERE tenant_id = %s AND work_id = %s
              AND lease_token = %s AND generation = %s
              AND released_at IS NULL
            """,
            (
                at,
                lease.tenant_id,
                lease.work_id,
                lease.token,
                lease.generation,
            ),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)
        cursor = await connection.execute(
            """
            UPDATE work_items
            SET status = 'cancelled', completed_at = %s
            WHERE tenant_id = %s AND work_id = %s
              AND status IN ('claimed', 'running')
              AND cancel_requested_at IS NOT NULL
            """,
            (at, lease.tenant_id, lease.work_id),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)

    @classmethod
    async def _dead_letter_in_transaction(
        cls,
        connection: psycopg.AsyncConnection[Any],
        lease: WorkLease,
        *,
        at: datetime,
        reason: str,
    ) -> None:
        await cls._complete_in_transaction(
            connection,
            lease,
            at=at,
            status=WorkStatus.DEAD_LETTER,
            reason="dead_letter",
        )
        await connection.execute(
            """
            UPDATE work_items
            SET last_error_code = %s
            WHERE tenant_id = %s AND work_id = %s
            """,
            (reason, lease.tenant_id, lease.work_id),
        )
        await connection.execute(
            """
            INSERT INTO work_dead_letters (
                tenant_id, work_id, dead_lettered_at, reason_code, attempts
            ) VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, work_id) DO UPDATE
            SET dead_lettered_at = EXCLUDED.dead_lettered_at,
                reason_code = EXCLUDED.reason_code,
                attempts = EXCLUDED.attempts
            """,
            (
                lease.tenant_id,
                lease.work_id,
                at,
                reason,
                lease.attempt,
            ),
        )

    @staticmethod
    async def _dead_letter_expired_in_transaction(
        connection: psycopg.AsyncConnection[Any],
        lease: WorkLease,
        *,
        at: datetime,
        reason: str,
    ) -> None:
        cursor = await connection.execute(
            """
            UPDATE work_leases
            SET released_at = %s, release_reason = 'dead_letter'
            WHERE tenant_id = %s AND work_id = %s
              AND lease_token = %s AND generation = %s
              AND released_at IS NULL
              AND expires_at <= clock_timestamp()
            """,
            (
                at,
                lease.tenant_id,
                lease.work_id,
                lease.token,
                lease.generation,
            ),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)
        cursor = await connection.execute(
            """
            UPDATE work_items
            SET status = 'dead_letter', completed_at = %s,
                last_error_code = %s
            WHERE tenant_id = %s AND work_id = %s
              AND status IN ('claimed', 'running')
            """,
            (at, reason, lease.tenant_id, lease.work_id),
        )
        if cursor.rowcount != 1:
            raise FencingError(lease.generation, 0)
        await connection.execute(
            """
            INSERT INTO work_dead_letters (
                tenant_id, work_id, dead_lettered_at, reason_code, attempts
            ) VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, work_id) DO UPDATE
            SET dead_lettered_at = EXCLUDED.dead_lettered_at,
                reason_code = EXCLUDED.reason_code,
                attempts = EXCLUDED.attempts
            """,
            (lease.tenant_id, lease.work_id, at, reason, lease.attempt),
        )

    async def _expire_one_in_transaction(
        self,
        context: TenantContext,
        work_id: UUID,
        now: datetime,
    ) -> None:
        cursor = await self._connection.execute(
            """
            UPDATE work_leases
            SET released_at = %s, release_reason = 'lease_expired'
            WHERE tenant_id = %s AND work_id = %s
              AND released_at IS NULL AND expires_at <= %s
            """,
            (now, str(context.tenant_id), work_id, now),
        )
        if cursor.rowcount:
            await self._connection.execute(
                """
                UPDATE work_items
                SET status = 'retry_wait', available_at = %s
                WHERE tenant_id = %s AND work_id = %s
                  AND status IN ('claimed', 'running')
                """,
                (now, str(context.tenant_id), work_id),
            )


def _request_from_delivery(delivery: QueueDelivery) -> WorkRequest:
    payload = delivery.envelope.payload
    request_payload = payload.get("request_payload", {})
    if not isinstance(request_payload, Mapping):
        raise ValueError("request_payload must be a mapping")
    try:
        return WorkRequest(
            work_id=delivery.envelope.work_id,
            tenant_id=delivery.envelope.tenant_id,
            work_kind=str(payload["work_kind"]),
            idempotency_key=str(payload["idempotency_key"]),
            correlation_id=delivery.envelope.correlation_id,
            causation_id=delivery.envelope.causation_id,
            requested_at=datetime.fromisoformat(str(payload["requested_at"])),
            payload=request_payload,
            max_attempts=int(str(payload["max_attempts"])),
            timeout_seconds=int(str(payload["timeout_seconds"])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("delivery has invalid work routing metadata") from error


def _request_payload(request: WorkRequest) -> Mapping[str, JsonValue]:
    return {
        "work_id": str(request.work_id),
        "work_kind": request.work_kind,
        "correlation_id": str(request.correlation_id),
        "causation_id": (
            str(request.causation_id) if request.causation_id is not None else None
        ),
        "requested_at": request.requested_at.isoformat(),
        "max_attempts": request.max_attempts,
        "timeout_seconds": request.timeout_seconds,
        "request_payload": request.payload,
        "idempotency_key": request.idempotency_key,
    }


def _validate_request_context(context: TenantContext, request: WorkRequest) -> None:
    if str(context.tenant_id) != request.tenant_id:
        raise ValueError("work request tenant does not match trusted context")


@asynccontextmanager
async def _tenant_transaction(
    connection: psycopg.AsyncConnection[Any],
    lock: asyncio.Lock,
    context: TenantContext,
) -> AsyncIterator[None]:
    async with lock, connection.transaction():
        await connection.execute(
            "SELECT set_config('aegis.tenant_id', %s, true)",
            (str(context.tenant_id),),
        )
        yield


__all__ = ["PostgresWorkRepository"]
