"""PostgreSQL event ledger adapter and rebuildable protocol projections."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    ProtocolOperationState,
    ProtocolOperationStatus,
    WorkLease,
    content_digest,
    replay_protocol_operation,
)
from aegis_agent_platform.event_store import ConcurrencyError
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    postgres_connection_lock,
)
from aegis_agent_platform.tenancy import TenantContext

_STATUS_BY_EVENT = {
    DomainEventType.MCP_INVOCATION_STARTED.value: ProtocolOperationStatus.STARTED,
    DomainEventType.MCP_INVOCATION_COMPLETED.value: ProtocolOperationStatus.COMPLETED,
    DomainEventType.MCP_INVOCATION_FAILED.value: ProtocolOperationStatus.FAILED,
    DomainEventType.MCP_INVOCATION_AMBIGUOUS.value: ProtocolOperationStatus.AMBIGUOUS,
    DomainEventType.MCP_INVOCATION_CANCEL_REQUESTED.value: (
        ProtocolOperationStatus.CANCEL_REQUESTED
    ),
    DomainEventType.MCP_INVOCATION_CANCELLED.value: ProtocolOperationStatus.CANCELLED,
    DomainEventType.MCP_RECONCILED.value: ProtocolOperationStatus.COMPLETED,
    DomainEventType.A2A_TASK_ACCEPTED.value: ProtocolOperationStatus.ACCEPTED,
    DomainEventType.A2A_TASK_PROGRESS_RECORDED.value: ProtocolOperationStatus.RUNNING,
    DomainEventType.A2A_ARTIFACT_RECORDED.value: ProtocolOperationStatus.RUNNING,
    DomainEventType.A2A_TASK_COMPLETED.value: ProtocolOperationStatus.COMPLETED,
    DomainEventType.A2A_TASK_FAILED.value: ProtocolOperationStatus.FAILED,
    DomainEventType.A2A_TASK_AMBIGUOUS.value: ProtocolOperationStatus.AMBIGUOUS,
    DomainEventType.A2A_TASK_CANCEL_REQUESTED.value: (
        ProtocolOperationStatus.CANCEL_REQUESTED
    ),
    DomainEventType.A2A_TASK_CANCELLED.value: ProtocolOperationStatus.CANCELLED,
    DomainEventType.A2A_RECONCILED.value: ProtocolOperationStatus.COMPLETED,
    DomainEventType.PROTOCOL_PEER_QUARANTINED.value: (
        ProtocolOperationStatus.QUARANTINED
    ),
}

_CLAIM_STATUS_BY_OPERATION = {
    ProtocolOperationStatus.REQUESTED: "intent_recorded",
    ProtocolOperationStatus.STARTED: "sending",
    ProtocolOperationStatus.ACCEPTED: "sending",
    ProtocolOperationStatus.RUNNING: "sending",
    ProtocolOperationStatus.COMPLETED: "completed",
    ProtocolOperationStatus.FAILED: "failed",
    ProtocolOperationStatus.AMBIGUOUS: "ambiguous",
    ProtocolOperationStatus.CANCEL_REQUESTED: "observing",
    ProtocolOperationStatus.CANCELLED: "cancelled",
    ProtocolOperationStatus.QUARANTINED: "quarantined",
}


class PostgresProtocolLedger:
    """Persist protocol event truth and update only rebuildable tenant projections."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
    ) -> None:
        self._connection = connection
        self._events = event_store
        self._lock = postgres_connection_lock(connection)

    async def append(
        self,
        context: TenantContext,
        operation_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        lease: WorkLease | None = None,
    ) -> int:
        if not events:
            raise ValueError("protocol append requires events")
        tenant_id = str(context.tenant_id)
        if any(
            event.tenant_id != tenant_id or event.aggregate_id != str(operation_id)
            for event in events
        ):
            raise PermissionError("cross_tenant_protocol_event")

        async def project(connection: psycopg.AsyncConnection[Any]) -> None:
            await _apply_operation_events(
                connection,
                tenant_id,
                operation_id,
                events,
                expected_version=expected_version,
                lease=lease,
            )

        if lease is None:
            return await self._events.append_atomic(
                context,
                events,
                expected_version=expected_version,
                mutation=project,
            )
        return await self._events.append_fenced(
            context,
            events,
            expected_version=expected_version,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=events[0].occurred_at,
            mutation=project,
        )

    async def load(
        self,
        context: TenantContext,
        operation_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        events: list[EventEnvelope] = []
        after_version = 0
        while True:
            page = [
                event
                async for event in self._events.read_stream(
                    context,
                    str(operation_id),
                    after_version=after_version,
                    limit=100,
                )
            ]
            events.extend(page)
            if len(page) < 100:
                return tuple(events)
            after_version += len(page)

    async def by_idempotency_key(
        self,
        context: TenantContext,
        idempotency_key: str,
    ) -> ProtocolOperationState | None:
        async with _tenant_transaction(self._connection, self._lock, context):
            cursor = await self._connection.execute(
                """
                SELECT operation_id
                FROM protocol_operation_projection
                WHERE tenant_id = %s AND idempotency_key = %s
                """,
                (str(context.tenant_id), idempotency_key),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return replay_protocol_operation(await self.load(context, UUID(str(row[0]))))

    async def page(
        self,
        context: TenantContext,
        *,
        after_operation_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[ProtocolOperationState, ...], UUID | None]:
        if not 1 <= limit <= 100:
            raise ValueError("protocol operation page limit is invalid")
        async with _tenant_transaction(self._connection, self._lock, context):
            cursor = await self._connection.execute(
                """
                SELECT operation_id
                FROM protocol_operation_projection
                WHERE tenant_id = %s
                  AND (%s::uuid IS NULL OR operation_id > %s::uuid)
                ORDER BY operation_id
                LIMIT %s
                """,
                (
                    str(context.tenant_id),
                    after_operation_id,
                    after_operation_id,
                    limit + 1,
                ),
            )
            rows = await cursor.fetchall()
        page_rows = rows[:limit]
        states = [
            replay_protocol_operation(await self.load(context, UUID(str(row[0]))))
            for row in page_rows
        ]
        cursor_value = (
            UUID(str(page_rows[-1][0])) if len(rows) > limit and page_rows else None
        )
        return tuple(states), cursor_value

    async def rebuild_projection(
        self,
        context: TenantContext,
        operation_id: UUID,
    ) -> ProtocolOperationState:
        events = await self.load(context, operation_id)
        if not events:
            raise LookupError("protocol operation not found")
        async with _tenant_transaction(self._connection, self._lock, context):
            # Do NOT delete the claim row: _apply_operation_events only inserts
            # a claim when `lease` is provided, so deleting here and passing
            # lease=None permanently drops the claim projection.  Only the
            # read-model projection is rebuilt from the event stream.
            await self._connection.execute(
                """
                DELETE FROM protocol_operation_projection
                WHERE tenant_id = %s AND operation_id = %s
                """,
                (str(context.tenant_id), operation_id),
            )
            await _apply_operation_events(
                self._connection,
                str(context.tenant_id),
                operation_id,
                events,
                expected_version=0,
                lease=None,
            )
        return replay_protocol_operation(events)

    async def save_cursor(
        self,
        context: TenantContext,
        *,
        peer_id: str,
        stream_kind: str,
        cursor_digest: str,
        last_global_position: int,
        expected_version: int,
        at: datetime,
    ) -> int:
        next_version = expected_version + 1
        async with _tenant_transaction(self._connection, self._lock, context):
            cursor = await self._connection.execute(
                """
                INSERT INTO protocol_stream_cursors (
                    tenant_id, peer_id, stream_kind, opaque_cursor_digest,
                    last_global_position, version, updated_at
                ) VALUES (%s, %s, %s, %s, %s, 1, %s)
                ON CONFLICT (tenant_id, peer_id, stream_kind) DO UPDATE
                SET opaque_cursor_digest = EXCLUDED.opaque_cursor_digest,
                    last_global_position = EXCLUDED.last_global_position,
                    version = protocol_stream_cursors.version + 1,
                    updated_at = EXCLUDED.updated_at
                WHERE protocol_stream_cursors.version = %s
                RETURNING version
                """,
                (
                    str(context.tenant_id),
                    peer_id,
                    stream_kind,
                    cursor_digest,
                    last_global_position,
                    at,
                    expected_version,
                ),
            )
            row = await cursor.fetchone()
            if row is None:
                raise ConcurrencyError(expected_version, -1)
        actual = int(row[0])
        if actual != next_version:
            raise ConcurrencyError(next_version, actual)
        return actual


async def _apply_operation_events(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
    operation_id: UUID,
    events: Sequence[EventEnvelope],
    *,
    expected_version: int,
    lease: WorkLease | None,
) -> None:
    next_version = expected_version + len(events)
    first = events[0]
    if expected_version == 0:
        payload = first.payload
        actor = first.actor
        principal_digest = content_digest(
            {
                "actor_id": actor.actor_id if actor is not None else "unknown",
                "actor_kind": actor.kind.value if actor is not None else "unknown",
            }
        )
        initial_state = replay_protocol_operation(events)
        await connection.execute(
            """
            INSERT INTO protocol_operation_projection (
                tenant_id, operation_id, family, peer_id, capability_id,
                capability_digest, request_digest, policy_digest,
                principal_digest, idempotency_key, correlation_id,
                classification, purpose, status, aggregate_version,
                requested_at, deadline, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                tenant_id,
                operation_id,
                str(payload["family"]),
                str(payload["peer_id"]),
                str(payload["capability_id"]),
                str(payload["capability_digest"]),
                str(payload["request_digest"]),
                str(payload["policy_digest"]),
                principal_digest,
                first.idempotency_key,
                first.correlation_id,
                str(payload["classification"]),
                str(payload["purpose"]),
                initial_state.status.value,
                next_version,
                first.occurred_at,
                datetime.fromisoformat(str(payload["deadline"])),
                events[-1].occurred_at,
            ),
        )
        if lease is not None:
            await connection.execute(
                """
                INSERT INTO protocol_operation_claims (
                    tenant_id, operation_id, idempotency_key, request_digest,
                    capability_digest, peer_digest, lease_token,
                    lease_generation, attempt, status, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, 1,
                    'intent_recorded', %s
                )
                """,
                (
                    tenant_id,
                    operation_id,
                    first.idempotency_key,
                    str(payload["request_digest"]),
                    str(payload["capability_digest"]),
                    str(payload["peer_digest"]),
                    lease.token,
                    lease.generation,
                    events[-1].occurred_at,
                ),
            )
    else:
        status = _last_status(events)
        result_digest = _last_text(events, "result_digest")
        provider_reference = _last_text(events, "provider_reference")
        error_class = _last_text(events, "error_class")
        error_code = _last_text(events, "error_code")
        cursor = await connection.execute(
            """
            UPDATE protocol_operation_projection
            SET status = COALESCE(%s, status),
                result_digest = COALESCE(%s, result_digest),
                provider_reference_digest = COALESCE(
                    %s, provider_reference_digest
                ),
                error_class = COALESCE(%s, error_class),
                error_code = COALESCE(%s, error_code),
                aggregate_version = %s,
                updated_at = %s
            WHERE tenant_id = %s AND operation_id = %s
              AND aggregate_version = %s
            RETURNING aggregate_version
            """,
            (
                status.value if status is not None else None,
                result_digest,
                (
                    content_digest({"provider_reference": provider_reference})
                    if provider_reference is not None
                    else None
                ),
                error_class,
                error_code,
                next_version,
                events[-1].occurred_at,
                tenant_id,
                operation_id,
                expected_version,
            ),
        )
        if await cursor.fetchone() is None:
            raise ConcurrencyError(expected_version, -1)
        if lease is not None and status is not None:
            await connection.execute(
                """
                UPDATE protocol_operation_claims
                SET status = %s,
                    result_digest = COALESCE(%s, result_digest),
                    last_error_code = COALESCE(%s, last_error_code),
                    updated_at = %s
                WHERE tenant_id = %s AND operation_id = %s
                  AND lease_token = %s AND lease_generation = %s
                """,
                (
                    _CLAIM_STATUS_BY_OPERATION[status],
                    result_digest,
                    error_code,
                    events[-1].occurred_at,
                    tenant_id,
                    operation_id,
                    lease.token,
                    lease.generation,
                ),
            )

    for event in events:
        position = await _global_position(connection, tenant_id, event.event_id)
        if event.event_type == DomainEventType.PROTOCOL_POLICY_DECIDED.value:
            await _insert_audit(connection, event, position)
        artifact = event.payload.get("artifact")
        if isinstance(artifact, Mapping):
            await _insert_artifact(connection, event, artifact, position)
        artifacts = event.payload.get("artifacts")
        if isinstance(artifacts, Sequence) and not isinstance(artifacts, str):
            for item in artifacts:
                if isinstance(item, Mapping):
                    await _insert_artifact(connection, event, item, position)


async def _insert_audit(
    connection: psycopg.AsyncConnection[Any],
    event: EventEnvelope,
    position: int,
) -> None:
    actor = event.actor
    await connection.execute(
        """
        INSERT INTO protocol_audit_projection (
            tenant_id, audit_id, peer_id, operation_id, action, outcome,
            principal_digest, request_digest, policy_digest, metadata,
            ledger_position, recorded_at
        ) VALUES (
            %s, %s, %s, %s, 'protocol_request', %s, %s, %s, %s, %s, %s, %s
        ) ON CONFLICT (tenant_id, audit_id) DO NOTHING
        """,
        (
            event.tenant_id,
            event.event_id,
            str(event.payload["peer_id"]),
            UUID(event.aggregate_id),
            str(event.payload.get("decision", "recorded")),
            content_digest(
                {
                    "actor_id": actor.actor_id if actor is not None else "unknown",
                    "actor_kind": actor.kind.value if actor is not None else "unknown",
                }
            ),
            str(event.payload["request_digest"]),
            str(event.payload["policy_digest"]),
            Jsonb(
                {
                    "family": str(event.payload["family"]),
                    "capability_id": str(event.payload["capability_id"]),
                }
            ),
            position,
            event.occurred_at,
        ),
    )


async def _insert_artifact(
    connection: psycopg.AsyncConnection[Any],
    event: EventEnvelope,
    artifact: Mapping[str, JsonValue],
    position: int,
) -> None:
    citation_digests = artifact.get("citation_digests", ())
    if not isinstance(citation_digests, Sequence) or isinstance(citation_digests, str):
        raise ValueError("protocol artifact citation digests are invalid")
    byte_count = artifact["byte_count"]
    if not isinstance(byte_count, int):
        raise ValueError("protocol artifact byte count is invalid")
    await connection.execute(
        """
        INSERT INTO protocol_artifact_projection (
            tenant_id, operation_id, artifact_id, content_type,
            content_digest, content_reference, classification, trust_label,
            citation_digests, byte_count, complete, ledger_position, recorded_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        ) ON CONFLICT (tenant_id, operation_id, content_digest) DO NOTHING
        """,
        (
            event.tenant_id,
            UUID(event.aggregate_id),
            str(artifact["artifact_id"]),
            str(artifact["content_type"]),
            str(artifact["content_digest"]),
            str(artifact["content_reference"]),
            str(artifact["classification"]),
            str(artifact["trust_label"]),
            Jsonb(list(citation_digests)),
            byte_count,
            bool(artifact["complete"]),
            position,
            event.occurred_at,
        ),
    )


async def _global_position(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
    event_id: UUID,
) -> int:
    cursor = await connection.execute(
        """
        SELECT global_position
        FROM events
        WHERE tenant_id = %s AND event_id = %s
        """,
        (tenant_id, event_id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise RuntimeError("protocol projection event position is missing")
    return int(row[0])


def _last_status(events: Sequence[EventEnvelope]) -> ProtocolOperationStatus | None:
    return next(
        (
            _STATUS_BY_EVENT[event.event_type]
            for event in reversed(events)
            if event.event_type in _STATUS_BY_EVENT
        ),
        None,
    )


def _last_text(events: Sequence[EventEnvelope], key: str) -> str | None:
    return next(
        (
            value
            for event in reversed(events)
            if isinstance((value := event.payload.get(key)), str)
        ),
        None,
    )


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


__all__ = ["PostgresProtocolLedger"]
