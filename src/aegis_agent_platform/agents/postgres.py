"""PostgreSQL ledger adapter and rebuildable specialist projections."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from aegis_agent_platform.agents.artifacts import (
    artifact_confidence,
    artifact_from_payload,
    artifact_kind,
    artifact_summary,
    artifact_to_payload,
)
from aegis_agent_platform.agents.coordination import (
    InvestigationPlan,
    InvestigationStatus,
    TaskStatus,
    plan_from_payload,
    replay_investigation,
)
from aegis_agent_platform.agents.repository import (
    AgentRepository,
    InvestigationIdempotencyConflictError,
    InvestigationRequestResult,
)
from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    WorkLease,
    WorkRequest,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    postgres_connection_lock,
)
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext


class PostgresAgentRepository(AgentRepository):
    """Commit events and version-checked projections under the active work fence."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
        work_repository: PostgresWorkRepository,
    ) -> None:
        self._connection = connection
        self._events = event_store
        self._work = work_repository
        self._lock = postgres_connection_lock(connection)

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        agent_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> InvestigationRequestResult:
        existing = await self._work.work_id_for_idempotency(
            context,
            request.idempotency_key,
            work_kind=request.work_kind,
            request_payload=request.payload,
        )
        if existing is not None:
            return InvestigationRequestResult(False, existing)
        if await self._work.idempotency_key_in_use(
            context,
            request.idempotency_key,
        ):
            raise InvestigationIdempotencyConflictError(
                "investigation_idempotency_key_reused"
            )
        plan = _plan_event(agent_events)

        async def insert_projection(
            connection: psycopg.AsyncConnection[Any],
        ) -> None:
            await connection.execute(
                """
                INSERT INTO agent_run_projection (
                    tenant_id, run_id, incident_id, plan_id, plan_digest,
                    status, aggregate_version, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, 'requested', %s, %s, %s)
                """,
                (
                    plan.tenant_id,
                    plan.run_id,
                    plan.incident_id,
                    plan.plan_id,
                    plan.digest,
                    1 + len(agent_events),
                    plan.created_at,
                    plan.created_at,
                ),
            )
            for assignment in plan.assignments:
                await connection.execute(
                    """
                    INSERT INTO agent_task_projection (
                        tenant_id, run_id, assignment_id, ordinal, role,
                        depends_on, capabilities, status, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, 'pending', %s
                    )
                    """,
                    (
                        plan.tenant_id,
                        plan.run_id,
                        assignment.assignment_id,
                        assignment.ordinal,
                        assignment.role.value,
                        list(assignment.depends_on),
                        sorted(assignment.capabilities),
                        plan.created_at,
                    ),
                )

        await self._work.register(
            context,
            request,
            requested_event_id=requested_event_id,
            outbox_message_id=outbox_message_id,
            additional_events=agent_events,
            additional_mutation=insert_projection,
        )
        return InvestigationRequestResult(True, request.work_id)

    async def load(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        events = [
            event async for event in self._events.read_stream(context, str(run_id))
        ]
        return tuple(events)

    async def append_fenced(
        self,
        context: TenantContext,
        run_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
    ) -> int:
        stream = await self.load(context, run_id)
        expected_version = len(stream)

        async def apply_projection(
            connection: psycopg.AsyncConnection[Any],
        ) -> None:
            await _apply_projection_events(
                connection,
                str(context.tenant_id),
                run_id,
                events,
                ledger_version=expected_version,
            )

        return await self._events.append_fenced(
            context,
            events,
            expected_version=expected_version,
            work_id=run_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=events[0].occurred_at,
            mutation=apply_projection,
        )

    async def status(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> Mapping[str, JsonValue] | None:
        async with _tenant_transaction(self._connection, self._lock, context):
            cursor = await self._connection.execute(
                """
                SELECT incident_id, plan_id, plan_digest, status,
                       aggregate_version, used_tokens, reserved_tokens,
                       final_artifact_id, terminal_reason
                FROM agent_run_projection
                WHERE tenant_id = %s AND run_id = %s
                """,
                (str(context.tenant_id), run_id),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "run_id": str(run_id),
            "incident_id": str(row[0]),
            "plan_id": str(row[1]),
            "plan_digest": str(row[2]),
            "status": str(row[3]),
            "version": int(row[4]),
            "used_tokens": int(row[5]),
            "reserved_tokens": int(row[6]),
            "final_artifact_id": str(row[7]) if row[7] is not None else None,
            "terminal_reason": str(row[8]) if row[8] is not None else None,
        }

    async def task_page(
        self,
        context: TenantContext,
        run_id: UUID,
        *,
        after_ordinal: int = -1,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        _page_limit(limit)
        async with _tenant_transaction(self._connection, self._lock, context):
            cursor = await self._connection.execute(
                """
                SELECT assignment_id, ordinal, role, status, attempt_count,
                       used_tokens, artifact_count, last_error_code
                FROM agent_task_projection
                WHERE tenant_id = %s AND run_id = %s AND ordinal > %s
                ORDER BY ordinal, assignment_id
                LIMIT %s
                """,
                (str(context.tenant_id), run_id, after_ordinal, limit + 1),
            )
            rows = await cursor.fetchall()
        page = rows[:limit]
        values = tuple(
            {
                "assignment_id": str(row[0]),
                "ordinal": int(row[1]),
                "role": str(row[2]),
                "status": str(row[3]),
                "attempts": int(row[4]),
                "used_tokens": int(row[5]),
                "artifact_count": int(row[6]),
                "last_error_code": (str(row[7]) if row[7] is not None else None),
            }
            for row in page
        )
        return values, int(page[-1][1]) if len(rows) > limit else None

    async def artifact_page(
        self,
        context: TenantContext,
        run_id: UUID,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        _page_limit(limit)
        async with _tenant_transaction(self._connection, self._lock, context):
            cursor = await self._connection.execute(
                """
                SELECT ledger_sequence, artifact_id, assignment_id,
                       artifact_kind, produced_by, summary, confidence,
                       citation_ids, created_at, schema_version
                FROM reasoning_artifact_projection
                WHERE tenant_id = %s AND run_id = %s
                  AND ledger_sequence > %s
                ORDER BY ledger_sequence, artifact_id
                LIMIT %s
                """,
                (str(context.tenant_id), run_id, after_position, limit + 1),
            )
            rows = await cursor.fetchall()
        page = rows[:limit]
        values = tuple(
            {
                "position": int(row[0]),
                "artifact_id": str(row[1]),
                "task_id": str(row[2]),
                "kind": str(row[3]),
                "role": str(row[4]),
                "summary": str(row[5]),
                "confidence": float(row[6]) if row[6] is not None else None,
                "citation_ids": tuple(str(item) for item in row[7]),
                "created_at": row[8].isoformat(),
                "schema_version": int(row[9]),
                "redacted": True,
            }
            for row in page
        )
        return values, int(page[-1][0]) if len(rows) > limit else None

    async def rebuild_projection(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> None:
        """Recreate disposable run/task/artifact rows from ledger truth."""
        events = await self.load(context, run_id)
        if not events:
            return
        state = replay_investigation(events)
        artifact_sequences: dict[UUID, int] = {}
        for event in events:
            if event.event_type != DomainEventType.REASONING_ARTIFACT_RECORDED:
                continue
            value = event.payload.get("artifact")
            if isinstance(value, Mapping):
                artifact = artifact_from_payload(value)
                artifact_sequences[artifact.artifact_id] = event.aggregate_sequence
        async with _tenant_transaction(self._connection, self._lock, context):
            await self._connection.execute(
                """
                DELETE FROM reasoning_artifact_projection
                WHERE tenant_id = %s AND run_id = %s
                """,
                (str(context.tenant_id), run_id),
            )
            await self._connection.execute(
                """
                DELETE FROM agent_task_projection
                WHERE tenant_id = %s AND run_id = %s
                """,
                (str(context.tenant_id), run_id),
            )
            await self._connection.execute(
                """
                DELETE FROM agent_run_projection
                WHERE tenant_id = %s AND run_id = %s
                """,
                (str(context.tenant_id), run_id),
            )
            latest = events[-1]
            await self._connection.execute(
                """
                INSERT INTO agent_run_projection (
                    tenant_id, run_id, incident_id, plan_id, plan_digest,
                    status, aggregate_version, used_tokens, reserved_tokens,
                    final_artifact_id, terminal_reason, lease_token,
                    lease_generation, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    state.plan.tenant_id,
                    state.plan.run_id,
                    state.plan.incident_id,
                    state.plan.plan_id,
                    state.plan.digest,
                    state.status.value,
                    len(events),
                    state.used_tokens,
                    state.reserved_tokens,
                    state.final_artifact_id,
                    state.terminal_reason,
                    latest.payload.get("lease_token"),
                    latest.payload.get("lease_generation"),
                    state.plan.created_at,
                    latest.occurred_at,
                ),
            )
            for assignment in state.plan.assignments:
                task = state.tasks[assignment.assignment_id]
                await self._connection.execute(
                    """
                    INSERT INTO agent_task_projection (
                        tenant_id, run_id, assignment_id, ordinal, role,
                        depends_on, capabilities, status, attempt_count,
                        reserved_tokens, used_tokens, artifact_count,
                        last_error_code, lease_token, lease_generation, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        state.plan.tenant_id,
                        state.plan.run_id,
                        assignment.assignment_id,
                        assignment.ordinal,
                        assignment.role.value,
                        list(assignment.depends_on),
                        sorted(assignment.capabilities),
                        task.status.value,
                        task.attempts,
                        task.reserved_tokens,
                        task.used_tokens,
                        len(task.artifact_ids),
                        task.last_error_code,
                        latest.payload.get("lease_token"),
                        latest.payload.get("lease_generation"),
                        latest.occurred_at,
                    ),
                )
            for artifact in state.artifacts:
                payload = artifact_to_payload(artifact)
                await self._connection.execute(
                    """
                    INSERT INTO reasoning_artifact_projection (
                        tenant_id, run_id, artifact_id, assignment_id,
                        ledger_sequence, artifact_kind, produced_by,
                        schema_version, summary, confidence, citation_ids,
                        artifact_content, created_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        artifact.tenant_id,
                        artifact.run_id,
                        artifact.artifact_id,
                        artifact.task_id,
                        artifact_sequences[artifact.artifact_id],
                        artifact_kind(artifact).value,
                        artifact.produced_by.value,
                        artifact.schema_version,
                        artifact_summary(artifact),
                        artifact_confidence(artifact),
                        Jsonb(
                            [citation.evidence_id for citation in artifact.citations]
                        ),
                        Jsonb(thaw_json(payload)),
                        artifact.created_at,
                    ),
                )


async def _apply_projection_events(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
    run_id: UUID,
    events: Sequence[EventEnvelope],
    *,
    ledger_version: int,
) -> None:
    current = await connection.execute(
        """
        SELECT aggregate_version
        FROM agent_run_projection
        WHERE tenant_id = %s AND run_id = %s
        FOR UPDATE
        """,
        (tenant_id, run_id),
    )
    row = await current.fetchone()
    if row is None:
        raise ValueError("agent run projection is missing")
    projection_version = int(row[0])
    version = ledger_version
    run_status: InvestigationStatus | None = None
    terminal_reason: str | None = None
    final_artifact_id: UUID | None = None
    used_tokens = 0
    reserved_delta = 0
    for event in events:
        version += 1
        event_type = DomainEventType(event.event_type)
        assignment_id = (
            UUID(str(event.payload["assignment_id"]))
            if event.payload.get("assignment_id") is not None
            else None
        )
        if event_type is DomainEventType.SPECIALIST_TASK_DISPATCH_REQUESTED:
            assert assignment_id is not None
            reserved_delta += int(str(event.payload["reserved_tokens"]))
            await connection.execute(
                """
                UPDATE agent_task_projection
                SET status = 'dispatched', attempt_count = attempt_count + 1,
                    reserved_tokens = %s,
                    lease_token = %s, lease_generation = %s, updated_at = %s,
                    last_error_code = NULL
                WHERE tenant_id = %s AND run_id = %s AND assignment_id = %s
                """,
                (
                    event.payload["reserved_tokens"],
                    event.payload["lease_token"],
                    event.payload["lease_generation"],
                    event.occurred_at,
                    tenant_id,
                    run_id,
                    assignment_id,
                ),
            )
            run_status = InvestigationStatus.RUNNING
        elif event_type is DomainEventType.SPECIALIST_TASK_STARTED:
            assert assignment_id is not None
            await connection.execute(
                """
                UPDATE agent_task_projection
                SET status = 'running', updated_at = %s
                WHERE tenant_id = %s AND run_id = %s AND assignment_id = %s
                  AND status = 'dispatched'
                """,
                (event.occurred_at, tenant_id, run_id, assignment_id),
            )
        elif event_type is DomainEventType.REASONING_ARTIFACT_RECORDED:
            assert assignment_id is not None
            artifact_value = event.payload["artifact"]
            if not isinstance(artifact_value, Mapping):
                raise ValueError("artifact projection requires an object")
            artifact = artifact_from_payload(artifact_value)
            await connection.execute(
                """
                INSERT INTO reasoning_artifact_projection (
                    tenant_id, run_id, artifact_id, assignment_id,
                    ledger_sequence, artifact_kind, produced_by,
                    schema_version, summary, confidence, citation_ids,
                    artifact_content, created_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    tenant_id,
                    run_id,
                    artifact.artifact_id,
                    assignment_id,
                    version,
                    artifact_kind(artifact).value,
                    artifact.produced_by.value,
                    artifact.schema_version,
                    artifact_summary(artifact),
                    artifact_confidence(artifact),
                    Jsonb([citation.evidence_id for citation in artifact.citations]),
                    Jsonb(thaw_json(artifact_value)),
                    artifact.created_at,
                ),
            )
            await connection.execute(
                """
                UPDATE agent_task_projection
                SET artifact_count = artifact_count + 1, updated_at = %s
                WHERE tenant_id = %s AND run_id = %s AND assignment_id = %s
                """,
                (event.occurred_at, tenant_id, run_id, assignment_id),
            )
        elif event_type in {
            DomainEventType.SPECIALIST_TASK_SUCCEEDED,
            DomainEventType.SPECIALIST_TASK_FAILED,
            DomainEventType.SPECIALIST_TASK_TIMED_OUT,
            DomainEventType.SPECIALIST_TASK_CANCELLED,
        }:
            assert assignment_id is not None
            task_status = {
                DomainEventType.SPECIALIST_TASK_SUCCEEDED: TaskStatus.SUCCEEDED,
                DomainEventType.SPECIALIST_TASK_FAILED: TaskStatus.FAILED,
                DomainEventType.SPECIALIST_TASK_TIMED_OUT: TaskStatus.TIMED_OUT,
                DomainEventType.SPECIALIST_TASK_CANCELLED: TaskStatus.CANCELLED,
            }[event_type]
            tokens = int(str(event.payload.get("used_tokens", 0)))
            used_tokens += tokens
            reserved_delta -= int(str(event.payload["reserved_tokens"]))
            await connection.execute(
                """
                UPDATE agent_task_projection
                SET status = %s, used_tokens = used_tokens + %s,
                    reserved_tokens = 0,
                    last_error_code = %s, updated_at = %s
                WHERE tenant_id = %s AND run_id = %s AND assignment_id = %s
                """,
                (
                    task_status.value,
                    tokens,
                    event.payload.get("error_code"),
                    event.occurred_at,
                    tenant_id,
                    run_id,
                    assignment_id,
                ),
            )
        elif event_type is DomainEventType.INVESTIGATION_BUDGET_EXHAUSTED:
            run_status = InvestigationStatus.BUDGET_EXHAUSTED
            terminal_reason = str(event.payload["reason"])
        elif event_type is DomainEventType.INVESTIGATION_CANCEL_REQUESTED:
            run_status = InvestigationStatus.CANCELLED
            terminal_reason = str(event.payload["reason"])
        elif event_type is DomainEventType.RUN_FAILED:
            run_status = InvestigationStatus.FAILED
            terminal_reason = str(event.payload["reason"])
        elif event_type is DomainEventType.INVESTIGATION_FINALIZED:
            outcome = str(event.payload["outcome"])
            run_status = {
                "finalize": InvestigationStatus.SUCCEEDED,
                "abstain": InvestigationStatus.ABSTAINED,
                "escalate": InvestigationStatus.ESCALATED,
            }[outcome]
            terminal_reason = str(event.payload["reason"])
            final_artifact_id = UUID(str(event.payload["artifact_id"]))
    cursor = await connection.execute(
        """
        UPDATE agent_run_projection
        SET status = COALESCE(%s, status),
            aggregate_version = %s,
            used_tokens = used_tokens + %s,
            reserved_tokens = GREATEST(0, reserved_tokens + %s),
            final_artifact_id = COALESCE(%s, final_artifact_id),
            terminal_reason = COALESCE(%s, terminal_reason),
            lease_token = %s, lease_generation = %s, updated_at = %s
        WHERE tenant_id = %s AND run_id = %s AND aggregate_version = %s
        """,
        (
            run_status.value if run_status is not None else None,
            version,
            used_tokens,
            reserved_delta,
            final_artifact_id,
            terminal_reason,
            events[-1].payload["lease_token"],
            events[-1].payload["lease_generation"],
            events[-1].occurred_at,
            tenant_id,
            run_id,
            projection_version,
        ),
    )
    if cursor.rowcount != 1:
        raise ValueError("agent projection expected-version mismatch")


def _plan_event(events: Sequence[EventEnvelope]) -> InvestigationPlan:
    event = next(
        (
            item
            for item in events
            if item.event_type == DomainEventType.INVESTIGATION_PLAN_RECORDED
        ),
        None,
    )
    if event is None:
        raise ValueError("request requires an investigation plan event")
    value = event.payload.get("plan")
    if not isinstance(value, Mapping):
        raise ValueError("plan event has no typed plan")
    return plan_from_payload(value)


def _page_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("page limit must be between 1 and 100")


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


__all__ = ["PostgresAgentRepository"]
