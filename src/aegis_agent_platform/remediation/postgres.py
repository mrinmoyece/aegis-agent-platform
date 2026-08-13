"""PostgreSQL remediation projections reconciled atomically with ledger truth."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg

from aegis_agent_platform.domain import (
    ActionSpecification,
    ApprovalStatus,
    DomainEventType,
    EventEnvelope,
    JsonValue,
    RemediationState,
    WorkLease,
    WorkRequest,
    WorkTransition,
    plan_from_payload,
    replay_remediation,
)
from aegis_agent_platform.event_store import PermanentStorageError
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    classify_storage_error,
    postgres_connection_lock,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.remediation.policy import (
    ActionQuotaUsage,
    RemediationPolicyEvaluator,
)
from aegis_agent_platform.remediation.repository import (
    ProposalResult,
    RemediationIdempotencyConflictError,
    RemediationRepository,
)
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext


class PostgresRemediationRepository(RemediationRepository):
    """Fenced ledger adapter with RLS projections and effect conflict detection."""

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
        remediation_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> ProposalResult:
        existing = await self._work.work_id_for_idempotency(
            context,
            request.idempotency_key,
            work_kind=request.work_kind,
            request_payload=request.payload,
        )
        if existing is not None:
            return ProposalResult(False, existing)
        if await self._work.idempotency_key_in_use(
            context,
            request.idempotency_key,
        ):
            raise RemediationIdempotencyConflictError(
                "remediation_idempotency_key_reused"
            )
        work_event = WorkTransition(
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
        candidate = [replace(work_event, aggregate_sequence=1)]
        candidate.extend(
            replace(event, aggregate_sequence=index)
            for index, event in enumerate(remediation_events, start=2)
        )
        state = replay_remediation(candidate)

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _replace_projection(connection, state)
            await _append_decisions(connection, remediation_events)

        try:
            await self._work.register(
                context,
                request,
                requested_event_id=requested_event_id,
                outbox_message_id=outbox_message_id,
                additional_events=remediation_events,
                additional_mutation=mutation,
            )
        except PermanentStorageError:
            existing = await self._work.work_id_for_idempotency(
                context,
                request.idempotency_key,
                work_kind=request.work_kind,
                request_payload=request.payload,
            )
            if existing is not None:
                return ProposalResult(False, existing)
            if await self._work.idempotency_key_in_use(
                context,
                request.idempotency_key,
            ):
                raise RemediationIdempotencyConflictError(
                    "remediation_idempotency_key_reused"
                ) from None
            raise
        return ProposalResult(True, request.work_id)

    async def load(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        loaded: list[EventEnvelope] = []
        while True:
            page = [
                event
                async for event in self._events.read_stream(
                    context,
                    str(plan_id),
                    after_version=len(loaded),
                    limit=1_000,
                )
            ]
            loaded.extend(page)
            if len(page) < 1_000:
                return tuple(loaded)

    async def append(
        self,
        context: TenantContext,
        plan_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        _reject_unfenced_action_events(events)
        state = await self._candidate(context, plan_id, events, expected_version)

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _replace_projection(connection, state)
            await _append_decisions(connection, events)
            await _apply_effect_claims(connection, state, events)

        return await self._events.append_atomic(
            context,
            events,
            expected_version=expected_version,
            mutation=mutation,
        )

    async def append_fenced(
        self,
        context: TenantContext,
        plan_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        state = await self._candidate(context, plan_id, events, expected_version)

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _replace_projection(connection, state)
            await _append_decisions(connection, events)
            await _apply_effect_claims(connection, state, events)

        return await self._events.append_fenced(
            context,
            events,
            expected_version=expected_version,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=events[0].occurred_at,
            mutation=mutation,
        )

    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> ActionQuotaUsage:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT
                        COALESCE(SUM(actions_started) FILTER (
                            WHERE usage_period = %s
                        ), 0),
                        COALESCE(SUM(active_actions), 0)
                    FROM remediation_quota_projection
                    WHERE tenant_id = %s
                    """,
                    (at.date().isoformat(), str(context.tenant_id)),
                )
                row = await cursor.fetchone()
                actions = int(row[0]) if row is not None else 0
                active = int(row[1]) if row is not None else 0
                if exclude_idempotency_key is not None:
                    claim = await self._connection.execute(
                        """
                        SELECT started_at, status
                        FROM remediation_effect_claims
                        WHERE tenant_id = %s AND idempotency_key = %s
                        """,
                        (str(context.tenant_id), exclude_idempotency_key),
                    )
                    existing = await claim.fetchone()
                    if existing is not None:
                        if existing[0].date() == at.date():
                            actions = max(0, actions - 1)
                        if existing[1] in {"intent_recorded", "ambiguous"}:
                            active = max(0, active - 1)
                return ActionQuotaUsage(actions, active)
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def page(
        self,
        context: TenantContext,
        *,
        after_plan_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        if not 1 <= limit <= 100:
            raise ValueError("remediation page limit must be between 1 and 100")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT plan_id, incident_id, revision, plan_digest,
                        policy_digest, action_count, aggregate_version,
                        created_at, updated_at
                    FROM remediation_plan_projection
                    WHERE tenant_id = %s
                      AND (%s::uuid IS NULL OR plan_id > %s::uuid)
                    ORDER BY plan_id
                    LIMIT %s
                    """,
                    (
                        str(context.tenant_id),
                        after_plan_id,
                        after_plan_id,
                        limit + 1,
                    ),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        page = rows[:limit]
        result: tuple[Mapping[str, JsonValue], ...] = tuple(
            {
                "plan_id": str(row[0]),
                "incident_id": str(row[1]),
                "revision": int(row[2]),
                "plan_digest": str(row[3]),
                "policy_digest": str(row[4]),
                "action_count": int(row[5]),
                "version": int(row[6]),
                "created_at": row[7].isoformat(),
                "updated_at": row[8].isoformat(),
                "redacted": True,
            }
            for row in page
        )
        next_cursor = UUID(str(page[-1][0])) if len(rows) > limit and page else None
        return result, next_cursor

    async def rebuild_projection(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> None:
        for _attempt in range(3):
            events = await self.load(context, plan_id)
            if not events:
                return
            state = replay_remediation(events)
            try:
                async with _tenant_transaction(self._connection, self._lock, context):
                    cursor = await self._connection.execute(
                        """
                        SELECT current_version
                        FROM event_stream_heads
                        WHERE tenant_id = %s AND aggregate_id = %s
                        FOR UPDATE
                        """,
                        (str(context.tenant_id), str(plan_id)),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        return
                    if int(row[0]) != len(events):
                        continue
                    await _replace_projection(self._connection, state)
                    await self._connection.execute(
                        """
                        DELETE FROM remediation_effect_claims
                        WHERE tenant_id = %s AND plan_id = %s
                        """,
                        (str(context.tenant_id), plan_id),
                    )
                    await _apply_effect_claims(
                        self._connection,
                        state,
                        events,
                        enforce_policy=False,
                    )
                    await _rebuild_quota_projection(
                        self._connection,
                        str(context.tenant_id),
                    )
                    return
            except psycopg.Error as error:
                raise classify_storage_error(error) from error
        raise PermanentStorageError(
            "remediation projection rebuild could not stabilize"
        )

    async def _candidate(
        self,
        context: TenantContext,
        plan_id: UUID,
        events: Sequence[EventEnvelope],
        expected_version: int,
    ) -> RemediationState:
        if not events:
            raise ValueError("remediation append requires events")
        current = await self.load(context, plan_id)
        if len(current) != expected_version:
            from aegis_agent_platform.event_store import ConcurrencyError

            raise ConcurrencyError(expected_version, len(current))
        prepared = tuple(
            replace(event, aggregate_sequence=expected_version + index)
            for index, event in enumerate(events, start=1)
        )
        return replay_remediation((*current, *prepared))


async def _replace_projection(
    connection: psycopg.AsyncConnection[Any],
    state: RemediationState,
) -> None:
    plan = state.plan
    await connection.execute(
        """
        INSERT INTO remediation_plan_projection (
            tenant_id, plan_id, incident_id, investigation_run_id, revision,
            plan_digest, policy_digest, action_count, aggregate_version,
            created_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (tenant_id, plan_id) DO UPDATE SET
            incident_id = EXCLUDED.incident_id,
            investigation_run_id = EXCLUDED.investigation_run_id,
            revision = EXCLUDED.revision,
            plan_digest = EXCLUDED.plan_digest,
            policy_digest = EXCLUDED.policy_digest,
            action_count = EXCLUDED.action_count,
            aggregate_version = EXCLUDED.aggregate_version,
            updated_at = EXCLUDED.updated_at
        """,
        (
            plan.tenant_id,
            plan.plan_id,
            plan.incident_id,
            plan.investigation_run_id,
            plan.revision,
            plan.digest,
            plan.approval_policy.digest,
            len(plan.actions),
            state.version,
            plan.created_at,
            _state_time(state),
        ),
    )
    await connection.execute(
        """
        DELETE FROM remediation_approval_projection
        WHERE tenant_id = %s AND plan_id = %s
        """,
        (plan.tenant_id, plan.plan_id),
    )
    await connection.execute(
        """
        DELETE FROM remediation_action_projection
        WHERE tenant_id = %s AND plan_id = %s
        """,
        (plan.tenant_id, plan.plan_id),
    )
    for action in plan.actions:
        await connection.execute(
            """
            INSERT INTO remediation_action_projection (
                tenant_id, plan_id, action_id, action_kind, action_digest,
                target_fingerprint, environment, resource_type, resource_id,
                risk, blast_radius, status, aggregate_version, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                plan.tenant_id,
                plan.plan_id,
                action.action_id,
                action.kind.value,
                action.digest,
                action.target.fingerprint,
                action.target.environment,
                action.target.resource_type,
                action.target.resource_id,
                int(action.risk),
                int(action.blast_radius),
                state.action_statuses[action.action_id].value,
                state.version,
                _state_time(state),
            ),
        )
    action_ids = {action.action_id for action in plan.actions}
    for approval in state.approvals.values():
        if approval.scope.action_id not in action_ids:
            continue
        await connection.execute(
            """
            INSERT INTO remediation_approval_projection (
                tenant_id, approval_id, plan_id, action_id, plan_digest,
                action_digest, policy_digest, target_fingerprint, risk,
                requester_id, status, required_quorum, approver_ids,
                requested_at, expires_at, decided_at, aggregate_version,
                updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            """,
            (
                plan.tenant_id,
                approval.scope.approval_id,
                plan.plan_id,
                approval.scope.action_id,
                approval.scope.plan_digest,
                approval.scope.action_digest,
                approval.scope.policy_digest,
                approval.scope.target_fingerprint,
                int(approval.scope.risk),
                approval.scope.requester_id,
                approval.status.value,
                approval.scope.required_quorum,
                list(approval.approver_ids),
                approval.scope.requested_at,
                approval.scope.expires_at,
                approval.decided_at,
                state.version,
                _state_time(state),
            ),
        )


async def _append_decisions(
    connection: psycopg.AsyncConnection[Any],
    events: Sequence[EventEnvelope],
) -> None:
    decisions = {
        DomainEventType.REMEDIATION_APPROVAL_GRANTED: "granted",
        DomainEventType.REMEDIATION_APPROVAL_DENIED: "denied",
        DomainEventType.REMEDIATION_APPROVAL_EXPIRED: "expired",
        DomainEventType.REMEDIATION_APPROVAL_REVOKED: "revoked",
    }
    for event in events:
        try:
            decision = decisions[DomainEventType(event.event_type)]
        except (KeyError, ValueError):
            continue
        approval_id = event.payload.get("approval_id")
        rationale = event.payload.get("rationale_code")
        actor_id = (
            event.actor.actor_id if event.actor is not None else "remediation-system"
        )
        if not isinstance(approval_id, str) or not isinstance(rationale, str):
            raise PermanentStorageError("approval decision payload is invalid")
        await connection.execute(
            """
            INSERT INTO remediation_approval_decisions (
                tenant_id, decision_event_id, approval_id, actor_id,
                decision, rationale_code, occurred_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, decision_event_id) DO NOTHING
            """,
            (
                event.tenant_id,
                event.event_id,
                UUID(approval_id),
                actor_id,
                decision,
                rationale,
                event.occurred_at,
            ),
        )


async def _apply_effect_claims(
    connection: psycopg.AsyncConnection[Any],
    state: RemediationState,
    events: Sequence[EventEnvelope],
    *,
    enforce_policy: bool = True,
) -> None:
    action_by_id = _actions_from_events(state, events)
    for event in events:
        try:
            event_type = DomainEventType(event.event_type)
        except ValueError:
            continue
        action_value = event.payload.get("action_id")
        attempt = event.payload.get("attempt")
        if not isinstance(action_value, str) or not isinstance(attempt, int):
            continue
        action = action_by_id.get(UUID(action_value))
        if action is None:
            raise PermanentStorageError("effect claim action does not exist")
        if event_type is DomainEventType.ACTION_EXECUTION_REQUESTED:
            claim_cursor = await connection.execute(
                """
                SELECT action_digest, target_fingerprint, status, started_at
                FROM remediation_effect_claims
                WHERE tenant_id = %s AND idempotency_key = %s
                FOR UPDATE
                """,
                (event.tenant_id, action.idempotency_key),
            )
            existing = await claim_cursor.fetchone()
            if existing is not None and (
                existing[0] != action.digest or existing[1] != action.target.fingerprint
            ):
                raise RemediationIdempotencyConflictError(
                    "action_idempotency_scope_conflict"
                )
            usage = await _locked_quota_usage(
                connection,
                event.tenant_id,
                at=event.occurred_at,
                existing_claim=existing,
            )
            if enforce_policy:
                evaluation = RemediationPolicyEvaluator().evaluate(
                    TenantContext(TenantId(event.tenant_id)),
                    state.plan,
                    action,
                    state.plan.approval_policy,
                    usage,
                    at=event.occurred_at,
                )
                approval = state.approval_for(action.action_id)
                if evaluation.outcome.value != "require_approval":
                    raise PermissionError("action runtime policy denied")
                if (
                    approval is None
                    or approval.status is not ApprovalStatus.GRANTED
                    or not approval.valid_for(
                        plan=state.plan,
                        action=action,
                        policy_digest=state.plan.approval_policy.digest,
                        at=event.occurred_at,
                    )
                ):
                    raise PermissionError("action runtime approval is invalid")
            if existing is None:
                await connection.execute(
                    """
                    INSERT INTO remediation_effect_claims (
                        tenant_id, idempotency_key, plan_id, action_id,
                        action_digest, target_fingerprint, lease_generation,
                        attempt, status, last_event_id, started_at, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        'intent_recorded', %s, %s, %s
                    )
                    """,
                    (
                        event.tenant_id,
                        action.idempotency_key,
                        state.plan.plan_id,
                        action.action_id,
                        action.digest,
                        action.target.fingerprint,
                        event.payload.get("lease_generation"),
                        attempt,
                        event.event_id,
                        event.occurred_at,
                        event.occurred_at,
                    ),
                )
                await _update_quota(
                    connection,
                    event.tenant_id,
                    event.occurred_at.date().isoformat(),
                    actions_delta=1,
                    active_delta=1,
                    updated_at=event.occurred_at,
                )
            else:
                was_active = existing[2] in {"intent_recorded", "ambiguous"}
                await connection.execute(
                    """
                    UPDATE remediation_effect_claims
                    SET lease_generation = %s, attempt = %s,
                        status = 'intent_recorded', last_event_id = %s,
                        updated_at = %s
                    WHERE tenant_id = %s AND idempotency_key = %s
                    """,
                    (
                        event.payload.get("lease_generation"),
                        attempt,
                        event.event_id,
                        event.occurred_at,
                        event.tenant_id,
                        action.idempotency_key,
                    ),
                )
                if not was_active:
                    await _update_quota(
                        connection,
                        event.tenant_id,
                        existing[3].date().isoformat(),
                        actions_delta=0,
                        active_delta=1,
                        updated_at=event.occurred_at,
                    )
        elif event_type in {
            DomainEventType.ACTION_EXECUTION_SUCCEEDED,
            DomainEventType.ACTION_EXECUTION_FAILED,
            DomainEventType.ACTION_EXECUTION_AMBIGUOUS,
            DomainEventType.ACTION_RECONCILIATION_COMPLETED,
        }:
            status = {
                DomainEventType.ACTION_EXECUTION_SUCCEEDED: "succeeded",
                DomainEventType.ACTION_EXECUTION_FAILED: "failed",
                DomainEventType.ACTION_EXECUTION_AMBIGUOUS: "ambiguous",
            }.get(event_type)
            if event_type is DomainEventType.ACTION_RECONCILIATION_COMPLETED:
                status = {
                    "applied": "succeeded",
                    "not_applied": "failed",
                    "unknown": "ambiguous",
                    "conflict": "ambiguous",
                }.get(str(event.payload.get("outcome")))
            if status is None:
                raise PermanentStorageError("effect outcome status is invalid")
            claim_cursor = await connection.execute(
                """
                SELECT status, started_at
                FROM remediation_effect_claims
                WHERE tenant_id = %s AND idempotency_key = %s
                  AND action_digest = %s AND target_fingerprint = %s
                FOR UPDATE
                """,
                (
                    event.tenant_id,
                    action.idempotency_key,
                    action.digest,
                    action.target.fingerprint,
                ),
            )
            claim = await claim_cursor.fetchone()
            if claim is None:
                raise PermanentStorageError("effect outcome has no durable intent")
            await connection.execute(
                """
                UPDATE remediation_effect_claims
                SET status = %s, last_event_id = %s, updated_at = %s
                WHERE tenant_id = %s AND idempotency_key = %s
                  AND action_digest = %s AND target_fingerprint = %s
                """,
                (
                    status,
                    event.event_id,
                    event.occurred_at,
                    event.tenant_id,
                    action.idempotency_key,
                    action.digest,
                    action.target.fingerprint,
                ),
            )
            was_active = claim[0] in {"intent_recorded", "ambiguous"}
            is_active = status in {"intent_recorded", "ambiguous"}
            active_delta = int(is_active) - int(was_active)
            if active_delta:
                await _update_quota(
                    connection,
                    event.tenant_id,
                    claim[1].date().isoformat(),
                    actions_delta=0,
                    active_delta=active_delta,
                    updated_at=event.occurred_at,
                )


async def _locked_quota_usage(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
    *,
    at: datetime,
    existing_claim: tuple[Any, ...] | None,
) -> ActionQuotaUsage:
    usage_period = at.date().isoformat()
    await connection.execute(
        """
        INSERT INTO remediation_quota_projection (
            tenant_id, usage_period, actions_started, active_actions, updated_at
        ) VALUES (%s, %s, 0, 0, %s)
        ON CONFLICT (tenant_id, usage_period) DO NOTHING
        """,
        (tenant_id, usage_period, at),
    )
    cursor = await connection.execute(
        """
        SELECT usage_period, actions_started, active_actions
        FROM remediation_quota_projection
        WHERE tenant_id = %s
        FOR UPDATE
        """,
        (tenant_id,),
    )
    rows = await cursor.fetchall()
    actions = sum(int(row[1]) for row in rows if row[0] == usage_period)
    active = sum(int(row[2]) for row in rows)
    if existing_claim is not None:
        if existing_claim[3].date() == at.date():
            actions = max(0, actions - 1)
        if existing_claim[2] in {"intent_recorded", "ambiguous"}:
            active = max(0, active - 1)
    return ActionQuotaUsage(actions, active)


async def _update_quota(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
    usage_period: str,
    *,
    actions_delta: int,
    active_delta: int,
    updated_at: datetime,
) -> None:
    cursor = await connection.execute(
        """
        UPDATE remediation_quota_projection
        SET actions_started = actions_started + %s,
            active_actions = active_actions + %s,
            updated_at = %s
        WHERE tenant_id = %s AND usage_period = %s
          AND actions_started + %s >= 0
          AND active_actions + %s >= 0
        RETURNING tenant_id
        """,
        (
            actions_delta,
            active_delta,
            updated_at,
            tenant_id,
            usage_period,
            actions_delta,
            active_delta,
        ),
    )
    if await cursor.fetchone() is None:
        raise PermanentStorageError("remediation quota projection is inconsistent")


async def _rebuild_quota_projection(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
) -> None:
    await connection.execute(
        "DELETE FROM remediation_quota_projection WHERE tenant_id = %s",
        (tenant_id,),
    )
    await connection.execute(
        """
        INSERT INTO remediation_quota_projection (
            tenant_id, usage_period, actions_started, active_actions, updated_at
        )
        SELECT tenant_id, to_char(started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'),
            COUNT(*)::integer,
            COUNT(*) FILTER (
                WHERE status IN ('intent_recorded', 'ambiguous')
            )::integer,
            MAX(updated_at)
        FROM remediation_effect_claims
        WHERE tenant_id = %s
        GROUP BY tenant_id, to_char(started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
        """,
        (tenant_id,),
    )


def _actions_from_events(
    state: RemediationState,
    events: Sequence[EventEnvelope],
) -> dict[UUID, ActionSpecification]:
    actions = {action.action_id: action for action in state.plan.actions}
    for event in events:
        if event.event_type not in {
            DomainEventType.REMEDIATION_PROPOSED,
            DomainEventType.REMEDIATION_PLAN_REVISED,
        }:
            continue
        value = event.payload.get("plan")
        if not isinstance(value, Mapping):
            continue
        historical = plan_from_payload(value)
        actions.update((action.action_id, action) for action in historical.actions)
    return actions


def _reject_unfenced_action_events(events: Sequence[EventEnvelope]) -> None:
    if any(str(event.event_type).startswith("action.") for event in events):
        raise PermissionError("action lifecycle events require a fenced append")


def _state_time(state: RemediationState) -> datetime:
    records = (
        tuple(item.occurred_at for item in state.executions)
        + tuple(item.occurred_at for item in state.reconciliations)
        + tuple(item.occurred_at for item in state.verifications)
        + tuple(
            item.decided_at
            for item in state.approvals.values()
            if item.decided_at is not None
        )
    )
    return max(records, default=state.plan.created_at)


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


__all__ = ["PostgresRemediationRepository"]
