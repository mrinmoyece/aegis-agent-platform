"""Durable remediation repository port and deterministic in-memory adapter."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    RemediationState,
    WorkLease,
    WorkRequest,
    WorkTransition,
    replay_remediation,
    thaw_json,
)
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    FencingError,
    OutboxMessage,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.remediation.policy import ActionQuotaUsage
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class ProposalResult:
    created: bool
    plan_id: UUID


class RemediationIdempotencyConflictError(ValueError):
    """A tenant idempotency key was rebound to different plan content."""


class RemediationRepository(Protocol):
    """Ledger-first remediation persistence with fenced execution appends."""

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        remediation_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> ProposalResult: ...

    async def load(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> tuple[EventEnvelope, ...]: ...

    async def append(
        self,
        context: TenantContext,
        plan_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int: ...

    async def append_fenced(
        self,
        context: TenantContext,
        plan_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int: ...

    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> ActionQuotaUsage: ...

    async def page(
        self,
        context: TenantContext,
        *,
        after_plan_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]: ...

    async def rebuild_projection(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> None: ...


class InMemoryRemediationRepository(RemediationRepository):
    """Race-safe event truth with disposable read models and strict fencing."""

    def __init__(
        self,
        *,
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._uuid_factory = uuid_factory
        self._lock = asyncio.Lock()
        self._events: dict[tuple[str, UUID], list[EventEnvelope]] = {}
        self._requests: dict[tuple[str, str], tuple[UUID, str]] = {}
        self._leases: dict[tuple[str, UUID], WorkLease] = {}
        self._projection: dict[tuple[str, UUID], Mapping[str, JsonValue]] = {}
        self.outbox: list[OutboxMessage] = []

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(
            event
            for key in sorted(self._events, key=lambda item: (item[0], str(item[1])))
            for event in self._events[key]
        )

    @property
    def projections(self) -> Mapping[tuple[str, UUID], Mapping[str, JsonValue]]:
        return MappingProxyType(dict(self._projection))

    def register_lease(self, lease: WorkLease) -> None:
        self._leases[(lease.tenant_id, lease.work_id)] = lease

    def replace_lease(self, lease: WorkLease) -> None:
        self.register_lease(lease)

    def clear_projections(self) -> None:
        self._projection.clear()

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        remediation_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> ProposalResult:
        tenant_id = str(context.tenant_id)
        if request.tenant_id != tenant_id or request.work_id.int == 0:
            raise PermissionError("cross_tenant_remediation_request")
        fingerprint = _request_fingerprint(request)
        key = (tenant_id, request.idempotency_key)
        async with self._lock:
            existing = self._requests.get(key)
            if existing is not None:
                if existing[1] != fingerprint:
                    raise RemediationIdempotencyConflictError(
                        "remediation_idempotency_key_reused"
                    )
                return ProposalResult(False, existing[0])
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
            pending = (work_event, *remediation_events)
            if any(
                event.tenant_id != tenant_id
                or event.aggregate_id != str(request.work_id)
                for event in pending
            ):
                raise ValueError("proposal events must match the tenant work aggregate")
            prepared = [
                replace(event, aggregate_sequence=position)
                for position, event in enumerate(pending, start=1)
            ]
            state = replay_remediation(prepared)
            self._events[(tenant_id, request.work_id)] = prepared
            self._requests[key] = (request.work_id, fingerprint)
            self.outbox.append(
                OutboxMessage(
                    message_id=outbox_message_id,
                    event_id=requested_event_id,
                    destination="aegis.work.remediation",
                    payload={
                        "tenant_id": tenant_id,
                        "plan_id": str(request.work_id),
                        "work_kind": request.work_kind,
                    },
                    headers={"schema_version": 1},
                    available_at=request.requested_at,
                    max_attempts=request.max_attempts,
                )
            )
            self._project(tenant_id, request.work_id, state)
            return ProposalResult(True, request.work_id)

    async def load(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        return tuple(self._events.get((str(context.tenant_id), plan_id), ()))

    async def append(
        self,
        context: TenantContext,
        plan_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        _reject_unfenced_action_events(events)
        async with self._lock:
            return self._append_locked(
                str(context.tenant_id),
                plan_id,
                events,
                expected_version=expected_version,
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
        if not events:
            raise ValueError("fenced remediation append requires events")
        tenant_id = str(context.tenant_id)
        async with self._lock:
            current = self._leases.get((tenant_id, plan_id))
            at = events[0].occurred_at
            if (
                lease.tenant_id != tenant_id
                or lease.work_id != plan_id
                or current is None
                or current.token != lease.token
                or current.generation != lease.generation
                or current.expires_at <= at
            ):
                raise FencingError(
                    lease.generation,
                    current.generation if current is not None else 0,
                )
            if any(
                event.payload.get("lease_token") != str(lease.token)
                or event.payload.get("lease_generation") != lease.generation
                for event in events
            ):
                raise ValueError("execution event does not match the active fence")
            return self._append_locked(
                tenant_id,
                plan_id,
                events,
                expected_version=expected_version,
            )

    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> ActionQuotaUsage:
        async with self._lock:
            return self._quota_usage_locked(
                str(context.tenant_id),
                at=at,
                exclude_idempotency_key=exclude_idempotency_key,
            )

    async def page(
        self,
        context: TenantContext,
        *,
        after_plan_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        if not 1 <= limit <= 100:
            raise ValueError("remediation page limit must be between 1 and 100")
        tenant_id = str(context.tenant_id)
        rows = tuple(
            value
            for (row_tenant, plan_id), value in sorted(
                self._projection.items(),
                key=lambda item: str(item[0][1]),
            )
            if row_tenant == tenant_id
            and (after_plan_id is None or str(plan_id) > str(after_plan_id))
        )
        page = rows[:limit]
        next_cursor = (
            UUID(str(page[-1]["plan_id"])) if len(rows) > len(page) and page else None
        )
        return page, next_cursor

    async def rebuild_projection(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> None:
        tenant_id = str(context.tenant_id)
        events = self._events.get((tenant_id, plan_id))
        if events is None:
            return
        self._project(tenant_id, plan_id, replay_remediation(events))

    def _append_locked(
        self,
        tenant_id: str,
        plan_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not events:
            raise ValueError("remediation append requires events")
        stream = self._events.get((tenant_id, plan_id))
        if stream is None:
            raise ValueError("remediation stream does not exist")
        if len(stream) != expected_version:
            raise ConcurrencyError(expected_version, len(stream))
        existing_ids = {event.event_id for event in stream}
        existing_keys = {
            event.idempotency_key
            for event in stream
            if event.idempotency_key is not None
        }
        if any(event.event_id in existing_ids for event in events):
            raise ValueError("replayed remediation decision event")
        if any(
            event.idempotency_key is not None and event.idempotency_key in existing_keys
            for event in events
        ):
            raise RemediationIdempotencyConflictError(
                "remediation_event_idempotency_key_reused"
            )
        prepared: list[EventEnvelope] = []
        for event in events:
            if (
                event.tenant_id != tenant_id
                or event.aggregate_id != str(plan_id)
                or event.aggregate_sequence != 0
            ):
                raise ValueError("remediation event linkage is invalid")
            prepared.append(
                replace(event, aggregate_sequence=len(stream) + len(prepared) + 1)
            )
        candidate = [*stream, *prepared]
        state = replay_remediation(candidate)
        for event in prepared:
            if event.event_type == DomainEventType.ACTION_EXECUTION_REQUESTED:
                action = state.plan.action(UUID(str(event.payload["action_id"])))
                usage = self._quota_usage_locked(
                    tenant_id,
                    at=event.occurred_at,
                    exclude_idempotency_key=action.idempotency_key,
                )
                _enforce_effect_intent(
                    state, action.action_id, usage, event.occurred_at
                )
        stream.extend(prepared)
        self._project(tenant_id, plan_id, state)
        return len(stream)

    def _quota_usage_locked(
        self,
        tenant_id: str,
        *,
        at: datetime,
        exclude_idempotency_key: str | None,
    ) -> ActionQuotaUsage:
        claims: dict[str, tuple[datetime, bool]] = {}
        for (stream_tenant, _plan_id), events in self._events.items():
            if stream_tenant != tenant_id:
                continue
            action_keys: dict[str, str] = {}
            for event in events:
                action_id = event.payload.get("action_id")
                if not isinstance(action_id, str):
                    continue
                if event.event_type == DomainEventType.ACTION_EXECUTION_REQUESTED:
                    key = event.payload.get("idempotency_key")
                    if not isinstance(key, str):
                        continue
                    action_keys[action_id] = key
                    started_at = claims.get(key, (event.occurred_at, False))[0]
                    claims[key] = (started_at, True)
                elif event.event_type in {
                    DomainEventType.ACTION_EXECUTION_SUCCEEDED,
                    DomainEventType.ACTION_EXECUTION_FAILED,
                    DomainEventType.ACTION_CANCELLED,
                }:
                    key = action_keys.get(action_id)
                    if key is not None and key in claims:
                        claims[key] = (claims[key][0], False)
                elif event.event_type == DomainEventType.ACTION_EXECUTION_AMBIGUOUS:
                    key = action_keys.get(action_id)
                    if key is not None and key in claims:
                        claims[key] = (claims[key][0], True)
                elif (
                    event.event_type == DomainEventType.ACTION_RECONCILIATION_COMPLETED
                ):
                    key = action_keys.get(action_id)
                    outcome = event.payload.get("outcome")
                    if (
                        key is not None
                        and key in claims
                        and outcome in {"applied", "not_applied"}
                    ):
                        claims[key] = (claims[key][0], False)
        period = at.date()
        return ActionQuotaUsage(
            actions_in_period=sum(
                1
                for key, (started_at, _active) in claims.items()
                if key != exclude_idempotency_key and started_at.date() == period
            ),
            active_actions=sum(
                1
                for key, (_started_at, active) in claims.items()
                if key != exclude_idempotency_key and active
            ),
        )

    def _project(
        self,
        tenant_id: str,
        plan_id: UUID,
        state: RemediationState,
    ) -> None:
        self._projection[(tenant_id, plan_id)] = {
            "plan_id": str(plan_id),
            "incident_id": state.plan.incident_id,
            "revision": state.plan.revision,
            "plan_digest": state.plan.digest,
            "policy_digest": state.plan.approval_policy.digest,
            "action_count": len(state.plan.actions),
            "action_statuses": {
                str(identifier): status.value
                for identifier, status in state.action_statuses.items()
            },
            "version": state.version,
            "redacted": True,
        }


def _request_fingerprint(request: WorkRequest) -> str:
    value = json.dumps(
        {
            "work_kind": request.work_kind,
            "payload": thaw_json(request.payload),
            "timeout_seconds": request.timeout_seconds,
            "max_attempts": request.max_attempts,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return sha256(value.encode()).hexdigest()


def _reject_unfenced_action_events(events: Sequence[EventEnvelope]) -> None:
    if any(str(event.event_type).startswith("action.") for event in events):
        raise PermissionError("action lifecycle events require a fenced append")


def _enforce_effect_intent(
    state: RemediationState,
    action_id: UUID,
    usage: ActionQuotaUsage,
    at: datetime,
) -> None:
    from aegis_agent_platform.domain import ApprovalStatus, PolicyOutcome
    from aegis_agent_platform.remediation.policy import RemediationPolicyEvaluator

    action = state.plan.action(action_id)
    approval = state.approval_for(action_id)
    evaluation = RemediationPolicyEvaluator().evaluate(
        TenantContext(TenantId(state.plan.tenant_id)),
        state.plan,
        action,
        state.plan.approval_policy,
        usage,
        at=at,
    )
    if evaluation.outcome is not PolicyOutcome.REQUIRE_APPROVAL:
        raise PermissionError("action runtime policy denied")
    if (
        approval is None
        or approval.status is not ApprovalStatus.GRANTED
        or not approval.valid_for(
            plan=state.plan,
            action=action,
            policy_digest=state.plan.approval_policy.digest,
            at=at,
        )
    ):
        raise PermissionError("action runtime approval is invalid")


__all__ = [
    "InMemoryRemediationRepository",
    "ProposalResult",
    "RemediationIdempotencyConflictError",
    "RemediationRepository",
]
