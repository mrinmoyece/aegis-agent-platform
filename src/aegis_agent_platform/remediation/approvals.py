"""Authenticated exact-scope remediation proposal and approval service."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditStore,
    InMemoryAuditStore,
    redact_details,
)
from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    ApprovalPolicySnapshot,
    ApprovalState,
    ApprovalStatus,
    DomainEventType,
    EventEnvelope,
    JsonValue,
    PolicyOutcome,
    RemediationPlan,
    RemediationState,
    WorkRequest,
    plan_to_payload,
    replay_remediation,
)
from aegis_agent_platform.event_store import ConcurrencyError
from aegis_agent_platform.identity import (
    AuthorizationDecision,
    AuthorizationService,
    Permission,
    Principal,
    PrincipalKind,
)
from aegis_agent_platform.remediation.policy import (
    ActionQuotaUsage,
    RemediationPolicyEvaluator,
)
from aegis_agent_platform.remediation.repository import (
    ProposalResult,
    RemediationIdempotencyConflictError,
    RemediationRepository,
)
from aegis_agent_platform.remediation.telemetry import RemediationMetrics
from aegis_agent_platform.tenancy import TenantContext

MAX_APPROVAL_COMMENT_BYTES = 1_024
MAX_DECISION_RETRIES = 5


class ApprovalDecision(StrEnum):
    GRANT = "grant"
    DENY = "deny"


class ApprovalDeniedError(PermissionError):
    """The approval decision failed an identity, role, scope, or SoD gate."""


@dataclass(frozen=True, slots=True)
class ProposalDecision:
    result: ProposalResult
    state: RemediationState


class RemediationApprovalService:
    """Persist proposals and race-safe decisions bound to immutable exact scope."""

    def __init__(
        self,
        repository: RemediationRepository,
        *,
        authorization: AuthorizationService | None = None,
        audit: AuditStore | None = None,
        policy_evaluator: RemediationPolicyEvaluator | None = None,
        metrics: RemediationMetrics | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._repository = repository
        self._authorization = authorization or AuthorizationService()
        self._audit = audit or InMemoryAuditStore()
        self._policy = policy_evaluator or RemediationPolicyEvaluator()
        self._metrics = metrics or RemediationMetrics()
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def propose(
        self,
        principal: Principal,
        context: TenantContext,
        plan: RemediationPlan,
        current_policy: ApprovalPolicySnapshot,
        usage: ActionQuotaUsage,
        *,
        idempotency_key: str,
    ) -> ProposalDecision:
        at = self._clock()
        self._require(
            principal,
            context,
            Permission.REMEDIATION_PROPOSE,
            at=at,
        )
        if not idempotency_key:
            raise ValueError("proposal idempotency key is required")
        if (
            plan.tenant_id != str(context.tenant_id)
            or plan.requested_by != principal.actor_id
        ):
            raise ApprovalDeniedError("proposal_identity_or_tenant_mismatch")
        if (
            current_policy.tenant_id != plan.tenant_id
            or current_policy.digest != plan.approval_policy.digest
        ):
            raise ApprovalDeniedError("proposal_policy_snapshot_is_stale")
        request = WorkRequest(
            work_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            work_kind="remediation.controlled_action.v1",
            idempotency_key=idempotency_key,
            correlation_id=plan.investigation_run_id,
            requested_at=at,
            payload={
                "incident_id": plan.incident_id,
                "investigation_run_id": str(plan.investigation_run_id),
                "plan_digest": plan.digest,
                "policy_digest": current_policy.digest,
                "revision": plan.revision,
            },
            max_attempts=5,
            timeout_seconds=3_600,
        )
        events: list[EventEnvelope] = [
            self._event(
                plan,
                principal,
                DomainEventType.REMEDIATION_PROPOSED,
                {
                    "plan": plan_to_payload(plan),
                    "plan_digest": plan.digest,
                    "policy_digest": current_policy.digest,
                },
                idempotency_key=f"{idempotency_key}:proposal",
                at=at,
            )
        ]
        for action in plan.actions:
            evaluation = self._policy.evaluate(
                context,
                plan,
                action,
                current_policy,
                usage,
                at=at,
            )
            events.append(
                self._event(
                    plan,
                    principal,
                    DomainEventType.REMEDIATION_POLICY_EVALUATED,
                    {
                        "action_id": str(action.action_id),
                        "action_digest": action.digest,
                        "outcome": evaluation.outcome.value,
                        "plan_digest": plan.digest,
                        "policy_digest": current_policy.digest,
                        "reasons": evaluation.reasons,
                    },
                    idempotency_key=(
                        f"{idempotency_key}:policy:{action.action_id}:"
                        f"{current_policy.digest}"
                    ),
                    at=at,
                )
            )
            self._audit_event(
                principal=principal,
                event_type=AuditEventType.REMEDIATION_POLICY_DECISION,
                outcome=(
                    AuditOutcome.DENIED
                    if evaluation.outcome is PolicyOutcome.DENY
                    else AuditOutcome.SUCCESS
                ),
                action="remediation:policy:evaluate",
                resource="remediation-policy",
                details={
                    "action_kind": action.kind.value,
                    "outcome": evaluation.outcome.value,
                    "policy_version": current_policy.policy_version,
                    "reasons": evaluation.reasons,
                },
            )
            if evaluation.outcome is PolicyOutcome.DENY:
                self._metrics.add("policy_denials", action_kind=action.kind)
                continue
            approval_id = self._uuid_factory()
            expires_at = at + timedelta(seconds=current_policy.approval_ttl_seconds)
            events.append(
                self._event(
                    plan,
                    principal,
                    DomainEventType.REMEDIATION_APPROVAL_REQUESTED,
                    {
                        "action_id": str(action.action_id),
                        "action_digest": action.digest,
                        "approval_id": str(approval_id),
                        "expires_at": expires_at.isoformat(),
                        "plan_digest": plan.digest,
                        "policy_digest": current_policy.digest,
                        "requester_id": principal.actor_id,
                        "required_quorum": current_policy.required_quorum,
                        "risk": int(action.risk),
                        "target_fingerprint": action.target.fingerprint,
                    },
                    idempotency_key=(
                        f"{idempotency_key}:approval:{action.action_id}:"
                        f"{current_policy.digest}"
                    ),
                    at=at,
                )
            )
            self._metrics.add("approvals_requested", action_kind=action.kind)
        result = await self._repository.request(
            context,
            request,
            tuple(events),
            requested_event_id=self._uuid_factory(),
            outbox_message_id=self._uuid_factory(),
        )
        loaded = await self._repository.load(context, result.plan_id)
        state = replay_remediation(loaded)
        if result.created:
            self._metrics.add("proposals")
        return ProposalDecision(result, state)

    async def decide(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        approval_id: UUID,
        decision: ApprovalDecision,
        *,
        decision_id: UUID,
        current_policy: ApprovalPolicySnapshot,
        rationale_code: str,
        comment: str,
    ) -> ApprovalState:
        at = self._clock()
        authorization = self._require(
            principal,
            context,
            Permission.APPROVAL_DECIDE,
            at=at,
        )
        if principal.kind is not PrincipalKind.USER:
            raise ApprovalDeniedError("human_user_approval_required")
        _safe_rationale(rationale_code, comment)
        for _attempt in range(MAX_DECISION_RETRIES):
            events = await self._repository.load(context, plan_id)
            if not events:
                raise ValueError("remediation plan was not found")
            state = replay_remediation(events)
            replayed = _matching_decision(
                events,
                event_id=decision_id,
                event_type=(
                    DomainEventType.REMEDIATION_APPROVAL_GRANTED
                    if decision is ApprovalDecision.GRANT
                    else DomainEventType.REMEDIATION_APPROVAL_DENIED
                ),
                approval_id=approval_id,
                actor_id=principal.actor_id,
                rationale_code=rationale_code,
            )
            if replayed:
                return _approval(state, approval_id)
            approval = _approval(state, approval_id)
            action = state.plan.action(approval.scope.action_id)
            if approval.status is ApprovalStatus.EXPIRED:
                raise ApprovalDeniedError("approval_expired")
            if approval.status is not ApprovalStatus.PENDING:
                raise ApprovalDeniedError("approval_is_not_pending")
            if at >= approval.scope.expires_at:
                try:
                    await self._append_expired(
                        principal,
                        context,
                        state,
                        approval,
                        at=at,
                    )
                except ConcurrencyError:
                    continue
                raise ApprovalDeniedError("approval_expired")
            if (
                current_policy.tenant_id != state.plan.tenant_id
                or current_policy.digest != approval.scope.policy_digest
                or current_policy.digest != state.plan.approval_policy.digest
                or state.plan.digest != approval.scope.plan_digest
                or action.digest != approval.scope.action_digest
                or action.target.fingerprint != approval.scope.target_fingerprint
            ):
                raise ApprovalDeniedError("approval_scope_is_stale")
            active_role_names = {role.value for role in authorization.active_roles}
            if not active_role_names.intersection(
                current_policy.required_approver_roles
            ):
                raise ApprovalDeniedError("required_approver_role_missing")
            if (
                current_policy.prohibit_self_approval
                and principal.actor_id == approval.scope.requester_id
            ):
                raise ApprovalDeniedError("requester_cannot_self_approve")
            if principal.actor_id in approval.approver_ids:
                raise ApprovalDeniedError("duplicate_approver_decision")
            event_type = (
                DomainEventType.REMEDIATION_APPROVAL_GRANTED
                if decision is ApprovalDecision.GRANT
                else DomainEventType.REMEDIATION_APPROVAL_DENIED
            )
            payload: dict[str, JsonValue] = {
                "action_id": str(action.action_id),
                "approval_id": str(approval_id),
                "approver_id": principal.actor_id,
                "comment": _redacted_comment(comment),
                "rationale_code": rationale_code,
            }
            event = self._event(
                state.plan,
                principal,
                event_type,
                payload,
                idempotency_key=f"approval-decision:{decision_id}",
                at=at,
                event_id=decision_id,
            )
            try:
                await self._repository.append(
                    context,
                    plan_id,
                    (event,),
                    expected_version=state.version,
                )
            except ConcurrencyError:
                continue
            updated = _approval(await self._state(context, plan_id), approval_id)
            metric = (
                "approvals_granted"
                if decision is ApprovalDecision.GRANT
                else "approvals_denied"
            )
            self._metrics.add(metric, action_kind=action.kind)
            self._audit_event(
                principal=principal,
                event_type=AuditEventType.REMEDIATION_APPROVAL_DECISION,
                outcome=(
                    AuditOutcome.SUCCESS
                    if decision is ApprovalDecision.GRANT
                    else AuditOutcome.DENIED
                ),
                action=f"approval:{decision.value}",
                resource="remediation-approval",
                details={
                    "decision_id": str(decision_id),
                    "rationale_code": rationale_code,
                    "risk": int(action.risk),
                },
            )
            return updated
        raise ConcurrencyError(-1, -1)

    async def revise(
        self,
        principal: Principal,
        context: TenantContext,
        plan: RemediationPlan,
        current_policy: ApprovalPolicySnapshot,
        usage: ActionQuotaUsage,
        *,
        idempotency_key: str,
    ) -> RemediationState:
        at = self._clock()
        self._require(
            principal,
            context,
            Permission.REMEDIATION_PROPOSE,
            at=at,
        )
        current = await self._state(context, plan.plan_id)
        if (
            plan.tenant_id != str(context.tenant_id)
            or plan.requested_by != principal.actor_id
            or plan.revision != current.plan.revision + 1
            or current_policy.digest != plan.approval_policy.digest
        ):
            raise ApprovalDeniedError("plan_revision_scope_is_invalid")
        events: list[EventEnvelope] = [
            self._event(
                plan,
                principal,
                DomainEventType.REMEDIATION_PLAN_REVISED,
                {
                    "previous_plan_digest": current.plan.digest,
                    "plan": plan_to_payload(plan),
                    "plan_digest": plan.digest,
                    "policy_digest": current_policy.digest,
                },
                idempotency_key=f"{idempotency_key}:revision:{plan.revision}",
                at=at,
            )
        ]
        for action in plan.actions:
            evaluation = self._policy.evaluate(
                context,
                plan,
                action,
                current_policy,
                usage,
                at=at,
            )
            events.append(
                self._event(
                    plan,
                    principal,
                    DomainEventType.REMEDIATION_POLICY_EVALUATED,
                    {
                        "action_id": str(action.action_id),
                        "action_digest": action.digest,
                        "outcome": evaluation.outcome.value,
                        "plan_digest": plan.digest,
                        "policy_digest": current_policy.digest,
                        "reasons": evaluation.reasons,
                    },
                    idempotency_key=(
                        f"{idempotency_key}:revision-policy:"
                        f"{action.action_id}:{current_policy.digest}"
                    ),
                    at=at,
                )
            )
            if evaluation.outcome is PolicyOutcome.DENY:
                continue
            approval_id = self._uuid_factory()
            events.append(
                self._event(
                    plan,
                    principal,
                    DomainEventType.REMEDIATION_APPROVAL_REQUESTED,
                    {
                        "action_id": str(action.action_id),
                        "action_digest": action.digest,
                        "approval_id": str(approval_id),
                        "expires_at": (
                            at + timedelta(seconds=current_policy.approval_ttl_seconds)
                        ).isoformat(),
                        "plan_digest": plan.digest,
                        "policy_digest": current_policy.digest,
                        "requester_id": principal.actor_id,
                        "required_quorum": current_policy.required_quorum,
                        "risk": int(action.risk),
                        "target_fingerprint": action.target.fingerprint,
                    },
                    idempotency_key=(
                        f"{idempotency_key}:revision-approval:"
                        f"{action.action_id}:{current_policy.digest}"
                    ),
                    at=at,
                )
            )
        await self._repository.append(
            context,
            plan.plan_id,
            tuple(events),
            expected_version=current.version,
        )
        return await self._state(context, plan.plan_id)

    async def revoke(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        approval_id: UUID,
        *,
        revocation_id: UUID,
        rationale_code: str,
    ) -> ApprovalState:
        at = self._clock()
        self._require(principal, context, Permission.APPROVAL_DECIDE, at=at)
        _safe_rationale(rationale_code, rationale_code)
        for _attempt in range(MAX_DECISION_RETRIES):
            events = await self._repository.load(context, plan_id)
            if not events:
                raise ValueError("remediation plan was not found")
            state = replay_remediation(events)
            replayed = _matching_decision(
                events,
                event_id=revocation_id,
                event_type=DomainEventType.REMEDIATION_APPROVAL_REVOKED,
                approval_id=approval_id,
                actor_id=principal.actor_id,
                rationale_code=rationale_code,
            )
            if replayed:
                return _approval(state, approval_id)
            approval = _approval(state, approval_id)
            if approval.status not in {
                ApprovalStatus.PENDING,
                ApprovalStatus.GRANTED,
            }:
                raise ApprovalDeniedError("approval_cannot_be_revoked")
            action = state.plan.action(approval.scope.action_id)
            event = self._event(
                state.plan,
                principal,
                DomainEventType.REMEDIATION_APPROVAL_REVOKED,
                {
                    "action_id": str(action.action_id),
                    "approval_id": str(approval_id),
                    "rationale_code": rationale_code,
                },
                idempotency_key=f"approval-revocation:{revocation_id}",
                at=at,
                event_id=revocation_id,
            )
            try:
                await self._repository.append(
                    context,
                    plan_id,
                    (event,),
                    expected_version=state.version,
                )
            except ConcurrencyError:
                continue
            self._metrics.add("approvals_revoked", action_kind=action.kind)
            return _approval(await self._state(context, plan_id), approval_id)
        raise ConcurrencyError(-1, -1)

    async def _append_expired(
        self,
        principal: Principal,
        context: TenantContext,
        state: RemediationState,
        approval: ApprovalState,
        *,
        at: datetime,
    ) -> None:
        action = state.plan.action(approval.scope.action_id)
        event = self._event(
            state.plan,
            principal,
            DomainEventType.REMEDIATION_APPROVAL_EXPIRED,
            {
                "action_id": str(action.action_id),
                "approval_id": str(approval.scope.approval_id),
                "rationale_code": "approval_ttl_elapsed",
            },
            idempotency_key=(
                f"approval-expiry:{approval.scope.approval_id}:"
                f"{approval.scope.expires_at.isoformat()}"
            ),
            at=at,
        )
        await self._repository.append(
            context,
            state.plan.plan_id,
            (event,),
            expected_version=state.version,
        )
        self._metrics.add("approvals_expired", action_kind=action.kind)

    async def _state(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> RemediationState:
        events = await self._repository.load(context, plan_id)
        if not events:
            raise ValueError("remediation plan was not found")
        return replay_remediation(events)

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        permission: Permission,
        *,
        at: datetime,
    ) -> AuthorizationDecision:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=permission,
            at=at,
        )
        if not decision.allowed:
            raise ApprovalDeniedError(decision.reason)
        return decision

    def _event(
        self,
        plan: RemediationPlan,
        principal: Principal,
        event_type: DomainEventType,
        payload: Mapping[str, JsonValue],
        *,
        idempotency_key: str,
        at: datetime,
        event_id: UUID | None = None,
    ) -> EventEnvelope:
        return EventEnvelope(
            event_id=event_id or self._uuid_factory(),
            tenant_id=plan.tenant_id,
            aggregate_id=str(plan.plan_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=at,
            payload=payload,
            correlation_id=plan.investigation_run_id,
            actor=ActorReference(principal.actor_id, _actor_kind(principal)),
            identity_reference=principal.subject,
            policy_reference=plan.approval_policy.digest,
            idempotency_key=idempotency_key,
        )

    def _audit_event(
        self,
        *,
        principal: Principal,
        event_type: AuditEventType,
        outcome: AuditOutcome,
        action: str,
        resource: str,
        details: Mapping[str, JsonValue],
    ) -> None:
        event = AuditEvent(
            event_id=self._uuid_factory(),
            tenant_id=principal.tenant_id,
            event_type=event_type,
            occurred_at=self._clock(),
            outcome=outcome,
            actor_id=principal.actor_id,
            action=action,
            resource=resource,
            correlation_id=self._uuid_factory(),
            details=details,
        )
        self._audit.append(TenantContext(principal.tenant_id), event)


def _approval(state: RemediationState, approval_id: UUID) -> ApprovalState:
    try:
        return state.approvals[approval_id]
    except KeyError as error:
        raise ApprovalDeniedError("approval_not_found") from error


def _matching_decision(
    events: tuple[EventEnvelope, ...],
    *,
    event_id: UUID,
    event_type: DomainEventType,
    approval_id: UUID,
    actor_id: str,
    rationale_code: str,
) -> bool:
    existing = next((event for event in events if event.event_id == event_id), None)
    if existing is None:
        return False
    if (
        existing.event_type != event_type
        or existing.payload.get("approval_id") != str(approval_id)
        or existing.payload.get("rationale_code") != rationale_code
        or existing.actor is None
        or existing.actor.actor_id != actor_id
    ):
        raise RemediationIdempotencyConflictError("approval_decision_identifier_reused")
    return True


def _actor_kind(principal: Principal) -> ActorKind:
    return (
        ActorKind.SERVICE if principal.kind is PrincipalKind.SERVICE else ActorKind.USER
    )


def _safe_rationale(rationale_code: str, comment: str) -> None:
    if (
        not rationale_code
        or rationale_code != rationale_code.strip()
        or len(rationale_code.encode()) > 128
        or not rationale_code.replace("_", "").isalnum()
    ):
        raise ValueError("approval rationale code is invalid")
    if (
        not comment
        or comment != comment.strip()
        or len(comment.encode()) > MAX_APPROVAL_COMMENT_BYTES
    ):
        raise ValueError("approval comment must be normalized and bounded")


def _redacted_comment(comment: str) -> str:
    del comment
    value = redact_details({"operator_comment": "[REDACTED]"})["operator_comment"]
    if not isinstance(value, str):
        raise TypeError("redacted approval comment must remain text")
    return value


__all__ = [
    "ApprovalDecision",
    "ApprovalDeniedError",
    "ProposalDecision",
    "RemediationApprovalService",
]
