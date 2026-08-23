"""Authorized redacted remediation API operations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import (
    ApprovalPolicySnapshot,
    JsonValue,
    RemediationPlan,
    replay_remediation,
)
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
)
from aegis_agent_platform.observability.context import PropagationContext
from aegis_agent_platform.remediation.approvals import (
    ApprovalDecision,
    ProposalDecision,
    RemediationApprovalService,
)
from aegis_agent_platform.remediation.policy import ActionQuotaUsage
from aegis_agent_platform.remediation.repository import RemediationRepository
from aegis_agent_platform.tenancy import TenantContext


class RemediationPolicyRepository(Protocol):
    def get(self, context: TenantContext) -> ApprovalPolicySnapshot | None: ...


class ActionQuotaReader(Protocol):
    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> ActionQuotaUsage: ...


class InMemoryRemediationPolicyRepository:
    def __init__(self, policies: tuple[ApprovalPolicySnapshot, ...]) -> None:
        self._policies = {policy.tenant_id: policy for policy in policies}

    def get(self, context: TenantContext) -> ApprovalPolicySnapshot | None:
        return self._policies.get(str(context.tenant_id))


class RemediationOperations:
    """Deny-by-default façade over proposal, decision, and read services."""

    def __init__(
        self,
        repository: RemediationRepository,
        approvals: RemediationApprovalService,
        policies: RemediationPolicyRepository,
        *,
        quotas: ActionQuotaReader | None = None,
        authorization: AuthorizationService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._approvals = approvals
        self._policies = policies
        self._quotas = quotas or repository
        self._authorization = authorization or AuthorizationService()
        self._clock = clock or (lambda: datetime.now(UTC))

    async def propose(
        self,
        principal: Principal,
        context: TenantContext,
        plan: RemediationPlan,
        *,
        idempotency_key: str,
        propagation: PropagationContext | None = None,
    ) -> ProposalDecision:
        policy = self._policy(context)
        usage = await self._quotas.quota_usage(context, at=self._clock())
        return await self._approvals.propose(
            principal,
            context,
            plan,
            policy,
            usage,
            idempotency_key=idempotency_key,
            propagation=propagation,
        )

    async def decide(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        approval_id: UUID,
        decision: ApprovalDecision,
        *,
        decision_id: UUID,
        rationale_code: str,
        comment: str,
    ) -> Mapping[str, JsonValue]:
        approval = await self._approvals.decide(
            principal,
            context,
            plan_id,
            approval_id,
            decision,
            decision_id=decision_id,
            current_policy=self._policy(context),
            rationale_code=rationale_code,
            comment=comment,
        )
        return _approval_body(approval)

    async def revoke(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        approval_id: UUID,
        *,
        revocation_id: UUID,
        rationale_code: str,
    ) -> Mapping[str, JsonValue]:
        approval = await self._approvals.revoke(
            principal,
            context,
            plan_id,
            approval_id,
            revocation_id=revocation_id,
            rationale_code=rationale_code,
        )
        return _approval_body(approval)

    async def status(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, at)
        events = await self._repository.load(context, plan_id)
        if not events:
            return None
        return _state_body(replay_remediation(events))

    async def page(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        after_plan_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        self._require(principal, context, at)
        return await self._repository.page(
            context,
            after_plan_id=after_plan_id,
            limit=limit,
        )

    def _policy(self, context: TenantContext) -> ApprovalPolicySnapshot:
        policy = self._policies.get(context)
        if policy is None:
            raise PermissionError("remediation_policy_not_configured")
        return policy

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        at: datetime,
    ) -> None:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=Permission.REMEDIATION_READ,
            at=at,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)


def _state_body(state: object) -> Mapping[str, JsonValue]:
    from aegis_agent_platform.domain import RemediationState

    if not isinstance(state, RemediationState):
        raise TypeError("remediation state is required")
    return {
        "plan_id": str(state.plan.plan_id),
        "incident_id": state.plan.incident_id,
        "revision": state.plan.revision,
        "plan_digest": state.plan.digest,
        "policy_digest": state.plan.approval_policy.digest,
        "actions": tuple(
            {
                "action_id": str(action.action_id),
                "kind": action.kind.value,
                "risk": int(action.risk),
                "blast_radius": int(action.blast_radius),
                "target_fingerprint": action.target.fingerprint,
                "status": state.action_statuses[action.action_id].value,
            }
            for action in state.plan.actions
        ),
        "approvals": tuple(
            _approval_body(approval)
            for approval in sorted(
                state.approvals.values(),
                key=lambda item: str(item.scope.approval_id),
            )
        ),
        "version": state.version,
        "redacted": True,
    }


def _approval_body(approval: object) -> Mapping[str, JsonValue]:
    from aegis_agent_platform.domain import ApprovalState

    if not isinstance(approval, ApprovalState):
        raise TypeError("approval state is required")
    return {
        "approval_id": str(approval.scope.approval_id),
        "action_id": str(approval.scope.action_id),
        "status": approval.status.value,
        "required_quorum": approval.scope.required_quorum,
        "approval_count": len(approval.approver_ids),
        "expires_at": approval.scope.expires_at.isoformat(),
        "plan_digest": approval.scope.plan_digest,
        "action_digest": approval.scope.action_digest,
        "policy_digest": approval.scope.policy_digest,
        "target_fingerprint": approval.scope.target_fingerprint,
        "redacted": True,
    }


__all__ = [
    "ActionQuotaReader",
    "InMemoryRemediationPolicyRepository",
    "RemediationOperations",
    "RemediationPolicyRepository",
]
