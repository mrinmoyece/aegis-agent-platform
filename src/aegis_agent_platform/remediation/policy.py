"""Deterministic deny-by-default policy for controlled external actions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    ApprovalPolicySnapshot,
    PolicyEvaluationRecord,
    PolicyOutcome,
    RemediationPlan,
)
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class ActionQuotaUsage:
    """Authoritative usage supplied by a tenant-scoped persistence adapter."""

    actions_in_period: int
    active_actions: int

    def __post_init__(self) -> None:
        if self.actions_in_period < 0 or self.active_actions < 0:
            raise ValueError("action quota usage cannot be negative")


class RemediationPolicyEvaluator:
    """Evaluate exact target, risk, evidence, window, and quota controls."""

    def evaluate(
        self,
        context: TenantContext,
        plan: RemediationPlan,
        action: ActionSpecification,
        policy: ApprovalPolicySnapshot,
        usage: ActionQuotaUsage,
        *,
        at: datetime,
    ) -> PolicyEvaluationRecord:
        if at.tzinfo is None:
            raise ValueError("policy evaluation time must be timezone-aware")
        reasons: list[str] = []
        tenant_id = str(context.tenant_id)
        if plan.tenant_id != tenant_id or policy.tenant_id != tenant_id:
            reasons.append("cross_tenant_policy")
        try:
            linked = plan.action(action.action_id)
        except ValueError:
            reasons.append("action_not_in_plan")
        else:
            if linked.digest != action.digest:
                reasons.append("action_digest_mismatch")
        allowed_action_values = {
            allowed_kind.value for allowed_kind in policy.allowed_action_kinds
        }
        if action.kind.value not in allowed_action_values:
            reasons.append("action_kind_not_allowed")
        if action.target.fingerprint not in policy.allowed_target_fingerprints:
            reasons.append("target_not_allowed")
        if action.risk > policy.maximum_risk:
            reasons.append("risk_threshold_exceeded")
        if action.blast_radius > policy.maximum_blast_radius:
            reasons.append("blast_radius_exceeded")
        if not policy.maintenance_windows or not any(
            window.contains(at) for window in policy.maintenance_windows
        ):
            reasons.append("outside_maintenance_window")
        if len(plan.actions) > policy.max_actions_per_plan:
            reasons.append("plan_action_limit_exceeded")
        if usage.actions_in_period >= policy.max_actions_per_period:
            reasons.append("period_action_limit_exceeded")
        if usage.active_actions >= policy.max_concurrent_actions:
            reasons.append("action_concurrency_limit_exceeded")
        if policy.require_evidence and (not action.evidence_ids or not plan.evidence):
            reasons.append("required_evidence_missing")
        if policy.require_critic_approval and not plan.critic_approved:
            reasons.append("critic_approval_missing")
        if _destructive(action.kind) and not policy.destructive_actions_enabled:
            reasons.append("destructive_actions_disabled")
        outcome = PolicyOutcome.DENY if reasons else PolicyOutcome.REQUIRE_APPROVAL
        return PolicyEvaluationRecord(
            action_id=action.action_id,
            plan_digest=plan.digest,
            action_digest=action.digest,
            policy_digest=policy.digest,
            outcome=outcome,
            reasons=tuple(reasons or ("exact_scope_approval_required",)),
            evaluated_at=at,
        )


def _destructive(kind: ActionKind) -> bool:
    del kind
    return False


__all__ = ["ActionQuotaUsage", "RemediationPolicyEvaluator"]
