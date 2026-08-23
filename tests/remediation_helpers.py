"""Deterministic Layer 8 test fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    ActionTarget,
    ApprovalPolicySnapshot,
    BlastRadius,
    Condition,
    ConditionOperator,
    MaintenanceWindow,
    ReconciliationPolicy,
    RemediationEvidenceCitation,
    RemediationPlan,
    RetryPolicy,
    RiskTier,
    WorkLease,
)
from aegis_agent_platform.identity import (
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    ServiceIdentity,
    TenantId,
    UserId,
)
from aegis_agent_platform.tenancy import TenantContext

NOW = datetime(2026, 8, 13, 10, 0, tzinfo=UTC)
TENANT_ID = TenantId("tenant-remediation")
CONTEXT = TenantContext(TENANT_ID)


@dataclass(slots=True)
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def principal(
    actor_id: str,
    role: Role,
    *,
    tenant_id: TenantId = TENANT_ID,
    assigned_at: datetime = NOW - timedelta(hours=1),
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
    service: bool = False,
) -> Principal:
    binding = RoleBinding(
        tenant_id,
        role,
        UserId("admin"),
        assigned_at,
        expires_at,
        revoked_at,
    )
    return Principal(
        subject=f"subject-{actor_id}",
        issuer="https://identity.test.invalid",
        tenant_id=tenant_id,
        kind=PrincipalKind.SERVICE if service else PrincipalKind.USER,
        role_bindings=(binding,),
        service_identity=ServiceIdentity(actor_id) if service else None,
        user_id=None if service else UserId(actor_id),
    )


def target() -> ActionTarget:
    return ActionTarget(
        "kubernetes",
        "staging",
        "deployment",
        "checkout-api",
        "checkout",
    )


def policy(
    action_target: ActionTarget | None = None,
    *,
    tenant_id: TenantId = TENANT_ID,
    quorum: int = 2,
    ttl_seconds: int = 300,
) -> ApprovalPolicySnapshot:
    selected = action_target or target()
    return ApprovalPolicySnapshot(
        tenant_id=str(tenant_id),
        policy_version="remediation-policy-v1",
        allowed_action_kinds=frozenset({ActionKind.KUBERNETES_ROLLOUT_RESTART}),
        allowed_target_fingerprints=frozenset({selected.fingerprint}),
        required_approver_roles=frozenset({Role.APPROVER.value}),
        maintenance_windows=(
            MaintenanceWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),
        ),
        maximum_risk=RiskTier.HIGH,
        maximum_blast_radius=BlastRadius.SINGLE_RESOURCE,
        approval_from_risk=RiskTier.LOW,
        required_quorum=quorum,
        prohibit_self_approval=True,
        require_evidence=True,
        require_critic_approval=True,
        max_actions_per_plan=4,
        max_actions_per_period=10,
        max_concurrent_actions=2,
        approval_ttl_seconds=ttl_seconds,
    )


def action(
    action_target: ActionTarget | None = None,
    *,
    action_id: UUID | None = None,
    idempotency_key: str = "tenant-remediation:checkout:restart:1",
    post_expected: bool = True,
) -> ActionSpecification:
    return ActionSpecification(
        action_id or uuid4(),
        ActionKind.KUBERNETES_ROLLOUT_RESTART,
        action_target or target(),
        RiskTier.HIGH,
        BlastRadius.SINGLE_RESOURCE,
        (
            Condition(
                "deployment.available",
                ConditionOperator.EQUALS,
                True,
                "evidence-checkout",
            ),
        ),
        (
            Condition(
                "deployment.restart_observed",
                ConditionOperator.EQUALS,
                post_expected,
            ),
        ),
        ("evidence-checkout",),
        idempotency_key,
        10,
        RetryPolicy(2, 0, 0),
        ReconciliationPolicy(interval_seconds=0),
        True,
        rollback_reference="aegis-runbook://checkout/rollback-review",
        compensation_reference="aegis-runbook://checkout/escalate",
    )


def plan(
    selected_action: ActionSpecification | None = None,
    selected_policy: ApprovalPolicySnapshot | None = None,
    *,
    plan_id: UUID | None = None,
    revision: int = 1,
    requested_by: str = "operator",
    critic_approved: bool = True,
    tenant_id: TenantId = TENANT_ID,
) -> RemediationPlan:
    item = selected_action or action()
    captured = selected_policy or policy(item.target, tenant_id=tenant_id)
    return RemediationPlan(
        plan_id or uuid4(),
        str(tenant_id),
        "checkout-incident",
        uuid4(),
        revision,
        requested_by,
        NOW,
        "Restart only the approved checkout deployment after bounded review.",
        (item,),
        (
            RemediationEvidenceCitation(
                "evidence-checkout",
                "aegis-evidence://checkout/incident",
                "a" * 64,
                NOW,
                0.95,
            ),
        ),
        captured,
        "aegis-artifact://checkout/verification",
        critic_approved,
    )


def lease(
    plan_id: UUID,
    *,
    tenant_id: TenantId = TENANT_ID,
    token: UUID | None = None,
    generation: int = 1,
    expires_at: datetime = NOW + timedelta(minutes=10),
) -> WorkLease:
    return WorkLease(
        plan_id,
        str(tenant_id),
        token or uuid4(),
        generation,
        "test-worker",
        1,
        NOW,
        NOW,
        expires_at,
    )
