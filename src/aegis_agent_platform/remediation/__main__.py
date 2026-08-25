"""Deterministic fake-only Layer 8 demonstration."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TypedDict
from uuid import NAMESPACE_URL, UUID, uuid5

from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    ActionTarget,
    ApprovalPolicySnapshot,
    BlastRadius,
    Condition,
    ConditionOperator,
    EffectOutcome,
    EventEnvelope,
    MaintenanceWindow,
    ReconciliationPolicy,
    RemediationEvidenceCitation,
    RemediationPlan,
    RemediationState,
    RetryPolicy,
    RiskTier,
    WorkLease,
    replay_remediation,
)
from aegis_agent_platform.identity import (
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    TenantId,
    UserId,
)
from aegis_agent_platform.remediation.approvals import (
    ApprovalDecision,
    ApprovalDeniedError,
    RemediationApprovalService,
)
from aegis_agent_platform.remediation.execution import (
    ControlledActionExecutor,
    FakeControlledActionAdapter,
    StaticApprovalAuthority,
)
from aegis_agent_platform.remediation.policy import ActionQuotaUsage
from aegis_agent_platform.remediation.repository import (
    InMemoryRemediationRepository,
)
from aegis_agent_platform.tenancy import TenantContext


class RemediationScenario(StrEnum):
    APPROVED_SUCCESS = "approved-success"
    DENIED = "denied"
    EXPIRED = "expired"
    AMBIGUOUS_RECONCILED = "ambiguous-reconciled"
    VERIFICATION_FAILURE = "verification-failure"
    POLICY_ATTACK = "policy-attack"
    CRASH_RECOVERY = "crash-recovery"


class RemediationDemoResult(TypedDict):
    demo_only: bool
    uses_live_network: bool
    uses_production_credentials: bool
    adapter: str
    scenario: str
    plan_id: str
    plan_digest: str
    policy_digest: str
    status: str
    event_types: tuple[str, ...]
    adapter_calls: tuple[str, ...]
    at_least_once: bool
    claims_exactly_once: bool
    redacted: bool


@dataclass(slots=True)
class _Clock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class _UUIDs:
    def __init__(self) -> None:
        self._index = 0

    def __call__(self) -> UUID:
        self._index += 1
        return uuid5(NAMESPACE_URL, f"aegis-layer-8-demo:{self._index}")


async def run_remediation_demo(
    scenario: RemediationScenario = RemediationScenario.APPROVED_SUCCESS,
    *,
    tenant_id: str = "tenant-demo",
    incident_id: str = "checkout-latency-42",
    investigation_run_id: UUID | None = None,
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> RemediationDemoResult:
    """Run proposal through verification without networks or real credentials."""
    clock = _Clock(datetime(2026, 8, 13, 14, 0, tzinfo=UTC))
    uuids = _UUIDs()
    tenant = TenantId(tenant_id)
    context = TenantContext(tenant)
    operator = _principal("operator-demo", Role.OPERATOR, tenant, clock())
    approver_one = _principal("approver-one", Role.APPROVER, tenant, clock())
    approver_two = _principal("approver-two", Role.APPROVER, tenant, clock())
    target = ActionTarget(
        provider="kubernetes",
        environment="staging",
        resource_type="deployment",
        resource_id="checkout-api",
        scope="checkout",
    )
    policy = _policy(tenant, target, clock())
    if scenario in {RemediationScenario.DENIED, RemediationScenario.POLICY_ATTACK}:
        policy = replace(policy, allowed_target_fingerprints=frozenset())
    action = ActionSpecification(
        action_id=uuids(),
        kind=ActionKind.KUBERNETES_ROLLOUT_RESTART,
        target=target,
        risk=RiskTier.HIGH,
        blast_radius=BlastRadius.SINGLE_RESOURCE,
        preconditions=(
            Condition(
                "deployment.available",
                ConditionOperator.EQUALS,
                True,
                "checkout-saturation",
            ),
        ),
        postconditions=(
            Condition(
                "deployment.restart_observed",
                ConditionOperator.EQUALS,
                True,
            ),
        ),
        evidence_ids=("checkout-saturation",),
        idempotency_key="tenant-demo:checkout:restart:incident-42",
        timeout_seconds=10,
        retry_policy=RetryPolicy(2, 0, 0),
        reconciliation_policy=ReconciliationPolicy(interval_seconds=0),
        dry_run_supported=True,
        rollback_reference="aegis-runbook://checkout/restart-review",
        compensation_reference="aegis-runbook://checkout/escalate",
    )
    plan = RemediationPlan(
        plan_id=uuids(),
        tenant_id=str(tenant),
        incident_id=incident_id,
        investigation_run_id=investigation_run_id or uuids(),
        revision=1,
        requested_by=operator.actor_id,
        created_at=clock(),
        rationale="Restart one saturated checkout deployment after exact approval.",
        actions=(action,),
        evidence=(
            RemediationEvidenceCitation(
                "checkout-saturation",
                "aegis-evidence://checkout/latency-42",
                "2" * 64,
                clock(),
                0.98,
            ),
        ),
        approval_policy=policy,
        verification_artifact_reference=(
            "aegis-artifact://checkout/verification-plan-42"
        ),
        critic_approved=True,
    )
    repository = InMemoryRemediationRepository(uuid_factory=uuids)
    approvals = RemediationApprovalService(
        repository,
        clock=clock,
        uuid_factory=uuids,
    )
    proposed = await approvals.propose(
        operator,
        context,
        plan,
        policy,
        ActionQuotaUsage(0, 0),
        idempotency_key="proposal:checkout-latency-42",
    )
    approval = proposed.state.approval_for(action.action_id)
    if approval is None:
        return _result(
            repository,
            proposed.state,
            scenario,
            "policy_denied",
            event_sink=event_sink,
        )
    if scenario is RemediationScenario.EXPIRED:
        clock.advance(policy.approval_ttl_seconds + 1)
        try:
            await approvals.decide(
                approver_one,
                context,
                plan.plan_id,
                approval.scope.approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuids(),
                current_policy=policy,
                rationale_code="reviewed",
                comment="Reviewed exact target and bounded action.",
            )
        except ApprovalDeniedError:
            state = replay_remediation(await repository.load(context, plan.plan_id))
            return _result(
                repository,
                state,
                scenario,
                "expired",
                event_sink=event_sink,
            )
        raise RuntimeError("expired approval was unexpectedly accepted")
    for approver in (approver_one, approver_two):
        await approvals.decide(
            approver,
            context,
            plan.plan_id,
            approval.scope.approval_id,
            ApprovalDecision.GRANT,
            decision_id=uuids(),
            current_policy=policy,
            rationale_code="reviewed",
            comment="Reviewed exact target and bounded action.",
        )
    lease = WorkLease(
        work_id=plan.plan_id,
        tenant_id=str(tenant),
        token=uuids(),
        generation=1,
        owner="demo-worker",
        attempt=1,
        acquired_at=clock(),
        heartbeat_at=clock(),
        expires_at=clock() + timedelta(minutes=10),
    )
    repository.register_lease(lease)
    outcomes = {
        RemediationScenario.AMBIGUOUS_RECONCILED: (EffectOutcome.AMBIGUOUS,),
        RemediationScenario.CRASH_RECOVERY: (
            EffectOutcome.RETRYABLE_FAILURE,
            EffectOutcome.SUCCEEDED,
        ),
    }.get(scenario, (EffectOutcome.SUCCEEDED,))
    verification_values = (
        {"deployment.restart_observed": False}
        if scenario is RemediationScenario.VERIFICATION_FAILURE
        else None
    )
    adapter = FakeControlledActionAdapter(
        execution_outcomes=outcomes,
        ambiguous_applied=scenario is RemediationScenario.AMBIGUOUS_RECONCILED,
        verification_values=verification_values,
        clock=clock,
    )
    executor = ControlledActionExecutor(
        repository,
        adapter,
        StaticApprovalAuthority(
            {
                approver_one.actor_id: frozenset({Role.APPROVER.value}),
                approver_two.actor_id: frozenset({Role.APPROVER.value}),
            }
        ),
        clock=clock,
        uuid_factory=uuids,
        sleep=_no_sleep,
    )
    state = await executor.execute(
        operator,
        context,
        plan.plan_id,
        action.action_id,
        lease,
        policy,
    )
    return _result(
        repository,
        state,
        scenario,
        state.action_statuses[action.action_id].value,
        adapter_calls=tuple(adapter.calls),
        event_sink=event_sink,
    )


async def _no_sleep(seconds: float) -> None:
    if seconds < 0:
        raise ValueError("sleep cannot be negative")


def _policy(
    tenant_id: TenantId,
    target: ActionTarget,
    at: datetime,
) -> ApprovalPolicySnapshot:
    return ApprovalPolicySnapshot(
        tenant_id=str(tenant_id),
        policy_version="demo-policy-v1",
        allowed_action_kinds=frozenset({ActionKind.KUBERNETES_ROLLOUT_RESTART}),
        allowed_target_fingerprints=frozenset({target.fingerprint}),
        required_approver_roles=frozenset({Role.APPROVER.value}),
        maintenance_windows=(
            MaintenanceWindow(
                at - timedelta(minutes=5),
                at + timedelta(hours=1),
            ),
        ),
        maximum_risk=RiskTier.HIGH,
        maximum_blast_radius=BlastRadius.SINGLE_RESOURCE,
        approval_from_risk=RiskTier.LOW,
        required_quorum=2,
        prohibit_self_approval=True,
        require_evidence=True,
        require_critic_approval=True,
        max_actions_per_plan=2,
        max_actions_per_period=10,
        max_concurrent_actions=2,
        approval_ttl_seconds=120,
    )


def _principal(
    actor_id: str,
    role: Role,
    tenant_id: TenantId,
    at: datetime,
) -> Principal:
    user_id = UserId(actor_id)
    return Principal(
        subject=f"oidc-{actor_id}",
        issuer="https://identity.demo.invalid",
        tenant_id=tenant_id,
        kind=PrincipalKind.USER,
        role_bindings=(
            RoleBinding(
                tenant_id=tenant_id,
                role=role,
                assigned_by=UserId("demo-admin"),
                assigned_at=at - timedelta(minutes=1),
            ),
        ),
        user_id=user_id,
    )


def _result(
    repository: InMemoryRemediationRepository,
    state: RemediationState,
    scenario: RemediationScenario,
    status: str,
    *,
    adapter_calls: tuple[str, ...] = (),
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> RemediationDemoResult:
    if event_sink is not None:
        event_sink(repository.events)
    return {
        "demo_only": True,
        "uses_live_network": False,
        "uses_production_credentials": False,
        "adapter": "deterministic-fake",
        "scenario": scenario.value,
        "plan_id": str(state.plan.plan_id),
        "plan_digest": state.plan.digest,
        "policy_digest": state.plan.approval_policy.digest,
        "status": status,
        "event_types": tuple(event.event_type for event in repository.events),
        "adapter_calls": adapter_calls,
        "at_least_once": True,
        "claims_exactly_once": False,
        "redacted": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the fake-only Layer 8 demo")
    parser.add_argument(
        "--scenario",
        choices=tuple(item.value for item in RemediationScenario),
        default=RemediationScenario.APPROVED_SUCCESS.value,
    )
    arguments = parser.parse_args()
    result = asyncio.run(run_remediation_demo(RemediationScenario(arguments.scenario)))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
