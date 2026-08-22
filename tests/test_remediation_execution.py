"""Fenced controlled-action, crash-recovery, and verification tests."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid4

import pytest

from aegis_agent_platform.domain import (
    ActionLifecycleStatus,
    ApprovalStatus,
    Condition,
    ConditionOperator,
    DomainEventType,
    EffectOutcome,
    EventEnvelope,
    ReconciliationOutcome,
    RemediationPlan,
    VerificationOutcome,
    WorkLease,
    replay_remediation,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.identity import Role
from aegis_agent_platform.remediation import (
    ActionAdapterResult,
    ActionObservation,
    ActionQuotaUsage,
    ApprovalDecision,
    ControlledActionError,
    ControlledActionExecutor,
    FakeControlledActionAdapter,
    InMemoryRemediationRepository,
    RemediationApprovalService,
    RemediationMetrics,
    RemediationTracer,
    StaticApprovalAuthority,
)
from aegis_agent_platform.remediation.execution import (
    ActionErrorClass,
    _conditions,
)
from aegis_agent_platform.tenancy import TenantContext
from remediation_helpers import (
    CONTEXT,
    NOW,
    Clock,
    action,
    lease,
    plan,
    principal,
)

APPROVER_ROLES = {
    "approver-one": frozenset({Role.APPROVER.value}),
    "approver-two": frozenset({Role.APPROVER.value}),
}


async def approved(
    *,
    selected_plan: RemediationPlan | None = None,
    selected_repository: InMemoryRemediationRepository | None = None,
) -> tuple[InMemoryRemediationRepository, RemediationPlan, WorkLease]:
    repository = selected_repository or InMemoryRemediationRepository()
    service = RemediationApprovalService(repository, clock=Clock())
    remediation_plan = selected_plan or plan(requested_by="operator")
    proposal = await service.propose(
        principal("operator", Role.OPERATOR),
        CONTEXT,
        remediation_plan,
        remediation_plan.approval_policy,
        ActionQuotaUsage(0, 0),
        idempotency_key=f"execution-proposal:{remediation_plan.plan_id}",
    )
    approval_id = next(iter(proposal.state.approvals))
    for actor in ("approver-one", "approver-two"):
        await service.decide(
            principal(actor, Role.APPROVER),
            CONTEXT,
            remediation_plan.plan_id,
            approval_id,
            ApprovalDecision.GRANT,
            decision_id=uuid4(),
            current_policy=remediation_plan.approval_policy,
            rationale_code="reviewed",
            comment="approved",
        )
    active_lease = lease(remediation_plan.plan_id)
    repository.register_lease(active_lease)
    return repository, remediation_plan, active_lease


def executor(
    repository: InMemoryRemediationRepository,
    adapter: FakeControlledActionAdapter,
    *,
    clock: Clock | None = None,
    roles: dict[str, frozenset[str]] | None = None,
    metrics: RemediationMetrics | None = None,
    tracer: RemediationTracer | None = None,
) -> ControlledActionExecutor:
    async def no_sleep(_seconds: float) -> None:
        return None

    return ControlledActionExecutor(
        repository,
        adapter,
        StaticApprovalAuthority(roles if roles is not None else APPROVER_ROLES),
        metrics=metrics,
        tracer=tracer,
        clock=clock or Clock(),
        sleep=no_sleep,
    )


def test_approved_action_records_intent_before_effect_and_verifies_state() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        adapter = FakeControlledActionAdapter(clock=Clock())
        state = await executor(repository, adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert (
            state.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )
        assert state.verifications[-1].outcome is VerificationOutcome.SUCCESS
        events = await repository.load(CONTEXT, selected.plan_id)
        types = [item.event_type for item in events]
        assert types.index(DomainEventType.ACTION_EXECUTION_REQUESTED) < types.index(
            DomainEventType.ACTION_EXECUTION_SUCCEEDED
        )
        assert adapter.calls == [
            "observe",
            "dry_run",
            "observe",
            "execute",
            "observe",
        ]
        duplicate = await executor(repository, adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert duplicate == state
        assert adapter.calls.count("execute") == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("outcomes", "ambiguous_applied", "expected_calls"),
    [
        (
            (EffectOutcome.RETRYABLE_FAILURE, EffectOutcome.SUCCEEDED),
            False,
            2,
        ),
        ((EffectOutcome.AMBIGUOUS,), True, 1),
        ((EffectOutcome.AMBIGUOUS, EffectOutcome.SUCCEEDED), False, 2),
    ],
)
def test_retry_and_ambiguous_outcomes_reconcile_before_redelivery(
    outcomes: Sequence[EffectOutcome],
    ambiguous_applied: bool,
    expected_calls: int,
) -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        adapter = FakeControlledActionAdapter(
            execution_outcomes=outcomes,
            ambiguous_applied=ambiguous_applied,
            clock=Clock(),
        )
        state = await executor(repository, adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert (
            state.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )
        assert adapter.calls.count("execute") == expected_calls
        assert "reconcile" in adapter.calls
        assert adapter.calls.index("reconcile") < (
            adapter.calls.index("execute", adapter.calls.index("execute") + 1)
            if expected_calls == 2
            else len(adapter.calls)
        )

    asyncio.run(scenario())


def test_permanent_failure_cancellation_and_precondition_change_fail_closed() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        permanent = FakeControlledActionAdapter(
            execution_outcomes=(EffectOutcome.PERMANENT_FAILURE,),
            clock=Clock(),
        )
        failed = await executor(repository, permanent).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert (
            failed.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.FAILED
        )

        repository2, selected2, active_lease2 = await approved()
        cancelled = await executor(
            repository2, FakeControlledActionAdapter(clock=Clock())
        ).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected2.plan_id,
            selected2.actions[0].action_id,
            active_lease2,
            selected2.approval_policy,
            cancellation=Cancellation(True),
        )
        assert (
            cancelled.action_statuses[selected2.actions[0].action_id]
            is ActionLifecycleStatus.CANCELLED
        )

        repository3, selected3, active_lease3 = await approved()
        unavailable = FakeControlledActionAdapter(
            verification_values={"deployment.available": False},
            clock=Clock(),
        )
        preflight = await executor(repository3, unavailable).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected3.plan_id,
            selected3.actions[0].action_id,
            active_lease3,
            selected3.approval_policy,
        )
        assert (
            preflight.action_statuses[selected3.actions[0].action_id]
            is ActionLifecycleStatus.FAILED
        )
        assert "execute" not in unavailable.calls

    asyncio.run(scenario())


def test_stale_fence_policy_role_and_adapter_capability_prevent_any_effect() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        adapter = FakeControlledActionAdapter(clock=Clock())
        stale = replace(active_lease, token=uuid4())
        with pytest.raises(FencingError):
            await executor(repository, adapter).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                stale,
                selected.approval_policy,
            )
        with pytest.raises(PermissionError, match="stale"):
            await executor(repository, adapter).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                replace(selected.approval_policy, policy_version="changed"),
            )
        with pytest.raises(PermissionError, match="role"):
            await executor(repository, adapter, roles={}).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
        with pytest.raises(PermissionError, match="configured"):
            await ControlledActionExecutor(
                repository,
                UnsupportedAdapter(clock=Clock()),
                StaticApprovalAuthority(APPROVER_ROLES),
                clock=Clock(),
            ).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
        assert "execute" not in adapter.calls

    asyncio.run(scenario())


def test_authority_policy_approval_and_cancellation_recheck_before_intent() -> None:
    async def scenario() -> None:
        policy_repository, policy_plan, policy_lease = await approved()
        policy_lease = replace(
            policy_lease,
            expires_at=NOW + timedelta(hours=3),
        )
        policy_repository.replace_lease(policy_lease)
        selected_clock = Clock()
        policy_adapter = AdvancingObservationAdapter(selected_clock)
        with pytest.raises(PermissionError, match="runtime_policy_denied"):
            await executor(
                policy_repository,
                policy_adapter,
                clock=selected_clock,
            ).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                policy_plan.plan_id,
                policy_plan.actions[0].action_id,
                policy_lease,
                policy_plan.approval_policy,
            )
        assert not any(
            event.event_type is DomainEventType.ACTION_EXECUTION_REQUESTED
            for event in policy_repository.events
        )

        role_repository, role_plan, role_lease = await approved()
        authority = MutableApprovalAuthority(APPROVER_ROLES)
        role_adapter = RevokingRoleObservationAdapter(authority, clock=Clock())
        with pytest.raises(PermissionError, match="role"):
            await ControlledActionExecutor(
                role_repository,
                role_adapter,
                authority,
                clock=Clock(),
            ).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                role_plan.plan_id,
                role_plan.actions[0].action_id,
                role_lease,
                role_plan.approval_policy,
            )
        assert not any(
            event.event_type is DomainEventType.ACTION_EXECUTION_REQUESTED
            for event in role_repository.events
        )

        approval_repository, approval_plan, approval_lease = await approved()
        approval_service = RemediationApprovalService(
            approval_repository,
            clock=Clock(),
        )
        approval_state = replay_remediation(
            await approval_repository.load(
                CONTEXT,
                approval_plan.plan_id,
            )
        )

        async def revoke_approval() -> None:
            exact_approval_id = next(iter(approval_state.approvals))
            await approval_service.revoke(
                principal("approver-one", Role.APPROVER),
                CONTEXT,
                approval_plan.plan_id,
                exact_approval_id,
                revocation_id=uuid4(),
                rationale_code="scope_withdrawn",
            )

        approval_adapter = MutatingObservationAdapter(
            revoke_approval,
            clock=Clock(),
        )
        with pytest.raises(PermissionError, match="approval"):
            await executor(approval_repository, approval_adapter).execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                approval_plan.plan_id,
                approval_plan.actions[0].action_id,
                approval_lease,
                approval_plan.approval_policy,
            )
        assert not any(
            event.event_type is DomainEventType.ACTION_EXECUTION_REQUESTED
            for event in approval_repository.events
        )

        cancel_repository, cancel_plan, cancel_lease = await approved()
        cancel_adapter = AdvancingObservationAdapter(Clock())
        cancelled = await executor(cancel_repository, cancel_adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            cancel_plan.plan_id,
            cancel_plan.actions[0].action_id,
            cancel_lease,
            cancel_plan.approval_policy,
            cancellation=ObservationCancellation(cancel_adapter),
        )
        assert (
            cancelled.action_statuses[cancel_plan.actions[0].action_id]
            is ActionLifecycleStatus.CANCELLED
        )
        assert not any(
            event.event_type is DomainEventType.ACTION_EXECUTION_REQUESTED
            for event in cancel_repository.events
        )

    asyncio.run(scenario())


def test_runtime_concurrency_quota_blocks_a_second_active_action() -> None:
    async def scenario() -> None:
        repository = InMemoryRemediationRepository()
        first_action = action(
            idempotency_key="tenant-remediation:checkout:restart:quota-one"
        )
        first_policy = replace(
            plan(first_action).approval_policy,
            max_concurrent_actions=1,
        )
        first_plan = plan(
            first_action,
            first_policy,
            requested_by="operator",
        )
        repository, first_plan, first_lease = await approved(
            selected_plan=first_plan,
            selected_repository=repository,
        )
        second_action = action(
            idempotency_key="tenant-remediation:checkout:restart:quota-two"
        )
        second_plan = plan(
            second_action,
            first_policy,
            requested_by="operator",
        )
        repository, second_plan, second_lease = await approved(
            selected_plan=second_plan,
            selected_repository=repository,
        )
        adapter = BlockingExecuteAdapter(clock=Clock())
        worker = executor(repository, adapter)
        first_task = asyncio.create_task(
            worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                first_plan.plan_id,
                first_plan.actions[0].action_id,
                first_lease,
                first_plan.approval_policy,
            )
        )
        await asyncio.wait_for(adapter.started.wait(), timeout=1)
        try:
            with pytest.raises(PermissionError, match="runtime_policy_denied"):
                await worker.execute(
                    principal("operator", Role.OPERATOR),
                    CONTEXT,
                    second_plan.plan_id,
                    second_plan.actions[0].action_id,
                    second_lease,
                    second_plan.approval_policy,
                )
        finally:
            adapter.release.set()
        completed = await first_task
        assert (
            completed.action_statuses[first_plan.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )
        assert adapter.calls.count("execute") == 1

    asyncio.run(scenario())


def test_crash_after_effect_reconciles_without_duplicate_provider_call() -> None:
    async def scenario() -> None:
        repository = FailingOutcomeRepository()
        service = RemediationApprovalService(repository, clock=Clock())
        selected = plan(requested_by="operator")
        proposal = await service.propose(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected,
            selected.approval_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="crash-proposal",
        )
        approval_id = next(iter(proposal.state.approvals))
        for actor in ("approver-one", "approver-two"):
            await service.decide(
                principal(actor, Role.APPROVER),
                CONTEXT,
                selected.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        active_lease = lease(selected.plan_id)
        repository.register_lease(active_lease)
        adapter = FakeControlledActionAdapter(clock=Clock())
        worker = executor(repository, adapter)
        with pytest.raises(RuntimeError, match="simulated_crash"):
            await worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
        recovered = await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert (
            recovered.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )
        assert adapter.calls.count("execute") == 1
        assert "reconcile" in adapter.calls

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("failed_event", "adapter"),
    [
        (
            DomainEventType.ACTION_RECONCILIATION_COMPLETED,
            FakeControlledActionAdapter(
                execution_outcomes=(EffectOutcome.AMBIGUOUS,),
                ambiguous_applied=True,
                clock=Clock(),
            ),
        ),
        (
            DomainEventType.ACTION_VERIFICATION_COMPLETED,
            FakeControlledActionAdapter(clock=Clock()),
        ),
    ],
)
def test_partial_reconciliation_and_verification_crashes_resume_idempotently(
    failed_event: DomainEventType,
    adapter: FakeControlledActionAdapter,
) -> None:
    async def scenario() -> None:
        selected_repository = FailingLifecycleAppendRepository(failed_event)
        repository, selected, active_lease = await approved(
            selected_repository=selected_repository
        )
        worker = executor(repository, adapter)
        with pytest.raises(RuntimeError, match="partial_lifecycle_crash"):
            await worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
        recovered = await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        requested_event = (
            DomainEventType.ACTION_RECONCILIATION_REQUESTED
            if failed_event is DomainEventType.ACTION_RECONCILIATION_COMPLETED
            else DomainEventType.ACTION_VERIFICATION_REQUESTED
        )
        assert (
            sum(event.event_type is requested_event for event in repository.events) == 1
        )
        assert adapter.calls.count("execute") == 1
        assert (
            recovered.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )

    asyncio.run(scenario())


def test_crash_between_retryable_failure_and_next_intent_resumes_retry() -> None:
    async def scenario() -> None:
        selected_repository = FailingSecondIntentRepository()
        repository, selected, active_lease = await approved(
            selected_repository=selected_repository
        )
        adapter = FakeControlledActionAdapter(
            execution_outcomes=(
                EffectOutcome.RETRYABLE_FAILURE,
                EffectOutcome.SUCCEEDED,
            ),
            clock=Clock(),
        )
        worker = executor(repository, adapter)
        with pytest.raises(RuntimeError, match="crash_before_retry_intent"):
            await worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
        interrupted = replay_remediation(
            await repository.load(CONTEXT, selected.plan_id)
        )
        assert (
            interrupted.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.FAILED
        )
        assert interrupted.executions[-1].outcome is EffectOutcome.RETRYABLE_FAILURE

        recovered = await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert (
            recovered.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )
        assert adapter.calls.count("execute") == 2

    asyncio.run(scenario())


def test_revoked_approval_after_effect_intent_still_reconciles_without_retry() -> None:
    async def scenario() -> None:
        selected_repository = FailingOutcomeRepository()
        repository, selected, active_lease = await approved(
            selected_repository=selected_repository
        )
        adapter = FakeControlledActionAdapter(clock=Clock())
        worker = executor(repository, adapter)
        with pytest.raises(RuntimeError, match="simulated_crash"):
            await worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
        state = replay_remediation(await repository.load(CONTEXT, selected.plan_id))
        approval_id = next(iter(state.approvals))
        await RemediationApprovalService(repository, clock=Clock()).revoke(
            principal("approver-one", Role.APPROVER),
            CONTEXT,
            selected.plan_id,
            approval_id,
            revocation_id=uuid4(),
            rationale_code="scope_withdrawn",
        )

        recovered = await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )

        assert (
            recovered.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )
        assert adapter.calls.count("execute") == 1
        assert "reconcile" in adapter.calls

    asyncio.run(scenario())


def test_permanent_and_exhausted_attempts_remain_terminal_on_redelivery() -> None:
    async def scenario() -> None:
        for outcomes in (
            (EffectOutcome.PERMANENT_FAILURE,),
            (EffectOutcome.RETRYABLE_FAILURE, EffectOutcome.RETRYABLE_FAILURE),
        ):
            repository, selected, active_lease = await approved()
            adapter = FakeControlledActionAdapter(
                execution_outcomes=outcomes,
                clock=Clock(),
            )
            worker = executor(repository, adapter)
            terminal = await worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
            calls = adapter.calls.count("execute")
            duplicate = await worker.execute(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
            assert duplicate == terminal
            assert adapter.calls.count("execute") == calls

    asyncio.run(scenario())


def test_verification_failure_unknown_and_controlled_reversals() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        failed_verification = FakeControlledActionAdapter(
            verification_values={"deployment.restart_observed": False},
            clock=Clock(),
        )
        state = await executor(repository, failed_verification).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert state.verifications[-1].outcome is VerificationOutcome.FAILURE
        rolled_back = await executor(repository, failed_verification).rollback(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert (
            rolled_back.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.ROLLED_BACK
        )
        compensated = await executor(repository, failed_verification).rollback(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
            compensate=True,
        )
        assert (
            compensated.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.COMPENSATED
        )

        repository2, selected2, active_lease2 = await approved()
        unknown_adapter = VerificationUnknownAdapter(clock=Clock())
        unknown = await executor(repository2, unknown_adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected2.plan_id,
            selected2.actions[0].action_id,
            active_lease2,
            selected2.approval_policy,
        )
        assert unknown.verifications[-1].outcome is VerificationOutcome.UNKNOWN

    asyncio.run(scenario())


def test_stale_verification_observation_is_rejected() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        stale = StaleVerificationObservationAdapter(clock=Clock())
        state = await executor(repository, stale).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert state.verifications[-1].outcome is VerificationOutcome.UNKNOWN
        assert (
            state.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.VERIFICATION_UNKNOWN
        )

    asyncio.run(scenario())


def test_revision_reexecutes_reused_action_ids() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        adapter = FakeControlledActionAdapter(clock=Clock())
        worker = executor(repository, adapter)

        initial = await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert initial.verifications[-1].outcome is VerificationOutcome.SUCCESS

        revised_action = replace(
            selected.actions[0],
            idempotency_key="tenant-remediation:checkout:restart:revision-2",
        )
        revised_plan = replace(
            selected,
            revision=2,
            rationale="Revalidate the rollout restart after renewed evidence.",
            actions=(revised_action,),
        )
        service = RemediationApprovalService(repository, clock=Clock())
        revised = await service.revise(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            revised_plan,
            revised_plan.approval_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="revision-reuse-action-id",
        )
        revised_approval = next(
            approval.scope.approval_id
            for approval in revised.approvals.values()
            if approval.scope.plan_digest == revised_plan.digest
            and approval.status is ApprovalStatus.PENDING
        )
        for actor_id in ("approver-one", "approver-two"):
            await service.decide(
                principal(actor_id, Role.APPROVER),
                CONTEXT,
                revised_plan.plan_id,
                revised_approval,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=revised_plan.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        rerun = await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            revised_plan.plan_id,
            revised_action.action_id,
            active_lease,
            revised_plan.approval_policy,
        )
        assert adapter.calls.count("execute") == 2
        assert len(rerun.executions) == 1
        assert len(rerun.verifications) == 1
        assert rerun.verifications[-1].outcome is VerificationOutcome.SUCCESS

    asyncio.run(scenario())


def test_dispatch_metric_counts_only_claim_events() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        metrics = RemediationMetrics()
        adapter = FakeControlledActionAdapter(clock=Clock())
        await executor(repository, adapter, metrics=metrics).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert metrics.snapshot()[
            ("actions_dispatched", selected.actions[0].kind.value)
        ] == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("failed_event", "compensate", "adapter_call", "error_code"),
    [
        (
            DomainEventType.ACTION_ROLLBACK_COMPLETED,
            False,
            "rollback",
            "rollback_outcome_missing_ambiguous",
        ),
        (
            DomainEventType.ACTION_COMPENSATION_COMPLETED,
            True,
            "compensate",
            "compensation_outcome_missing_ambiguous",
        ),
    ],
)
def test_reversal_crash_recovery_never_duplicates_the_external_effect(
    failed_event: DomainEventType,
    compensate: bool,
    adapter_call: str,
    error_code: str,
) -> None:
    async def scenario() -> None:
        selected_repository = FailingLifecycleAppendRepository(failed_event)
        repository, selected, active_lease = await approved(
            selected_repository=selected_repository
        )
        adapter = FakeControlledActionAdapter(clock=Clock())
        worker = executor(repository, adapter)
        await worker.execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        with pytest.raises(RuntimeError, match="partial_lifecycle_crash"):
            await worker.rollback(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
                compensate=compensate,
            )
        recovered = await worker.rollback(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
            compensate=compensate,
        )
        assert adapter.calls.count(adapter_call) == 1
        assert repository.events[-1].payload["error_code"] == error_code
        duplicate = await worker.rollback(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
            compensate=compensate,
        )
        assert duplicate == recovered
        assert adapter.calls.count(adapter_call) == 1

    asyncio.run(scenario())


def test_adapter_exceptions_and_target_conflicts_are_contained() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        buggy = BuggyAdapter(clock=Clock())
        state = await executor(repository, buggy).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert state.executions[-1].outcome is EffectOutcome.AMBIGUOUS
        assert state.reconciliations[-1].outcome is ReconciliationOutcome.UNKNOWN

        repository2, selected2, active_lease2 = await approved()
        conflicted = await executor(
            repository2,
            WrongTargetAdapter(clock=Clock()),
        ).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected2.plan_id,
            selected2.actions[0].action_id,
            active_lease2,
            selected2.approval_policy,
        )
        assert (
            conflicted.action_statuses[selected2.actions[0].action_id]
            is ActionLifecycleStatus.FAILED
        )
        assert (
            repository2.events[-1].event_type is DomainEventType.ACTION_PREFLIGHT_FAILED
        )
        with pytest.raises(ValueError, match="fingerprints"):
            ActionObservation(
                "not-a-digest",
                sha256(b"state").hexdigest(),
                {},
                (),
                NOW,
            )

    asyncio.run(scenario())


@dataclass(frozen=True, slots=True)
class Cancellation:
    cancelled: bool


class UnsupportedAdapter(FakeControlledActionAdapter):
    def supports(self, action_spec: object) -> bool:
        del action_spec
        return False


class MutatingObservationAdapter(FakeControlledActionAdapter):
    def __init__(
        self,
        mutation: Callable[[], Awaitable[None]],
        *,
        clock: Clock,
    ) -> None:
        super().__init__(clock=clock)
        self._mutation = mutation
        self.observations = 0

    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        observation = await super().observe(context, action_spec)  # type: ignore[arg-type]
        self.observations += 1
        if self.observations == 2:
            await self._mutation()
        return observation


class AdvancingObservationAdapter(FakeControlledActionAdapter):
    def __init__(self, clock: Clock) -> None:
        super().__init__(clock=clock)
        self._selected_clock = clock
        self.observations = 0

    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        observation = await super().observe(context, action_spec)  # type: ignore[arg-type]
        self.observations += 1
        if self.observations == 2:
            self._selected_clock.advance(7_201)
        return observation


class MutableApprovalAuthority:
    def __init__(self, roles: Mapping[str, frozenset[str]]) -> None:
        self.roles = roles
        self.active = True

    def current(
        self,
        context: TenantContext,
        approver_ids: Sequence[str],
        required_roles: frozenset[str],
        *,
        at: datetime,
    ) -> bool:
        del context, at
        return self.active and all(
            self.roles.get(actor, frozenset()).intersection(required_roles)
            for actor in approver_ids
        )


class RevokingRoleObservationAdapter(FakeControlledActionAdapter):
    def __init__(self, authority: MutableApprovalAuthority, *, clock: Clock) -> None:
        super().__init__(clock=clock)
        self._authority = authority
        self.observations = 0

    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        observation = await super().observe(context, action_spec)  # type: ignore[arg-type]
        self.observations += 1
        if self.observations == 2:
            self._authority.active = False
        return observation


@dataclass(slots=True)
class ObservationCancellation:
    adapter: AdvancingObservationAdapter

    @property
    def cancelled(self) -> bool:
        return self.adapter.observations >= 2


class BlockingExecuteAdapter(FakeControlledActionAdapter):
    def __init__(self, *, clock: Clock) -> None:
        super().__init__(clock=clock)
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        self.started.set()
        await self.release.wait()
        return await super().execute(context, action_spec)  # type: ignore[arg-type]


class FailingOutcomeRepository(InMemoryRemediationRepository):
    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    async def append_fenced(
        self,
        context: TenantContext,
        plan_id: UUID,
        active_lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not self.failed and any(
            event.event_type is DomainEventType.ACTION_EXECUTION_SUCCEEDED
            for event in events
        ):
            self.failed = True
            raise RuntimeError("simulated_crash_after_provider_effect")
        return await super().append_fenced(
            context,
            plan_id,
            active_lease,
            events,
            expected_version=expected_version,
        )


class FailingLifecycleAppendRepository(InMemoryRemediationRepository):
    def __init__(self, failed_event: DomainEventType) -> None:
        super().__init__()
        self.failed_event = failed_event
        self.failed = False

    async def append_fenced(
        self,
        context: TenantContext,
        plan_id: UUID,
        active_lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not self.failed and any(
            event.event_type is self.failed_event for event in events
        ):
            self.failed = True
            raise RuntimeError("simulated_partial_lifecycle_crash")
        return await super().append_fenced(
            context,
            plan_id,
            active_lease,
            events,
            expected_version=expected_version,
        )


class FailingSecondIntentRepository(InMemoryRemediationRepository):
    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    async def append_fenced(
        self,
        context: TenantContext,
        plan_id: UUID,
        active_lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not self.failed and any(
            event.event_type is DomainEventType.ACTION_EXECUTION_REQUESTED
            and event.payload.get("attempt") == 2
            for event in events
        ):
            self.failed = True
            raise RuntimeError("simulated_crash_before_retry_intent")
        return await super().append_fenced(
            context,
            plan_id,
            active_lease,
            events,
            expected_version=expected_version,
        )


class VerificationUnknownAdapter(FakeControlledActionAdapter):
    def __init__(self, *, clock: Clock) -> None:
        super().__init__(clock=clock)
        self.observations = 0

    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        self.observations += 1
        if self.observations >= 3:
            raise ControlledActionError(
                ActionErrorClass.TRANSIENT,
                "fresh_evidence_unavailable",
                retryable=True,
            )
        return await super().observe(context, action_spec)  # type: ignore[arg-type]


class StaleVerificationObservationAdapter(FakeControlledActionAdapter):
    def __init__(self, *, clock: Clock) -> None:
        super().__init__(clock=clock)
        self.observations = 0

    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        observation = await super().observe(context, action_spec)  # type: ignore[arg-type]
        self.observations += 1
        if self.observations >= 3:
            return replace(
                observation,
                observed_at=observation.observed_at - timedelta(seconds=1),
            )
        return observation


class BuggyAdapter(FakeControlledActionAdapter):
    async def execute(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        del context, action_spec
        raise RuntimeError("provider SDK exploded")

    async def reconcile(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> tuple[ReconciliationOutcome, ActionObservation]:
        del context, action_spec
        raise RuntimeError("provider SDK exploded again")


class WrongTargetAdapter(FakeControlledActionAdapter):
    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        observed = await super().observe(context, action_spec)  # type: ignore[arg-type]
        return replace(observed, target_fingerprint=sha256(b"wrong").hexdigest())


class DryRunTimeoutAdapter(FakeControlledActionAdapter):
    async def dry_run(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        del context, action_spec
        raise TimeoutError


class DryRunControlledAdapter(FakeControlledActionAdapter):
    async def dry_run(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        del context, action_spec
        raise ControlledActionError(
            ActionErrorClass.PERMANENT,
            "dry_run_rejected",
            retryable=False,
        )


class DryRunBugAdapter(FakeControlledActionAdapter):
    async def dry_run(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        del context, action_spec
        raise RuntimeError("provider secret must not escape")


class ObserveTimeoutAdapter(FakeControlledActionAdapter):
    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        del context, action_spec
        raise TimeoutError


class ObserveBugAdapter(FakeControlledActionAdapter):
    async def observe(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionObservation:
        del context, action_spec
        raise RuntimeError("provider secret must not escape")


class ExecuteTimeoutAdapter(FakeControlledActionAdapter):
    async def execute(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        del context, action_spec
        raise TimeoutError


class ExecuteWrongTargetAdapter(FakeControlledActionAdapter):
    async def execute(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        result = await super().execute(context, action_spec)  # type: ignore[arg-type]
        return replace(result, target_fingerprint=sha256(b"wrong").hexdigest())


class ReversalFailureAdapter(FakeControlledActionAdapter):
    async def rollback(
        self,
        context: TenantContext,
        action_spec: object,
    ) -> ActionAdapterResult:
        del context, action_spec
        raise TimeoutError


def test_execution_contract_bounds_and_all_condition_operators() -> None:
    selected = action()
    fingerprint = selected.target.fingerprint
    state_fingerprint = sha256(b"state").hexdigest()
    observation = ActionObservation(
        fingerprint,
        state_fingerprint,
        {
            "exists": "value",
            "equal": 3,
            "number": 5,
            "text": "safe",
        },
        ("evidence",),
        NOW,
    )

    assert (
        _conditions(
            (
                Condition("exists", ConditionOperator.EXISTS, True),
                Condition("equal", ConditionOperator.EQUALS, 3),
                Condition("text", ConditionOperator.NOT_EQUALS, "unsafe"),
                Condition("number", ConditionOperator.AT_LEAST, 4),
                Condition("number", ConditionOperator.AT_MOST, 6),
            ),
            observation,
        )
        is VerificationOutcome.SUCCESS
    )
    assert (
        _conditions(
            (
                Condition("missing", ConditionOperator.EQUALS, True),
                Condition("equal", ConditionOperator.EQUALS, 3),
            ),
            observation,
        )
        is VerificationOutcome.PARTIAL
    )
    assert (
        _conditions(
            (Condition("missing", ConditionOperator.EQUALS, True),),
            observation,
        )
        is VerificationOutcome.UNKNOWN
    )
    assert (
        _conditions(
            (Condition("text", ConditionOperator.AT_LEAST, 3),),
            observation,
        )
        is VerificationOutcome.FAILURE
    )
    with pytest.raises(ValueError, match="code"):
        ControlledActionError(
            ActionErrorClass.PERMANENT,
            "",
            retryable=False,
        )
    with pytest.raises(ValueError, match="timezone"):
        ActionObservation(
            fingerprint,
            state_fingerprint,
            {},
            (),
            datetime(2026, 1, 1),
        )
    with pytest.raises(ValueError, match="bounds"):
        ActionObservation(
            fingerprint,
            state_fingerprint,
            {f"signal-{index}": True for index in range(65)},
            (),
            NOW,
        )
    with pytest.raises(ValueError, match="signal"):
        ActionObservation(
            fingerprint,
            state_fingerprint,
            {"": True},
            (),
            NOW,
        )
    with pytest.raises(ValueError, match="evidence"):
        ActionObservation(
            fingerprint,
            state_fingerprint,
            {},
            ("",),
            NOW,
        )
    with pytest.raises(ValueError, match="provider reference"):
        ActionAdapterResult("", fingerprint, NOW)
    with pytest.raises(ValueError, match="target fingerprint"):
        ActionAdapterResult("provider-ref", "short", NOW)
    with pytest.raises(ValueError, match="completion"):
        ActionAdapterResult(
            "provider-ref",
            fingerprint,
            datetime(2026, 1, 1),
        )
    with pytest.raises(ValueError, match="at least one"):
        FakeControlledActionAdapter(execution_outcomes=())
    with pytest.raises(ValueError, match="timezone"):
        StaticApprovalAuthority(APPROVER_ROLES).current(
            CONTEXT,
            ("approver-one",),
            frozenset({Role.APPROVER.value}),
            at=datetime(2026, 1, 1),
        )


@pytest.mark.parametrize(
    "adapter_type",
    [DryRunTimeoutAdapter, DryRunControlledAdapter, DryRunBugAdapter],
)
def test_dry_run_failures_are_contained_before_effect(
    adapter_type: type[FakeControlledActionAdapter],
) -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        adapter = adapter_type(clock=Clock())
        state = await executor(repository, adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert not state.executions
        assert (
            state.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.FAILED
        )
        assert repository.events[-1].event_type == DomainEventType.ACTION_DRY_RUN_FAILED
        assert "execute" not in adapter.calls
        duplicate = await executor(repository, adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert duplicate == state
        assert "execute" not in adapter.calls

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("adapter_type", "expected_code"),
    [
        (ObserveTimeoutAdapter, "action_observation_timeout"),
        (ObserveBugAdapter, "action_observation_adapter_bug"),
    ],
)
def test_observation_failures_are_secret_safe(
    adapter_type: type[FakeControlledActionAdapter],
    expected_code: str,
) -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        state = await executor(repository, adapter_type(clock=Clock())).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert not state.executions
        assert (
            state.action_statuses[selected.actions[0].action_id]
            is ActionLifecycleStatus.FAILED
        )
        assert (
            repository.events[-1].event_type == DomainEventType.ACTION_PREFLIGHT_FAILED
        )
        assert repository.events[-1].payload["error_code"] == expected_code
        assert "provider secret must not escape" not in repr(repository.events)

    asyncio.run(scenario())


def test_timeout_wrong_result_target_and_failed_reversal_are_contained() -> None:
    async def scenario() -> None:
        repository, selected, active_lease = await approved()
        timeout_adapter = ExecuteTimeoutAdapter(clock=Clock())
        timed_out = await executor(repository, timeout_adapter).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected.plan_id,
            selected.actions[0].action_id,
            active_lease,
            selected.approval_policy,
        )
        assert timed_out.executions[-1].outcome is EffectOutcome.AMBIGUOUS
        assert timed_out.reconciliations[-1].outcome is (
            ReconciliationOutcome.NOT_APPLIED
        )

        repository2, selected2, active_lease2 = await approved()
        wrong_result = ExecuteWrongTargetAdapter(clock=Clock())
        conflicted = await executor(repository2, wrong_result).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected2.plan_id,
            selected2.actions[0].action_id,
            active_lease2,
            selected2.approval_policy,
        )
        assert conflicted.executions[-1].outcome is EffectOutcome.AMBIGUOUS
        assert conflicted.reconciliations[-1].outcome is ReconciliationOutcome.APPLIED
        assert (
            conflicted.action_statuses[selected2.actions[0].action_id]
            is ActionLifecycleStatus.VERIFIED
        )

        repository3, selected3, active_lease3 = await approved()
        reversal = ReversalFailureAdapter(clock=Clock())
        await executor(repository3, reversal).execute(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected3.plan_id,
            selected3.actions[0].action_id,
            active_lease3,
            selected3.approval_policy,
        )
        reversed_state = await executor(repository3, reversal).rollback(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected3.plan_id,
            selected3.actions[0].action_id,
            active_lease3,
            selected3.approval_policy,
        )
        assert reversed_state.executions[-1].outcome is EffectOutcome.SUCCEEDED
        assert (
            repository3.events[-1].event_type == DomainEventType.ACTION_ROLLBACK_FAILED
        )
        assert (
            repository3.events[-1].payload["error_code"] == "rollback_timeout_ambiguous"
        )

    asyncio.run(scenario())
