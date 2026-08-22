"""Policy and exact-scope human approval tests."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from aegis_agent_platform.audit import InMemoryAuditStore
from aegis_agent_platform.domain import (
    ActorKind,
    ApprovalStatus,
    BlastRadius,
    DomainEventType,
    EventEnvelope,
    PolicyOutcome,
    RemediationPlan,
    RemediationState,
    RiskTier,
    WorkLease,
)
from aegis_agent_platform.event_store import ConcurrencyError, FencingError
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.remediation import (
    ActionQuotaUsage,
    ApprovalDecision,
    ApprovalDeniedError,
    InMemoryRemediationRepository,
    RemediationApprovalService,
    RemediationIdempotencyConflictError,
    RemediationMetrics,
    RemediationPolicyEvaluator,
)
from aegis_agent_platform.tenancy import TenantContext
from remediation_helpers import (
    CONTEXT,
    NOW,
    TENANT_ID,
    Clock,
    action,
    plan,
    policy,
    principal,
)


class BarrierExpiryRepository(InMemoryRemediationRepository):
    def __init__(self, barrier: asyncio.Barrier) -> None:
        super().__init__()
        self._barrier = barrier

    async def append(
        self,
        context: TenantContext,
        plan_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if any(
            event.event_type is DomainEventType.REMEDIATION_APPROVAL_EXPIRED
            for event in events
        ):
            await asyncio.wait_for(self._barrier.wait(), timeout=3)
        return await super().append(
            context,
            plan_id,
            events,
            expected_version=expected_version,
        )


async def proposed(
    *,
    clock: Clock | None = None,
    quorum: int = 2,
    ttl_seconds: int = 300,
) -> tuple[
    InMemoryRemediationRepository,
    RemediationApprovalService,
    RemediationPlan,
    RemediationState,
]:
    repository = InMemoryRemediationRepository()
    service = RemediationApprovalService(
        repository,
        clock=clock or Clock(),
        uuid_factory=uuid4,
    )
    selected_policy = policy(quorum=quorum, ttl_seconds=ttl_seconds)
    selected_plan = plan(
        selected_policy=selected_policy,
        requested_by="operator",
    )
    decision = await service.propose(
        principal("operator", Role.OPERATOR),
        CONTEXT,
        selected_plan,
        selected_policy,
        ActionQuotaUsage(0, 0),
        idempotency_key="proposal-1",
    )
    return repository, service, selected_plan, decision.state


def test_default_deny_enforces_target_risk_blast_quotas_evidence_and_critic() -> None:
    evaluator = RemediationPolicyEvaluator()
    allowed = action()
    allowed_plan = plan(allowed)
    default_denied = replace(
        policy(),
        allowed_action_kinds=frozenset(),
        allowed_target_fingerprints=frozenset(),
        maximum_risk=RiskTier.LOW,
        maximum_blast_radius=BlastRadius.SINGLE_RESOURCE,
        maintenance_windows=(),
        max_actions_per_plan=1,
        max_actions_per_period=1,
        max_concurrent_actions=1,
    )
    foreign = replace(
        allowed,
        risk=RiskTier.CRITICAL,
        blast_radius=BlastRadius.NAMESPACE,
    )

    result = evaluator.evaluate(
        CONTEXT,
        replace(allowed_plan, critic_approved=False),
        foreign,
        default_denied,
        ActionQuotaUsage(actions_in_period=1, active_actions=1),
        at=NOW + timedelta(days=2),
    )

    assert result.outcome is PolicyOutcome.DENY
    assert {
        "action_digest_mismatch",
        "action_kind_not_allowed",
        "target_not_allowed",
        "risk_threshold_exceeded",
        "blast_radius_exceeded",
        "outside_maintenance_window",
        "period_action_limit_exceeded",
        "action_concurrency_limit_exceeded",
        "critic_approval_missing",
    }.issubset(result.reasons)


def test_policy_requires_exact_scope_approval_when_all_gates_pass() -> None:
    selected = plan()
    result = RemediationPolicyEvaluator().evaluate(
        CONTEXT,
        selected,
        selected.actions[0],
        selected.approval_policy,
        ActionQuotaUsage(0, 0),
        at=NOW,
    )

    assert result.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert result.reasons == ("exact_scope_approval_required",)


def test_proposal_is_idempotent_conflict_detecting_and_audited() -> None:
    async def scenario() -> None:
        repository = InMemoryRemediationRepository()
        audit = InMemoryAuditStore()
        metrics = RemediationMetrics()
        service = RemediationApprovalService(
            repository,
            audit=audit,
            metrics=metrics,
            clock=Clock(),
        )
        selected = plan(requested_by="operator")
        actor = principal("operator", Role.OPERATOR)
        first = await service.propose(
            actor,
            CONTEXT,
            selected,
            selected.approval_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="same-proposal",
        )
        duplicate = await service.propose(
            actor,
            CONTEXT,
            selected,
            selected.approval_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="same-proposal",
        )
        assert first.result.created
        assert not duplicate.result.created
        assert len(audit.query(CONTEXT)) == 2
        assert metrics.snapshot()[("proposals", "none")] == 1
        with pytest.raises(RemediationIdempotencyConflictError):
            await service.propose(
                actor,
                CONTEXT,
                replace(selected, incident_id="different-incident"),
                selected.approval_policy,
                ActionQuotaUsage(0, 0),
                idempotency_key="same-proposal",
            )

    asyncio.run(scenario())


def test_two_person_quorum_sod_duplicate_denial_and_redaction() -> None:
    async def scenario() -> None:
        repository, service, selected, state = await proposed()
        selected_plan = selected
        approval_id = next(iter(state.approvals))
        with pytest.raises(ApprovalDeniedError, match="self"):
            await service.decide(
                principal("operator", Role.APPROVER),
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="reviewed",
                comment="safe",
            )
        first_actor = principal("approver-one", Role.APPROVER)
        first = await service.decide(
            first_actor,
            CONTEXT,
            selected_plan.plan_id,
            approval_id,
            ApprovalDecision.GRANT,
            decision_id=uuid4(),
            current_policy=selected_plan.approval_policy,
            rationale_code="reviewed",
            comment="token=super-secret-value",
        )
        assert first.status is ApprovalStatus.PENDING
        with pytest.raises(ApprovalDeniedError, match="duplicate"):
            await service.decide(
                first_actor,
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="reviewed",
                comment="again",
            )
        granted = await service.decide(
            principal("approver-two", Role.APPROVER),
            CONTEXT,
            selected_plan.plan_id,
            approval_id,
            ApprovalDecision.GRANT,
            decision_id=uuid4(),
            current_policy=selected_plan.approval_policy,
            rationale_code="reviewed",
            comment="independently reviewed",
        )
        assert granted.status is ApprovalStatus.GRANTED
        events = await repository.load(CONTEXT, selected_plan.plan_id)
        assert "super-secret-value" not in repr(events)
        assert "[REDACTED]" in repr(events)

    asyncio.run(scenario())


def test_decision_and_revocation_identifiers_are_exactly_idempotent() -> None:
    async def scenario() -> None:
        _repository, service, selected, state = await proposed(quorum=1)
        approval_id = next(iter(state.approvals))
        actor = principal("approver", Role.APPROVER)
        decision_id = uuid4()
        granted = await service.decide(
            actor,
            CONTEXT,
            selected.plan_id,
            approval_id,
            ApprovalDecision.GRANT,
            decision_id=decision_id,
            current_policy=selected.approval_policy,
            rationale_code="reviewed",
            comment="approved",
        )
        replayed = await service.decide(
            actor,
            CONTEXT,
            selected.plan_id,
            approval_id,
            ApprovalDecision.GRANT,
            decision_id=decision_id,
            current_policy=selected.approval_policy,
            rationale_code="reviewed",
            comment="different redacted comment",
        )
        assert replayed == granted
        with pytest.raises(RemediationIdempotencyConflictError):
            await service.decide(
                actor,
                CONTEXT,
                selected.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=decision_id,
                current_policy=selected.approval_policy,
                rationale_code="different",
                comment="approved",
            )

        revocation_id = uuid4()
        revoked = await service.revoke(
            actor,
            CONTEXT,
            selected.plan_id,
            approval_id,
            revocation_id=revocation_id,
            rationale_code="scope_withdrawn",
        )
        replayed_revocation = await service.revoke(
            actor,
            CONTEXT,
            selected.plan_id,
            approval_id,
            revocation_id=revocation_id,
            rationale_code="scope_withdrawn",
        )
        assert replayed_revocation == revoked
        with pytest.raises(RemediationIdempotencyConflictError):
            await service.revoke(
                actor,
                CONTEXT,
                selected.plan_id,
                approval_id,
                revocation_id=revocation_id,
                rationale_code="different",
            )

    asyncio.run(scenario())


def test_concurrent_distinct_grants_are_race_safe() -> None:
    async def scenario() -> None:
        _repository, service, selected, state = await proposed()
        selected_plan = selected
        approval_id = next(iter(state.approvals))
        results = await asyncio.gather(
            *(
                service.decide(
                    principal(f"approver-{index}", Role.APPROVER),
                    CONTEXT,
                    selected_plan.plan_id,
                    approval_id,
                    ApprovalDecision.GRANT,
                    decision_id=uuid4(),
                    current_policy=selected_plan.approval_policy,
                    rationale_code="reviewed",
                    comment="approved",
                )
                for index in range(2)
            )
        )
        granted = next(
            result for result in results if result.status is ApprovalStatus.GRANTED
        )
        assert len(granted.approver_ids) == 2

    asyncio.run(scenario())


def test_denial_expiry_revocation_stale_policy_and_missing_role() -> None:
    async def scenario() -> None:
        clock = Clock()
        _repository, service, selected, state = await proposed(
            clock=clock,
            ttl_seconds=60,
        )
        selected_plan = selected
        approval_id = next(iter(state.approvals))
        with pytest.raises(ApprovalDeniedError, match="role"):
            await service.decide(
                principal("tenant-admin", Role.TENANT_ADMIN),
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        with pytest.raises(ApprovalDeniedError, match="stale"):
            await service.decide(
                principal("approver", Role.APPROVER),
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=replace(
                    selected_plan.approval_policy,
                    policy_version="changed",
                ),
                rationale_code="reviewed",
                comment="approved",
            )
        clock.advance(61)
        with pytest.raises(ApprovalDeniedError, match="expired"):
            await service.decide(
                principal("approver", Role.APPROVER),
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        _, revoke_service, revoke_plan, revoke_state = await proposed()
        revoke_approval = next(iter(revoke_state.approvals))
        assert (
            await revoke_service.revoke(
                principal("approver", Role.APPROVER),
                CONTEXT,
                revoke_plan.plan_id,
                revoke_approval,
                revocation_id=uuid4(),
                rationale_code="scope_withdrawn",
            )
        ).status is ApprovalStatus.REVOKED

        _, second_service, second_plan, second_state = await proposed(quorum=1)
        second_approval = next(iter(second_state.approvals))
        denied = await second_service.decide(
            principal("approver", Role.APPROVER),
            CONTEXT,
            second_plan.plan_id,
            second_approval,
            ApprovalDecision.DENY,
            decision_id=uuid4(),
            current_policy=second_plan.approval_policy,
            rationale_code="unsafe",
            comment="denied",
        )
        assert denied.status is ApprovalStatus.DENIED

    asyncio.run(scenario())


def test_cross_tenant_forged_service_and_malformed_decisions_fail() -> None:
    async def scenario() -> None:
        _repository, service, selected, state = await proposed()
        selected_plan = selected
        approval_id = next(iter(state.approvals))
        with pytest.raises(ValueError, match="not found"):
            await service.decide(
                principal(
                    "other",
                    Role.APPROVER,
                    tenant_id=TenantId("tenant-other"),
                ),
                TenantContext(TenantId("tenant-other")),
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        with pytest.raises(ApprovalDeniedError, match="human"):
            await service.decide(
                principal("service-worker", Role.APPROVER, service=True),
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        with pytest.raises(ValueError, match="rationale"):
            await service.decide(
                principal("approver", Role.APPROVER),
                CONTEXT,
                selected_plan.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected_plan.approval_policy,
                rationale_code="x" * 129,
                comment="approved",
            )

    asyncio.run(scenario())


def test_revision_invalidates_prior_approval_and_rebuilds_projection() -> None:
    async def scenario() -> None:
        repository, service, selected, state = await proposed(quorum=1)
        selected_plan = selected
        approval_id = next(iter(state.approvals))
        await service.decide(
            principal("approver", Role.APPROVER),
            CONTEXT,
            selected_plan.plan_id,
            approval_id,
            ApprovalDecision.GRANT,
            decision_id=uuid4(),
            current_policy=selected_plan.approval_policy,
            rationale_code="reviewed",
            comment="approved",
        )
        revised = replace(
            selected_plan,
            revision=2,
            rationale="Revised exact scope after new evidence.",
        )
        updated = await service.revise(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            revised,
            revised.approval_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="revision-2",
        )
        assert updated.plan.revision == 2
        assert updated.approvals[approval_id].status is ApprovalStatus.REVOKED
        await repository.rebuild_projection(CONTEXT, selected_plan.plan_id)
        page, cursor = await repository.page(CONTEXT, limit=1)
        assert page[0]["revision"] == 2
        assert cursor is None
        current_events = await repository.load(CONTEXT, selected_plan.plan_id)
        with pytest.raises(ConcurrencyError):
            await repository.append(
                CONTEXT,
                selected_plan.plan_id,
                (
                    replace(
                        current_events[-1],
                        event_id=uuid4(),
                        aggregate_sequence=0,
                    ),
                ),
                expected_version=-1,
            )

    asyncio.run(scenario())


def test_service_principals_preserve_actor_kind_for_proposal_and_revocation() -> None:
    async def scenario() -> None:
        repository = InMemoryRemediationRepository()
        service = RemediationApprovalService(repository, clock=Clock())
        selected_policy = policy(quorum=1)
        selected_plan = plan(
            selected_policy=selected_policy,
            requested_by="svc-operator",
        )
        proposal = await service.propose(
            principal("svc-operator", Role.OPERATOR, service=True),
            CONTEXT,
            selected_plan,
            selected_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="service-proposal",
        )
        approval_id = next(iter(proposal.state.approvals))
        await service.revoke(
            principal("svc-approver", Role.APPROVER, service=True),
            CONTEXT,
            selected_plan.plan_id,
            approval_id,
            revocation_id=uuid4(),
            rationale_code="scope_withdrawn",
        )
        events = await repository.load(CONTEXT, selected_plan.plan_id)
        proposed_event = next(
            event
            for event in events
            if event.event_type is DomainEventType.REMEDIATION_PROPOSED
        )
        revoked_event = next(
            event
            for event in events
            if event.event_type is DomainEventType.REMEDIATION_APPROVAL_REVOKED
        )
        assert proposed_event.actor is not None
        assert proposed_event.actor.kind is ActorKind.SERVICE
        assert revoked_event.actor is not None
        assert revoked_event.actor.kind is ActorKind.SERVICE

    asyncio.run(scenario())


def test_concurrent_expired_grants_retry_without_leaking_concurrency_error() -> None:
    async def scenario() -> None:
        clock = Clock()
        repository = BarrierExpiryRepository(asyncio.Barrier(2))
        service = RemediationApprovalService(
            repository,
            clock=clock,
            uuid_factory=uuid4,
        )
        selected_policy = policy(ttl_seconds=60)
        selected_plan = plan(
            selected_policy=selected_policy,
            requested_by="operator",
        )
        decision = await service.propose(
            principal("operator", Role.OPERATOR),
            CONTEXT,
            selected_plan,
            selected_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="expired-race",
        )
        approval_id = next(iter(decision.state.approvals))
        clock.advance(61)
        results = await asyncio.gather(
            *(
                service.decide(
                    principal(f"approver-{index}", Role.APPROVER),
                    CONTEXT,
                    selected_plan.plan_id,
                    approval_id,
                    ApprovalDecision.GRANT,
                    decision_id=uuid4(),
                    current_policy=selected_policy,
                    rationale_code="reviewed",
                    comment="approved",
                )
                for index in range(2)
            ),
            return_exceptions=True,
        )
        assert (
            len(
                [
                    result
                    for result in results
                    if isinstance(result, ApprovalDeniedError)
                    and str(result) == "approval_expired"
                ]
            )
            == 2
        )
        assert not any(isinstance(result, ConcurrencyError) for result in results)

    asyncio.run(scenario())


def test_repository_fencing_pagination_and_replay_guards() -> None:
    async def scenario() -> None:
        repository, _service, selected, state = await proposed()
        assert repository.outbox
        assert repository.events
        assert repository.projections
        assert (
            await repository.load(
                TenantContext(TenantId("tenant-other")),
                selected.plan_id,
            )
            == ()
        )
        with pytest.raises(ValueError, match="between"):
            await repository.page(CONTEXT, limit=0)
        with pytest.raises(ValueError, match="requires events"):
            await repository.append(
                CONTEXT,
                selected.plan_id,
                (),
                expected_version=state.version,
            )
        current_events = await repository.load(CONTEXT, selected.plan_id)
        candidate = replace(
            current_events[-1],
            event_id=uuid4(),
            aggregate_sequence=0,
            idempotency_key="repository-candidate",
        )
        with pytest.raises(ValueError, match="linkage"):
            await repository.append(
                CONTEXT,
                selected.plan_id,
                (replace(candidate, tenant_id="other"),),
                expected_version=state.version,
            )
        with pytest.raises(ValueError, match="replayed"):
            await repository.append(
                CONTEXT,
                selected.plan_id,
                (replace(candidate, event_id=current_events[-1].event_id),),
                expected_version=state.version,
            )
        with pytest.raises(RemediationIdempotencyConflictError):
            await repository.append(
                CONTEXT,
                selected.plan_id,
                (
                    replace(
                        candidate,
                        idempotency_key=current_events[-1].idempotency_key,
                    ),
                ),
                expected_version=state.version,
            )
        active_lease = WorkLease(
            selected.plan_id,
            str(TENANT_ID),
            uuid4(),
            1,
            "worker",
            1,
            NOW,
            NOW,
            NOW + timedelta(minutes=5),
        )
        with pytest.raises(ValueError, match="requires events"):
            await repository.append_fenced(
                CONTEXT,
                selected.plan_id,
                active_lease,
                (),
                expected_version=state.version,
            )
        with pytest.raises(FencingError):
            await repository.append_fenced(
                CONTEXT,
                selected.plan_id,
                active_lease,
                (candidate,),
                expected_version=state.version,
            )
        repository.register_lease(active_lease)
        repository.replace_lease(replace(active_lease, generation=2))
        with pytest.raises(FencingError):
            await repository.append_fenced(
                CONTEXT,
                selected.plan_id,
                active_lease,
                (candidate,),
                expected_version=state.version,
            )
        replacement = replace(active_lease, generation=2)
        with pytest.raises(ValueError, match="active fence"):
            await repository.append_fenced(
                CONTEXT,
                selected.plan_id,
                replacement,
                (candidate,),
                expected_version=state.version,
            )
        repository.clear_projections()
        assert not repository.projections
        await repository.rebuild_projection(CONTEXT, selected.plan_id)
        assert repository.projections
        await repository.rebuild_projection(CONTEXT, uuid4())

    asyncio.run(scenario())


def test_proposal_revision_and_terminal_decision_guards() -> None:
    async def scenario() -> None:
        repository = InMemoryRemediationRepository()
        service = RemediationApprovalService(repository, clock=Clock())
        selected = plan(requested_by="operator")
        actor = principal("operator", Role.OPERATOR)
        with pytest.raises(ValueError, match="idempotency"):
            await service.propose(
                actor,
                CONTEXT,
                selected,
                selected.approval_policy,
                ActionQuotaUsage(0, 0),
                idempotency_key="",
            )
        with pytest.raises(ApprovalDeniedError, match="identity"):
            await service.propose(
                actor,
                CONTEXT,
                replace(selected, requested_by="forged"),
                selected.approval_policy,
                ActionQuotaUsage(0, 0),
                idempotency_key="forged-requester",
            )
        with pytest.raises(ApprovalDeniedError, match="stale"):
            await service.propose(
                actor,
                CONTEXT,
                selected,
                replace(selected.approval_policy, policy_version="changed"),
                ActionQuotaUsage(0, 0),
                idempotency_key="stale-policy",
            )
        proposal = await service.propose(
            actor,
            CONTEXT,
            selected,
            selected.approval_policy,
            ActionQuotaUsage(0, 0),
            idempotency_key="valid",
        )
        approval_id = next(iter(proposal.state.approvals))
        with pytest.raises(ApprovalDeniedError, match="revision"):
            await service.revise(
                actor,
                CONTEXT,
                replace(selected, revision=3),
                selected.approval_policy,
                ActionQuotaUsage(0, 0),
                idempotency_key="bad-revision",
            )
        await service.decide(
            principal("approver-one", Role.APPROVER),
            CONTEXT,
            selected.plan_id,
            approval_id,
            ApprovalDecision.DENY,
            decision_id=uuid4(),
            current_policy=selected.approval_policy,
            rationale_code="unsafe",
            comment="denied",
        )
        with pytest.raises(ApprovalDeniedError, match="not_pending"):
            await service.decide(
                principal("approver-two", Role.APPROVER),
                CONTEXT,
                selected.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected.approval_policy,
                rationale_code="reviewed",
                comment="approved",
            )
        with pytest.raises(ApprovalDeniedError, match="cannot_be_revoked"):
            await service.revoke(
                principal("approver-two", Role.APPROVER),
                CONTEXT,
                selected.plan_id,
                approval_id,
                revocation_id=uuid4(),
                rationale_code="withdrawn",
            )
        with pytest.raises(ValueError, match="comment"):
            await service.decide(
                principal("approver-two", Role.APPROVER),
                CONTEXT,
                selected.plan_id,
                approval_id,
                ApprovalDecision.GRANT,
                decision_id=uuid4(),
                current_policy=selected.approval_policy,
                rationale_code="reviewed",
                comment="",
            )

    asyncio.run(scenario())


def test_policy_cross_tenant_missing_action_plan_limit_and_naive_time() -> None:
    evaluator = RemediationPolicyEvaluator()
    selected = plan()
    foreign_action = action()
    denied = evaluator.evaluate(
        TenantContext(TenantId("tenant-other")),
        selected,
        foreign_action,
        selected.approval_policy,
        ActionQuotaUsage(0, 0),
        at=NOW,
    )
    assert "cross_tenant_policy" in denied.reasons
    assert "action_not_in_plan" in denied.reasons
    with pytest.raises(ValueError, match="timezone"):
        evaluator.evaluate(
            CONTEXT,
            selected,
            selected.actions[0],
            selected.approval_policy,
            ActionQuotaUsage(0, 0),
            at=NOW.replace(tzinfo=None),
        )
