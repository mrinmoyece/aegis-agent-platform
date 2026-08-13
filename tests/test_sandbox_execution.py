"""Fenced Layer 9 request, execution, failure, and recovery tests."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from uuid import UUID

import pytest

from aegis_agent_platform.domain import (
    CapturedArtifact,
    DomainEventType,
    EgressRule,
    EventEnvelope,
    NetworkMode,
    SandboxApprovalBinding,
    SandboxExecutionOutcome,
    SandboxReconciliationOutcome,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    WorkLease,
    replay_sandbox,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.sandbox.egress import (
    DenyAllEgressBroker,
    EgressDecision,
)
from aegis_agent_platform.sandbox.execution import (
    BackendReadiness,
    FakeSandboxBackend,
    ProvisionedSandbox,
    SandboxApprovalAuthority,
    SandboxBackendError,
    SandboxErrorClass,
    SandboxObservation,
    SandboxOrchestrator,
    SandboxRequestService,
    StaticInputSnapshotVerifier,
    StaticSandboxApprovalAuthority,
)
from aegis_agent_platform.sandbox.policy import SandboxPolicy
from aegis_agent_platform.sandbox.repository import (
    InMemorySandboxRepository,
    SandboxIdempotencyConflictError,
)
from aegis_agent_platform.tenancy import TenantContext
from sandbox_helpers import (
    CONTEXT,
    NOW,
    Clock,
    UUIDs,
    binding,
    lease,
    policy,
    principal,
    request,
    result,
    spec,
)


@dataclass(frozen=True, slots=True)
class _Cancellation:
    cancelled: bool


class _DurableCommitCrash(BaseException):
    pass


class _ReadinessLossBackend(FakeSandboxBackend):
    def __init__(self, *, selected_result: SandboxResult, clock: Clock) -> None:
        super().__init__(result=selected_result, clock=clock)
        self._readiness_checks = 0

    async def readiness(self, context: TenantContext) -> BackendReadiness:
        self._readiness_checks += 1
        if self._readiness_checks == 1:
            return await super().readiness(context)
        self.calls.append("readiness")
        return BackendReadiness(
            False,
            "fencing_admission_unverified",
            "fake-sandbox-v1",
            False,
            False,
            False,
        )


def test_backend_and_egress_boundary_records_validate_strictly() -> None:
    naive = NOW.replace(tzinfo=None)
    rule = EgressRule("https", "packages.example.com", 443)
    with pytest.raises(ValueError, match="bounded"):
        SandboxBackendError(SandboxErrorClass.PERMANENT, "", retryable=False)
    with pytest.raises(ValueError, match="reason"):
        BackendReadiness(True, "", "backend", True, True, True)
    with pytest.raises(ValueError, match="identity"):
        BackendReadiness(True, "ready", "", True, True, True)
    with pytest.raises(ValueError, match="overstate"):
        BackendReadiness(True, "ready", "backend", False, True, True)
    with pytest.raises(ValueError, match="timezone"):
        SandboxObservation(SandboxReconciliationOutcome.ABSENT, None, None, naive)
    with pytest.raises(ValueError, match="reference"):
        SandboxObservation(SandboxReconciliationOutcome.PRESENT, "", None, NOW)
    with pytest.raises(ValueError, match="spec digest"):
        SandboxObservation(SandboxReconciliationOutcome.PRESENT, "ref", "bad", NOW)
    with pytest.raises(ValueError, match="reference"):
        ProvisionedSandbox("", "a" * 64, NOW)
    with pytest.raises(ValueError, match="spec digest"):
        ProvisionedSandbox("ref", "bad", NOW)
    with pytest.raises(ValueError, match="time"):
        ProvisionedSandbox("ref", "a" * 64, naive)
    with pytest.raises(ValueError, match="reason"):
        EgressDecision(True, "", rule, "a" * 64, NOW)
    with pytest.raises(ValueError, match="policy digest"):
        EgressDecision(True, "allowed", rule, "bad", NOW)
    with pytest.raises(ValueError, match="time"):
        EgressDecision(True, "allowed", rule, "a" * 64, naive)


@pytest.mark.asyncio
async def test_default_egress_broker_rejects_cross_tenant_context() -> None:
    sandbox_request = request(UUIDs("cross-tenant-egress"))
    with pytest.raises(PermissionError, match="cross_tenant"):
        await DenyAllEgressBroker().authorize(
            TenantContext(TenantId("tenant-other")),
            sandbox_request,
            EgressRule("https", "packages.example.com", 443),
            policy_digest="a" * 64,
            at=NOW,
        )


async def _approved(
    uuids: UUIDs,
    repository: InMemorySandboxRepository,
    authority: SandboxApprovalAuthority,
) -> tuple[SandboxRequest, SandboxPolicy, SandboxApprovalBinding]:
    sandbox_request = request(uuids)
    sandbox_policy = policy(sandbox_request)
    approval = binding(sandbox_request, sandbox_policy)
    decision = await SandboxRequestService(
        repository,
        authority,
        clock=Clock(),
        uuid_factory=uuids,
    ).request(
        principal(),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        approval,
    )
    assert decision.state.status is SandboxStatus.APPROVED
    return sandbox_request, sandbox_policy, approval


@pytest.mark.asyncio
async def test_request_authorizes_at_trusted_clock_not_payload_timestamp() -> None:
    uuids = UUIDs("trusted-request-clock")
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request = request(
        uuids,
        requested_at=NOW - timedelta(minutes=5),
    )
    sandbox_policy = policy(sandbox_request)

    decision = await SandboxRequestService(
        repository,
        authority,
        clock=Clock(),
        uuid_factory=uuids,
    ).request(
        principal(issued_at=NOW - timedelta(minutes=1)),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        binding(sandbox_request, sandbox_policy),
    )

    assert decision.state.status is SandboxStatus.APPROVED
    assert decision.policy.evaluated_at == NOW


@pytest.mark.asyncio
async def test_success_records_result_attestation_and_cleans_up() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )
    state = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert state.status is SandboxStatus.CLEANED
    assert state.result is not None
    assert state.result.outcome is SandboxExecutionOutcome.SUCCEEDED
    assert state.attestation is not None
    assert state.attestation.spec_digest == sandbox_request.spec.digest
    assert backend.calls == [
        "readiness",
        "observe",
        "provision",
        "observe",
        "start",
        "collect",
        "readiness",
        "cleanup",
    ]


@pytest.mark.asyncio
async def test_brokered_egress_decision_is_durable_and_denied_before_dispatch() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    rule = EgressRule("https", "packages.example.com", 443)
    sandbox_request = request(
        uuids,
        sandbox_spec=spec(
            network_mode=NetworkMode.BROKERED,
            egress_rules=(rule,),
        ),
    )
    sandbox_policy = policy(sandbox_request)
    approval = binding(sandbox_request, sandbox_policy)
    decision = await SandboxRequestService(
        repository,
        authority,
        clock=Clock(),
        uuid_factory=uuids,
    ).request(
        principal(),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        approval,
    )
    assert decision.state.status is SandboxStatus.APPROVED
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )

    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        egress_broker=DenyAllEgressBroker(),
        clock=Clock(),
        uuid_factory=uuids,
    )
    state = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert state.status is SandboxStatus.POLICY_VIOLATION
    assert backend.calls == []
    redelivered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert redelivered.status is SandboxStatus.POLICY_VIOLATION
    assert backend.calls == []
    events = tuple(
        event
        for event in repository.events
        if event.aggregate_id == str(sandbox_request.sandbox_id)
    )
    assert [event.event_type for event in events[-2:]] == [
        DomainEventType.SANDBOX_EGRESS_DECIDED.value,
        DomainEventType.SANDBOX_POLICY_VIOLATION.value,
    ]
    assert events[-2].payload["allowed"] is False


@pytest.mark.asyncio
async def test_stale_fence_cannot_call_backend_or_append_execution_intent() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    stale = lease(sandbox_request, uuids)
    repository.register_lease(stale)
    repository.replace_lease(lease(sandbox_request, uuids, generation=2))
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )
    with pytest.raises(FencingError):
        await SandboxOrchestrator(
            repository,
            backend,
            authority,
            StaticInputSnapshotVerifier(),
            clock=Clock(),
            uuid_factory=uuids,
        ).execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            stale,
            sandbox_policy,
            approval,
        )
    assert backend.calls == []
    assert all(
        event.event_type != DomainEventType.SANDBOX_DISPATCH_CLAIMED
        for event in repository.events
    )


@pytest.mark.asyncio
async def test_runtime_rechecks_fail_closed_before_provision() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        readiness=BackendReadiness(
            False,
            "admission_unverified",
            "fake-sandbox-v1",
            False,
            False,
            False,
        ),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )
    with pytest.raises(PermissionError, match="backend_not_ready"):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )
    assert "provision" not in backend.calls

    with pytest.raises(PermissionError, match="runtime_policy_denied"):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            replace(sandbox_policy, policy_version="changed"),
            approval,
        )
    with pytest.raises(PermissionError, match="input_snapshot_invalid"):
        await SandboxOrchestrator(
            repository,
            backend,
            authority,
            StaticInputSnapshotVerifier(available=False),
            clock=Clock(),
            uuid_factory=uuids,
        ).execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "terminal_type"),
    [
        (SandboxExecutionOutcome.TIMED_OUT, DomainEventType.SANDBOX_TIMED_OUT),
        (SandboxExecutionOutcome.OOM_KILLED, DomainEventType.SANDBOX_OOM_KILLED),
        (SandboxExecutionOutcome.CANCELLED, DomainEventType.SANDBOX_CANCELLED),
        (SandboxExecutionOutcome.FAILED, DomainEventType.SANDBOX_FAILED),
    ],
)
async def test_backend_terminal_results_are_replayed_and_cleaned(
    outcome: SandboxExecutionOutcome,
    terminal_type: DomainEventType,
) -> None:
    uuids = UUIDs(outcome.value)
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    state = await SandboxOrchestrator(
        repository,
        FakeSandboxBackend(
            result=result(uuids, outcome=outcome),
            clock=Clock(),
        ),
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    ).execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert state.status is SandboxStatus.CLEANED
    assert state.result is not None
    assert state.result.outcome is outcome
    event_types = [event.event_type for event in repository.events]
    assert terminal_type in event_types
    if outcome is SandboxExecutionOutcome.CANCELLED:
        assert event_types.index(
            DomainEventType.SANDBOX_CANCELLATION_REQUESTED
        ) < event_types.index(DomainEventType.SANDBOX_CANCELLED)


@pytest.mark.asyncio
async def test_operator_cancellation_persists_intent_before_termination() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )
    state = await SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    ).execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
        cancellation=_Cancellation(True),
    )
    assert state.status is SandboxStatus.CLEANED
    assert "start" not in backend.calls
    assert backend.calls[-2:] == ["terminate", "cleanup"]
    event_types = [event.event_type for event in repository.events]
    assert event_types.index(
        DomainEventType.SANDBOX_CANCELLATION_REQUESTED
    ) < event_types.index(DomainEventType.SANDBOX_CANCELLED)


class _BuggyBackend(FakeSandboxBackend):
    def __init__(
        self,
        *,
        fail_phase: str,
        cleanup_failures: int = 0,
        result: SandboxResult,
        clock: Callable[[], datetime],
    ) -> None:
        super().__init__(result=result, clock=clock)
        self._fail_phase = fail_phase
        self._cleanup_failures = cleanup_failures

    async def start(
        self,
        context: TenantContext,
        request: SandboxRequest,
        reference: str,
        work_lease: WorkLease,
    ) -> None:
        if self._fail_phase == "start":
            raise RuntimeError("provider object leaked only to supervisor boundary")
        await super().start(context, request, reference, work_lease)

    async def collect(
        self,
        context: TenantContext,
        request: SandboxRequest,
        reference: str,
    ) -> SandboxResult:
        if self._fail_phase == "collect":
            raise RuntimeError("provider object leaked only to supervisor boundary")
        return await super().collect(context, request, reference)

    async def cleanup(
        self,
        context: TenantContext,
        request: SandboxRequest,
        reference: str,
        work_lease: WorkLease,
    ) -> None:
        if self._cleanup_failures:
            self._cleanup_failures -= 1
            raise SandboxBackendError(
                SandboxErrorClass.TRANSIENT,
                "cleanup_transient",
                retryable=True,
            )
        await super().cleanup(context, request, reference, work_lease)


class _CrashAfterEffectRepository(InMemorySandboxRepository):
    def __init__(
        self,
        crash_event: DomainEventType,
        *,
        uuid_factory: Callable[[], UUID],
    ) -> None:
        super().__init__(uuid_factory=uuid_factory)
        self._crash_event = crash_event
        self._crashed = False

    async def append_fenced(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        work_lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not self._crashed and any(
            event.event_type == self._crash_event for event in events
        ):
            self._crashed = True
            raise RuntimeError("simulated crash after backend effect")
        return await super().append_fenced(
            context,
            sandbox_id,
            work_lease,
            events,
            expected_version=expected_version,
        )


class _CrashAfterCommitRepository(InMemorySandboxRepository):
    def __init__(
        self,
        crash_event: DomainEventType,
        *,
        uuid_factory: Callable[[], UUID],
    ) -> None:
        super().__init__(uuid_factory=uuid_factory)
        self._crash_event = crash_event
        self._crashed = False

    async def append_fenced(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        work_lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        version = await super().append_fenced(
            context,
            sandbox_id,
            work_lease,
            events,
            expected_version=expected_version,
        )
        if not self._crashed and any(
            event.event_type == self._crash_event for event in events
        ):
            self._crashed = True
            raise _DurableCommitCrash("simulated crash after durable commit")
        return version


class _TransientCollectBackend(FakeSandboxBackend):
    def __init__(self, *, selected_result: SandboxResult, clock: Clock) -> None:
        super().__init__(result=selected_result, clock=clock)
        self._failed = False
        self.observation_error: Exception | None = None
        self.observation_override: SandboxObservation | None = None

    async def observe(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> SandboxObservation:
        if self.observation_error is not None:
            self.calls.append("observe")
            raise self.observation_error
        if self.observation_override is not None:
            self.calls.append("observe")
            return self.observation_override
        return await super().observe(context, request)

    async def collect(
        self,
        context: TenantContext,
        request: SandboxRequest,
        reference: str,
    ) -> SandboxResult:
        if not self._failed:
            self._failed = True
            raise SandboxBackendError(
                SandboxErrorClass.TRANSIENT,
                "artifact_collector_temporarily_unavailable",
                retryable=True,
            )
        return await super().collect(context, request, reference)


class _ObservationFailureBackend(FakeSandboxBackend):
    def __init__(
        self,
        *,
        selected_result: SandboxResult,
        clock: Clock,
        ambiguous_cleanup: bool,
    ) -> None:
        super().__init__(
            result=selected_result,
            clock=clock,
            ambiguous_cleanup=ambiguous_cleanup,
        )
        self.observation_error: Exception | None = None

    async def observe(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> SandboxObservation:
        if self.observation_error is not None:
            self.calls.append("observe")
            raise self.observation_error
        return await super().observe(context, request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("crash_event", "cancel_first"),
    [
        (DomainEventType.SANDBOX_STARTED, False),
        (DomainEventType.SANDBOX_CANCELLED, True),
        (DomainEventType.SANDBOX_CLEANUP_COMPLETED, False),
    ],
)
async def test_durable_intents_resume_after_backend_effect_crashes(
    crash_event: DomainEventType,
    cancel_first: bool,
) -> None:
    uuids = UUIDs(f"resume-{crash_event.value}")
    repository = _CrashAfterEffectRepository(crash_event, uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
            cancellation=_Cancellation(cancel_first),
        )

    resumed = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert resumed.status is SandboxStatus.CLEANED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_event",
    [
        DomainEventType.SANDBOX_STARTED,
        DomainEventType.SANDBOX_CLEANUP_COMPLETED,
    ],
)
async def test_expired_approval_still_allows_termination_and_cleanup_recovery(
    crash_event: DomainEventType,
) -> None:
    uuids = UUIDs(f"expired-recovery-{crash_event.value}")
    repository = _CrashAfterEffectRepository(crash_event, uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(
        sandbox_request,
        uuids,
        expires_at=NOW + timedelta(hours=1),
    )
    repository.register_lease(work_lease)
    runtime_clock = Clock()
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=runtime_clock,
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=runtime_clock,
        uuid_factory=uuids,
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )
    runtime_clock.advance(601)

    recovered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert recovered.status is SandboxStatus.CLEANED
    if crash_event is DomainEventType.SANDBOX_STARTED:
        assert "terminate" in backend.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("finalization_event", "quarantined"),
    [
        (DomainEventType.SANDBOX_ATTESTED, False),
        (DomainEventType.SANDBOX_QUARANTINED, True),
    ],
)
async def test_terminal_result_and_finalization_commit_atomically(
    finalization_event: DomainEventType,
    quarantined: bool,
) -> None:
    uuids = UUIDs(f"atomic-finalization-{finalization_event.value}")
    repository = _CrashAfterEffectRepository(
        finalization_event,
        uuid_factory=uuids,
    )
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = FakeSandboxBackend(
        result=result(
            uuids,
            outcome=SandboxExecutionOutcome.SUCCEEDED,
            quarantined=quarantined,
        ),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )
    assert DomainEventType.SANDBOX_COMPLETED not in {
        event.event_type for event in repository.events
    }

    recovered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert recovered.status is SandboxStatus.CLEANED
    assert finalization_event in {event.event_type for event in repository.events}


@pytest.mark.asyncio
async def test_success_is_quarantined_if_final_backend_readiness_is_lost() -> None:
    uuids = UUIDs("final-readiness-loss")
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    state = await SandboxOrchestrator(
        repository,
        _ReadinessLossBackend(
            selected_result=result(
                uuids,
                outcome=SandboxExecutionOutcome.SUCCEEDED,
            ),
            clock=Clock(),
        ),
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    ).execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert state.status is SandboxStatus.CLEANED
    assert state.attestation is None
    assert state.quarantine_reason == "backend_readiness_unverified"


@pytest.mark.asyncio
async def test_cleanup_resumes_when_backend_readiness_is_lost() -> None:
    uuids = UUIDs("cleanup-after-readiness-loss")
    repository = _CrashAfterCommitRepository(
        DomainEventType.SANDBOX_CLEANUP_REQUESTED,
        uuid_factory=uuids,
    )
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = _ReadinessLossBackend(
        selected_result=result(
            uuids,
            outcome=SandboxExecutionOutcome.SUCCEEDED,
        ),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )

    with pytest.raises(
        _DurableCommitCrash, match="simulated crash after durable commit"
    ):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )
    recovered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert recovered.status is SandboxStatus.CLEANED
    assert backend.calls.count("readiness") == 2
    assert "cleanup" in backend.calls


@pytest.mark.asyncio
async def test_transient_collection_is_reconciled_before_cleanup() -> None:
    uuids = UUIDs("transient-collection")
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    runtime_clock = Clock()

    state = await SandboxOrchestrator(
        repository,
        _TransientCollectBackend(
            selected_result=result(
                uuids,
                outcome=SandboxExecutionOutcome.SUCCEEDED,
            ),
            clock=runtime_clock,
        ),
        authority,
        StaticInputSnapshotVerifier(),
        clock=runtime_clock,
        uuid_factory=uuids,
    ).execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert state.status is SandboxStatus.CLEANED
    assert any(
        event.event_type == DomainEventType.SANDBOX_RECONCILIATION_REQUESTED
        and event.payload["phase"] == "collect"
        for event in repository.events
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "recovery_behavior",
    [
        "success",
        "error",
        "conflict",
    ],
)
async def test_committed_collection_reconciliation_resumes_with_observation(
    recovery_behavior: str,
) -> None:
    uuids = UUIDs("collection-reconciliation-crash")
    repository = _CrashAfterCommitRepository(
        DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
        uuid_factory=uuids,
    )
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = _TransientCollectBackend(
        selected_result=result(
            uuids,
            outcome=SandboxExecutionOutcome.SUCCEEDED,
        ),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )

    with pytest.raises(
        _DurableCommitCrash, match="simulated crash after durable commit"
    ):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )
    crashed = replay_sandbox(await repository.load(CONTEXT, sandbox_request.sandbox_id))
    assert crashed.pending_reconciliation_phase == "collect"
    calls_before_recovery = len(backend.calls)
    if recovery_behavior == "error":
        backend.observation_error = SandboxBackendError(
            SandboxErrorClass.TRANSIENT,
            "collection_observation_unavailable",
            retryable=True,
        )
    elif recovery_behavior == "conflict":
        backend.observation_override = SandboxObservation(
            SandboxReconciliationOutcome.RUNNING,
            "fake-sandbox/replaced",
            sandbox_request.spec.digest,
            NOW,
        )

    recovered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert recovered.status is SandboxStatus.CLEANED
    assert recovered.pending_reconciliation_phase is None
    assert backend.calls[calls_before_recovery] == "observe"
    assert any(
        event.event_type == DomainEventType.SANDBOX_RECONCILED
        and event.payload["phase"] == "collect"
        for event in repository.events
    )


@pytest.mark.asyncio
async def test_cleanup_reconciliation_observation_failure_is_redriven() -> None:
    uuids = UUIDs("cleanup-reconciliation-observation-failure")
    repository = _CrashAfterCommitRepository(
        DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
        uuid_factory=uuids,
    )
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = _ObservationFailureBackend(
        selected_result=result(
            uuids,
            outcome=SandboxExecutionOutcome.SUCCEEDED,
        ),
        clock=Clock(),
        ambiguous_cleanup=True,
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )

    with pytest.raises(_DurableCommitCrash):
        await orchestrator.execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            work_lease,
            sandbox_policy,
            approval,
        )
    backend.observation_error = RuntimeError("observation unavailable")
    recovered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert recovered.status is SandboxStatus.CLEANED
    assert recovered.pending_reconciliation_phase is None
    assert DomainEventType.SANDBOX_CLEANUP_FAILED in {
        event.event_type for event in repository.events
    }


@pytest.mark.asyncio
async def test_cleanup_failure_is_redriven_within_attempt_limit() -> None:
    uuids = UUIDs("cleanup-redrive")
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request = request(
        uuids,
        sandbox_spec=spec(
            cleanup_policy=replace(
                spec().cleanup_policy,
                max_attempts=2,
            )
        ),
    )
    sandbox_policy = policy(sandbox_request)
    approval = binding(sandbox_request, sandbox_policy)
    await SandboxRequestService(
        repository,
        authority,
        clock=Clock(),
        uuid_factory=uuids,
    ).request(
        principal(),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        approval,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    runtime_clock = Clock()
    backend = _BuggyBackend(
        fail_phase="none",
        cleanup_failures=1,
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=runtime_clock,
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=runtime_clock,
        uuid_factory=uuids,
    )

    failed = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    recovered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert failed.status is SandboxStatus.CLEANUP_FAILED
    assert recovered.status is SandboxStatus.CLEANED
    assert recovered.cleanup_attempts == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "error_code"),
    [
        ("missing", "sandbox_required_artifact_missing"),
        ("unexpected", "sandbox_artifact_path_not_approved"),
        ("media", "sandbox_artifact_media_type_not_approved"),
        ("oversized", "sandbox_artifact_output_limit_exceeded"),
        ("duplicate", "sandbox_artifact_path_conflict"),
    ],
)
async def test_result_artifacts_must_match_approved_contract(
    case: str,
    error_code: str,
) -> None:
    uuids = UUIDs(f"artifact-contract-{case}")
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    selected_result = result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED)
    artifact = selected_result.artifacts[0]
    artifacts: tuple[CapturedArtifact, ...]
    if case == "missing":
        artifacts = ()
    elif case == "unexpected":
        artifacts = (replace(artifact, path="outputs/unreviewed.json"),)
    elif case == "media":
        artifacts = (replace(artifact, media_type="text/plain"),)
    elif case == "oversized":
        artifacts = (
            replace(
                artifact,
                size_bytes=sandbox_request.spec.expected_outputs[0].max_bytes + 1,
            ),
        )
    else:
        artifacts = (artifact, replace(artifact, artifact_id=uuids()))

    state = await SandboxOrchestrator(
        repository,
        FakeSandboxBackend(
            result=replace(selected_result, artifacts=artifacts),
            clock=Clock(),
        ),
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    ).execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )

    assert state.status is SandboxStatus.CLEANED
    assert state.attestation is None
    violation = next(
        event
        for event in repository.events
        if event.event_type == DomainEventType.SANDBOX_POLICY_VIOLATION
    )
    assert violation.payload["error_code"] == error_code


@pytest.mark.asyncio
async def test_fake_backend_rejects_a_lower_external_fence() -> None:
    uuids = UUIDs("backend-fence")
    sandbox_request = request(uuids)
    newer = lease(sandbox_request, uuids, generation=2)
    stale = lease(sandbox_request, uuids, generation=1)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )
    provisioned = await backend.provision(CONTEXT, sandbox_request, newer)

    with pytest.raises(SandboxBackendError, match="sandbox_backend_fence_stale"):
        await backend.start(
            CONTEXT,
            sandbox_request,
            provisioned.backend_reference,
            stale,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["start", "collect"])
async def test_backend_bugs_are_contained_and_cleanup_is_attempted(phase: str) -> None:
    uuids = UUIDs(phase)
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = _BuggyBackend(
        fail_phase=phase,
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )
    state = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert state.status is SandboxStatus.CLEANED
    assert "cleanup" in backend.calls


@pytest.mark.asyncio
async def test_output_limit_violation_and_cleanup_retry_quarantine() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request = request(
        uuids,
        sandbox_spec=spec(
            cleanup_policy=replace(
                spec().cleanup_policy,
                max_attempts=1,
            )
        ),
    )
    sandbox_policy = policy(sandbox_request)
    approval = binding(sandbox_request, sandbox_policy)
    await SandboxRequestService(
        repository,
        authority,
        clock=Clock(),
        uuid_factory=uuids,
    ).request(
        principal(),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        approval,
    )
    work_lease = lease(sandbox_request, uuids)
    repository.register_lease(work_lease)
    backend = _BuggyBackend(
        fail_phase="none",
        cleanup_failures=1,
        result=result(
            uuids,
            outcome=SandboxExecutionOutcome.SUCCEEDED,
            output_bytes=sandbox_request.spec.resources.max_output_bytes + 1,
        ),
        clock=Clock(),
    )
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=Clock(),
        uuid_factory=uuids,
    )
    state = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert state.status is SandboxStatus.QUARANTINED
    assert state.quarantine_reason == "cleanup_attempts_exhausted"
    cleanup_calls = backend.calls.count("cleanup")
    redelivered = await orchestrator.execute(
        principal(),
        CONTEXT,
        sandbox_request.sandbox_id,
        work_lease,
        sandbox_policy,
        approval,
    )
    assert redelivered.cleanup_attempts == 1
    assert backend.calls.count("cleanup") == cleanup_calls
    assert DomainEventType.SANDBOX_POLICY_VIOLATION in {
        event.event_type for event in repository.events
    }


@pytest.mark.asyncio
async def test_duplicate_delivery_is_idempotent_and_conflicts_are_rejected() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request = request(uuids)
    sandbox_policy = policy(sandbox_request)
    approval = binding(sandbox_request, sandbox_policy)
    service = SandboxRequestService(
        repository,
        authority,
        clock=Clock(),
        uuid_factory=uuids,
    )
    first = await service.request(
        principal(),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        approval,
    )
    duplicate = await service.request(
        principal(),
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        approval,
    )
    assert first.result.created
    assert not duplicate.result.created
    assert len(repository.outbox) == 1

    conflicting = replace(
        request(uuids),
        idempotency_key=sandbox_request.idempotency_key,
    )
    conflicting_policy = policy(conflicting)
    with pytest.raises(SandboxIdempotencyConflictError):
        await service.request(
            principal(),
            CONTEXT,
            conflicting,
            conflicting_policy,
            binding(conflicting, conflicting_policy),
        )


@pytest.mark.asyncio
async def test_expired_lease_fails_before_backend_call() -> None:
    uuids = UUIDs()
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    sandbox_request, sandbox_policy, approval = await _approved(
        uuids,
        repository,
        authority,
    )
    expired = lease(
        sandbox_request,
        uuids,
        expires_at=NOW + timedelta(seconds=1),
    )
    repository.register_lease(expired)
    backend = FakeSandboxBackend(
        result=result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED)
    )
    with pytest.raises(FencingError):
        await SandboxOrchestrator(
            repository,
            backend,
            authority,
            StaticInputSnapshotVerifier(),
            clock=Clock(NOW + timedelta(seconds=2)),
            uuid_factory=uuids,
        ).execute(
            principal(),
            CONTEXT,
            sandbox_request.sandbox_id,
            expired,
            sandbox_policy,
            approval,
        )
    assert backend.calls == []
