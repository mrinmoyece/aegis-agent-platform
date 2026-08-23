"""Fenced sandbox request, execution, reconciliation, and cleanup orchestration."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Protocol, cast
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    CapturedArtifact,
    CapturedOutput,
    DomainEventType,
    EgressRule,
    EventEnvelope,
    JsonValue,
    SandboxApprovalBinding,
    SandboxExecutionOutcome,
    SandboxReconciliationOutcome,
    SandboxRequest,
    SandboxResult,
    SandboxState,
    SandboxStatus,
    WorkLease,
    WorkRequest,
    replay_sandbox,
    sandbox_request_to_payload,
    sandbox_result_digest,
    sandbox_result_to_payload,
)
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
)
from aegis_agent_platform.sandbox.egress import EgressBroker
from aegis_agent_platform.sandbox.policy import (
    SandboxPolicy,
    SandboxPolicyDecision,
    SandboxPolicyEvaluator,
)
from aegis_agent_platform.sandbox.repository import (
    SandboxRepository,
    SandboxRequestResult,
)
from aegis_agent_platform.sandbox.telemetry import SandboxMetrics, SandboxTracer
from aegis_agent_platform.tenancy import TenantContext


class SandboxErrorClass(StrEnum):
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFLICT = "conflict"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    AMBIGUOUS = "ambiguous"
    PROVIDER_BUG = "provider_bug"


class SandboxBackendError(RuntimeError):
    """Secret-safe provider-neutral backend failure."""

    def __init__(
        self,
        error_class: SandboxErrorClass,
        code: str,
        *,
        retryable: bool,
        ambiguous: bool = False,
    ) -> None:
        super().__init__(code)
        if not code or len(code) > 128:
            raise ValueError("sandbox backend error code must be bounded")
        self.error_class = error_class
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


@dataclass(frozen=True, slots=True)
class BackendReadiness:
    ready: bool
    reason: str
    backend_identity: str
    isolation_verified: bool
    egress_verified: bool
    admission_verified: bool

    def __post_init__(self) -> None:
        if not self.reason or len(self.reason) > 128:
            raise ValueError("sandbox readiness reason must be bounded")
        if not self.backend_identity or len(self.backend_identity) > 128:
            raise ValueError("sandbox backend identity must be bounded")
        if self.ready and not (
            self.isolation_verified and self.egress_verified and self.admission_verified
        ):
            raise ValueError("sandbox readiness cannot overstate missing controls")


@dataclass(frozen=True, slots=True)
class SandboxObservation:
    outcome: SandboxReconciliationOutcome
    backend_reference: str | None
    observed_spec_digest: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("sandbox observation time must be timezone-aware")
        if self.backend_reference is not None and (
            not self.backend_reference or len(self.backend_reference.encode()) > 512
        ):
            raise ValueError("sandbox backend reference must be bounded")
        if (
            self.observed_spec_digest is not None
            and len(self.observed_spec_digest) != 64
        ):
            raise ValueError("sandbox observed spec digest is invalid")


@dataclass(frozen=True, slots=True)
class ProvisionedSandbox:
    backend_reference: str
    spec_digest: str
    provisioned_at: datetime

    def __post_init__(self) -> None:
        if not self.backend_reference or len(self.backend_reference.encode()) > 512:
            raise ValueError("sandbox backend reference must be bounded")
        if len(self.spec_digest) != 64:
            raise ValueError("sandbox provisioned spec digest is invalid")
        if self.provisioned_at.tzinfo is None:
            raise ValueError("sandbox provision time must be timezone-aware")


class CancellationSignal(Protocol):
    @property
    def cancelled(self) -> bool: ...


class SandboxBackend(Protocol):
    """Provider-neutral idempotent lifecycle port for an isolated runtime."""

    async def readiness(self, context: TenantContext) -> BackendReadiness: ...

    async def observe(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> SandboxObservation: ...

    async def provision(
        self,
        context: TenantContext,
        request: SandboxRequest,
        lease: WorkLease,
    ) -> ProvisionedSandbox: ...

    async def start(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None: ...

    async def collect(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
    ) -> SandboxResult: ...

    async def terminate(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None: ...

    async def cleanup(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None: ...


class SandboxApprovalAuthority(Protocol):
    """Rechecks authoritative approver role bindings at execution time."""

    async def current(
        self,
        context: TenantContext,
        binding: SandboxApprovalBinding,
        *,
        at: datetime,
    ) -> bool: ...


class InputSnapshotVerifier(Protocol):
    """Verifies tenant binding, digest, immutability, and availability."""

    async def current(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> bool: ...


class StaticSandboxApprovalAuthority:
    def __init__(self, current_approvers: frozenset[str]) -> None:
        self._current_approvers = current_approvers

    async def current(
        self,
        context: TenantContext,
        binding: SandboxApprovalBinding,
        *,
        at: datetime,
    ) -> bool:
        del context
        if at.tzinfo is None:
            raise ValueError("sandbox authority time must be timezone-aware")
        return set(binding.approver_ids).issubset(self._current_approvers)


class StaticInputSnapshotVerifier:
    def __init__(self, *, available: bool = True) -> None:
        self._available = available

    async def current(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> bool:
        return self._available and request.linkage.tenant_id == str(context.tenant_id)


class FakeSandboxBackend:
    """Deterministic fake; it never launches a process, shell, or network call."""

    def __init__(
        self,
        *,
        result: SandboxResult,
        ambiguous_provision: bool = False,
        ambiguous_cleanup: bool = False,
        readiness: BackendReadiness | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._result = result
        self._ambiguous_provision = ambiguous_provision
        self._ambiguous_cleanup = ambiguous_cleanup
        self._readiness = readiness or BackendReadiness(
            True,
            "fake_controls_verified",
            "fake-sandbox-v1",
            True,
            True,
            True,
        )
        self._clock = clock
        self._provisioned = False
        self._running = False
        self._cleaned = False
        self._fence_generation = 0
        self._fence_token: UUID | None = None
        self.calls: list[str] = []

    async def readiness(self, context: TenantContext) -> BackendReadiness:
        del context
        self.calls.append("readiness")
        return self._readiness

    async def observe(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> SandboxObservation:
        _backend_context(context, request)
        self.calls.append("observe")
        return SandboxObservation(
            (
                SandboxReconciliationOutcome.DELETED
                if self._cleaned
                else SandboxReconciliationOutcome.RUNNING
                if self._running
                else SandboxReconciliationOutcome.PRESENT
                if self._provisioned
                else SandboxReconciliationOutcome.ABSENT
            ),
            (
                f"fake-sandbox/{request.sandbox_id}"
                if self._provisioned and not self._cleaned
                else None
            ),
            request.spec.digest if self._provisioned else None,
            self._clock(),
        )

    async def provision(
        self,
        context: TenantContext,
        request: SandboxRequest,
        lease: WorkLease,
    ) -> ProvisionedSandbox:
        _backend_context(context, request)
        self._claim_fence(context, request, lease)
        self.calls.append("provision")
        self._provisioned = True
        reference = f"fake-sandbox/{request.sandbox_id}"
        if self._ambiguous_provision:
            self._ambiguous_provision = False
            raise SandboxBackendError(
                SandboxErrorClass.AMBIGUOUS,
                "fake_ambiguous_provision",
                retryable=True,
                ambiguous=True,
            )
        return ProvisionedSandbox(reference, request.spec.digest, self._clock())

    async def start(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None:
        _backend_reference(context, request, backend_reference)
        self._claim_fence(context, request, lease)
        self.calls.append("start")
        self._running = True

    async def collect(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
    ) -> SandboxResult:
        _backend_reference(context, request, backend_reference)
        self.calls.append("collect")
        self._running = False
        return self._result

    async def terminate(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None:
        _backend_reference(context, request, backend_reference)
        self._claim_fence(context, request, lease)
        self.calls.append("terminate")
        self._running = False

    async def cleanup(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None:
        _backend_reference(context, request, backend_reference)
        self._claim_fence(context, request, lease)
        self.calls.append("cleanup")
        self._running = False
        self._cleaned = True
        if self._ambiguous_cleanup:
            self._ambiguous_cleanup = False
            raise SandboxBackendError(
                SandboxErrorClass.AMBIGUOUS,
                "fake_ambiguous_cleanup",
                retryable=True,
                ambiguous=True,
            )

    def _claim_fence(
        self,
        context: TenantContext,
        request: SandboxRequest,
        lease: WorkLease,
    ) -> None:
        _backend_context(context, request)
        if (
            lease.work_id != request.sandbox_id
            or lease.tenant_id != request.linkage.tenant_id
            or lease.generation < self._fence_generation
            or (
                lease.generation == self._fence_generation
                and self._fence_token is not None
                and lease.token != self._fence_token
            )
        ):
            raise SandboxBackendError(
                SandboxErrorClass.CONFLICT,
                "sandbox_backend_fence_stale",
                retryable=False,
            )
        self._fence_generation = lease.generation
        self._fence_token = lease.token


@dataclass(frozen=True, slots=True)
class SandboxRequestDecision:
    result: SandboxRequestResult
    state: SandboxState
    policy: SandboxPolicyDecision


class SandboxRequestService:
    """Authorize, evaluate, bind exact approval scope, then enqueue durably."""

    def __init__(
        self,
        repository: SandboxRepository,
        approval_authority: SandboxApprovalAuthority,
        *,
        authorization: AuthorizationService | None = None,
        evaluator: SandboxPolicyEvaluator | None = None,
        metrics: SandboxMetrics | None = None,
        tracer: SandboxTracer | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._repository = repository
        self._approval_authority = approval_authority
        self._authorization = authorization or AuthorizationService()
        self._evaluator = evaluator or SandboxPolicyEvaluator()
        self._metrics = metrics or SandboxMetrics()
        self._tracer = tracer or SandboxTracer()
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def request(
        self,
        principal: Principal,
        context: TenantContext,
        request: SandboxRequest,
        policy: SandboxPolicy,
        binding: SandboxApprovalBinding,
    ) -> SandboxRequestDecision:
        at = self._clock()
        _authorize(
            self._authorization,
            principal,
            context,
            Permission.SANDBOX_EXECUTE,
            at,
        )
        usage = await self._repository.quota_usage(context, at=at)
        with self._tracer.operation("policy", request.purpose):
            decision = self._evaluator.evaluate(
                context,
                request,
                policy,
                usage,
                at=at,
            )
        approval_valid = binding.valid_for(
            request,
            policy_digest=policy.digest,
            at=at,
        ) and await self._approval_authority.current(context, binding, at=at)
        if decision.allowed and not approval_valid:
            decision = SandboxPolicyDecision(
                False,
                ("exact_scope_approval_invalid",),
                policy.digest,
                request.spec.digest,
                at,
            )
        actor = ActorReference(principal.actor_id, ActorKind.USER)
        request_event = _unfenced_event(
            request,
            DomainEventType.SANDBOX_REQUESTED,
            {
                "request": sandbox_request_to_payload(request),
                "request_digest": request.digest,
            },
            at=at,
            event_id=self._uuid_factory(),
            actor=actor,
            suffix="requested",
        )
        policy_event = _unfenced_event(
            request,
            DomainEventType.SANDBOX_POLICY_EVALUATED,
            {
                "outcome": "allow" if decision.allowed else "deny",
                "policy_digest": decision.policy_digest,
                "reasons": decision.reasons,
                "spec_digest": decision.spec_digest,
            },
            at=at,
            event_id=self._uuid_factory(),
            actor=actor,
            suffix="policy",
        )
        events = [request_event, policy_event]
        if decision.allowed:
            events.append(
                _unfenced_event(
                    request,
                    DomainEventType.SANDBOX_APPROVAL_BOUND,
                    {
                        "approval_id": str(binding.approval_id),
                        "approval_scope_digest": binding.scope_digest,
                        "policy_digest": binding.policy_digest,
                        "spec_digest": binding.spec_digest,
                    },
                    at=at,
                    event_id=self._uuid_factory(),
                    actor=actor,
                    suffix="approval",
                )
            )
        work = WorkRequest(
            work_id=request.sandbox_id,
            tenant_id=request.linkage.tenant_id,
            work_kind="sandbox.execution.v1",
            idempotency_key=request.idempotency_key,
            correlation_id=request.linkage.run_id,
            causation_id=request.linkage.remediation_action_id,
            requested_at=at,
            payload={
                "approval_scope_digest": binding.scope_digest,
                "purpose": request.purpose.value,
                "spec_digest": request.spec.digest,
                "task_id": str(request.linkage.task_id),
            },
            max_attempts=request.spec.retry_policy.max_attempts,
            timeout_seconds=request.spec.resources.timeout_seconds,
        )
        result = await self._repository.request(
            context,
            work,
            events,
            requested_event_id=self._uuid_factory(),
            outbox_message_id=self._uuid_factory(),
        )
        stored = replay_sandbox(await self._repository.load(context, result.sandbox_id))
        self._metrics.add("requests", purpose=request.purpose)
        if not decision.allowed:
            self._metrics.add("policy_denials", purpose=request.purpose)
        return SandboxRequestDecision(result, stored, decision)


class SandboxOrchestrator:
    """Recheck exact authority and fence every external lifecycle operation."""

    def __init__(
        self,
        repository: SandboxRepository,
        backend: SandboxBackend,
        approval_authority: SandboxApprovalAuthority,
        input_verifier: InputSnapshotVerifier,
        *,
        egress_broker: EgressBroker | None = None,
        authorization: AuthorizationService | None = None,
        evaluator: SandboxPolicyEvaluator | None = None,
        metrics: SandboxMetrics | None = None,
        tracer: SandboxTracer | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._repository = repository
        self._backend = backend
        self._approval_authority = approval_authority
        self._input_verifier = input_verifier
        self._egress_broker = egress_broker
        self._authorization = authorization or AuthorizationService()
        self._evaluator = evaluator or SandboxPolicyEvaluator()
        self._metrics = metrics or SandboxMetrics()
        self._tracer = tracer or SandboxTracer()
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def execute(
        self,
        principal: Principal,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        policy: SandboxPolicy,
        binding: SandboxApprovalBinding,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> SandboxState:
        state, execution_allowed = await self._scope(
            principal,
            context,
            sandbox_id,
            lease,
            policy,
            binding,
        )
        egress_events: tuple[
            tuple[DomainEventType, Mapping[str, JsonValue], str],
            ...,
        ] = ()
        if state.status in {
            SandboxStatus.POLICY_DENIED,
            SandboxStatus.CLEANED,
        }:
            return state
        if (
            state.status is SandboxStatus.QUARANTINED
            and state.quarantine_reason == "cleanup_attempts_exhausted"
        ):
            return state
        if state.status is SandboxStatus.APPROVED and state.request.spec.egress_rules:
            if self._egress_broker is None:
                raise PermissionError("sandbox_egress_enforcement_not_ready")
            await self._assert_fence(context, state, lease)
            try:
                decisions = tuple(
                    [
                        await self._egress_broker.authorize(
                            context,
                            state.request,
                            rule,
                            policy_digest=policy.digest,
                            at=self._clock(),
                        )
                        for rule in state.request.spec.egress_rules
                    ]
                )
            except Exception as error:
                raise PermissionError("sandbox_egress_decision_failed") from error
            for requested_rule, decision in zip(
                state.request.spec.egress_rules,
                decisions,
                strict=True,
            ):
                if (
                    decision.rule != requested_rule
                    or decision.policy_digest != policy.digest
                ):
                    raise PermissionError("sandbox_egress_decision_mismatch")
            egress_events = tuple(
                (
                    DomainEventType.SANDBOX_EGRESS_DECIDED,
                    {
                        "allowed": decision.allowed,
                        "policy_digest": decision.policy_digest,
                        "reason": decision.reason,
                        "rule_digest": _egress_rule_digest(decision.rule),
                    },
                    f"egress-{index}",
                )
                for index, decision in enumerate(decisions)
            )
            if any(not decision.allowed for decision in decisions):
                state = await self._append(
                    context,
                    state,
                    lease,
                    egress_events,
                )
                return await self._append(
                    context,
                    state,
                    lease,
                    (
                        (
                            DomainEventType.SANDBOX_POLICY_VIOLATION,
                            {"error_code": "sandbox_egress_denied"},
                            "egress-denied",
                        ),
                    ),
                )
        if state.pending_reconciliation_phase is not None:
            state = await self._resume_reconciliation(context, state, lease)
        reference = state.backend_reference
        if reference is None and state.status in {
            SandboxStatus.FAILED,
            SandboxStatus.POLICY_VIOLATION,
            SandboxStatus.QUARANTINED,
        }:
            return state
        if reference is not None and state.status in {
            SandboxStatus.COMPLETED,
            SandboxStatus.FAILED,
            SandboxStatus.TIMED_OUT,
            SandboxStatus.OOM_KILLED,
            SandboxStatus.POLICY_VIOLATION,
            SandboxStatus.CANCELLED,
            SandboxStatus.QUARANTINED,
            SandboxStatus.CLEANUP_PENDING,
            SandboxStatus.CLEANUP_FAILED,
        }:
            return await self._cleanup(context, state, lease, reference)
        if reference is not None and state.status is SandboxStatus.CANCELLING:
            return await self._resume_cancel(context, state, lease, reference)
        if reference is not None and not execution_allowed:
            return await self._cancel(context, state, lease, reference)
        if (
            reference is not None
            and cancellation is not None
            and cancellation.cancelled
        ):
            return await self._cancel(context, state, lease, reference)
        readiness = await self._safe_readiness(context)
        if not readiness.ready:
            raise PermissionError(f"sandbox_backend_not_ready:{readiness.reason}")
        if state.status is SandboxStatus.APPROVED:
            await self._assert_fence(context, state, lease)
            dispatch_events: tuple[
                tuple[DomainEventType, Mapping[str, JsonValue], str],
                ...,
            ] = (
                (
                    DomainEventType.SANDBOX_DISPATCH_CLAIMED,
                    {
                        "attempt": lease.attempt,
                        "estimated_artifact_bytes": sum(
                            output.max_bytes
                            for output in state.request.spec.expected_outputs
                        ),
                        "estimated_cpu_millis_seconds": (
                            state.request.spec.resources.cpu_millis
                            * state.request.spec.resources.timeout_seconds
                        ),
                        "max_artifact_bytes_per_period": (
                            policy.max_artifact_bytes_per_period
                        ),
                        "max_concurrent_runs": policy.max_concurrent_runs,
                        "max_cpu_millis_seconds_per_period": (
                            policy.max_cpu_millis_seconds_per_period
                        ),
                        "max_runs_per_period": policy.max_runs_per_period,
                    },
                    "dispatch",
                ),
                (
                    DomainEventType.SANDBOX_PROVISIONING_REQUESTED,
                    {"attempt": lease.attempt},
                    "provision-intent",
                ),
            )
            if state.request.spec.egress_rules:
                state = await self._append(
                    context,
                    state,
                    lease,
                    (*egress_events, *dispatch_events),
                )
            else:
                state = await self._append(
                    context,
                    state,
                    lease,
                    dispatch_events,
                )
            self._metrics.add("queue_claims", purpose=state.request.purpose)
        reference = state.backend_reference
        if state.status is SandboxStatus.PROVISIONING:
            provisioned = await self._provision(
                context,
                state,
                lease,
                allow_create=execution_allowed,
            )
            if provisioned is None:
                return await self._state(context, sandbox_id)
            state, reference = provisioned
        if reference is None and state.status in {
            SandboxStatus.FAILED,
            SandboxStatus.POLICY_VIOLATION,
            SandboxStatus.QUARANTINED,
        }:
            return state
        if reference is None:
            return await self._record_failure(
                context,
                state,
                lease,
                "sandbox_backend_reference_missing",
            )
        if state.status in {
            SandboxStatus.COMPLETED,
            SandboxStatus.FAILED,
            SandboxStatus.TIMED_OUT,
            SandboxStatus.OOM_KILLED,
            SandboxStatus.POLICY_VIOLATION,
            SandboxStatus.CANCELLED,
            SandboxStatus.QUARANTINED,
            SandboxStatus.CLEANUP_PENDING,
            SandboxStatus.CLEANUP_FAILED,
        }:
            return await self._cleanup(context, state, lease, reference)
        if state.status is SandboxStatus.CANCELLING:
            return await self._resume_cancel(context, state, lease, reference)
        if not execution_allowed:
            return await self._cancel(context, state, lease, reference)
        if cancellation is not None and cancellation.cancelled:
            return await self._cancel(context, state, lease, reference)
        if state.status in {SandboxStatus.PROVISIONED, SandboxStatus.STARTING}:
            if state.status is SandboxStatus.PROVISIONED:
                state = await self._append(
                    context,
                    state,
                    lease,
                    (
                        (
                            DomainEventType.SANDBOX_START_REQUESTED,
                            {"backend_reference": reference},
                            "start-intent",
                        ),
                    ),
                )
            try:
                await self._assert_fence(context, state, lease)
                observation = await self._backend.observe(context, state.request)
                if (
                    observation.backend_reference != reference
                    or observation.observed_spec_digest != state.request.spec.digest
                ):
                    raise SandboxBackendError(
                        SandboxErrorClass.CONFLICT,
                        "sandbox_start_observed_scope_conflict",
                        retryable=False,
                    )
                if observation.outcome is SandboxReconciliationOutcome.PRESENT:
                    await self._assert_fence(context, state, lease)
                    with self._tracer.operation("start", state.request.purpose):
                        await self._backend.start(
                            context,
                            state.request,
                            reference,
                            lease,
                        )
                elif observation.outcome not in {
                    SandboxReconciliationOutcome.RUNNING,
                    SandboxReconciliationOutcome.TERMINAL,
                }:
                    raise SandboxBackendError(
                        SandboxErrorClass.AMBIGUOUS,
                        "sandbox_start_reconciliation_ambiguous",
                        retryable=True,
                        ambiguous=True,
                    )
            except SandboxBackendError as error:
                state = await self._backend_failure(
                    context,
                    state,
                    lease,
                    error,
                )
                return await self._cleanup(context, state, lease, reference)
            except Exception:
                state = await self._record_failure(
                    context,
                    state,
                    lease,
                    "sandbox_start_backend_bug",
                )
                return await self._cleanup(context, state, lease, reference)
            state = await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_STARTED,
                        {"backend_reference": reference},
                        "started",
                    ),
                ),
            )
        if state.status is not SandboxStatus.RUNNING:
            return state
        result: SandboxResult | None = None
        try:
            async with asyncio.timeout(state.request.spec.resources.timeout_seconds):
                for collect_attempt in range(
                    1,
                    state.request.spec.retry_policy.max_attempts + 1,
                ):
                    await self._assert_fence(context, state, lease)
                    try:
                        with self._tracer.operation(
                            "collect",
                            state.request.purpose,
                        ):
                            result = await self._backend.collect(
                                context,
                                state.request,
                                reference,
                            )
                        break
                    except SandboxBackendError as error:
                        if (
                            not error.retryable
                            or collect_attempt
                            >= state.request.spec.retry_policy.max_attempts
                        ):
                            raise
                        state = await self._append(
                            context,
                            state,
                            lease,
                            (
                                (
                                    DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
                                    {
                                        "attempt": collect_attempt,
                                        "phase": "collect",
                                    },
                                    f"collect-reconcile-intent-{collect_attempt}",
                                ),
                            ),
                        )
                        await self._assert_fence(context, state, lease)
                        observation = await self._backend.observe(
                            context,
                            state.request,
                        )
                        state = await self._append(
                            context,
                            state,
                            lease,
                            (
                                (
                                    DomainEventType.SANDBOX_RECONCILED,
                                    {
                                        "outcome": observation.outcome.value,
                                        "phase": "collect",
                                    },
                                    f"collect-reconciled-{collect_attempt}",
                                ),
                            ),
                        )
                        if (
                            observation.backend_reference != reference
                            or observation.observed_spec_digest
                            != state.request.spec.digest
                            or observation.outcome
                            not in {
                                SandboxReconciliationOutcome.RUNNING,
                                SandboxReconciliationOutcome.TERMINAL,
                            }
                        ):
                            raise SandboxBackendError(
                                SandboxErrorClass.CONFLICT,
                                "sandbox_collect_reconciliation_conflict",
                                retryable=False,
                            ) from error
        except TimeoutError:
            state = await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_TIMED_OUT,
                        {"error_code": "sandbox_runtime_timeout"},
                        "timed-out",
                    ),
                ),
            )
            self._metrics.add("limit_terminations", purpose=state.request.purpose)
            return await self._cleanup(context, state, lease, reference)
        except SandboxBackendError as error:
            state = await self._backend_failure(context, state, lease, error)
            return await self._cleanup(context, state, lease, reference)
        except Exception:
            state = await self._record_failure(
                context,
                state,
                lease,
                "sandbox_collect_backend_bug",
            )
            return await self._cleanup(context, state, lease, reference)
        if result is None:
            raise RuntimeError("sandbox collection ended without a result")
        state = await self._record_result(context, state, lease, result)
        return await self._cleanup(context, state, lease, reference)

    async def _scope(
        self,
        principal: Principal,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        policy: SandboxPolicy,
        binding: SandboxApprovalBinding,
    ) -> tuple[SandboxState, bool]:
        at = self._clock()
        _authorize(
            self._authorization,
            principal,
            context,
            Permission.SANDBOX_EXECUTE,
            at,
        )
        state = await self._state(context, sandbox_id)
        request = state.request
        if lease.work_id != sandbox_id or lease.tenant_id != str(context.tenant_id):
            raise PermissionError("sandbox_lease_scope_mismatch")
        await self._repository.assert_fence(context, sandbox_id, lease, at=at)
        if state.status in {
            SandboxStatus.COMPLETED,
            SandboxStatus.FAILED,
            SandboxStatus.TIMED_OUT,
            SandboxStatus.OOM_KILLED,
            SandboxStatus.POLICY_VIOLATION,
            SandboxStatus.CANCELLING,
            SandboxStatus.CANCELLED,
            SandboxStatus.QUARANTINED,
            SandboxStatus.CLEANUP_PENDING,
            SandboxStatus.CLEANUP_FAILED,
        }:
            return state, False
        usage = await self._repository.quota_usage(
            context,
            at=at,
            exclude_idempotency_key=request.idempotency_key,
        )
        decision = self._evaluator.evaluate(
            context,
            request,
            policy,
            usage,
            at=at,
        )
        policy_valid = decision.allowed and state.policy_digest == policy.digest
        approval_valid = (
            (state.approval_scope_digest == binding.scope_digest)
            and binding.valid_for(
                request,
                policy_digest=policy.digest,
                at=at,
            )
            and await self._approval_authority.current(context, binding, at=at)
        )
        input_valid = await self._input_verifier.current(context, request)
        egress_valid = not request.spec.egress_rules or (
            self._egress_broker is not None and self._egress_broker.enforcement_ready
        )
        execution_allowed = (
            policy_valid and approval_valid and input_valid and egress_valid
        )
        if state.status is SandboxStatus.APPROVED:
            if not policy_valid:
                raise PermissionError("sandbox_runtime_policy_denied")
            if not approval_valid:
                raise PermissionError("sandbox_runtime_approval_invalid")
            if not input_valid:
                raise PermissionError("sandbox_input_snapshot_invalid")
            if not egress_valid:
                raise PermissionError("sandbox_egress_enforcement_not_ready")
        if (
            request.spec.egress_rules
            and (
                self._egress_broker is None or not self._egress_broker.enforcement_ready
            )
            and state.status is SandboxStatus.APPROVED
        ):
            raise PermissionError("sandbox_egress_enforcement_not_ready")
        return state, execution_allowed

    async def _resume_reconciliation(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
    ) -> SandboxState:
        phase = cast(str, state.pending_reconciliation_phase)
        try:
            await self._assert_fence(context, state, lease)
            observation = await self._backend.observe(context, state.request)
        except SandboxBackendError as error:
            state = await self._record_resumed_reconciliation(
                context,
                state,
                lease,
                phase,
                SandboxReconciliationOutcome.UNKNOWN,
            )
            if phase == "cleanup":
                return await self._cleanup_failed(context, state, lease, error.code)
            return await self._backend_failure(context, state, lease, error)
        except Exception:
            state = await self._record_resumed_reconciliation(
                context,
                state,
                lease,
                phase,
                SandboxReconciliationOutcome.UNKNOWN,
            )
            if phase == "cleanup":
                return await self._cleanup_failed(
                    context,
                    state,
                    lease,
                    "sandbox_cleanup_reconciliation_failed",
                )
            return await self._record_failure(
                context,
                state,
                lease,
                f"sandbox_{phase}_reconciliation_failed",
            )
        state = await self._record_resumed_reconciliation(
            context,
            state,
            lease,
            phase,
            observation.outcome,
        )
        present = observation.outcome in {
            SandboxReconciliationOutcome.PRESENT,
            SandboxReconciliationOutcome.RUNNING,
            SandboxReconciliationOutcome.TERMINAL,
        }
        identity_matches = (
            observation.backend_reference == state.backend_reference
            and observation.observed_spec_digest == state.request.spec.digest
        )
        valid = (
            (
                phase == "provision"
                and (
                    observation.outcome
                    in {
                        SandboxReconciliationOutcome.ABSENT,
                        SandboxReconciliationOutcome.DELETED,
                    }
                    or (
                        present
                        and observation.backend_reference is not None
                        and observation.observed_spec_digest
                        == state.request.spec.digest
                    )
                )
            )
            or (
                phase == "collect"
                and identity_matches
                and observation.outcome
                in {
                    SandboxReconciliationOutcome.RUNNING,
                    SandboxReconciliationOutcome.TERMINAL,
                }
            )
            or (
                phase == "cleanup"
                and (
                    observation.outcome
                    in {
                        SandboxReconciliationOutcome.ABSENT,
                        SandboxReconciliationOutcome.DELETED,
                    }
                    or identity_matches
                )
            )
        )
        if valid:
            self._metrics.add("reconciliations", purpose=state.request.purpose)
            return state
        return await self._record_failure(
            context,
            state,
            lease,
            f"sandbox_{phase}_reconciliation_conflict",
        )

    async def _record_resumed_reconciliation(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        phase: str,
        outcome: SandboxReconciliationOutcome,
    ) -> SandboxState:
        return await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_RECONCILED,
                    {
                        "outcome": outcome.value,
                        "phase": phase,
                    },
                    (
                        f"{phase}-reconciled-resume-"
                        f"{state.pending_reconciliation_attempt or 0}"
                    ),
                ),
            ),
        )

    async def _provision(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        *,
        allow_create: bool,
    ) -> tuple[SandboxState, str] | None:
        request = state.request
        try:
            await self._assert_fence(context, state, lease)
            with self._tracer.operation("reconcile", request.purpose):
                observation = await self._backend.observe(context, request)
        except SandboxBackendError as error:
            await self._backend_failure(context, state, lease, error)
            return None
        except Exception:
            await self._record_failure(
                context,
                state,
                lease,
                "sandbox_observe_backend_bug",
            )
            return None
        provisioned: ProvisionedSandbox | None = None
        if observation.outcome in {
            SandboxReconciliationOutcome.PRESENT,
            SandboxReconciliationOutcome.RUNNING,
            SandboxReconciliationOutcome.TERMINAL,
        }:
            if (
                observation.observed_spec_digest != request.spec.digest
                or observation.backend_reference is None
            ):
                await self._append(
                    context,
                    state,
                    lease,
                    (
                        (
                            DomainEventType.SANDBOX_POLICY_VIOLATION,
                            {"error_code": "sandbox_observed_scope_conflict"},
                            "scope-conflict",
                        ),
                    ),
                )
                return None
            provisioned = ProvisionedSandbox(
                observation.backend_reference,
                request.spec.digest,
                observation.observed_at,
            )
        elif observation.outcome not in {
            SandboxReconciliationOutcome.ABSENT,
            SandboxReconciliationOutcome.DELETED,
        }:
            await self._record_failure(
                context,
                state,
                lease,
                "sandbox_observation_ambiguous",
            )
            return None
        if provisioned is None:
            if not allow_create:
                await self._append(
                    context,
                    state,
                    lease,
                    (
                        (
                            DomainEventType.SANDBOX_POLICY_VIOLATION,
                            {"error_code": "sandbox_runtime_authority_revoked"},
                            "authority-revoked",
                        ),
                    ),
                )
                return None
            try:
                await self._assert_fence(context, state, lease)
                self._metrics.add("provision_attempts", purpose=request.purpose)
                with self._tracer.operation("provision", request.purpose):
                    provisioned = await self._backend.provision(context, request, lease)
            except SandboxBackendError as error:
                if not error.ambiguous:
                    await self._backend_failure(context, state, lease, error)
                    return None
                provisioned = await self._reconcile_provision(context, state, lease)
                if provisioned is None:
                    return None
            except Exception:
                await self._record_failure(
                    context,
                    state,
                    lease,
                    "sandbox_provision_backend_bug",
                )
                return None
        if provisioned.spec_digest != request.spec.digest:
            updated = await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_POLICY_VIOLATION,
                        {"error_code": "sandbox_backend_spec_mismatch"},
                        "spec-mismatch",
                    ),
                ),
            )
            await self._cleanup(
                context,
                updated,
                lease,
                provisioned.backend_reference,
            )
            return None
        state = await self._state(context, request.sandbox_id)
        updated = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_PROVISIONED,
                    {
                        "backend_reference": provisioned.backend_reference,
                        "spec_digest": provisioned.spec_digest,
                    },
                    "provisioned",
                ),
            ),
        )
        return updated, provisioned.backend_reference

    async def _reconcile_provision(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
    ) -> ProvisionedSandbox | None:
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
                    {"phase": "provision"},
                    "provision-reconcile-intent",
                ),
            ),
        )
        try:
            await self._assert_fence(context, state, lease)
            observation = await self._backend.observe(context, state.request)
        except Exception:
            await self._record_failure(
                context,
                state,
                lease,
                "sandbox_provision_reconciliation_failed",
            )
            return None
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_RECONCILED,
                    {
                        "outcome": observation.outcome.value,
                        "phase": "provision",
                    },
                    "provision-reconciled",
                ),
            ),
        )
        self._metrics.add("reconciliations", purpose=state.request.purpose)
        if (
            observation.outcome
            not in {
                SandboxReconciliationOutcome.PRESENT,
                SandboxReconciliationOutcome.RUNNING,
            }
            or observation.backend_reference is None
            or observation.observed_spec_digest != state.request.spec.digest
        ):
            await self._record_failure(
                context,
                state,
                lease,
                "sandbox_ambiguous_provision_unresolved",
            )
            return None
        return ProvisionedSandbox(
            observation.backend_reference,
            state.request.spec.digest,
            observation.observed_at,
        )

    async def _record_result(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        result: SandboxResult,
    ) -> SandboxState:
        request = state.request
        contract_violation = _artifact_contract_violation(request, result)
        if contract_violation is not None:
            return await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_POLICY_VIOLATION,
                        {"error_code": contract_violation},
                        "artifact-contract",
                    ),
                ),
            )
        if result.stdout.captured_bytes + result.stderr.captured_bytes > (
            request.spec.resources.max_output_bytes
        ):
            return await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_POLICY_VIOLATION,
                        {"error_code": "sandbox_output_limit_exceeded"},
                        "output-limit",
                    ),
                ),
            )
        output_events: tuple[
            tuple[DomainEventType, Mapping[str, JsonValue], str], ...
        ] = tuple(
            (
                DomainEventType.SANDBOX_OUTPUT_CAPTURED,
                {
                    "captured_bytes": output.captured_bytes,
                    "digest": output.digest,
                    "redacted": output.redacted,
                    "stream": output.stream,
                    "truncated": output.truncated,
                },
                f"output-{output.stream}",
            )
            for output in (result.stdout, result.stderr)
        )
        artifact_events: tuple[
            tuple[DomainEventType, Mapping[str, JsonValue], str], ...
        ] = tuple(
            (
                DomainEventType.SANDBOX_ARTIFACT_CAPTURED,
                {
                    "artifact_id": str(artifact.artifact_id),
                    "digest": artifact.digest,
                    "media_type": artifact.media_type,
                    "quarantined": artifact.quarantined,
                    "size_bytes": artifact.size_bytes,
                },
                f"artifact-{artifact.artifact_id}",
            )
            for artifact in result.artifacts
        )
        terminal_type = {
            SandboxExecutionOutcome.SUCCEEDED: DomainEventType.SANDBOX_COMPLETED,
            SandboxExecutionOutcome.FAILED: DomainEventType.SANDBOX_FAILED,
            SandboxExecutionOutcome.TIMED_OUT: DomainEventType.SANDBOX_TIMED_OUT,
            SandboxExecutionOutcome.OOM_KILLED: DomainEventType.SANDBOX_OOM_KILLED,
            SandboxExecutionOutcome.POLICY_VIOLATION: (
                DomainEventType.SANDBOX_POLICY_VIOLATION
            ),
            SandboxExecutionOutcome.AMBIGUOUS: DomainEventType.SANDBOX_FAILED,
        }.get(result.outcome)
        terminal_events: tuple[
            tuple[DomainEventType, Mapping[str, JsonValue], str], ...
        ]
        terminal_payload: Mapping[str, JsonValue] = {
            "error_code": result.error_code,
            "exit_code": result.exit_code,
            "outcome": result.outcome.value,
            "result": sandbox_result_to_payload(result),
        }
        if result.outcome is SandboxExecutionOutcome.CANCELLED:
            terminal_events = (
                (
                    DomainEventType.SANDBOX_CANCELLATION_REQUESTED,
                    {"reason": "backend_reported_cancellation"},
                    "backend-cancel-intent",
                ),
                (
                    DomainEventType.SANDBOX_CANCELLED,
                    terminal_payload,
                    "result",
                ),
            )
        else:
            if terminal_type is None:
                raise RuntimeError("unhandled sandbox execution outcome")
            terminal_events = ((terminal_type, terminal_payload, "result"),)
        quarantine_reason = (
            "artifact_scanner_quarantine"
            if any(artifact.quarantined for artifact in result.artifacts)
            else None
        )
        finalization_events: tuple[
            tuple[DomainEventType, Mapping[str, JsonValue], str], ...
        ] = ()
        if (
            result.outcome is SandboxExecutionOutcome.SUCCEEDED
            and quarantine_reason is None
        ):
            readiness = await self._safe_readiness(context)
            if readiness.ready:
                finalization_events = (
                    (
                        DomainEventType.SANDBOX_ATTESTED,
                        {
                            "approval_scope_digest": state.approval_scope_digest,
                            "backend_identity": readiness.backend_identity,
                            "image_digest": request.spec.image_digest,
                            "input_digest": request.spec.input_snapshot.digest,
                            "policy_digest": state.policy_digest,
                            "result_digest": sandbox_result_digest(result),
                            "spec_digest": request.spec.digest,
                        },
                        "attestation",
                    ),
                )
            else:
                quarantine_reason = "backend_readiness_unverified"
        if quarantine_reason is not None:
            finalization_events = (
                (
                    DomainEventType.SANDBOX_QUARANTINED,
                    {"reason": quarantine_reason},
                    "quarantine",
                ),
            )
        state = await self._append(
            context,
            state,
            lease,
            (
                *output_events,
                *artifact_events,
                *terminal_events,
                *finalization_events,
            ),
        )
        if quarantine_reason is not None:
            self._metrics.add("quarantines", purpose=request.purpose)
        return state

    async def _cancel(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        reference: str,
    ) -> SandboxState:
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_CANCELLATION_REQUESTED,
                    {"reason": "operator_cancellation"},
                    "cancel-intent",
                ),
            ),
        )
        return await self._resume_cancel(context, state, lease, reference)

    async def _resume_cancel(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        reference: str,
    ) -> SandboxState:
        try:
            await self._assert_fence(context, state, lease)
            await self._backend.terminate(context, state.request, reference, lease)
        except Exception:
            state = await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_FAILED,
                        {"error_code": "sandbox_termination_failed"},
                        "termination-failed",
                    ),
                ),
            )
            return await self._cleanup(context, state, lease, reference)
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_CANCELLED,
                    {"error_code": "sandbox_cancelled"},
                    "cancelled",
                ),
            ),
        )
        return await self._cleanup(context, state, lease, reference)

    async def _cleanup(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        reference: str,
    ) -> SandboxState:
        if (
            state.status is SandboxStatus.QUARANTINED
            and state.quarantine_reason == "cleanup_attempts_exhausted"
        ):
            return state
        if state.status not in {
            SandboxStatus.COMPLETED,
            SandboxStatus.FAILED,
            SandboxStatus.TIMED_OUT,
            SandboxStatus.OOM_KILLED,
            SandboxStatus.POLICY_VIOLATION,
            SandboxStatus.CANCELLED,
            SandboxStatus.QUARANTINED,
            SandboxStatus.CLEANUP_PENDING,
            SandboxStatus.CLEANUP_FAILED,
        }:
            return state
        if state.status is not SandboxStatus.CLEANUP_PENDING:
            state = await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_CLEANUP_REQUESTED,
                        {
                            "attempt": state.cleanup_attempts + 1,
                            "backend_reference": reference,
                        },
                        f"cleanup-intent-{state.cleanup_attempts + 1}",
                    ),
                ),
            )
        self._metrics.add("cleanup_attempts", purpose=state.request.purpose)
        try:
            await self._assert_fence(context, state, lease)
            with self._tracer.operation("cleanup", state.request.purpose):
                await self._backend.cleanup(context, state.request, reference, lease)
        except SandboxBackendError as error:
            if error.ambiguous:
                return await self._reconcile_cleanup(context, state, lease)
            return await self._cleanup_failed(context, state, lease, error.code)
        except Exception:
            return await self._cleanup_failed(
                context,
                state,
                lease,
                "sandbox_cleanup_backend_bug",
            )
        return await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_CLEANUP_COMPLETED,
                    {"backend_reference": reference},
                    f"cleanup-completed-{state.cleanup_attempts}",
                ),
            ),
        )

    async def _reconcile_cleanup(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
    ) -> SandboxState:
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
                    {"phase": "cleanup"},
                    f"cleanup-reconcile-intent-{state.cleanup_attempts}",
                ),
            ),
        )
        try:
            await self._assert_fence(context, state, lease)
            observation = await self._backend.observe(context, state.request)
        except Exception:
            return await self._cleanup_failed(
                context,
                state,
                lease,
                "sandbox_cleanup_reconciliation_failed",
            )
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_RECONCILED,
                    {
                        "outcome": observation.outcome.value,
                        "phase": "cleanup",
                    },
                    f"cleanup-reconciled-{state.cleanup_attempts}",
                ),
            ),
        )
        self._metrics.add("reconciliations", purpose=state.request.purpose)
        if observation.outcome in {
            SandboxReconciliationOutcome.ABSENT,
            SandboxReconciliationOutcome.DELETED,
        }:
            return await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_CLEANUP_COMPLETED,
                        {"reconciled": True},
                        f"cleanup-completed-{state.cleanup_attempts}",
                    ),
                ),
            )
        return await self._cleanup_failed(
            context,
            state,
            lease,
            "sandbox_ambiguous_cleanup_unresolved",
        )

    async def _cleanup_failed(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        code: str,
    ) -> SandboxState:
        self._metrics.add("cleanup_failures", purpose=state.request.purpose)
        state = await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_CLEANUP_FAILED,
                    {"error_code": code},
                    f"cleanup-failed-{state.cleanup_attempts}",
                ),
            ),
        )
        if (
            state.cleanup_attempts >= state.request.spec.cleanup_policy.max_attempts
            and state.request.spec.cleanup_policy.quarantine_on_failure
        ):
            self._metrics.add("quarantines", purpose=state.request.purpose)
            state = await self._append(
                context,
                state,
                lease,
                (
                    (
                        DomainEventType.SANDBOX_QUARANTINED,
                        {"reason": "cleanup_attempts_exhausted"},
                        "cleanup-quarantine",
                    ),
                ),
            )
        return state

    async def _backend_failure(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        error: SandboxBackendError,
    ) -> SandboxState:
        return await self._record_failure(context, state, lease, error.code)

    async def _record_failure(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        code: str,
    ) -> SandboxState:
        return await self._append(
            context,
            state,
            lease,
            (
                (
                    DomainEventType.SANDBOX_FAILED,
                    {"error_code": code},
                    f"failed-{state.version}",
                ),
            ),
        )

    async def _safe_readiness(
        self,
        context: TenantContext,
    ) -> BackendReadiness:
        try:
            return await self._backend.readiness(context)
        except Exception:
            return BackendReadiness(
                False,
                "backend_readiness_bug",
                "unknown-backend",
                False,
                False,
                False,
            )

    async def _assert_fence(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
    ) -> None:
        await self._repository.assert_fence(
            context,
            state.request.sandbox_id,
            lease,
            at=self._clock(),
        )

    async def _append(
        self,
        context: TenantContext,
        state: SandboxState,
        lease: WorkLease,
        events: Sequence[tuple[DomainEventType, Mapping[str, JsonValue], str]],
    ) -> SandboxState:
        at = self._clock()
        envelopes = tuple(
            _fenced_event(
                state.request,
                event_type,
                payload,
                lease,
                at=at,
                event_id=self._uuid_factory(),
                suffix=suffix,
            )
            for event_type, payload, suffix in events
        )
        await self._repository.append_fenced(
            context,
            state.request.sandbox_id,
            lease,
            envelopes,
            expected_version=state.version,
        )
        return await self._state(context, state.request.sandbox_id)

    async def _state(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> SandboxState:
        events = await self._repository.load(context, sandbox_id)
        if not events:
            raise ValueError("sandbox stream does not exist")
        return replay_sandbox(events)


def _authorize(
    authorization: AuthorizationService,
    principal: Principal,
    context: TenantContext,
    permission: Permission,
    at: datetime,
) -> None:
    decision = authorization.decide(
        principal=principal,
        tenant_id=context.tenant_id,
        permission=permission,
        at=at,
    )
    if not decision.allowed:
        raise PermissionError(decision.reason)


def _backend_context(context: TenantContext, request: SandboxRequest) -> None:
    if request.linkage.tenant_id != str(context.tenant_id):
        raise PermissionError("sandbox backend tenant mismatch")


def _backend_reference(
    context: TenantContext,
    request: SandboxRequest,
    backend_reference: str,
) -> None:
    _backend_context(context, request)
    if backend_reference != f"fake-sandbox/{request.sandbox_id}":
        raise PermissionError("fake sandbox backend reference mismatch")


def _unfenced_event(
    request: SandboxRequest,
    event_type: DomainEventType,
    payload: Mapping[str, JsonValue],
    *,
    at: datetime,
    event_id: UUID,
    actor: ActorReference,
    suffix: str,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        tenant_id=request.linkage.tenant_id,
        aggregate_id=str(request.sandbox_id),
        event_type=event_type,
        schema_version=1,
        occurred_at=at,
        payload=payload,
        correlation_id=request.linkage.run_id,
        causation_id=request.linkage.remediation_action_id,
        actor=actor,
        policy_reference=None,
        idempotency_key=f"{request.idempotency_key}:{suffix}",
    )


def _fenced_event(
    request: SandboxRequest,
    event_type: DomainEventType,
    payload: Mapping[str, JsonValue],
    lease: WorkLease,
    *,
    at: datetime,
    event_id: UUID,
    suffix: str,
) -> EventEnvelope:
    complete: dict[str, JsonValue] = dict(payload)
    complete.update(
        {
            "lease_generation": lease.generation,
            "lease_token": str(lease.token),
            "sandbox_id": str(request.sandbox_id),
            "spec_digest": request.spec.digest,
        }
    )
    return EventEnvelope(
        event_id=event_id,
        tenant_id=request.linkage.tenant_id,
        aggregate_id=str(request.sandbox_id),
        event_type=event_type,
        schema_version=1,
        occurred_at=at,
        payload=complete,
        correlation_id=request.linkage.run_id,
        causation_id=request.linkage.remediation_action_id,
        idempotency_key=f"{request.idempotency_key}:{suffix}:{lease.generation}",
    )


def _artifact_contract_violation(
    request: SandboxRequest,
    result: SandboxResult,
) -> str | None:
    artifacts = result.artifacts
    resources = request.spec.resources
    if len(artifacts) > resources.max_files:
        return "sandbox_artifact_file_count_exceeded"
    if (
        sum(artifact.size_bytes for artifact in artifacts)
        > resources.max_artifact_bytes
    ):
        return "sandbox_artifact_bytes_exceeded"
    paths = [artifact.path for artifact in artifacts]
    if len(paths) != len(set(paths)):
        return "sandbox_artifact_path_conflict"
    artifact_ids = [artifact.artifact_id for artifact in artifacts]
    if len(artifact_ids) != len(set(artifact_ids)):
        return "sandbox_artifact_identity_conflict"
    expected = {output.path: output for output in request.spec.expected_outputs}
    for artifact in artifacts:
        output = expected.get(artifact.path)
        if output is None:
            return "sandbox_artifact_path_not_approved"
        if artifact.media_type != output.media_type:
            return "sandbox_artifact_media_type_not_approved"
        if artifact.size_bytes > output.max_bytes:
            return "sandbox_artifact_output_limit_exceeded"
    if result.outcome is SandboxExecutionOutcome.SUCCEEDED and any(
        output.required and output.path not in paths
        for output in request.spec.expected_outputs
    ):
        return "sandbox_required_artifact_missing"
    return None


def _egress_rule_digest(rule: EgressRule) -> str:
    return sha256(
        json.dumps(
            {
                "host": rule.host,
                "port": rule.port,
                "protocol": rule.protocol,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def fake_result(
    *,
    outcome: SandboxExecutionOutcome,
    at: datetime,
    artifact: CapturedArtifact | None = None,
    error_code: str | None = None,
) -> SandboxResult:
    """Create bounded result metadata for deterministic tests and demos."""
    empty_digest = sha256(b"").hexdigest()
    return SandboxResult(
        outcome=outcome,
        exit_code=0 if outcome is SandboxExecutionOutcome.SUCCEEDED else 1,
        started_at=at,
        completed_at=at,
        stdout=CapturedOutput("stdout", empty_digest, 0, False, True),
        stderr=CapturedOutput("stderr", empty_digest, 0, False, True),
        artifacts=(artifact,) if artifact is not None else (),
        error_code=error_code,
    )


__all__ = [
    "BackendReadiness",
    "CancellationSignal",
    "FakeSandboxBackend",
    "InputSnapshotVerifier",
    "ProvisionedSandbox",
    "SandboxApprovalAuthority",
    "SandboxBackend",
    "SandboxBackendError",
    "SandboxErrorClass",
    "SandboxObservation",
    "SandboxOrchestrator",
    "SandboxRequestDecision",
    "SandboxRequestService",
    "StaticInputSnapshotVerifier",
    "StaticSandboxApprovalAuthority",
    "fake_result",
]
