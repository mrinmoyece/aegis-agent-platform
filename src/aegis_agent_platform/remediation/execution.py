"""Fenced controlled-action execution, reconciliation, and verification."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActionLifecycleStatus,
    ActionSpecification,
    ApprovalPolicySnapshot,
    ApprovalStatus,
    Condition,
    ConditionOperator,
    DomainEventType,
    EffectOutcome,
    EventEnvelope,
    JsonScalar,
    JsonValue,
    ReconciliationOutcome,
    ReconciliationRecord,
    RemediationReplayError,
    RemediationState,
    VerificationOutcome,
    WorkLease,
    replay_remediation,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
)
from aegis_agent_platform.remediation.policy import RemediationPolicyEvaluator
from aegis_agent_platform.remediation.repository import RemediationRepository
from aegis_agent_platform.remediation.telemetry import (
    RemediationMetrics,
    RemediationTracer,
)
from aegis_agent_platform.tenancy import TenantContext


class ActionErrorClass(StrEnum):
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFLICT = "conflict"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    PROVIDER_BUG = "provider_bug"


class ControlledActionError(RuntimeError):
    """Secret-safe provider-neutral action failure."""

    def __init__(
        self,
        error_class: ActionErrorClass,
        code: str,
        *,
        retryable: bool,
        ambiguous: bool = False,
    ) -> None:
        super().__init__(code)
        if not code:
            raise ValueError("action error code is required")
        self.error_class = error_class
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


@dataclass(frozen=True, slots=True)
class ActionObservation:
    """Fresh bounded evidence read from the exact provider target."""

    target_fingerprint: str
    state_fingerprint: str
    values: Mapping[str, JsonScalar]
    evidence_ids: tuple[str, ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        for value in (self.target_fingerprint, self.state_fingerprint):
            if len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError("observation fingerprints must be sha256 digests")
        if self.observed_at.tzinfo is None:
            raise ValueError("observation time must be timezone-aware")
        if len(self.values) > 64 or len(self.evidence_ids) > 64:
            raise ValueError("action observation exceeds its bounds")
        if any(not key or len(key) > 256 for key in self.values):
            raise ValueError("observation signal is invalid")
        if any(not value or len(value) > 256 for value in self.evidence_ids):
            raise ValueError("observation evidence identifier is invalid")
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))


@dataclass(frozen=True, slots=True)
class ActionAdapterResult:
    provider_reference: str
    target_fingerprint: str
    completed_at: datetime

    def __post_init__(self) -> None:
        if not self.provider_reference or len(self.provider_reference.encode()) > 512:
            raise ValueError("provider reference must be bounded")
        if len(self.target_fingerprint) != 64:
            raise ValueError("adapter target fingerprint is invalid")
        if self.completed_at.tzinfo is None:
            raise ValueError("adapter completion time must be timezone-aware")


class ControlledActionPort(Protocol):
    """Provider-neutral controlled effect and reconciliation boundary."""

    def supports(self, action: ActionSpecification) -> bool: ...

    async def observe(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionObservation: ...

    async def dry_run(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult: ...

    async def execute(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult: ...

    async def reconcile(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> tuple[ReconciliationOutcome, ActionObservation]: ...

    async def rollback(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult: ...

    async def compensate(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult: ...


class ApprovalAuthority(Protocol):
    """Checks whether recorded approvers still hold required roles."""

    def current(
        self,
        context: TenantContext,
        approver_ids: Sequence[str],
        required_roles: frozenset[str],
        *,
        at: datetime,
    ) -> bool: ...


class StaticApprovalAuthority:
    """Deterministic server-side role view for tests and the fake-only demo."""

    def __init__(self, roles: Mapping[str, frozenset[str]]) -> None:
        self._roles = dict(roles)

    def current(
        self,
        context: TenantContext,
        approver_ids: Sequence[str],
        required_roles: frozenset[str],
        *,
        at: datetime,
    ) -> bool:
        del context
        if at.tzinfo is None:
            raise ValueError("approval validation time must be timezone-aware")
        return bool(approver_ids) and all(
            self._roles.get(actor_id, frozenset()).intersection(required_roles)
            for actor_id in approver_ids
        )


class CancellationSignal(Protocol):
    @property
    def cancelled(self) -> bool: ...


class FakeControlledActionAdapter(ControlledActionPort):
    """Deterministic fake with explicit outcome and ambiguity controls."""

    def __init__(
        self,
        *,
        execution_outcomes: Sequence[EffectOutcome] = (EffectOutcome.SUCCEEDED,),
        ambiguous_applied: bool = False,
        verification_values: Mapping[str, JsonScalar] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not execution_outcomes:
            raise ValueError("fake adapter requires at least one execution outcome")
        self._execution_outcomes = tuple(execution_outcomes)
        self._ambiguous_applied = ambiguous_applied
        self._verification_values = dict(verification_values or {})
        self._clock = clock
        self._attempt = 0
        self._applied = False
        self.calls: list[str] = []

    def supports(self, action: ActionSpecification) -> bool:
        return action.kind.value == "kubernetes.rollout_restart.v1"

    async def observe(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionObservation:
        _adapter_context(context, action)
        self.calls.append("observe")
        values: dict[str, JsonScalar] = {
            "deployment.available": True,
            "deployment.restart_observed": self._applied,
        }
        values.update(self._verification_values)
        state_digest = sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return ActionObservation(
            target_fingerprint=action.target.fingerprint,
            state_fingerprint=state_digest,
            values=values,
            evidence_ids=("fake-observation",),
            observed_at=self._clock(),
        )

    async def dry_run(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        _adapter_context(context, action)
        self.calls.append("dry_run")
        return self._result(action, "fake-dry-run")

    async def execute(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        _adapter_context(context, action)
        self.calls.append("execute")
        index = min(self._attempt, len(self._execution_outcomes) - 1)
        outcome = self._execution_outcomes[index]
        self._attempt += 1
        if outcome is EffectOutcome.SUCCEEDED:
            self._applied = True
            return self._result(action, f"fake-execution-{self._attempt}")
        if outcome is EffectOutcome.AMBIGUOUS:
            self._applied = self._ambiguous_applied
            raise ControlledActionError(
                ActionErrorClass.TIMEOUT,
                "fake_ambiguous_timeout",
                retryable=True,
                ambiguous=True,
            )
        if outcome is EffectOutcome.RETRYABLE_FAILURE:
            raise ControlledActionError(
                ActionErrorClass.TRANSIENT,
                "fake_retryable_failure",
                retryable=True,
            )
        raise ControlledActionError(
            ActionErrorClass.PERMANENT,
            "fake_permanent_failure",
            retryable=False,
        )

    async def reconcile(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> tuple[ReconciliationOutcome, ActionObservation]:
        _adapter_context(context, action)
        self.calls.append("reconcile")
        observation = await self.observe(context, action)
        return (
            ReconciliationOutcome.APPLIED
            if self._applied
            else ReconciliationOutcome.NOT_APPLIED,
            observation,
        )

    async def rollback(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        _adapter_context(context, action)
        self.calls.append("rollback")
        self._applied = False
        return self._result(action, "fake-rollback")

    async def compensate(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        _adapter_context(context, action)
        self.calls.append("compensate")
        self._applied = False
        return self._result(action, "fake-compensation")

    def _result(
        self,
        action: ActionSpecification,
        reference: str,
    ) -> ActionAdapterResult:
        return ActionAdapterResult(
            provider_reference=reference,
            target_fingerprint=action.target.fingerprint,
            completed_at=self._clock(),
        )


class ControlledActionExecutor:
    """Rechecks exact authority, records intent, and contains adapter outcomes."""

    def __init__(
        self,
        repository: RemediationRepository,
        adapter: ControlledActionPort,
        approval_authority: ApprovalAuthority,
        *,
        authorization: AuthorizationService | None = None,
        metrics: RemediationMetrics | None = None,
        tracer: RemediationTracer | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._repository = repository
        self._adapter = adapter
        self._approval_authority = approval_authority
        self._authorization = authorization or AuthorizationService()
        self._metrics = metrics or RemediationMetrics()
        self._tracer = tracer or RemediationTracer()
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._sleep = sleep

    async def execute(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        action_id: UUID,
        lease: WorkLease,
        current_policy: ApprovalPolicySnapshot,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> RemediationState:
        state, action, _at = await self._base_scope(
            principal,
            context,
            plan_id,
            action_id,
            lease,
            Permission.ACTION_EXECUTE,
        )
        latest = tuple(item for item in state.executions if item.action_id == action_id)
        if state.action_statuses[action_id] in {
            ActionLifecycleStatus.CANCELLED,
            ActionLifecycleStatus.ROLLED_BACK,
            ActionLifecycleStatus.COMPENSATED,
            ActionLifecycleStatus.VERIFIED,
            ActionLifecycleStatus.VERIFICATION_FAILED,
            ActionLifecycleStatus.VERIFICATION_PARTIAL,
            ActionLifecycleStatus.VERIFICATION_UNKNOWN,
        } or (
            state.action_statuses[action_id] is ActionLifecycleStatus.FAILED
            and not latest
        ):
            return state
        if latest:
            execution = latest[-1]
            reconciliation = _reconciliation_for(
                state,
                action_id,
                execution.attempt,
            )
            if execution.outcome is EffectOutcome.SUCCEEDED:
                return await self._verify(context, state, action, lease)
            if execution.outcome in {
                EffectOutcome.PERMANENT_FAILURE,
                EffectOutcome.CANCELLED,
            }:
                return state
            if reconciliation is None:
                reconciled = await self._reconcile(
                    context,
                    state,
                    action,
                    lease,
                    execution.attempt,
                )
            else:
                reconciled = reconciliation.outcome
            if reconciled is ReconciliationOutcome.APPLIED:
                return await self._verify(
                    context,
                    await self._state(context, plan_id),
                    action,
                    lease,
                )
            if reconciled is not ReconciliationOutcome.NOT_APPLIED:
                return await self._state(context, plan_id)
            first_attempt = execution.attempt + 1
            if first_attempt > action.retry_policy.max_attempts:
                return await self._state(context, plan_id)
            state, action = await self._scope(
                principal,
                context,
                plan_id,
                action_id,
                lease,
                current_policy,
                Permission.ACTION_EXECUTE,
            )
        else:
            first_attempt = 1
        in_flight_attempt = await self._in_flight_attempt(
            context,
            plan_id,
            action_id,
        )
        if latest:
            in_flight_attempt = None
        if (
            not latest
            and in_flight_attempt is None
            and cancellation is not None
            and cancellation.cancelled
        ):
            return await self._cancel(context, state, action, lease)
        if in_flight_attempt is not None:
            reconciled = await self._reconcile(
                context,
                state,
                action,
                lease,
                in_flight_attempt,
            )
            if reconciled is ReconciliationOutcome.APPLIED:
                return await self._verify(
                    context,
                    await self._state(context, plan_id),
                    action,
                    lease,
                )
            if reconciled is not ReconciliationOutcome.NOT_APPLIED:
                return await self._state(context, plan_id)
            first_attempt = in_flight_attempt + 1
            if first_attempt > action.retry_policy.max_attempts:
                return await self._state(context, plan_id)
            state, action = await self._scope(
                principal,
                context,
                plan_id,
                action_id,
                lease,
                current_policy,
                Permission.ACTION_EXECUTE,
            )
        elif not latest:
            state, action = await self._scope(
                principal,
                context,
                plan_id,
                action_id,
                lease,
                current_policy,
                Permission.ACTION_EXECUTE,
            )
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_DISPATCH_CLAIMED,
                        {"attempt": 1},
                        "dispatch",
                    ),
                    (
                        DomainEventType.ACTION_PREFLIGHT_REQUESTED,
                        {"attempt": 1},
                        "preflight-requested",
                    ),
                ),
            )
            try:
                with self._tracer.operation("preflight", action.kind):
                    observation = await self._observe(context, action)
            except ControlledActionError as error:
                return await self._record_phase_failure(
                    context,
                    state,
                    action,
                    lease,
                    event_type=DomainEventType.ACTION_PREFLIGHT_FAILED,
                    error=error,
                )
            preflight = _conditions(action.preconditions, observation)
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_PREFLIGHT_COMPLETED,
                        {
                            "attempt": 1,
                            "outcome": preflight.value,
                            "state_fingerprint": observation.state_fingerprint,
                        },
                        "preflight-completed",
                    ),
                ),
            )
            if preflight is not VerificationOutcome.SUCCESS:
                return await self._append(
                    context,
                    state,
                    action,
                    lease,
                    (
                        (
                            DomainEventType.ACTION_PREFLIGHT_FAILED,
                            {
                                "attempt": 1,
                                "error_class": ActionErrorClass.CONFLICT.value,
                                "error_code": "action_precondition_failed",
                            },
                            "preflight-failed",
                        ),
                    ),
                )
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_DRY_RUN_REQUESTED,
                        {"attempt": 1},
                        "dry-run-requested",
                    ),
                ),
            )
            try:
                with self._tracer.operation("dry_run", action.kind):
                    dry_run = await asyncio.wait_for(
                        self._adapter.dry_run(context, action),
                        timeout=action.timeout_seconds,
                    )
                _target_matches(action, dry_run.target_fingerprint)
            except TimeoutError:
                return await self._record_phase_failure(
                    context,
                    state,
                    action,
                    lease,
                    event_type=DomainEventType.ACTION_DRY_RUN_FAILED,
                    error=ControlledActionError(
                        ActionErrorClass.TIMEOUT,
                        "dry_run_timeout",
                        retryable=False,
                    ),
                )
            except ControlledActionError as error:
                return await self._record_phase_failure(
                    context,
                    state,
                    action,
                    lease,
                    event_type=DomainEventType.ACTION_DRY_RUN_FAILED,
                    error=error,
                )
            except Exception:
                return await self._record_phase_failure(
                    context,
                    state,
                    action,
                    lease,
                    event_type=DomainEventType.ACTION_DRY_RUN_FAILED,
                    error=ControlledActionError(
                        ActionErrorClass.PROVIDER_BUG,
                        "dry_run_adapter_bug",
                        retryable=False,
                    ),
                )
            self._metrics.add("dry_runs", action_kind=action.kind)
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_DRY_RUN_COMPLETED,
                        {
                            "attempt": 1,
                            "outcome": "success",
                            "provider_reference": dry_run.provider_reference,
                        },
                        "dry-run-completed",
                    ),
                ),
            )
        for attempt in range(first_attempt, action.retry_policy.max_attempts + 1):
            state, action = await self._scope(
                principal,
                context,
                plan_id,
                action_id,
                lease,
                current_policy,
                Permission.ACTION_EXECUTE,
            )
            if cancellation is not None and cancellation.cancelled:
                return await self._cancel(context, state, action, lease)
            latest_observation = await self._observe(context, action)
            state, action = await self._scope(
                principal,
                context,
                plan_id,
                action_id,
                lease,
                current_policy,
                Permission.ACTION_EXECUTE,
            )
            if cancellation is not None and cancellation.cancelled:
                return await self._cancel(context, state, action, lease)
            _target_matches(action, latest_observation.target_fingerprint)
            if _conditions(action.preconditions, latest_observation) is not (
                VerificationOutcome.SUCCESS
            ):
                return await self._record_phase_failure(
                    context,
                    state,
                    action,
                    lease,
                    event_type=DomainEventType.ACTION_PREFLIGHT_FAILED,
                    attempt=attempt,
                    error=ControlledActionError(
                        ActionErrorClass.CONFLICT,
                        "action_precondition_changed",
                        retryable=False,
                    ),
                )
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_EXECUTION_REQUESTED,
                        {
                            "attempt": attempt,
                            "idempotency_key": action.idempotency_key,
                            "target_fingerprint": action.target.fingerprint,
                        },
                        f"execution-requested:{attempt}",
                    ),
                    (
                        DomainEventType.ACTION_EXECUTION_STARTED,
                        {"attempt": attempt},
                        f"execution-started:{attempt}",
                    ),
                ),
            )
            self._metrics.add("attempts", action_kind=action.kind)
            failure: ControlledActionError | None = None
            try:
                with self._tracer.operation("execute", action.kind):
                    result = await asyncio.wait_for(
                        self._adapter.execute(context, action),
                        timeout=action.timeout_seconds,
                    )
                _target_matches(
                    action,
                    result.target_fingerprint,
                    ambiguous=True,
                )
            except TimeoutError:
                failure = ControlledActionError(
                    ActionErrorClass.TIMEOUT,
                    "action_timeout_ambiguous",
                    retryable=True,
                    ambiguous=True,
                )
            except ControlledActionError as caught:
                failure = caught
            except Exception:
                failure = ControlledActionError(
                    ActionErrorClass.PROVIDER_BUG,
                    "action_adapter_bug",
                    retryable=False,
                    ambiguous=True,
                )
            else:
                state = await self._append(
                    context,
                    state,
                    action,
                    lease,
                    (
                        (
                            DomainEventType.ACTION_EXECUTION_SUCCEEDED,
                            {
                                "attempt": attempt,
                                "provider_reference": result.provider_reference,
                            },
                            f"execution-succeeded:{attempt}",
                        ),
                    ),
                )
                return await self._verify(context, state, action, lease)
            if failure is None:
                raise RuntimeError("action attempt ended without a result")
            if failure.ambiguous:
                self._metrics.add("ambiguous_outcomes", action_kind=action.kind)
                state = await self._append(
                    context,
                    state,
                    action,
                    lease,
                    (
                        (
                            DomainEventType.ACTION_EXECUTION_AMBIGUOUS,
                            {
                                "attempt": attempt,
                                "error_code": failure.code,
                            },
                            f"execution-ambiguous:{attempt}",
                        ),
                    ),
                )
                reconciled = await self._reconcile(
                    context,
                    state,
                    action,
                    lease,
                    attempt,
                )
                if reconciled is ReconciliationOutcome.APPLIED:
                    return await self._verify(
                        context,
                        await self._state(context, plan_id),
                        action,
                        lease,
                    )
                if reconciled is not ReconciliationOutcome.NOT_APPLIED:
                    return await self._state(context, plan_id)

            else:
                state = await self._record_failure(
                    context,
                    state,
                    action,
                    lease,
                    attempt=attempt,
                    error=failure,
                )
                if not failure.retryable:
                    return state
                reconciled = await self._reconcile(
                    context,
                    state,
                    action,
                    lease,
                    attempt,
                )
                if reconciled is ReconciliationOutcome.APPLIED:
                    return await self._verify(
                        context,
                        await self._state(context, plan_id),
                        action,
                        lease,
                    )
                if reconciled is not ReconciliationOutcome.NOT_APPLIED:
                    return await self._state(context, plan_id)
            if attempt < action.retry_policy.max_attempts:
                self._metrics.add("retries", action_kind=action.kind)
                delay = min(
                    action.retry_policy.maximum_backoff_seconds,
                    action.retry_policy.initial_backoff_seconds * (2 ** (attempt - 1)),
                )
                await self._sleep(delay)
        return await self._state(context, plan_id)

    async def _in_flight_attempt(
        self,
        context: TenantContext,
        plan_id: UUID,
        action_id: UUID,
    ) -> int | None:
        events = await self._repository.load(context, plan_id)
        terminal_attempts: set[int] = set()
        started_attempts: list[int] = []
        for event in events:
            if event.payload.get("action_id") != str(action_id):
                continue
            attempt = event.payload.get("attempt")
            if not isinstance(attempt, int) or isinstance(attempt, bool):
                continue
            if event.event_type in {
                DomainEventType.ACTION_EXECUTION_SUCCEEDED,
                DomainEventType.ACTION_EXECUTION_FAILED,
                DomainEventType.ACTION_EXECUTION_AMBIGUOUS,
                DomainEventType.ACTION_CANCELLED,
            }:
                terminal_attempts.add(attempt)
            elif event.event_type == DomainEventType.ACTION_EXECUTION_STARTED:
                started_attempts.append(attempt)
        for attempt in reversed(started_attempts):
            if attempt not in terminal_attempts:
                return attempt
        return None

    async def rollback(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        action_id: UUID,
        lease: WorkLease,
        current_policy: ApprovalPolicySnapshot,
        *,
        compensate: bool = False,
    ) -> RemediationState:
        state, action, _at = await self._base_scope(
            principal,
            context,
            plan_id,
            action_id,
            lease,
            Permission.ACTION_ROLLBACK,
        )
        reference = (
            action.compensation_reference if compensate else action.rollback_reference
        )
        if reference is None:
            raise PermissionError("action_has_no_controlled_reversal")
        requested = (
            DomainEventType.ACTION_COMPENSATION_REQUESTED
            if compensate
            else DomainEventType.ACTION_ROLLBACK_REQUESTED
        )
        completed = (
            DomainEventType.ACTION_COMPENSATION_COMPLETED
            if compensate
            else DomainEventType.ACTION_ROLLBACK_COMPLETED
        )
        failed = (
            DomainEventType.ACTION_COMPENSATION_FAILED
            if compensate
            else DomainEventType.ACTION_ROLLBACK_FAILED
        )
        name = "compensation" if compensate else "rollback"
        lifecycle_events = await self._repository.load(context, plan_id)
        matching_events = tuple(
            event
            for event in lifecycle_events
            if event.payload.get("action_id") == str(action_id)
        )
        if any(event.event_type in {completed, failed} for event in matching_events):
            return state
        if any(event.event_type is requested for event in matching_events):
            return await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        failed,
                        {
                            "error_class": ActionErrorClass.TIMEOUT.value,
                            "error_code": f"{name}_outcome_missing_ambiguous",
                            "ambiguous": True,
                        },
                        f"{name}-recovery-ambiguous",
                    ),
                ),
            )
        state, action = await self._scope(
            principal,
            context,
            plan_id,
            action_id,
            lease,
            current_policy,
            Permission.ACTION_ROLLBACK,
        )
        state = await self._append(
            context,
            state,
            action,
            lease,
            ((requested, {"reference": reference}, f"{name}-requested"),),
        )
        try:
            result = await asyncio.wait_for(
                (
                    self._adapter.compensate(context, action)
                    if compensate
                    else self._adapter.rollback(context, action)
                ),
                timeout=action.timeout_seconds,
            )
            _target_matches(
                action,
                result.target_fingerprint,
                ambiguous=True,
            )
        except ControlledActionError as error:
            return await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        failed,
                        {
                            "error_class": error.error_class.value,
                            "error_code": error.code,
                            "ambiguous": error.ambiguous,
                        },
                        f"{name}-failed",
                    ),
                ),
            )
        except TimeoutError:
            return await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        failed,
                        {
                            "error_class": ActionErrorClass.TIMEOUT.value,
                            "error_code": f"{name}_timeout_ambiguous",
                            "ambiguous": True,
                        },
                        f"{name}-failed",
                    ),
                ),
            )
        except Exception:
            return await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        failed,
                        {
                            "error_class": ActionErrorClass.PROVIDER_BUG.value,
                            "error_code": f"{name}_adapter_bug",
                            "ambiguous": True,
                        },
                        f"{name}-failed",
                    ),
                ),
            )
        state = await self._append(
            context,
            state,
            action,
            lease,
            (
                (
                    completed,
                    {"provider_reference": result.provider_reference},
                    f"{name}-completed",
                ),
            ),
        )
        self._metrics.add(
            "compensations" if compensate else "rollbacks",
            action_kind=action.kind,
        )
        return state

    async def _scope(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        action_id: UUID,
        lease: WorkLease,
        policy: ApprovalPolicySnapshot,
        permission: Permission,
    ) -> tuple[RemediationState, ActionSpecification]:
        state, action, at = await self._base_scope(
            principal,
            context,
            plan_id,
            action_id,
            lease,
            permission,
        )
        usage = await self._repository.quota_usage(
            context,
            at=at,
            exclude_idempotency_key=action.idempotency_key,
        )
        current_evaluation = RemediationPolicyEvaluator().evaluate(
            context,
            state.plan,
            action,
            policy,
            usage,
            at=at,
        )
        if current_evaluation.outcome.value != "require_approval":
            raise PermissionError("action_runtime_policy_denied")
        evaluation = state.policy_evaluations.get(action_id)
        approval = state.approval_for(action_id)
        if evaluation is None or evaluation.outcome.value != "require_approval":
            raise PermissionError("action_policy_not_approved")
        if (
            policy.tenant_id != state.plan.tenant_id
            or policy.digest != state.plan.approval_policy.digest
            or evaluation.plan_digest != state.plan.digest
            or evaluation.action_digest != action.digest
            or evaluation.policy_digest != policy.digest
        ):
            raise PermissionError("action_policy_or_plan_is_stale")
        if (
            approval is None
            or approval.status is not ApprovalStatus.GRANTED
            or not approval.valid_for(
                plan=state.plan,
                action=action,
                policy_digest=policy.digest,
                at=at,
            )
        ):
            raise PermissionError("exact_scope_approval_is_not_valid")
        if not self._approval_authority.current(
            context,
            approval.approver_ids,
            policy.required_approver_roles,
            at=at,
        ):
            raise PermissionError("approver_role_is_stale_or_revoked")
        return state, action

    async def _base_scope(
        self,
        principal: Principal,
        context: TenantContext,
        plan_id: UUID,
        action_id: UUID,
        lease: WorkLease,
        permission: Permission,
    ) -> tuple[RemediationState, ActionSpecification, datetime]:
        at = self._clock()
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=permission,
            at=at,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)
        state = await self._state(context, plan_id)
        action = state.plan.action(action_id)
        if (
            lease.tenant_id != str(context.tenant_id)
            or lease.work_id != plan_id
            or lease.expires_at <= at
        ):
            raise FencingError(lease.generation, 0)
        if not self._adapter.supports(action):
            raise PermissionError("action_adapter_not_configured")
        return state, action, at

    async def _observe(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionObservation:
        try:
            observation = await asyncio.wait_for(
                self._adapter.observe(context, action),
                timeout=action.timeout_seconds,
            )
        except ControlledActionError:
            raise
        except TimeoutError as error:
            raise ControlledActionError(
                ActionErrorClass.TIMEOUT,
                "action_observation_timeout",
                retryable=True,
            ) from error
        except Exception as error:
            raise ControlledActionError(
                ActionErrorClass.PROVIDER_BUG,
                "action_observation_adapter_bug",
                retryable=False,
            ) from error
        _target_matches(action, observation.target_fingerprint)
        return observation

    async def _reconcile(
        self,
        context: TenantContext,
        state: RemediationState,
        action: ActionSpecification,
        lease: WorkLease,
        attempt: int,
    ) -> ReconciliationOutcome:
        existing = _reconciliation_for(state, action.action_id, attempt)
        if existing is not None:
            return existing.outcome
        events = await self._repository.load(context, state.plan.plan_id)
        requested = any(
            event.event_type == DomainEventType.ACTION_RECONCILIATION_REQUESTED
            and event.payload.get("action_id") == str(action.action_id)
            and event.payload.get("attempt") == attempt
            for event in events
        )
        if not requested:
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_RECONCILIATION_REQUESTED,
                        {"attempt": attempt},
                        f"reconciliation-requested:{attempt}",
                    ),
                ),
            )
        else:
            state = await self._state(context, state.plan.plan_id)
        try:
            with self._tracer.operation("reconcile", action.kind):
                outcome, observation = await asyncio.wait_for(
                    self._adapter.reconcile(context, action),
                    timeout=action.timeout_seconds,
                )
            if observation.target_fingerprint != action.target.fingerprint:
                outcome = ReconciliationOutcome.CONFLICT
        except (ControlledActionError, TimeoutError):
            outcome = ReconciliationOutcome.UNKNOWN
            observation = ActionObservation(
                target_fingerprint=action.target.fingerprint,
                state_fingerprint=sha256(b"unknown").hexdigest(),
                values={},
                evidence_ids=(),
                observed_at=self._clock(),
            )
        except Exception:
            outcome = ReconciliationOutcome.UNKNOWN
            observation = ActionObservation(
                target_fingerprint=action.target.fingerprint,
                state_fingerprint=sha256(b"provider-bug").hexdigest(),
                values={},
                evidence_ids=(),
                observed_at=self._clock(),
            )
        await self._append(
            context,
            state,
            action,
            lease,
            (
                (
                    DomainEventType.ACTION_RECONCILIATION_COMPLETED,
                    {
                        "attempt": attempt,
                        "observed_target_fingerprint": (observation.target_fingerprint),
                        "outcome": outcome.value,
                        "state_fingerprint": observation.state_fingerprint,
                    },
                    f"reconciliation-completed:{attempt}",
                ),
            ),
        )
        self._metrics.add("reconciliations", action_kind=action.kind)
        return outcome

    async def _verify(
        self,
        context: TenantContext,
        state: RemediationState,
        action: ActionSpecification,
        lease: WorkLease,
    ) -> RemediationState:
        events = await self._repository.load(context, state.plan.plan_id)
        requested_attempts: list[int] = []
        for event in events:
            attempt_value = event.payload.get("attempt")
            if (
                event.event_type == DomainEventType.ACTION_VERIFICATION_REQUESTED
                and event.payload.get("action_id") == str(action.action_id)
                and isinstance(attempt_value, int)
                and not isinstance(attempt_value, bool)
            ):
                requested_attempts.append(attempt_value)
        completed_attempts = {
            event.payload.get("attempt")
            for event in events
            if event.event_type == DomainEventType.ACTION_VERIFICATION_COMPLETED
            and event.payload.get("action_id") == str(action.action_id)
        }
        open_attempts = [
            attempt
            for attempt in requested_attempts
            if attempt not in completed_attempts
        ]
        index = (
            open_attempts[-1]
            if open_attempts
            else sum(item.action_id == action.action_id for item in state.verifications)
            + 1
        )
        if not open_attempts:
            state = await self._append(
                context,
                state,
                action,
                lease,
                (
                    (
                        DomainEventType.ACTION_VERIFICATION_REQUESTED,
                        {
                            "attempt": index,
                            "verification_artifact_reference": (
                                state.plan.verification_artifact_reference
                            ),
                        },
                        f"verification-requested:{index}",
                    ),
                ),
            )
        else:
            state = await self._state(context, state.plan.plan_id)
        events = await self._repository.load(context, state.plan.plan_id)
        not_before = _verification_observation_not_before(
            events,
            action.action_id,
            attempt=index,
        )
        try:
            with self._tracer.operation("verify", action.kind):
                observation = await self._observe(context, action)
            _require_fresh_observation(observation, not_before)
            outcome = _conditions(action.postconditions, observation)
        except ControlledActionError:
            outcome = VerificationOutcome.UNKNOWN
            observation = ActionObservation(
                target_fingerprint=action.target.fingerprint,
                state_fingerprint=sha256(b"verification-unknown").hexdigest(),
                values={},
                evidence_ids=(),
                observed_at=self._clock(),
            )
        state = await self._append(
            context,
            state,
            action,
            lease,
            (
                (
                    DomainEventType.ACTION_VERIFICATION_COMPLETED,
                    {
                        "attempt": index,
                        "evidence_ids": observation.evidence_ids,
                        "outcome": outcome.value,
                        "state_fingerprint": observation.state_fingerprint,
                    },
                    f"verification-completed:{index}",
                ),
            ),
        )
        self._metrics.add(
            (
                "verification_successes"
                if outcome is VerificationOutcome.SUCCESS
                else "verification_failures"
            ),
            action_kind=action.kind,
        )
        return state

    async def _cancel(
        self,
        context: TenantContext,
        state: RemediationState,
        action: ActionSpecification,
        lease: WorkLease,
    ) -> RemediationState:
        return await self._append(
            context,
            state,
            action,
            lease,
            (
                (
                    DomainEventType.ACTION_CANCELLATION_REQUESTED,
                    {"attempt": 1, "reason": "operator_or_deadline_cancellation"},
                    "cancellation-requested",
                ),
                (
                    DomainEventType.ACTION_CANCELLED,
                    {"attempt": 1, "error_code": "action_cancelled"},
                    "cancelled",
                ),
            ),
        )

    async def _record_failure(
        self,
        context: TenantContext,
        state: RemediationState,
        action: ActionSpecification,
        lease: WorkLease,
        *,
        attempt: int,
        error: ControlledActionError,
    ) -> RemediationState:
        return await self._append(
            context,
            state,
            action,
            lease,
            (
                (
                    DomainEventType.ACTION_EXECUTION_FAILED,
                    {
                        "attempt": attempt,
                        "error_class": error.error_class.value,
                        "error_code": error.code,
                        "retryable": error.retryable,
                    },
                    f"execution-failed:{attempt}:{error.code}",
                ),
            ),
        )

    async def _record_phase_failure(
        self,
        context: TenantContext,
        state: RemediationState,
        action: ActionSpecification,
        lease: WorkLease,
        *,
        event_type: DomainEventType,
        error: ControlledActionError,
        attempt: int = 1,
    ) -> RemediationState:
        return await self._append(
            context,
            state,
            action,
            lease,
            (
                (
                    event_type,
                    {
                        "attempt": attempt,
                        "error_class": error.error_class.value,
                        "error_code": error.code,
                    },
                    f"{event_type.value}:{attempt}:{error.code}",
                ),
            ),
        )

    async def _append(
        self,
        context: TenantContext,
        state: RemediationState,
        action: ActionSpecification,
        lease: WorkLease,
        events: Sequence[tuple[DomainEventType, Mapping[str, JsonValue], str]],
    ) -> RemediationState:
        at = self._clock()
        prepared = tuple(
            EventEnvelope(
                event_id=self._uuid_factory(),
                tenant_id=state.plan.tenant_id,
                aggregate_id=str(state.plan.plan_id),
                event_type=event_type,
                schema_version=1,
                occurred_at=at,
                payload={
                    **details,
                    "action_id": str(action.action_id),
                    "lease_generation": lease.generation,
                    "lease_token": str(lease.token),
                    "work_id": str(lease.work_id),
                },
                correlation_id=state.plan.investigation_run_id,
                policy_reference=state.plan.approval_policy.digest,
                idempotency_key=(
                    f"{action.idempotency_key}:{suffix}:{lease.generation}"
                ),
            )
            for event_type, details, suffix in events
        )
        await self._repository.append_fenced(
            context,
            state.plan.plan_id,
            lease,
            prepared,
            expected_version=state.version,
        )
        if any(
            event.event_type is DomainEventType.ACTION_DISPATCH_CLAIMED
            for event in prepared
        ):
            self._metrics.add("actions_dispatched", action_kind=action.kind)
        return await self._state(context, state.plan.plan_id)

    async def _state(
        self,
        context: TenantContext,
        plan_id: UUID,
    ) -> RemediationState:
        events = await self._repository.load(context, plan_id)
        if not events:
            raise ValueError("remediation plan was not found")
        return replay_remediation(events)


def _adapter_context(
    context: TenantContext,
    action: ActionSpecification,
) -> None:
    if not str(context.tenant_id):
        raise PermissionError("action tenant context is required")
    if not action.idempotency_key:
        raise ValueError("action idempotency key is required")


def _target_matches(
    action: ActionSpecification,
    fingerprint: str,
    *,
    ambiguous: bool = False,
) -> None:
    if fingerprint != action.target.fingerprint:
        raise ControlledActionError(
            ActionErrorClass.CONFLICT,
            "action_target_identity_changed",
            retryable=False,
            ambiguous=ambiguous,
        )


def _reconciliation_for(
    state: RemediationState,
    action_id: UUID,
    attempt: int,
) -> ReconciliationRecord | None:
    for reconciliation in reversed(state.reconciliations):
        if reconciliation.action_id == action_id and reconciliation.attempt == attempt:
            return reconciliation
    return None


def _verification_observation_not_before(
    events: Sequence[EventEnvelope],
    action_id: UUID,
    *,
    attempt: int,
) -> datetime:
    relevant = str(action_id)
    verification_requested_at = next(
        (
            event.occurred_at
            for event in reversed(events)
            if event.event_type == DomainEventType.ACTION_VERIFICATION_REQUESTED
            and event.payload.get("action_id") == relevant
            and event.payload.get("attempt") == attempt
        ),
        None,
    )
    if verification_requested_at is None:
        raise RemediationReplayError("verification request is missing")
    effect_at = max(
        (
            event.occurred_at
            for event in events
            if event.payload.get("action_id") == relevant
            and (
                event.event_type == DomainEventType.ACTION_EXECUTION_SUCCEEDED
                or (
                    event.event_type == DomainEventType.ACTION_RECONCILIATION_COMPLETED
                    and event.payload.get("outcome")
                    == ReconciliationOutcome.APPLIED.value
                )
            )
        ),
        default=verification_requested_at,
    )
    return max(verification_requested_at, effect_at)


def _require_fresh_observation(
    observation: ActionObservation,
    not_before: datetime,
) -> None:
    if observation.observed_at < not_before:
        raise ControlledActionError(
            ActionErrorClass.CONFLICT,
            "stale_verification_observation",
            retryable=True,
        )


def _conditions(
    conditions: Sequence[Condition],
    observation: ActionObservation,
) -> VerificationOutcome:
    matches: list[bool | None] = []
    for condition in conditions:
        value = observation.values.get(condition.signal)
        if value is None and condition.signal not in observation.values:
            matches.append(None)
            continue
        if condition.operator is ConditionOperator.EXISTS:
            matches.append(True)
        elif condition.operator is ConditionOperator.EQUALS:
            matches.append(value == condition.expected)
        elif condition.operator is ConditionOperator.NOT_EQUALS:
            matches.append(value != condition.expected)
        elif (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and isinstance(condition.expected, (int, float))
            and not isinstance(condition.expected, bool)
        ):
            matches.append(
                value >= condition.expected
                if condition.operator is ConditionOperator.AT_LEAST
                else value <= condition.expected
            )
        else:
            matches.append(False)
    if all(item is True for item in matches):
        return VerificationOutcome.SUCCESS
    if all(item is None for item in matches):
        return VerificationOutcome.UNKNOWN
    if any(item is None for item in matches):
        return VerificationOutcome.PARTIAL
    return VerificationOutcome.FAILURE


__all__ = [
    "ActionAdapterResult",
    "ActionErrorClass",
    "ActionObservation",
    "ApprovalAuthority",
    "CancellationSignal",
    "ControlledActionError",
    "ControlledActionExecutor",
    "ControlledActionPort",
    "FakeControlledActionAdapter",
    "StaticApprovalAuthority",
]
