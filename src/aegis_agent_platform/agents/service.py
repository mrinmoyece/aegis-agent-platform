"""Fenced durable coordinator supervisor for fixed specialist assignments."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol, cast
from uuid import UUID, uuid4

from aegis_agent_platform.agents.artifacts import (
    CoordinatorDecisionArtifact,
    CritiqueArtifact,
    DurableAgentArtifact,
    EvidenceCitation,
    FinalIncidentAssessmentArtifact,
    artifact_kind,
    artifact_to_payload,
)
from aegis_agent_platform.agents.coordination import (
    ArtifactPolicyError,
    InvestigationPlan,
    InvestigationState,
    SpecialistAssignment,
    TaskStatus,
    plan_to_payload,
    ready_assignments,
    replay_investigation,
    validate_artifact,
)
from aegis_agent_platform.agents.repository import (
    AgentRepository,
    InvestigationRequestResult,
)
from aegis_agent_platform.agents.telemetry import AgentMetrics, AgentTracer
from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EventEnvelope,
    JsonValue,
    MemoryContext,
    ModelGatewayError,
    WorkLease,
    WorkRequest,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.gateway import BudgetDeniedError
from aegis_agent_platform.tenancy import TenantContext


class CancellationSignal(Protocol):
    @property
    def cancelled(self) -> bool: ...


class SpecialistMemoryContextProvider(Protocol):
    async def context_for(
        self,
        *,
        tenant_id: str,
        run_id: UUID,
        assignment: SpecialistAssignment,
        upstream_artifacts: tuple[DurableAgentArtifact, ...],
        evidence: tuple[EvidenceCitation, ...],
        lease: WorkLease,
    ) -> MemoryContext | None: ...


@dataclass(frozen=True, slots=True)
class SpecialistContext:
    """Bounded redacted input assembled only from committed upstream artifacts."""

    tenant_id: str
    incident_id: str
    run_id: UUID
    assignment: SpecialistAssignment
    upstream_artifacts: tuple[DurableAgentArtifact, ...]
    evidence: tuple[EvidenceCitation, ...]
    attempt: int = 1
    memory_context: MemoryContext | None = None


@dataclass(frozen=True, slots=True)
class SpecialistResult:
    artifacts: Sequence[DurableAgentArtifact]
    used_tokens: int
    used_cost_usd: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        artifacts = tuple(self.artifacts)
        if not artifacts:
            raise ValueError("specialist result requires at least one artifact")
        if self.used_tokens < 0:
            raise ValueError("specialist token usage cannot be negative")
        if self.used_cost_usd < 0:
            raise ValueError("specialist cost usage cannot be negative")
        object.__setattr__(self, "artifacts", artifacts)


class SpecialistEngine(Protocol):
    """Provider-neutral execution boundary; implementations cannot mutate state."""

    async def execute(
        self,
        context: SpecialistContext,
        lease: WorkLease,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> SpecialistResult: ...

    def estimate_cost(self, context: SpecialistContext) -> Decimal: ...


@dataclass(frozen=True, slots=True)
class _ScheduledAssignment:
    assignment: SpecialistAssignment
    reserved_cost_usd: Decimal = Decimal("0")


@dataclass(frozen=True, slots=True)
class _ExecutionOutcome:
    assignment: SpecialistAssignment
    result: SpecialistResult | None
    event_type: DomainEventType
    reserved_cost_usd: Decimal = Decimal("0")
    error_code: str | None = None
    budget_exhausted: bool = False


class DurableCoordinator:
    """One supervisor boundary; all authoritative state remains in events."""

    def __init__(
        self,
        repository: AgentRepository,
        engine: SpecialistEngine,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
        metrics: AgentMetrics | None = None,
        tracer: AgentTracer | None = None,
        memory_context_provider: SpecialistMemoryContextProvider | None = None,
    ) -> None:
        self._repository = repository
        self._engine = engine
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._metrics = metrics or AgentMetrics()
        self._tracer = tracer or AgentTracer()
        self._memory_context_provider = memory_context_provider

    async def request(
        self,
        context: TenantContext,
        plan: InvestigationPlan,
        *,
        actor_id: str,
        idempotency_key: str,
    ) -> InvestigationRequestResult:
        if str(context.tenant_id) != plan.tenant_id:
            raise PermissionError("cross_tenant_investigation_request")
        if not actor_id or not idempotency_key:
            raise ValueError("actor and idempotency key are required")
        request = WorkRequest(
            work_id=plan.run_id,
            tenant_id=plan.tenant_id,
            work_kind="investigation.coordinate.v1",
            idempotency_key=idempotency_key,
            correlation_id=plan.run_id,
            requested_at=plan.created_at,
            payload={
                "incident_id": plan.incident_id,
                "plan_id": str(plan.plan_id),
                "plan_digest": plan.digest,
                "schema_version": plan.schema_version,
            },
            max_attempts=5,
            timeout_seconds=3_600,
        )
        plan_event = EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=plan.tenant_id,
            aggregate_id=str(plan.run_id),
            event_type=DomainEventType.INVESTIGATION_PLAN_RECORDED,
            schema_version=1,
            occurred_at=plan.created_at,
            payload={"plan": plan_to_payload(plan), "plan_digest": plan.digest},
            correlation_id=plan.run_id,
            actor=ActorReference(actor_id, ActorKind.USER),
            idempotency_key=f"{idempotency_key}:plan",
        )
        result = await self._repository.request(
            context,
            request,
            (plan_event,),
            requested_event_id=self._uuid_factory(),
            outbox_message_id=self._uuid_factory(),
        )
        if result.created:
            self._metrics.add("investigations_requested")
        return result

    async def execute(
        self,
        context: TenantContext,
        run_id: UUID,
        lease: WorkLease,
        evidence: Mapping[str, EvidenceCitation],
        *,
        cancellation: CancellationSignal | None = None,
    ) -> InvestigationState:
        state = await self._state(context, run_id)
        if state.terminal:
            return state
        maximum_rounds = len(state.plan.assignments) * 4 + 4
        for _round in range(maximum_rounds):
            if cancellation is not None and cancellation.cancelled:
                await self._append(
                    context,
                    state,
                    lease,
                    self._cancellation_events(state, lease),
                )
                return await self._state(context, run_id)
            ready = ready_assignments(state)
            if not ready:
                return await self._finish_or_fail(context, state, lease)
            batch, budget_reason = self._bounded_batch(state, ready, evidence)
            if not batch:
                await self._append(
                    context,
                    state,
                    lease,
                    (
                        self._event(
                            state.plan,
                            lease,
                            DomainEventType.INVESTIGATION_BUDGET_EXHAUSTED,
                            {
                                "reason": (
                                    budget_reason or "global_runtime_budget_exhausted"
                                )
                            },
                            suffix=f"budget:{state.version}",
                        ),
                    ),
                )
                return await self._state(context, run_id)
            intents: list[EventEnvelope] = []
            for scheduled in batch:
                assignment = scheduled.assignment
                attempt = state.tasks[assignment.assignment_id].attempts + 1
                self._metrics.add("tasks_dispatched", role=assignment.role)
                if attempt > 1:
                    self._metrics.add("task_retries", role=assignment.role)
                intents.extend(
                    (
                        self._event(
                            state.plan,
                            lease,
                            DomainEventType.SPECIALIST_TASK_DISPATCH_REQUESTED,
                            {
                                "assignment_id": str(assignment.assignment_id),
                                "role": assignment.role.value,
                                "attempt": attempt,
                                "reserved_tokens": (
                                    assignment.budget.token_reservation
                                ),
                                "reserved_cost_usd": str(scheduled.reserved_cost_usd),
                            },
                            suffix=f"dispatch:{assignment.assignment_id}:{attempt}",
                        ),
                        self._event(
                            state.plan,
                            lease,
                            DomainEventType.SPECIALIST_TASK_STARTED,
                            {
                                "assignment_id": str(assignment.assignment_id),
                                "attempt": attempt,
                            },
                            suffix=f"started:{assignment.assignment_id}:{attempt}",
                        ),
                    )
                )
            await self._append(context, state, lease, tuple(intents))
            state = await self._state(context, run_id)
            outcomes = await asyncio.gather(
                *(
                    self._execute_one(
                        state,
                        scheduled,
                        lease,
                        evidence,
                        cancellation=cancellation,
                    )
                    for scheduled in batch
                )
            )
            events: list[EventEnvelope] = []
            budget_exhausted = False
            for outcome in sorted(
                outcomes,
                key=lambda item: (
                    item.assignment.ordinal,
                    str(item.assignment.assignment_id),
                ),
            ):
                if outcome.result is not None:
                    for artifact in sorted(
                        outcome.result.artifacts,
                        key=lambda item: (
                            artifact_kind(item).value,
                            str(item.artifact_id),
                        ),
                    ):
                        events.append(
                            self._event(
                                state.plan,
                                lease,
                                DomainEventType.REASONING_ARTIFACT_RECORDED,
                                {
                                    "assignment_id": str(
                                        outcome.assignment.assignment_id
                                    ),
                                    "artifact": artifact_to_payload(artifact),
                                },
                                suffix=f"artifact:{artifact.artifact_id}",
                            )
                        )
                        self._metrics.add(
                            "artifacts_recorded",
                            role=outcome.assignment.role,
                        )
                        if (
                            isinstance(artifact, CritiqueArtifact)
                            and not artifact.accepted
                        ):
                            self._metrics.add(
                                "critic_rejections",
                                role=outcome.assignment.role,
                            )
                        if isinstance(artifact, CoordinatorDecisionArtifact):
                            events.append(
                                self._event(
                                    state.plan,
                                    lease,
                                    DomainEventType.COORDINATOR_DECISION_RECORDED,
                                    {
                                        "assignment_id": str(
                                            outcome.assignment.assignment_id
                                        ),
                                        "artifact_id": str(artifact.artifact_id),
                                        "outcome": artifact.outcome.value,
                                    },
                                    suffix=f"decision:{artifact.artifact_id}",
                                )
                            )
                used_tokens = (
                    outcome.result.used_tokens if outcome.result is not None else 0
                )
                details: dict[str, JsonValue] = {
                    "assignment_id": str(outcome.assignment.assignment_id),
                    "used_tokens": used_tokens,
                    "reserved_tokens": (outcome.assignment.budget.token_reservation),
                    "used_cost_usd": (
                        str(outcome.result.used_cost_usd)
                        if outcome.result is not None
                        else "0"
                    ),
                    "reserved_cost_usd": str(outcome.reserved_cost_usd),
                }
                if outcome.error_code is not None:
                    details["error_code"] = outcome.error_code
                events.append(
                    self._event(
                        state.plan,
                        lease,
                        outcome.event_type,
                        details,
                        suffix=(
                            f"outcome:{outcome.assignment.assignment_id}:"
                            f"{state.tasks[outcome.assignment.assignment_id].attempts}"
                        ),
                    )
                )
                budget_exhausted = budget_exhausted or outcome.budget_exhausted
                metric = {
                    DomainEventType.SPECIALIST_TASK_SUCCEEDED: "tasks_succeeded",
                    DomainEventType.SPECIALIST_TASK_FAILED: "tasks_failed",
                    DomainEventType.SPECIALIST_TASK_TIMED_OUT: "tasks_timed_out",
                }.get(outcome.event_type)
                if metric is not None:
                    self._metrics.add(metric, role=outcome.assignment.role)
            await self._append(context, state, lease, tuple(events))
            state = await self._state(context, run_id)
            if budget_exhausted:
                self._metrics.add("budget_exhaustions")
                await self._append(
                    context,
                    state,
                    lease,
                    (
                        self._event(
                            state.plan,
                            lease,
                            DomainEventType.INVESTIGATION_BUDGET_EXHAUSTED,
                            {"reason": "model_gateway_budget_denied"},
                            suffix=f"budget:{state.version}",
                        ),
                    ),
                )
                return await self._state(context, run_id)
        raise RuntimeError("coordinator round bound exhausted")

    async def _execute_one(
        self,
        state: InvestigationState,
        scheduled: _ScheduledAssignment,
        lease: WorkLease,
        evidence: Mapping[str, EvidenceCitation],
        *,
        cancellation: CancellationSignal | None,
    ) -> _ExecutionOutcome:
        assignment = scheduled.assignment
        upstream_tasks = set(assignment.depends_on)
        upstream_artifacts = tuple(
            artifact
            for artifact in state.artifacts
            if artifact.task_id in upstream_tasks
        )
        cited_evidence = tuple(
            sorted(evidence.values(), key=lambda item: item.evidence_id)
        )
        try:
            memory_context = (
                await self._memory_context_provider.context_for(
                    tenant_id=state.plan.tenant_id,
                    run_id=state.plan.run_id,
                    assignment=assignment,
                    upstream_artifacts=upstream_artifacts,
                    evidence=cited_evidence,
                    lease=lease,
                )
                if self._memory_context_provider is not None
                else None
            )
            specialist_context = SpecialistContext(
                tenant_id=state.plan.tenant_id,
                incident_id=state.plan.incident_id,
                run_id=state.plan.run_id,
                assignment=assignment,
                upstream_artifacts=upstream_artifacts,
                evidence=cited_evidence,
                memory_context=memory_context,
            )
            with self._tracer.task(assignment.role):
                result = await asyncio.wait_for(
                    self._engine.execute(
                        specialist_context,
                        lease,
                        cancellation=cancellation,
                    ),
                    timeout=assignment.budget.timeout_seconds,
                )
            if result.used_tokens > assignment.budget.token_reservation:
                raise ArtifactPolicyError("specialist usage exceeded reservation")
            if result.used_cost_usd > scheduled.reserved_cost_usd:
                raise ArtifactPolicyError("specialist cost exceeded reservation")
            seen_kinds: set[object] = set()
            for artifact in result.artifacts:
                kind = artifact_kind(artifact)
                if kind in seen_kinds:
                    raise ArtifactPolicyError("duplicate artifact kind in task result")
                seen_kinds.add(kind)
                validate_artifact(
                    state,
                    assignment,
                    artifact,
                    evidence=evidence,
                )
            return _ExecutionOutcome(
                assignment,
                result,
                DomainEventType.SPECIALIST_TASK_SUCCEEDED,
                reserved_cost_usd=scheduled.reserved_cost_usd,
            )
        except TimeoutError:
            return _ExecutionOutcome(
                assignment,
                None,
                DomainEventType.SPECIALIST_TASK_TIMED_OUT,
                reserved_cost_usd=scheduled.reserved_cost_usd,
                error_code="specialist_timeout",
            )
        except BudgetDeniedError:
            return _ExecutionOutcome(
                assignment,
                None,
                DomainEventType.SPECIALIST_TASK_FAILED,
                reserved_cost_usd=scheduled.reserved_cost_usd,
                error_code="model_budget_denied",
                budget_exhausted=True,
            )
        except FencingError:
            raise
        except ModelGatewayError as error:
            return _ExecutionOutcome(
                assignment,
                None,
                DomainEventType.SPECIALIST_TASK_FAILED,
                reserved_cost_usd=scheduled.reserved_cost_usd,
                error_code=f"model_{error.error_class.value}",
            )
        except (ArtifactPolicyError, TypeError, ValueError):
            return _ExecutionOutcome(
                assignment,
                None,
                DomainEventType.SPECIALIST_TASK_FAILED,
                reserved_cost_usd=scheduled.reserved_cost_usd,
                error_code="invalid_specialist_output",
            )
        except Exception:
            return _ExecutionOutcome(
                assignment,
                None,
                DomainEventType.SPECIALIST_TASK_FAILED,
                reserved_cost_usd=scheduled.reserved_cost_usd,
                error_code="specialist_bug",
            )

    async def _finish_or_fail(
        self,
        context: TenantContext,
        state: InvestigationState,
        lease: WorkLease,
    ) -> InvestigationState:
        final = next(
            (
                artifact
                for artifact in reversed(state.artifacts)
                if isinstance(artifact, FinalIncidentAssessmentArtifact)
            ),
            None,
        )
        if final is not None:
            self._metrics.add("investigations_finalized")
            if final.outcome.value == "abstain":
                self._metrics.add("abstentions")
            await self._append(
                context,
                state,
                lease,
                (
                    self._event(
                        state.plan,
                        lease,
                        DomainEventType.INVESTIGATION_FINALIZED,
                        {
                            "artifact_id": str(final.artifact_id),
                            "outcome": final.outcome.value,
                            "reason": final.outcome.value,
                        },
                        suffix=f"finalized:{final.artifact_id}",
                    ),
                ),
            )
            return await self._state(context, state.plan.run_id)
        exhausted = any(
            task.status
            in {
                TaskStatus.DISPATCHED,
                TaskStatus.RUNNING,
                TaskStatus.FAILED,
                TaskStatus.TIMED_OUT,
                TaskStatus.CANCELLED,
            }
            and task.attempts
            >= next(
                assignment.budget.max_iterations
                for assignment in state.plan.assignments
                if assignment.assignment_id == identifier
            )
            for identifier, task in state.tasks.items()
        )
        if exhausted:
            await self._append(
                context,
                state,
                lease,
                (
                    self._event(
                        state.plan,
                        lease,
                        DomainEventType.RUN_FAILED,
                        {"reason": "specialist_attempts_exhausted"},
                        suffix=f"failed:{state.version}",
                    ),
                ),
            )
            return await self._state(context, state.plan.run_id)
        raise RuntimeError("investigation DAG has no runnable or terminal state")

    def _bounded_batch(
        self,
        state: InvestigationState,
        ready: Sequence[SpecialistAssignment],
        evidence: Mapping[str, EvidenceCitation],
    ) -> tuple[tuple[_ScheduledAssignment, ...], str | None]:
        remaining_tokens = (
            state.plan.max_total_tokens - state.used_tokens - state.reserved_tokens
        )
        remaining_cost = (
            state.plan.max_total_cost_usd
            - state.used_cost_usd
            - state.reserved_cost_usd
        )
        batch: list[_ScheduledAssignment] = []
        token_blocked = False
        cost_blocked = False
        for assignment in ready:
            if len(batch) >= state.plan.max_parallel:
                break
            reservation = assignment.budget.token_reservation
            estimated_cost = self._estimated_cost(state, assignment, evidence)
            if reservation > remaining_tokens:
                token_blocked = True
                continue
            if estimated_cost > remaining_cost:
                cost_blocked = True
                continue
            batch.append(_ScheduledAssignment(assignment, estimated_cost))
            remaining_tokens -= reservation
            remaining_cost -= estimated_cost
        if batch:
            return tuple(batch), None
        if cost_blocked and not token_blocked:
            return (), "global_cost_budget_exhausted"
        if token_blocked and not cost_blocked:
            return (), "global_token_budget_exhausted"
        return (), "global_runtime_budget_exhausted"

    def _estimated_cost(
        self,
        state: InvestigationState,
        assignment: SpecialistAssignment,
        evidence: Mapping[str, EvidenceCitation],
    ) -> Decimal:
        estimator = getattr(self._engine, "estimate_cost", None)
        if not callable(estimator):
            return Decimal("0")
        estimate_cost = cast("Callable[[SpecialistContext], Decimal]", estimator)
        context = self._specialist_context(
            state,
            assignment,
            evidence,
            attempt=state.tasks[assignment.assignment_id].attempts + 1,
        )
        try:
            return estimate_cost(context)
        except Exception:
            return Decimal("0")

    def _specialist_context(
        self,
        state: InvestigationState,
        assignment: SpecialistAssignment,
        evidence: Mapping[str, EvidenceCitation],
        *,
        attempt: int,
    ) -> SpecialistContext:
        upstream_tasks = set(assignment.depends_on)
        upstream_artifacts = tuple(
            artifact
            for artifact in state.artifacts
            if artifact.task_id in upstream_tasks
        )
        return SpecialistContext(
            tenant_id=state.plan.tenant_id,
            incident_id=state.plan.incident_id,
            run_id=state.plan.run_id,
            assignment=assignment,
            upstream_artifacts=upstream_artifacts,
            evidence=tuple(
                sorted(evidence.values(), key=lambda item: item.evidence_id)
            ),
            attempt=attempt,
        )

    def _cancellation_events(
        self,
        state: InvestigationState,
        lease: WorkLease,
    ) -> tuple[EventEnvelope, ...]:
        events = [
            self._event(
                state.plan,
                lease,
                DomainEventType.SPECIALIST_TASK_CANCELLED,
                {
                    "assignment_id": str(identifier),
                    "used_tokens": 0,
                    "reserved_tokens": task.reserved_tokens,
                    "used_cost_usd": "0",
                    "reserved_cost_usd": str(task.reserved_cost_usd),
                    "error_code": "operator_or_deadline_cancellation",
                },
                suffix=f"cancel-task:{identifier}:{task.attempts}",
            )
            for identifier, task in state.tasks.items()
            if task.status in {TaskStatus.DISPATCHED, TaskStatus.RUNNING}
        ]
        events.append(
            self._event(
                state.plan,
                lease,
                DomainEventType.INVESTIGATION_CANCEL_REQUESTED,
                {"reason": "operator_or_deadline_cancellation"},
                suffix=f"cancel:{state.version}",
            )
        )
        return tuple(events)

    async def _state(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> InvestigationState:
        events = await self._repository.load(context, run_id)
        return replay_investigation(events)

    async def _append(
        self,
        context: TenantContext,
        state: InvestigationState,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
    ) -> None:
        await self._repository.append_fenced(
            context,
            state.plan.run_id,
            lease,
            events,
        )

    def _event(
        self,
        plan: InvestigationPlan,
        lease: WorkLease,
        event_type: DomainEventType,
        details: Mapping[str, JsonValue],
        *,
        suffix: str,
    ) -> EventEnvelope:
        now = self._clock()
        payload = dict(details)
        payload.update(
            {
                "work_id": str(lease.work_id),
                "lease_token": str(lease.token),
                "lease_generation": lease.generation,
            }
        )
        return EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=plan.tenant_id,
            aggregate_id=str(plan.run_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=now,
            payload=payload,
            correlation_id=plan.run_id,
            idempotency_key=f"investigation:{plan.run_id}:{suffix}",
        )


__all__ = [
    "CancellationSignal",
    "DurableCoordinator",
    "SpecialistContext",
    "SpecialistEngine",
    "SpecialistResult",
]
