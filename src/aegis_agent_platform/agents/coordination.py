"""Pure deterministic specialist DAG, capability, and replay contracts."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol, cast
from uuid import UUID

from aegis_agent_platform.agents.artifacts import (
    AgentArtifact,
    AgentRole,
    ArtifactKind,
    CoordinatorDecisionArtifact,
    CoordinatorOutcome,
    CritiqueArtifact,
    DurableAgentArtifact,
    EvidenceCitation,
    FinalIncidentAssessmentArtifact,
    HypothesisArtifact,
    artifact_from_payload,
    artifact_kind,
)
from aegis_agent_platform.domain import DomainEventType, EventEnvelope, JsonValue

MAX_DAG_TASKS = 32
MAX_DAG_DEPTH = 8
MAX_DAG_FAN_OUT = 8
MAX_PARALLEL_TASKS = 8


class TaskStatus(StrEnum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class InvestigationStatus(StrEnum):
    REQUESTED = "requested"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    ABSTAINED = "abstained"
    ESCALATED = "escalated"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"


TERMINAL_INVESTIGATION_STATUSES = frozenset(
    {
        InvestigationStatus.SUCCEEDED,
        InvestigationStatus.ABSTAINED,
        InvestigationStatus.ESCALATED,
        InvestigationStatus.FAILED,
        InvestigationStatus.CANCELLED,
        InvestigationStatus.BUDGET_EXHAUSTED,
    }
)


@dataclass(frozen=True, slots=True)
class RolePolicy:
    capabilities: frozenset[str]
    artifact_kinds: frozenset[ArtifactKind]
    read_only: bool


ROLE_POLICIES: Mapping[AgentRole, RolePolicy] = MappingProxyType(
    {
        AgentRole.INCIDENT_COORDINATOR: RolePolicy(
            frozenset({"artifact:read", "plan:coordinate", "decision:write"}),
            frozenset(
                {
                    ArtifactKind.HYPOTHESIS,
                    ArtifactKind.ALTERNATIVE_HYPOTHESIS,
                    ArtifactKind.CAUSAL_GRAPH_REFERENCE,
                    ArtifactKind.TIMELINE_REFERENCE,
                    ArtifactKind.COORDINATOR_DECISION,
                    ArtifactKind.FINAL_INCIDENT_ASSESSMENT,
                }
            ),
            True,
        ),
        AgentRole.TELEMETRY_INVESTIGATOR: RolePolicy(
            frozenset({"evidence:telemetry:read"}),
            frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
            True,
        ),
        AgentRole.CHANGE_INVESTIGATOR: RolePolicy(
            frozenset({"evidence:change:read", "github:read"}),
            frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
            True,
        ),
        AgentRole.RUNTIME_INVESTIGATOR: RolePolicy(
            frozenset({"evidence:runtime:read"}),
            frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
            True,
        ),
        AgentRole.KNOWLEDGE_INVESTIGATOR: RolePolicy(
            frozenset({"evidence:knowledge:read"}),
            frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
            True,
        ),
        AgentRole.CRITIC_REVIEWER: RolePolicy(
            frozenset({"artifact:read", "critique:write"}),
            frozenset({ArtifactKind.CONTRADICTION, ArtifactKind.CRITIQUE}),
            True,
        ),
        AgentRole.REMEDIATION_PLANNER: RolePolicy(
            frozenset({"artifact:read", "remediation:propose"}),
            frozenset({ArtifactKind.REMEDIATION_RECOMMENDATION}),
            True,
        ),
        AgentRole.VERIFICATION_AGENT: RolePolicy(
            frozenset(
                {
                    "artifact:read",
                    "evidence:telemetry:read",
                    "verification:plan",
                }
            ),
            frozenset({ArtifactKind.VERIFICATION_PLAN}),
            True,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class SpecialistBudget:
    """Hard execution limits assigned by the incident coordinator."""

    max_steps: int
    max_input_tokens: int
    timeout_seconds: int
    max_output_tokens: int = 1_024
    max_artifact_bytes: int = 32_768
    max_iterations: int = 2

    def __post_init__(self) -> None:
        if not 1 <= self.max_steps <= 64:
            raise ValueError("max_steps must be between 1 and 64")
        if not 1 <= self.max_input_tokens <= 1_000_000:
            raise ValueError("max_input_tokens must be between 1 and 1000000")
        if not 1 <= self.max_output_tokens <= 64_000:
            raise ValueError("max_output_tokens must be between 1 and 64000")
        if not 1 <= self.timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be between 1 and 600")
        if not 1_024 <= self.max_artifact_bytes <= 262_144:
            raise ValueError("max_artifact_bytes must be between 1024 and 262144")
        if not 1 <= self.max_iterations <= 4:
            raise ValueError("max_iterations must be between 1 and 4")

    @property
    def token_reservation(self) -> int:
        return self.max_input_tokens + self.max_output_tokens


@dataclass(frozen=True, slots=True)
class SpecialistAssignment:
    """One coordinator-declared node with fixed role, outputs, and authority."""

    assignment_id: UUID
    role: AgentRole
    depends_on: tuple[UUID, ...]
    capabilities: frozenset[str]
    budget: SpecialistBudget
    read_only: bool
    output_kinds: tuple[ArtifactKind, ...] = ()
    ordinal: int = 0

    def __post_init__(self) -> None:
        if self.assignment_id.int == 0 or self.ordinal < 0:
            raise ValueError("assignment identifier and ordinal are invalid")
        dependencies = tuple(sorted(set(self.depends_on), key=str))
        if self.assignment_id in dependencies:
            raise ValueError("assignment cannot depend on itself")
        policy = ROLE_POLICIES.get(self.role)
        if policy is None:
            raise ValueError("assignment role is not governed")
        if not self.capabilities or not self.capabilities <= policy.capabilities:
            raise PermissionError("assignment requests a denied capability")
        if self.read_only is not policy.read_only:
            raise PermissionError("specialist read/write authority is fixed by role")
        outputs = tuple(dict.fromkeys(self.output_kinds))
        if outputs and not set(outputs) <= policy.artifact_kinds:
            raise PermissionError("assignment requests a denied artifact transition")
        object.__setattr__(self, "depends_on", dependencies)
        object.__setattr__(self, "output_kinds", outputs)


@dataclass(frozen=True, slots=True)
class InvestigationPlan:
    """Coordinator-owned immutable DAG and aggregate safety limits."""

    plan_id: UUID
    tenant_id: str
    incident_id: str
    run_id: UUID
    assignments: tuple[SpecialistAssignment, ...]
    created_at: datetime
    max_depth: int = 6
    max_fan_out: int = 6
    max_parallel: int = 4
    max_total_tokens: int = 100_000
    max_total_cost_usd: Decimal = Decimal("20")
    finalization_confidence: float = 0.7
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            self.plan_id.int == 0
            or self.run_id.int == 0
            or not self.tenant_id
            or not self.incident_id
        ):
            raise ValueError("plan identity and linkage are required")
        if self.created_at.tzinfo is None:
            raise ValueError("plan time must be timezone-aware")
        if self.schema_version < 1:
            raise ValueError("plan schema version must be positive")
        if not 1 <= self.max_depth <= MAX_DAG_DEPTH:
            raise ValueError("plan depth exceeds the runtime bound")
        if not 1 <= self.max_fan_out <= MAX_DAG_FAN_OUT:
            raise ValueError("plan fan-out exceeds the runtime bound")
        if not 1 <= self.max_parallel <= MAX_PARALLEL_TASKS:
            raise ValueError("plan parallelism exceeds the runtime bound")
        if self.max_total_tokens < 1 or self.max_total_cost_usd < 0:
            raise ValueError("global budget must be positive")
        if not 0.0 <= self.finalization_confidence <= 1.0:
            raise ValueError("finalization confidence must be between 0 and 1")
        assignments = tuple(
            sorted(
                self.assignments,
                key=lambda item: (item.ordinal, str(item.assignment_id)),
            )
        )
        _validate_dag(
            assignments,
            max_depth=self.max_depth,
            max_fan_out=self.max_fan_out,
        )
        object.__setattr__(self, "assignments", assignments)

    @property
    def digest(self) -> str:
        value = json.dumps(plan_to_payload(self), sort_keys=True, separators=(",", ":"))
        return sha256(value.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class TaskState:
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    reserved_tokens: int = 0
    used_tokens: int = 0
    artifact_ids: tuple[UUID, ...] = ()
    last_error_code: str | None = None


@dataclass(frozen=True, slots=True)
class InvestigationState:
    """Authoritative state reconstructed only by folding ledger events."""

    plan: InvestigationPlan
    status: InvestigationStatus
    tasks: Mapping[UUID, TaskState]
    artifacts: tuple[DurableAgentArtifact, ...] = ()
    event_ids: frozenset[UUID] = frozenset()
    idempotency_keys: frozenset[str] = frozenset()
    version: int = 0
    used_tokens: int = 0
    reserved_tokens: int = 0
    final_artifact_id: UUID | None = None
    terminal_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tasks", MappingProxyType(dict(self.tasks)))

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_INVESTIGATION_STATUSES

    def artifacts_for(self, task_id: UUID) -> tuple[DurableAgentArtifact, ...]:
        return tuple(item for item in self.artifacts if item.task_id == task_id)


class ReplayCorruptionError(RuntimeError):
    """Ledger events violate an invariant required for deterministic replay."""


class ArtifactPolicyError(PermissionError):
    """A specialist output exceeds its fixed role, evidence, or transition policy."""


class ArtifactLedger(Protocol):
    """Compatibility port: specialists communicate only by durable artifacts."""

    async def record(self, artifact: AgentArtifact) -> None: ...

    async def read_incident(
        self, tenant_id: str, incident_id: str
    ) -> tuple[AgentArtifact, ...]: ...


def ready_assignments(state: InvestigationState) -> tuple[SpecialistAssignment, ...]:
    """Return deterministic runnable nodes, including bounded crash retries."""
    if state.terminal:
        return ()
    ready: list[SpecialistAssignment] = []
    for assignment in state.plan.assignments:
        task = state.tasks[assignment.assignment_id]
        retryable = (
            task.status
            in {
                TaskStatus.PENDING,
                TaskStatus.DISPATCHED,
                TaskStatus.RUNNING,
                TaskStatus.FAILED,
                TaskStatus.TIMED_OUT,
            }
            and task.attempts < assignment.budget.max_iterations
        )
        if not retryable:
            continue
        if all(
            state.tasks[dependency].status is TaskStatus.SUCCEEDED
            for dependency in assignment.depends_on
        ):
            ready.append(assignment)
    return tuple(ready)


def validate_artifact(
    state: InvestigationState,
    assignment: SpecialistAssignment,
    artifact: DurableAgentArtifact,
    *,
    evidence: Mapping[str, EvidenceCitation],
) -> None:
    """Enforce role, transition, provenance, citation, and finalization gates."""
    if (
        artifact.tenant_id != state.plan.tenant_id
        or artifact.incident_id != state.plan.incident_id
        or artifact.run_id != state.plan.run_id
        or artifact.task_id != assignment.assignment_id
        or artifact.produced_by is not assignment.role
    ):
        raise ArtifactPolicyError("artifact linkage does not match its assignment")
    kind = artifact_kind(artifact)
    policy = ROLE_POLICIES[assignment.role]
    if kind not in policy.artifact_kinds or (
        assignment.output_kinds and kind not in assignment.output_kinds
    ):
        raise ArtifactPolicyError("artifact transition is not allowed for role")
    if any(citation.evidence_id not in evidence for citation in artifact.citations):
        raise ArtifactPolicyError("artifact contains an unknown evidence citation")
    for citation in artifact.citations:
        if citation != evidence[citation.evidence_id]:
            raise ArtifactPolicyError("artifact citation provenance does not match")
    available_artifacts = {
        item.artifact_id: item
        for item in state.artifacts
        if _dependency_reachable(state.plan, assignment.assignment_id, item.task_id)
    }
    if any(
        identifier not in available_artifacts
        for identifier in artifact.provenance_artifact_ids
    ):
        raise ArtifactPolicyError("artifact cites an unavailable upstream artifact")
    encoded = json.dumps(
        cast(dict[str, object], artifact_to_plain_payload(artifact)),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(encoded) > assignment.budget.max_artifact_bytes:
        raise ArtifactPolicyError("artifact exceeds its assignment output limit")
    if isinstance(artifact, CoordinatorDecisionArtifact):
        _validate_decision_gate(state, artifact)
    if isinstance(artifact, FinalIncidentAssessmentArtifact):
        _validate_final_assessment(state, artifact)


def replay_investigation(events: Sequence[EventEnvelope]) -> InvestigationState:
    """Rebuild authoritative investigation state and reject corrupt history."""
    if not events:
        raise ReplayCorruptionError("investigation stream is empty")
    seen_events: set[UUID] = set()
    seen_keys: set[str] = set()
    plan: InvestigationPlan | None = None
    state: InvestigationState | None = None
    expected_sequence = 1
    for event in events:
        if event.event_id in seen_events:
            raise ReplayCorruptionError("duplicate event identifier")
        seen_events.add(event.event_id)
        if event.idempotency_key is not None:
            if event.idempotency_key in seen_keys:
                raise ReplayCorruptionError("duplicate durable idempotency key")
            seen_keys.add(event.idempotency_key)
        if event.aggregate_sequence:
            if event.aggregate_sequence != expected_sequence:
                raise ReplayCorruptionError("aggregate sequence is not gapless")
            expected_sequence += 1
        if event.event_type == DomainEventType.INVESTIGATION_PLAN_RECORDED:
            if plan is not None:
                raise ReplayCorruptionError("investigation plan was recorded twice")
            plan_value = event.payload.get("plan")
            if not isinstance(plan_value, Mapping):
                raise ReplayCorruptionError("plan event has no typed plan payload")
            try:
                plan = plan_from_payload(plan_value)
            except (KeyError, TypeError, ValueError) as error:
                raise ReplayCorruptionError("plan payload is invalid") from error
            if event.tenant_id != plan.tenant_id or event.aggregate_id != str(
                plan.run_id
            ):
                raise ReplayCorruptionError("plan event linkage is corrupt")
            state = InvestigationState(
                plan=plan,
                status=InvestigationStatus.REQUESTED,
                tasks={
                    assignment.assignment_id: TaskState()
                    for assignment in plan.assignments
                },
            )
        elif state is not None:
            state = _fold_event(state, event)
    if state is None:
        raise ReplayCorruptionError("investigation stream has no plan")
    return replace(
        state,
        event_ids=frozenset(seen_events),
        idempotency_keys=frozenset(seen_keys),
        version=len(events),
    )


def plan_to_payload(plan: InvestigationPlan) -> Mapping[str, JsonValue]:
    return {
        "plan_id": str(plan.plan_id),
        "tenant_id": plan.tenant_id,
        "incident_id": plan.incident_id,
        "run_id": str(plan.run_id),
        "created_at": plan.created_at.isoformat(),
        "max_depth": plan.max_depth,
        "max_fan_out": plan.max_fan_out,
        "max_parallel": plan.max_parallel,
        "max_total_tokens": plan.max_total_tokens,
        "max_total_cost_usd": str(plan.max_total_cost_usd),
        "finalization_confidence": plan.finalization_confidence,
        "schema_version": plan.schema_version,
        "assignments": tuple(
            {
                "assignment_id": str(item.assignment_id),
                "role": item.role.value,
                "depends_on": tuple(str(value) for value in item.depends_on),
                "capabilities": tuple(sorted(item.capabilities)),
                "read_only": item.read_only,
                "output_kinds": tuple(value.value for value in item.output_kinds),
                "ordinal": item.ordinal,
                "budget": {
                    "max_steps": item.budget.max_steps,
                    "max_input_tokens": item.budget.max_input_tokens,
                    "max_output_tokens": item.budget.max_output_tokens,
                    "timeout_seconds": item.budget.timeout_seconds,
                    "max_artifact_bytes": item.budget.max_artifact_bytes,
                    "max_iterations": item.budget.max_iterations,
                },
            }
            for item in plan.assignments
        ),
    }


def plan_from_payload(value: Mapping[str, JsonValue]) -> InvestigationPlan:
    assignments_value = value["assignments"]
    if not isinstance(assignments_value, Sequence) or isinstance(
        assignments_value, str
    ):
        raise ValueError("plan assignments must be a sequence")
    assignments: list[SpecialistAssignment] = []
    for raw in assignments_value:
        if not isinstance(raw, Mapping):
            raise ValueError("assignment must be an object")
        budget_value = raw["budget"]
        if not isinstance(budget_value, Mapping):
            raise ValueError("assignment budget must be an object")
        assignments.append(
            SpecialistAssignment(
                assignment_id=UUID(str(raw["assignment_id"])),
                role=AgentRole(str(raw["role"])),
                depends_on=tuple(
                    UUID(str(item)) for item in _sequence(raw["depends_on"])
                ),
                capabilities=frozenset(
                    str(item) for item in _sequence(raw["capabilities"])
                ),
                budget=SpecialistBudget(
                    max_steps=int(str(budget_value["max_steps"])),
                    max_input_tokens=int(str(budget_value["max_input_tokens"])),
                    max_output_tokens=int(str(budget_value["max_output_tokens"])),
                    timeout_seconds=int(str(budget_value["timeout_seconds"])),
                    max_artifact_bytes=int(str(budget_value["max_artifact_bytes"])),
                    max_iterations=int(str(budget_value["max_iterations"])),
                ),
                read_only=bool(raw["read_only"]),
                output_kinds=tuple(
                    ArtifactKind(str(item)) for item in _sequence(raw["output_kinds"])
                ),
                ordinal=int(str(raw["ordinal"])),
            )
        )
    return InvestigationPlan(
        plan_id=UUID(str(value["plan_id"])),
        tenant_id=str(value["tenant_id"]),
        incident_id=str(value["incident_id"]),
        run_id=UUID(str(value["run_id"])),
        assignments=tuple(assignments),
        created_at=datetime.fromisoformat(str(value["created_at"])),
        max_depth=int(str(value["max_depth"])),
        max_fan_out=int(str(value["max_fan_out"])),
        max_parallel=int(str(value["max_parallel"])),
        max_total_tokens=int(str(value["max_total_tokens"])),
        max_total_cost_usd=Decimal(str(value["max_total_cost_usd"])),
        finalization_confidence=float(str(value["finalization_confidence"])),
        schema_version=int(str(value["schema_version"])),
    )


def artifact_to_plain_payload(
    artifact: DurableAgentArtifact,
) -> Mapping[str, JsonValue]:
    from aegis_agent_platform.agents.artifacts import artifact_to_payload

    return artifact_to_payload(artifact)


def _fold_event(
    state: InvestigationState,
    event: EventEnvelope,
) -> InvestigationState:
    if event.tenant_id != state.plan.tenant_id or event.aggregate_id != str(
        state.plan.run_id
    ):
        raise ReplayCorruptionError("cross-tenant or cross-run event in stream")
    try:
        event_type = DomainEventType(event.event_type)
    except ValueError:
        return state
    if event_type == DomainEventType.SPECIALIST_TASK_DISPATCH_REQUESTED:
        assignment_id = _assignment_id(event)
        task = state.tasks[assignment_id]
        assignment = _assignment(state.plan, assignment_id)
        if task.status not in {
            TaskStatus.PENDING,
            TaskStatus.DISPATCHED,
            TaskStatus.RUNNING,
            TaskStatus.FAILED,
            TaskStatus.TIMED_OUT,
        }:
            raise ReplayCorruptionError("task dispatch from invalid state")
        if task.attempts >= assignment.budget.max_iterations:
            raise ReplayCorruptionError("task iteration bound exceeded")
        if not all(
            state.tasks[dependency].status is TaskStatus.SUCCEEDED
            for dependency in assignment.depends_on
        ):
            raise ReplayCorruptionError("task dispatched before dependencies completed")
        reservation = int(str(event.payload.get("reserved_tokens", 0)))
        if reservation != assignment.budget.token_reservation:
            raise ReplayCorruptionError("task reservation does not match plan")
        tasks = dict(state.tasks)
        tasks[assignment_id] = replace(
            task,
            status=TaskStatus.DISPATCHED,
            attempts=task.attempts + 1,
            reserved_tokens=reservation,
            last_error_code=None,
        )
        reserved = state.reserved_tokens + reservation
        if state.used_tokens + reserved > state.plan.max_total_tokens:
            raise ReplayCorruptionError("dispatch exceeded the global token budget")
        return replace(
            state,
            status=InvestigationStatus.RUNNING,
            tasks=tasks,
            reserved_tokens=reserved,
        )
    if event_type == DomainEventType.SPECIALIST_TASK_STARTED:
        assignment_id = _assignment_id(event)
        task = state.tasks[assignment_id]
        if task.status is not TaskStatus.DISPATCHED:
            raise ReplayCorruptionError("task start without durable dispatch intent")
        tasks = dict(state.tasks)
        tasks[assignment_id] = replace(task, status=TaskStatus.RUNNING)
        return replace(state, tasks=tasks)
    if event_type == DomainEventType.REASONING_ARTIFACT_RECORDED:
        artifact_value = event.payload.get("artifact")
        if not isinstance(artifact_value, Mapping):
            raise ReplayCorruptionError("artifact event has no typed payload")
        try:
            artifact = artifact_from_payload(artifact_value)
        except (KeyError, TypeError, ValueError) as error:
            raise ReplayCorruptionError("artifact payload is invalid") from error
        assignment = _assignment(state.plan, artifact.task_id)
        task = state.tasks[assignment.assignment_id]
        if task.status not in {TaskStatus.DISPATCHED, TaskStatus.RUNNING}:
            raise ReplayCorruptionError("artifact recorded outside task execution")
        if (
            artifact.tenant_id != state.plan.tenant_id
            or artifact.incident_id != state.plan.incident_id
            or artifact.run_id != state.plan.run_id
            or artifact.produced_by is not assignment.role
        ):
            raise ReplayCorruptionError("artifact linkage is corrupt")
        kind = artifact_kind(artifact)
        if kind not in ROLE_POLICIES[assignment.role].artifact_kinds or (
            assignment.output_kinds and kind not in assignment.output_kinds
        ):
            raise ReplayCorruptionError("artifact transition violates role policy")
        existing = {item.artifact_id for item in state.artifacts}
        if artifact.artifact_id in existing:
            raise ReplayCorruptionError("artifact identifier was reused")
        available = {
            item.artifact_id
            for item in state.artifacts
            if _dependency_reachable(
                state.plan,
                assignment.assignment_id,
                item.task_id,
            )
        }
        if not set(artifact.provenance_artifact_ids) <= available:
            raise ReplayCorruptionError("artifact provenance is not dependency-bound")
        if isinstance(artifact, CoordinatorDecisionArtifact):
            _validate_decision_gate(state, artifact)
        if isinstance(artifact, FinalIncidentAssessmentArtifact):
            _validate_final_assessment(state, artifact)
        tasks = dict(state.tasks)
        tasks[assignment.assignment_id] = replace(
            task,
            artifact_ids=(*task.artifact_ids, artifact.artifact_id),
        )
        return replace(state, tasks=tasks, artifacts=(*state.artifacts, artifact))
    if event_type in {
        DomainEventType.SPECIALIST_TASK_SUCCEEDED,
        DomainEventType.SPECIALIST_TASK_FAILED,
        DomainEventType.SPECIALIST_TASK_TIMED_OUT,
        DomainEventType.SPECIALIST_TASK_CANCELLED,
    }:
        assignment_id = _assignment_id(event)
        task = state.tasks[assignment_id]
        if task.status not in {TaskStatus.DISPATCHED, TaskStatus.RUNNING}:
            raise ReplayCorruptionError("task terminal event from invalid state")
        used_tokens = int(str(event.payload.get("used_tokens", 0)))
        if not 0 <= used_tokens <= task.reserved_tokens:
            raise ReplayCorruptionError("task usage exceeds its reservation")
        task_status = {
            DomainEventType.SPECIALIST_TASK_SUCCEEDED: TaskStatus.SUCCEEDED,
            DomainEventType.SPECIALIST_TASK_FAILED: TaskStatus.FAILED,
            DomainEventType.SPECIALIST_TASK_TIMED_OUT: TaskStatus.TIMED_OUT,
            DomainEventType.SPECIALIST_TASK_CANCELLED: TaskStatus.CANCELLED,
        }[event_type]
        tasks = dict(state.tasks)
        tasks[assignment_id] = replace(
            task,
            status=task_status,
            reserved_tokens=0,
            used_tokens=task.used_tokens + used_tokens,
            last_error_code=(
                str(event.payload["error_code"])
                if event.payload.get("error_code") is not None
                else None
            ),
        )
        return replace(
            state,
            tasks=tasks,
            used_tokens=state.used_tokens + used_tokens,
            reserved_tokens=state.reserved_tokens - task.reserved_tokens,
        )
    if event_type == DomainEventType.INVESTIGATION_BUDGET_EXHAUSTED:
        return replace(
            state,
            status=InvestigationStatus.BUDGET_EXHAUSTED,
            terminal_reason="budget_exhausted",
        )
    if event_type == DomainEventType.INVESTIGATION_CANCEL_REQUESTED:
        return replace(
            state,
            status=InvestigationStatus.CANCELLED,
            terminal_reason="cancelled",
        )
    if event_type == DomainEventType.INVESTIGATION_FINALIZED:
        outcome = CoordinatorOutcome(str(event.payload["outcome"]))
        investigation_status = {
            CoordinatorOutcome.FINALIZE: InvestigationStatus.SUCCEEDED,
            CoordinatorOutcome.ABSTAIN: InvestigationStatus.ABSTAINED,
            CoordinatorOutcome.ESCALATE: InvestigationStatus.ESCALATED,
        }[outcome]
        return replace(
            state,
            status=investigation_status,
            final_artifact_id=UUID(str(event.payload["artifact_id"])),
            terminal_reason=str(event.payload.get("reason", outcome.value)),
        )
    if event_type == DomainEventType.RUN_FAILED:
        return replace(
            state,
            status=InvestigationStatus.FAILED,
            terminal_reason=str(event.payload.get("reason", "run_failed")),
        )
    return state


def _validate_decision_gate(
    state: InvestigationState,
    artifact: CoordinatorDecisionArtifact,
) -> None:
    if artifact.outcome is not CoordinatorOutcome.FINALIZE:
        return
    hypotheses = {
        item.artifact_id: item
        for item in state.artifacts
        if isinstance(item, HypothesisArtifact)
    }
    selected = (
        hypotheses.get(artifact.selected_hypothesis_id)
        if artifact.selected_hypothesis_id is not None
        else None
    )
    critiques = tuple(
        item for item in state.artifacts if isinstance(item, CritiqueArtifact)
    )
    if (
        selected is None
        or selected.confidence.score < state.plan.finalization_confidence
    ):
        raise ArtifactPolicyError("selected hypothesis is absent or below confidence")
    if not critiques or not all(
        item.accepted
        and not item.unsupported_claims
        and not item.unresolved_contradiction_ids
        for item in critiques
    ):
        raise ArtifactPolicyError("critic gate has not accepted the hypothesis")


def _validate_final_assessment(
    state: InvestigationState,
    artifact: FinalIncidentAssessmentArtifact,
) -> None:
    decisions = {
        item.artifact_id: item
        for item in state.artifacts
        if isinstance(item, CoordinatorDecisionArtifact)
    }
    decision = decisions.get(artifact.decision_id)
    if decision is None or decision.outcome is not artifact.outcome:
        raise ArtifactPolicyError("final assessment does not match a durable decision")


def _validate_dag(
    assignments: tuple[SpecialistAssignment, ...],
    *,
    max_depth: int,
    max_fan_out: int,
) -> None:
    if not assignments or len(assignments) > MAX_DAG_TASKS:
        raise ValueError("plan must contain between 1 and 32 assignments")
    identifiers = {item.assignment_id for item in assignments}
    if len(identifiers) != len(assignments):
        raise ValueError("duplicate assignment identifier")
    ordinals = [item.ordinal for item in assignments]
    if len(set(ordinals)) != len(ordinals):
        raise ValueError("assignment ordinals must be unique")
    for assignment in assignments:
        if not set(assignment.depends_on) <= identifiers:
            raise ValueError("assignment depends on an unknown node")
    fan_out = Counter(
        dependency for item in assignments for dependency in item.depends_on
    )
    if fan_out and max(fan_out.values()) > max_fan_out:
        raise ValueError("plan fan-out exceeds its declared bound")
    by_id = {item.assignment_id: item for item in assignments}
    visiting: set[UUID] = set()
    visited: set[UUID] = set()

    def depth(identifier: UUID) -> int:
        if identifier in visiting:
            raise ValueError("investigation plan contains a cycle")
        if identifier in visited:
            return depth_by_id[identifier]
        visiting.add(identifier)
        value = 1 + max(
            (depth(dependency) for dependency in by_id[identifier].depends_on),
            default=0,
        )
        visiting.remove(identifier)
        visited.add(identifier)
        depth_by_id[identifier] = value
        return value

    depth_by_id: dict[UUID, int] = {}
    if max(depth(identifier) for identifier in identifiers) > max_depth:
        raise ValueError("plan depth exceeds its declared bound")


def _dependency_reachable(
    plan: InvestigationPlan,
    assignment_id: UUID,
    candidate_id: UUID,
) -> bool:
    if assignment_id == candidate_id:
        return False
    by_id = {item.assignment_id: item for item in plan.assignments}
    pending = list(by_id[assignment_id].depends_on)
    while pending:
        current = pending.pop()
        if current == candidate_id:
            return True
        pending.extend(by_id[current].depends_on)
    return False


def _assignment(plan: InvestigationPlan, identifier: UUID) -> SpecialistAssignment:
    try:
        return next(
            item for item in plan.assignments if item.assignment_id == identifier
        )
    except StopIteration as error:
        raise ReplayCorruptionError("event references an unknown assignment") from error


def _assignment_id(event: EventEnvelope) -> UUID:
    try:
        return UUID(str(event.payload["assignment_id"]))
    except (KeyError, ValueError) as error:
        raise ReplayCorruptionError("task event has no valid assignment") from error


def _sequence(value: JsonValue) -> Sequence[JsonValue]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError("expected a JSON sequence")
    return value


__all__ = [
    "MAX_DAG_DEPTH",
    "MAX_DAG_FAN_OUT",
    "MAX_DAG_TASKS",
    "MAX_PARALLEL_TASKS",
    "ROLE_POLICIES",
    "ArtifactLedger",
    "ArtifactPolicyError",
    "InvestigationPlan",
    "InvestigationState",
    "InvestigationStatus",
    "ReplayCorruptionError",
    "RolePolicy",
    "SpecialistAssignment",
    "SpecialistBudget",
    "TaskState",
    "TaskStatus",
    "plan_from_payload",
    "plan_to_payload",
    "ready_assignments",
    "replay_investigation",
    "validate_artifact",
]
