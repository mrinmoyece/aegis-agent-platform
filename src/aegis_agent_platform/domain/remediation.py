"""Pure contracts and replay rules for approval-gated controlled actions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import cast
from uuid import UUID

from aegis_agent_platform.domain.events import (
    DomainEventType,
    EventEnvelope,
    JsonScalar,
    JsonValue,
    freeze_json_mapping,
    thaw_json,
)

MAX_ACTIONS_PER_PLAN = 16
MAX_CONDITIONS_PER_ACTION = 16
MAX_EVIDENCE_PER_PLAN = 64
MAX_RATIONALE_BYTES = 4_096
MAX_EVENT_REASON_BYTES = 1_024
_IDENTIFIER_REST = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"
)
_HEX_LOWER = frozenset("0123456789abcdef")


class RiskTier(IntEnum):
    """Ordered action risk used by deterministic policy gates."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class BlastRadius(IntEnum):
    """Ordered maximum scope an action may affect."""

    SINGLE_RESOURCE = 1
    NAMESPACE = 2
    SERVICE = 3
    ENVIRONMENT = 4
    TENANT = 5


class ActionKind(StrEnum):
    """Provider-neutral controlled actions implemented by Layer 8."""

    KUBERNETES_ROLLOUT_RESTART = "kubernetes.rollout_restart.v1"
    SANDBOX_CHANGE_PREPARATION = "sandbox.change_preparation.v1"


class ConditionOperator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    AT_LEAST = "at_least"
    AT_MOST = "at_most"
    EXISTS = "exists"


class ReconciliationStrategy(StrEnum):
    READ_AFTER_WRITE = "read_after_write"
    TARGET_FINGERPRINT = "target_fingerprint"


class PolicyOutcome(StrEnum):
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class EffectOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"
    AMBIGUOUS = "ambiguous"
    CANCELLED = "cancelled"


class ReconciliationOutcome(StrEnum):
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class VerificationOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ActionLifecycleStatus(StrEnum):
    PROPOSED = "proposed"
    POLICY_DENIED = "policy_denied"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DISPATCHED = "dispatched"
    PREFLIGHT = "preflight"
    DRY_RUN = "dry_run"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    RECONCILING = "reconciling"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"
    COMPENSATED = "compensated"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_PARTIAL = "verification_partial"
    VERIFICATION_UNKNOWN = "verification_unknown"


def _bounded_text(value: str, name: str, maximum: int) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty and normalized")
    if len(value.encode()) > maximum:
        raise ValueError(f"{name} exceeds {maximum} bytes")


def _identifier(value: str, name: str) -> None:
    if (
        not value
        or value[0] not in _IDENTIFIER_REST - frozenset("._:/-")
        or any(character not in _IDENTIFIER_REST for character in value)
        or len(value) > 256
    ):
        raise ValueError(f"{name} is not a safe normalized identifier")


def _digest(value: str, name: str) -> None:
    if len(value) != 64 or any(character not in _HEX_LOWER for character in value):
        raise ValueError(f"{name} must be a lowercase sha256 digest")


def _aware(value: datetime, name: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")


def _canonical_text(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '"')
        return f'"{escaped}"'
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, UUID):
        return f'"{value}"'
    if isinstance(value, datetime):
        return f'"{value.isoformat()}"'
    if isinstance(value, Mapping):
        items = sorted((str(key), _canonical_text(item)) for key, item in value.items())
        return (
            "{"
            + ",".join(f"{_canonical_text(key)}:{item}" for key, item in items)
            + "}"
        )
    if isinstance(value, Sequence) and not isinstance(value, str):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    raise ValueError(f"unsupported canonical value: {type(value).__name__}")


def _canonical_digest(value: Mapping[str, object]) -> str:
    text = _canonical_text(value)
    parts = [
        0x243F6A8885A308D3,
        0x13198A2E03707344,
        0xA4093822299F31D0,
        0x082EFA98EC4E6C89,
    ]
    for index, character in enumerate(text):
        code = ord(character) + index + 1
        for slot, multiplier in enumerate(
            (0x100000001B3, 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9)
        ):
            parts[slot] = (
                parts[slot] ^ (code + slot * 17)
            ) * multiplier & 0xFFFFFFFFFFFFFFFF
            parts[slot] ^= parts[(slot - 1) % 4] >> ((slot + 1) * 7)
    return "".join(f"{part:016x}" for part in parts)


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """Immutable citation to redacted evidence already stored by Layer 6."""

    evidence_id: str
    source_reference: str
    content_digest: str
    observed_at: datetime
    confidence: float

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence_id")
        if not self.source_reference.startswith("aegis-evidence://"):
            raise ValueError("evidence source must use aegis-evidence://")
        _digest(self.content_digest, "evidence content digest")
        _aware(self.observed_at, "evidence observation")
        if not 0 <= self.confidence <= 1:
            raise ValueError("evidence confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class ActionTarget:
    """Exact provider-neutral target identity.

    Mutable payload data cannot replace this trusted identity.
    """

    provider: str
    environment: str
    resource_type: str
    resource_id: str
    scope: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.provider, "provider"),
            (self.environment, "environment"),
            (self.resource_type, "resource_type"),
            (self.resource_id, "resource_id"),
            (self.scope, "scope"),
        ):
            _identifier(value, name)

    @property
    def fingerprint(self) -> str:
        return _canonical_digest(
            {
                "environment": self.environment,
                "provider": self.provider,
                "resource_id": self.resource_id,
                "resource_type": self.resource_type,
                "scope": self.scope,
            }
        )


@dataclass(frozen=True, slots=True)
class Condition:
    """Explicit precondition or postcondition evaluated against fresh evidence."""

    signal: str
    operator: ConditionOperator
    expected: JsonScalar
    evidence_id: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.signal, "condition signal")
        if self.operator is ConditionOperator.EXISTS and self.expected is not True:
            raise ValueError("exists conditions require expected=true")
        if self.evidence_id is not None:
            _identifier(self.evidence_id, "condition evidence_id")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 2
    initial_backoff_seconds: float = 1
    maximum_backoff_seconds: float = 30

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("action attempts must be between 1 and 5")
        if not 0 <= self.initial_backoff_seconds <= 60:
            raise ValueError("initial action backoff must be between 0 and 60")
        if not self.initial_backoff_seconds <= self.maximum_backoff_seconds <= 300:
            raise ValueError("maximum action backoff must be bounded")
        object.__setattr__(
            self,
            "initial_backoff_seconds",
            float(self.initial_backoff_seconds),
        )
        object.__setattr__(
            self,
            "maximum_backoff_seconds",
            float(self.maximum_backoff_seconds),
        )


@dataclass(frozen=True, slots=True)
class ReconciliationPolicy:
    strategy: ReconciliationStrategy = ReconciliationStrategy.READ_AFTER_WRITE
    max_attempts: int = 3
    interval_seconds: float = 1
    escalate_on_unknown: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("reconciliation attempts must be between 1 and 10")
        if not 0 <= self.interval_seconds <= 3_600:
            raise ValueError("reconciliation interval must be bounded")
        object.__setattr__(self, "interval_seconds", float(self.interval_seconds))


@dataclass(frozen=True, slots=True)
class MaintenanceWindow:
    starts_at: datetime
    ends_at: datetime

    def __post_init__(self) -> None:
        _aware(self.starts_at, "maintenance window start")
        _aware(self.ends_at, "maintenance window end")
        if self.ends_at <= self.starts_at:
            raise ValueError("maintenance window end must follow its start")
        if (self.ends_at - self.starts_at).total_seconds() > 86_400:
            raise ValueError("maintenance window cannot exceed 24 hours")

    def contains(self, at: datetime) -> bool:
        _aware(at, "policy evaluation time")
        return self.starts_at <= at < self.ends_at


@dataclass(frozen=True, slots=True)
class ApprovalPolicySnapshot:
    """Immutable exact-scope policy captured when a plan is proposed."""

    tenant_id: str
    policy_version: str
    allowed_action_kinds: frozenset[ActionKind]
    allowed_target_fingerprints: frozenset[str]
    required_approver_roles: frozenset[str]
    maintenance_windows: tuple[MaintenanceWindow, ...]
    maximum_risk: RiskTier
    maximum_blast_radius: BlastRadius
    approval_from_risk: RiskTier
    required_quorum: int
    prohibit_self_approval: bool
    require_evidence: bool
    require_critic_approval: bool
    max_actions_per_plan: int
    max_actions_per_period: int
    max_concurrent_actions: int
    approval_ttl_seconds: int
    destructive_actions_enabled: bool = False
    schema_version: int = 1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "policy tenant_id")
        _identifier(self.policy_version, "policy version")
        if not self.required_approver_roles:
            raise ValueError("at least one remediation approver role is required")
        for role in self.required_approver_roles:
            _identifier(role, "approver role")
        for target_digest in self.allowed_target_fingerprints:
            _digest(target_digest, "allowed target fingerprint")
        if not 1 <= self.required_quorum <= 5:
            raise ValueError("approval quorum must be between 1 and 5")
        if not 1 <= self.max_actions_per_plan <= MAX_ACTIONS_PER_PLAN:
            raise ValueError("policy action-plan bound is invalid")
        if not 1 <= self.max_actions_per_period <= 10_000:
            raise ValueError("policy action-period bound is invalid")
        if not 1 <= self.max_concurrent_actions <= 100:
            raise ValueError("policy action concurrency bound is invalid")
        if not 60 <= self.approval_ttl_seconds <= 604_800:
            raise ValueError("approval ttl must be between one minute and seven days")
        if self.schema_version != 1:
            raise ValueError("new policy schemas require an additive contract")
        object.__setattr__(
            self,
            "maintenance_windows",
            tuple(sorted(self.maintenance_windows, key=lambda item: item.starts_at)),
        )
        object.__setattr__(self, "digest", _canonical_digest(_policy_plain(self)))


@dataclass(frozen=True, slots=True)
class ActionSpecification:
    """Immutable provider-neutral action with no arbitrary-command escape hatch."""

    action_id: UUID
    kind: ActionKind
    target: ActionTarget
    risk: RiskTier
    blast_radius: BlastRadius
    preconditions: tuple[Condition, ...]
    postconditions: tuple[Condition, ...]
    evidence_ids: tuple[str, ...]
    idempotency_key: str
    timeout_seconds: int
    retry_policy: RetryPolicy
    reconciliation_policy: ReconciliationPolicy
    dry_run_supported: bool
    parameters: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )
    rollback_reference: str | None = None
    compensation_reference: str | None = None
    schema_version: int = 1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.action_id.int == 0:
            raise ValueError("action_id cannot be nil")
        if not self.preconditions or not self.postconditions:
            raise ValueError(
                "controlled actions require preconditions and postconditions"
            )
        if len(self.preconditions) > MAX_CONDITIONS_PER_ACTION:
            raise ValueError("too many action preconditions")
        if len(self.postconditions) > MAX_CONDITIONS_PER_ACTION:
            raise ValueError("too many action postconditions")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("action evidence identifiers must be unique")
        for identifier in self.evidence_ids:
            _identifier(identifier, "action evidence_id")
        _identifier(self.idempotency_key, "action idempotency key")
        if not 1 <= self.timeout_seconds <= 300:
            raise ValueError("action timeout must be between 1 and 300 seconds")
        if not self.dry_run_supported:
            raise ValueError("Layer 8 actions must support deterministic dry-run")
        parameters = freeze_json_mapping(self.parameters)
        if self.kind is ActionKind.KUBERNETES_ROLLOUT_RESTART:
            if self.target.provider != "kubernetes":
                raise ValueError("rollout restart requires a Kubernetes target")
            if self.target.resource_type != "deployment":
                raise ValueError("rollout restart requires a deployment target")
            if parameters:
                raise ValueError("rollout restart accepts no free-form parameters")
        elif self.kind is ActionKind.SANDBOX_CHANGE_PREPARATION:
            if self.target.provider != "aegis":
                raise ValueError("sandbox preparation requires the Aegis provider")
            if self.target.resource_type != "sandbox":
                raise ValueError("sandbox preparation requires a sandbox target")
            required = {
                "sandbox_policy_digest",
                "sandbox_purpose",
                "sandbox_risk",
                "sandbox_spec_digest",
            }
            if set(parameters) != required:
                raise ValueError("sandbox preparation requires an exact reviewed scope")
            for key in ("sandbox_policy_digest", "sandbox_spec_digest"):
                value = parameters[key]
                if not isinstance(value, str):
                    raise ValueError("sandbox preparation digests must be strings")
                _digest(value, key)
            purpose = parameters["sandbox_purpose"]
            if purpose not in {
                "code_analysis",
                "config_analysis",
                "test_execution",
                "patch_preparation",
                "evidence_production",
            }:
                raise ValueError("sandbox preparation purpose is invalid")
            risk = parameters["sandbox_risk"]
            if (
                not isinstance(risk, int)
                or isinstance(risk, bool)
                or risk not in {1, 2, 3, 4}
            ):
                raise ValueError("sandbox preparation risk is invalid")
            if risk != int(self.risk):
                raise ValueError("sandbox preparation risk must match action risk")
        for reference, name in (
            (self.rollback_reference, "rollback"),
            (self.compensation_reference, "compensation"),
        ):
            if reference is not None and not reference.startswith("aegis-runbook://"):
                raise ValueError(f"{name} reference must use aegis-runbook://")
        if self.schema_version != 1:
            raise ValueError("new action schemas require an additive contract")
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "digest", _canonical_digest(_action_plain(self)))


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """Coordinator-linked immutable remediation plan revision."""

    plan_id: UUID
    tenant_id: str
    incident_id: str
    investigation_run_id: UUID
    revision: int
    requested_by: str
    created_at: datetime
    rationale: str
    actions: tuple[ActionSpecification, ...]
    evidence: tuple[EvidenceCitation, ...]
    approval_policy: ApprovalPolicySnapshot
    verification_artifact_reference: str
    critic_approved: bool
    schema_version: int = 1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.plan_id.int == 0 or self.investigation_run_id.int == 0:
            raise ValueError("plan and investigation identifiers cannot be nil")
        _identifier(self.tenant_id, "plan tenant_id")
        _identifier(self.incident_id, "incident_id")
        _identifier(self.requested_by, "plan requester")
        _aware(self.created_at, "plan creation")
        _bounded_text(self.rationale, "operator rationale", MAX_RATIONALE_BYTES)
        if not 1 <= self.revision <= 10_000:
            raise ValueError("plan revision must be positive and bounded")
        if not 1 <= len(self.actions) <= MAX_ACTIONS_PER_PLAN:
            raise ValueError("plan action count is invalid")
        if len(self.actions) > self.approval_policy.max_actions_per_plan:
            raise ValueError("plan exceeds the captured policy action bound")
        if len(self.evidence) > MAX_EVIDENCE_PER_PLAN:
            raise ValueError("plan evidence count exceeds the bound")
        if self.tenant_id != self.approval_policy.tenant_id:
            raise ValueError("plan and approval policy tenants must match")
        if len({action.action_id for action in self.actions}) != len(self.actions):
            raise ValueError("plan action identifiers must be unique")
        action_keys = {action.idempotency_key for action in self.actions}
        if len(action_keys) != len(self.actions):
            raise ValueError("plan action idempotency keys must be unique")
        available_evidence = {citation.evidence_id for citation in self.evidence}
        if any(
            identifier not in available_evidence
            for action in self.actions
            for identifier in action.evidence_ids
        ):
            raise ValueError("every action evidence id must resolve in the plan")
        if not self.verification_artifact_reference.startswith("aegis-artifact://"):
            raise ValueError("verification artifact must use aegis-artifact://")
        if self.schema_version != 1:
            raise ValueError("new plan schemas require an additive contract")
        object.__setattr__(
            self,
            "actions",
            tuple(sorted(self.actions, key=lambda item: str(item.action_id))),
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(self.evidence, key=lambda item: item.evidence_id)),
        )
        object.__setattr__(self, "digest", _canonical_digest(_plan_plain(self)))

    def action(self, action_id: UUID) -> ActionSpecification:
        try:
            return next(item for item in self.actions if item.action_id == action_id)
        except StopIteration as error:
            raise ValueError("action does not belong to remediation plan") from error


@dataclass(frozen=True, slots=True)
class PolicyEvaluationRecord:
    action_id: UUID
    plan_digest: str
    action_digest: str
    policy_digest: str
    outcome: PolicyOutcome
    reasons: tuple[str, ...]
    evaluated_at: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.plan_digest, "plan digest"),
            (self.action_digest, "action digest"),
            (self.policy_digest, "policy digest"),
        ):
            _digest(value, name)
        if not self.reasons or len(self.reasons) > 32:
            raise ValueError("policy evaluation requires bounded reasons")
        for reason in self.reasons:
            _identifier(reason, "policy reason")
        _aware(self.evaluated_at, "policy evaluation")


@dataclass(frozen=True, slots=True)
class ApprovalScope:
    approval_id: UUID
    action_id: UUID
    plan_digest: str
    action_digest: str
    policy_digest: str
    target_fingerprint: str
    risk: RiskTier
    requester_id: str
    required_quorum: int
    requested_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.approval_id.int == 0:
            raise ValueError("approval_id cannot be nil")
        for value, name in (
            (self.plan_digest, "approval plan digest"),
            (self.action_digest, "approval action digest"),
            (self.policy_digest, "approval policy digest"),
            (self.target_fingerprint, "approval target fingerprint"),
        ):
            _digest(value, name)
        _identifier(self.requester_id, "approval requester")
        if not 1 <= self.required_quorum <= 5:
            raise ValueError("approval quorum must be between 1 and 5")
        _aware(self.requested_at, "approval request")
        _aware(self.expires_at, "approval expiry")
        if self.expires_at <= self.requested_at:
            raise ValueError("approval expiry must follow its request")


@dataclass(frozen=True, slots=True)
class ApprovalState:
    scope: ApprovalScope
    status: ApprovalStatus
    approver_ids: tuple[str, ...] = ()
    decision_event_ids: tuple[UUID, ...] = ()
    decided_at: datetime | None = None
    rationale_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(set(self.approver_ids)) != len(self.approver_ids):
            raise ValueError("approval actors must be distinct")
        if len(self.approver_ids) != len(self.decision_event_ids):
            raise ValueError("approval actors and decision events must align")
        if self.decided_at is not None:
            _aware(self.decided_at, "approval decision")

    def valid_for(
        self,
        *,
        plan: RemediationPlan,
        action: ActionSpecification,
        policy_digest: str,
        at: datetime,
    ) -> bool:
        return (
            self.status is ApprovalStatus.GRANTED
            and at < self.scope.expires_at
            and self.scope.plan_digest == plan.digest
            and self.scope.action_digest == action.digest
            and self.scope.policy_digest == policy_digest
            and self.scope.target_fingerprint == action.target.fingerprint
            and self.scope.risk is action.risk
            and len(self.approver_ids) >= self.scope.required_quorum
        )


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    action_id: UUID
    attempt: int
    outcome: EffectOutcome
    occurred_at: datetime
    error_code: str | None = None
    provider_reference: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.attempt <= 5:
            raise ValueError("execution attempt must be between 1 and 5")
        _aware(self.occurred_at, "execution record")
        if self.error_code is not None:
            _identifier(self.error_code, "execution error code")
        if self.provider_reference is not None:
            _bounded_text(self.provider_reference, "provider reference", 512)


@dataclass(frozen=True, slots=True)
class ReconciliationRecord:
    action_id: UUID
    attempt: int
    outcome: ReconciliationOutcome
    observed_target_fingerprint: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if not 1 <= self.attempt <= 10:
            raise ValueError("reconciliation attempt must be between 1 and 10")
        _digest(self.observed_target_fingerprint, "observed target fingerprint")
        _aware(self.occurred_at, "reconciliation record")


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    action_id: UUID
    outcome: VerificationOutcome
    checked_conditions: tuple[Condition, ...]
    evidence_ids: tuple[str, ...]
    occurred_at: datetime

    def __post_init__(self) -> None:
        if not self.checked_conditions:
            raise ValueError("verification must check explicit postconditions")
        for evidence_id in self.evidence_ids:
            _identifier(evidence_id, "verification evidence_id")
        _aware(self.occurred_at, "verification record")


@dataclass(frozen=True, slots=True)
class RemediationState:
    """Authoritative remediation state reconstructed only from ledger events."""

    plan: RemediationPlan
    version: int
    action_statuses: Mapping[UUID, ActionLifecycleStatus]
    policy_evaluations: Mapping[UUID, PolicyEvaluationRecord]
    approvals: Mapping[UUID, ApprovalState]
    executions: tuple[ExecutionRecord, ...]
    reconciliations: tuple[ReconciliationRecord, ...]
    verifications: tuple[VerificationRecord, ...]
    event_ids: frozenset[UUID]
    idempotency_keys: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "action_statuses",
            MappingProxyType(dict(self.action_statuses)),
        )
        object.__setattr__(
            self,
            "policy_evaluations",
            MappingProxyType(dict(self.policy_evaluations)),
        )
        object.__setattr__(self, "approvals", MappingProxyType(dict(self.approvals)))

    def approval_for(self, action_id: UUID) -> ApprovalState | None:
        matches = tuple(
            approval
            for approval in self.approvals.values()
            if approval.scope.action_id == action_id
        )
        return matches[-1] if matches else None


class RemediationReplayError(RuntimeError):
    """Committed remediation history violates a deterministic invariant."""


def plan_to_payload(plan: RemediationPlan) -> Mapping[str, JsonValue]:
    return cast(Mapping[str, JsonValue], _plan_plain(plan))


def plan_from_payload(value: Mapping[str, JsonValue]) -> RemediationPlan:
    actions_value = _sequence(value["actions"])
    evidence_value = _sequence(value["evidence"])
    policy_value = _mapping(value["approval_policy"])
    return RemediationPlan(
        plan_id=UUID(_string(value["plan_id"])),
        tenant_id=_string(value["tenant_id"]),
        incident_id=_string(value["incident_id"]),
        investigation_run_id=UUID(_string(value["investigation_run_id"])),
        revision=_integer(value["revision"]),
        requested_by=_string(value["requested_by"]),
        created_at=datetime.fromisoformat(_string(value["created_at"])),
        rationale=_string(value["rationale"]),
        actions=tuple(_action_from_payload(_mapping(item)) for item in actions_value),
        evidence=tuple(
            EvidenceCitation(
                evidence_id=_string(item_value["evidence_id"]),
                source_reference=_string(item_value["source_reference"]),
                content_digest=_string(item_value["content_digest"]),
                observed_at=datetime.fromisoformat(_string(item_value["observed_at"])),
                confidence=_number(item_value["confidence"]),
            )
            for item in evidence_value
            for item_value in (_mapping(item),)
        ),
        approval_policy=_policy_from_payload(policy_value),
        verification_artifact_reference=_string(
            value["verification_artifact_reference"]
        ),
        critic_approved=_boolean(value["critic_approved"]),
        schema_version=_integer(value["schema_version"]),
    )


def replay_remediation(events: Sequence[EventEnvelope]) -> RemediationState:
    """Fold one remediation stream while rejecting duplicate or corrupt history."""
    if not events:
        raise RemediationReplayError("remediation stream is empty")
    state: RemediationState | None = None
    seen_events: set[UUID] = set()
    seen_keys: set[str] = set()
    action_history: dict[UUID, list[EventEnvelope]] = {}
    expected_sequence = 1
    for event in events:
        if event.event_id in seen_events:
            raise RemediationReplayError("duplicate remediation event identifier")
        seen_events.add(event.event_id)
        if event.idempotency_key is not None:
            if event.idempotency_key in seen_keys:
                raise RemediationReplayError("duplicate remediation idempotency key")
            seen_keys.add(event.idempotency_key)
        if event.aggregate_sequence:
            if event.aggregate_sequence != expected_sequence:
                raise RemediationReplayError("remediation sequence is not gapless")
            expected_sequence += 1
        try:
            event_type = DomainEventType(event.event_type)
        except ValueError:
            continue
        if event_type is DomainEventType.REMEDIATION_PROPOSED:
            if state is not None:
                raise RemediationReplayError("remediation was proposed twice")
            plan_value = event.payload.get("plan")
            if not isinstance(plan_value, Mapping):
                raise RemediationReplayError("proposal lacks a typed plan")
            try:
                plan = plan_from_payload(plan_value)
            except (KeyError, TypeError, ValueError) as error:
                raise RemediationReplayError("proposal plan is invalid") from error
            if event.tenant_id != plan.tenant_id or event.aggregate_id != str(
                plan.plan_id
            ):
                raise RemediationReplayError("proposal linkage is corrupt")
            state = RemediationState(
                plan=plan,
                version=0,
                action_statuses={
                    action.action_id: ActionLifecycleStatus.PROPOSED
                    for action in plan.actions
                },
                policy_evaluations={},
                approvals={},
                executions=(),
                reconciliations=(),
                verifications=(),
                event_ids=frozenset(),
                idempotency_keys=frozenset(),
            )
        elif state is not None:
            _validate_action_lifecycle(state, event_type, event, action_history)
            state = _fold_event(state, event_type, event)
            action_value = event.payload.get("action_id")
            if event_type.value.startswith("action.") and isinstance(action_value, str):
                action_history.setdefault(UUID(action_value), []).append(event)
    if state is None:
        raise RemediationReplayError("remediation stream has no proposal")
    return replace(
        state,
        version=len(events),
        event_ids=frozenset(seen_events),
        idempotency_keys=frozenset(seen_keys),
    )


def _validate_action_lifecycle(
    state: RemediationState,
    event_type: DomainEventType,
    event: EventEnvelope,
    history_by_action: Mapping[UUID, Sequence[EventEnvelope]],
) -> None:
    if not event_type.value.startswith("action."):
        return
    try:
        action_id = UUID(_payload_string(event, "action_id"))
        state.plan.action(action_id)
    except (ValueError, KeyError) as error:
        raise RemediationReplayError("action lifecycle target is invalid") from error
    history = history_by_action.get(action_id, ())
    attempt_value = event.payload.get("attempt")
    attempt = (
        attempt_value
        if isinstance(attempt_value, int) and not isinstance(attempt_value, bool)
        else None
    )

    def seen(kind: DomainEventType, selected_attempt: int | None = None) -> bool:
        return any(
            prior.event_type == kind
            and (
                selected_attempt is None
                or prior.payload.get("attempt") == selected_attempt
            )
            for prior in history
        )

    if event_type is DomainEventType.ACTION_DISPATCH_CLAIMED:
        if state.action_statuses[action_id] is not ActionLifecycleStatus.APPROVED:
            raise RemediationReplayError("action dispatch lacks exact approval")
    elif event_type is DomainEventType.ACTION_PREFLIGHT_REQUESTED:
        if not seen(DomainEventType.ACTION_DISPATCH_CLAIMED):
            raise RemediationReplayError("action preflight lacks dispatch")
    elif event_type in {
        DomainEventType.ACTION_PREFLIGHT_COMPLETED,
        DomainEventType.ACTION_PREFLIGHT_FAILED,
    }:
        if not seen(DomainEventType.ACTION_PREFLIGHT_REQUESTED):
            raise RemediationReplayError("action preflight outcome lacks request")
    elif event_type is DomainEventType.ACTION_DRY_RUN_REQUESTED:
        if not seen(DomainEventType.ACTION_PREFLIGHT_COMPLETED):
            raise RemediationReplayError("action dry run lacks successful preflight")
    elif event_type in {
        DomainEventType.ACTION_DRY_RUN_COMPLETED,
        DomainEventType.ACTION_DRY_RUN_FAILED,
    }:
        if not seen(DomainEventType.ACTION_DRY_RUN_REQUESTED):
            raise RemediationReplayError("action dry-run outcome lacks request")
    elif event_type is DomainEventType.ACTION_EXECUTION_REQUESTED:
        if attempt is None:
            raise RemediationReplayError("action intent lacks attempt")
        if attempt == 1:
            if not seen(DomainEventType.ACTION_DRY_RUN_COMPLETED):
                raise RemediationReplayError("action intent lacks dry run")
        elif not any(
            prior.event_type == DomainEventType.ACTION_RECONCILIATION_COMPLETED
            and prior.payload.get("attempt") == attempt - 1
            and prior.payload.get("outcome") == ReconciliationOutcome.NOT_APPLIED.value
            for prior in history
        ):
            raise RemediationReplayError(
                "action retry lacks not-applied reconciliation"
            )
    elif event_type is DomainEventType.ACTION_EXECUTION_STARTED:
        if attempt is None or not seen(
            DomainEventType.ACTION_EXECUTION_REQUESTED,
            attempt,
        ):
            raise RemediationReplayError("action start lacks durable intent")
    elif event_type in {
        DomainEventType.ACTION_EXECUTION_SUCCEEDED,
        DomainEventType.ACTION_EXECUTION_FAILED,
        DomainEventType.ACTION_EXECUTION_AMBIGUOUS,
    }:
        if attempt is None or not seen(
            DomainEventType.ACTION_EXECUTION_STARTED,
            attempt,
        ):
            raise RemediationReplayError("action outcome lacks started intent")
    elif event_type is DomainEventType.ACTION_RECONCILIATION_REQUESTED:
        if attempt is None or not seen(
            DomainEventType.ACTION_EXECUTION_STARTED,
            attempt,
        ):
            raise RemediationReplayError("action reconciliation lacks effect intent")
    elif event_type is DomainEventType.ACTION_RECONCILIATION_COMPLETED:
        if attempt is None or not seen(
            DomainEventType.ACTION_RECONCILIATION_REQUESTED,
            attempt,
        ):
            raise RemediationReplayError("action reconciliation lacks request")
    elif event_type is DomainEventType.ACTION_VERIFICATION_REQUESTED:
        if not (
            seen(DomainEventType.ACTION_EXECUTION_SUCCEEDED)
            or any(
                prior.event_type == DomainEventType.ACTION_RECONCILIATION_COMPLETED
                and prior.payload.get("outcome") == ReconciliationOutcome.APPLIED.value
                for prior in history
            )
        ):
            raise RemediationReplayError("action verification lacks applied effect")
    elif event_type is DomainEventType.ACTION_VERIFICATION_COMPLETED:
        if attempt is None or not seen(
            DomainEventType.ACTION_VERIFICATION_REQUESTED,
            attempt,
        ):
            raise RemediationReplayError("action verification lacks request")
    elif event_type in {
        DomainEventType.ACTION_ROLLBACK_REQUESTED,
        DomainEventType.ACTION_COMPENSATION_REQUESTED,
    }:
        if not (
            seen(DomainEventType.ACTION_EXECUTION_SUCCEEDED)
            or any(
                prior.event_type == DomainEventType.ACTION_RECONCILIATION_COMPLETED
                and prior.payload.get("outcome") == ReconciliationOutcome.APPLIED.value
                for prior in history
            )
        ):
            raise RemediationReplayError("action reversal lacks applied effect")
    elif event_type in {
        DomainEventType.ACTION_ROLLBACK_COMPLETED,
        DomainEventType.ACTION_ROLLBACK_FAILED,
    }:
        if not seen(DomainEventType.ACTION_ROLLBACK_REQUESTED):
            raise RemediationReplayError("action rollback outcome lacks request")
    elif event_type in {
        DomainEventType.ACTION_COMPENSATION_COMPLETED,
        DomainEventType.ACTION_COMPENSATION_FAILED,
    }:
        if not seen(DomainEventType.ACTION_COMPENSATION_REQUESTED):
            raise RemediationReplayError("action compensation outcome lacks request")
    elif event_type is DomainEventType.ACTION_CANCELLED and not seen(
        DomainEventType.ACTION_CANCELLATION_REQUESTED
    ):
        raise RemediationReplayError("action cancellation lacks request")


def _fold_event(
    state: RemediationState,
    event_type: DomainEventType,
    event: EventEnvelope,
) -> RemediationState:
    if event.tenant_id != state.plan.tenant_id:
        raise RemediationReplayError("remediation event tenant changed")
    if event_type is DomainEventType.REMEDIATION_PLAN_REVISED:
        value = event.payload.get("plan")
        if not isinstance(value, Mapping):
            raise RemediationReplayError("plan revision lacks a typed plan")
        try:
            plan = plan_from_payload(value)
        except (KeyError, TypeError, ValueError) as error:
            raise RemediationReplayError("plan revision is invalid") from error
        if (
            plan.plan_id != state.plan.plan_id
            or plan.revision != state.plan.revision + 1
            or plan.tenant_id != state.plan.tenant_id
        ):
            raise RemediationReplayError("plan revision linkage is invalid")
        approvals = {
            identifier: replace(
                approval,
                status=(
                    ApprovalStatus.REVOKED
                    if approval.status
                    in {ApprovalStatus.PENDING, ApprovalStatus.GRANTED}
                    else approval.status
                ),
                decided_at=event.occurred_at,
            )
            for identifier, approval in state.approvals.items()
        }
        revised_action_ids = {action.action_id for action in plan.actions}
        return replace(
            state,
            plan=plan,
            action_statuses={
                action.action_id: ActionLifecycleStatus.PROPOSED
                for action in plan.actions
            },
            policy_evaluations={},
            approvals=approvals,
            executions=tuple(
                record
                for record in state.executions
                if record.action_id not in revised_action_ids
            ),
            reconciliations=tuple(
                record
                for record in state.reconciliations
                if record.action_id not in revised_action_ids
            ),
            verifications=tuple(
                record
                for record in state.verifications
                if record.action_id not in revised_action_ids
            ),
        )
    action_id = _event_action_id(event)
    statuses = dict(state.action_statuses)
    if action_id is not None and action_id not in statuses:
        raise RemediationReplayError("event refers to an unknown action")
    if event_type is DomainEventType.REMEDIATION_POLICY_EVALUATED:
        if action_id is None:
            raise RemediationReplayError("policy event lacks action_id")
        record = PolicyEvaluationRecord(
            action_id=action_id,
            plan_digest=_payload_string(event, "plan_digest"),
            action_digest=_payload_string(event, "action_digest"),
            policy_digest=_payload_string(event, "policy_digest"),
            outcome=PolicyOutcome(_payload_string(event, "outcome")),
            reasons=tuple(_payload_strings(event, "reasons")),
            evaluated_at=event.occurred_at,
        )
        action = state.plan.action(action_id)
        if (
            record.plan_digest != state.plan.digest
            or record.action_digest != action.digest
            or record.policy_digest != state.plan.approval_policy.digest
        ):
            raise RemediationReplayError("policy evaluation scope is stale")
        evaluations = dict(state.policy_evaluations)
        evaluations[action_id] = record
        statuses[action_id] = (
            ActionLifecycleStatus.POLICY_DENIED
            if record.outcome is PolicyOutcome.DENY
            else ActionLifecycleStatus.AWAITING_APPROVAL
        )
        return replace(
            state,
            policy_evaluations=evaluations,
            action_statuses=statuses,
        )
    if event_type is DomainEventType.REMEDIATION_APPROVAL_REQUESTED:
        if action_id is None:
            raise RemediationReplayError("approval request lacks action_id")
        scope = ApprovalScope(
            approval_id=UUID(_payload_string(event, "approval_id")),
            action_id=action_id,
            plan_digest=_payload_string(event, "plan_digest"),
            action_digest=_payload_string(event, "action_digest"),
            policy_digest=_payload_string(event, "policy_digest"),
            target_fingerprint=_payload_string(event, "target_fingerprint"),
            risk=RiskTier(_payload_int(event, "risk")),
            requester_id=_payload_string(event, "requester_id"),
            required_quorum=_payload_int(event, "required_quorum"),
            requested_at=event.occurred_at,
            expires_at=datetime.fromisoformat(_payload_string(event, "expires_at")),
        )
        action = state.plan.action(action_id)
        if (
            scope.plan_digest != state.plan.digest
            or scope.action_digest != action.digest
            or scope.policy_digest != state.plan.approval_policy.digest
            or scope.target_fingerprint != action.target.fingerprint
            or scope.risk is not action.risk
        ):
            raise RemediationReplayError("approval request scope is stale")
        approvals = dict(state.approvals)
        if scope.approval_id in approvals:
            raise RemediationReplayError("approval was requested twice")
        approvals[scope.approval_id] = ApprovalState(scope, ApprovalStatus.PENDING)
        return replace(state, approvals=approvals)
    if event_type in {
        DomainEventType.REMEDIATION_APPROVAL_GRANTED,
        DomainEventType.REMEDIATION_APPROVAL_DENIED,
        DomainEventType.REMEDIATION_APPROVAL_EXPIRED,
        DomainEventType.REMEDIATION_APPROVAL_REVOKED,
    }:
        return _fold_approval_decision(state, event_type, event)
    if action_id is None:
        return state
    status = {
        DomainEventType.ACTION_DISPATCH_CLAIMED: ActionLifecycleStatus.DISPATCHED,
        DomainEventType.ACTION_PREFLIGHT_REQUESTED: ActionLifecycleStatus.PREFLIGHT,
        DomainEventType.ACTION_PREFLIGHT_COMPLETED: ActionLifecycleStatus.PREFLIGHT,
        DomainEventType.ACTION_PREFLIGHT_FAILED: ActionLifecycleStatus.FAILED,
        DomainEventType.ACTION_DRY_RUN_REQUESTED: ActionLifecycleStatus.DRY_RUN,
        DomainEventType.ACTION_DRY_RUN_COMPLETED: ActionLifecycleStatus.DRY_RUN,
        DomainEventType.ACTION_DRY_RUN_FAILED: ActionLifecycleStatus.FAILED,
        DomainEventType.ACTION_EXECUTION_REQUESTED: ActionLifecycleStatus.EXECUTING,
        DomainEventType.ACTION_EXECUTION_STARTED: ActionLifecycleStatus.EXECUTING,
        DomainEventType.ACTION_EXECUTION_SUCCEEDED: ActionLifecycleStatus.SUCCEEDED,
        DomainEventType.ACTION_EXECUTION_FAILED: ActionLifecycleStatus.FAILED,
        DomainEventType.ACTION_EXECUTION_AMBIGUOUS: ActionLifecycleStatus.AMBIGUOUS,
        DomainEventType.ACTION_RECONCILIATION_REQUESTED: (
            ActionLifecycleStatus.RECONCILING
        ),
        DomainEventType.ACTION_CANCELLATION_REQUESTED: (
            ActionLifecycleStatus.CANCELLED
        ),
        DomainEventType.ACTION_CANCELLED: ActionLifecycleStatus.CANCELLED,
        DomainEventType.ACTION_ROLLBACK_COMPLETED: ActionLifecycleStatus.ROLLED_BACK,
        DomainEventType.ACTION_COMPENSATION_COMPLETED: (
            ActionLifecycleStatus.COMPENSATED
        ),
    }.get(event_type)
    if status is not None:
        statuses[action_id] = status
    executions = state.executions
    if event_type in {
        DomainEventType.ACTION_EXECUTION_SUCCEEDED,
        DomainEventType.ACTION_EXECUTION_FAILED,
        DomainEventType.ACTION_EXECUTION_AMBIGUOUS,
        DomainEventType.ACTION_CANCELLED,
    }:
        effect_outcome = {
            DomainEventType.ACTION_EXECUTION_SUCCEEDED: EffectOutcome.SUCCEEDED,
            DomainEventType.ACTION_EXECUTION_AMBIGUOUS: EffectOutcome.AMBIGUOUS,
            DomainEventType.ACTION_CANCELLED: EffectOutcome.CANCELLED,
        }.get(event_type)
        if effect_outcome is None:
            effect_outcome = (
                EffectOutcome.RETRYABLE_FAILURE
                if _payload_bool(event, "retryable", False)
                else EffectOutcome.PERMANENT_FAILURE
            )
        executions = (
            *executions,
            ExecutionRecord(
                action_id=action_id,
                attempt=_payload_int(event, "attempt"),
                outcome=effect_outcome,
                occurred_at=event.occurred_at,
                error_code=_payload_optional_string(event, "error_code"),
                provider_reference=_payload_optional_string(
                    event, "provider_reference"
                ),
            ),
        )
    reconciliations = state.reconciliations
    if event_type is DomainEventType.ACTION_RECONCILIATION_COMPLETED:
        reconciliation_outcome = ReconciliationOutcome(
            _payload_string(event, "outcome")
        )
        reconciliations = (
            *reconciliations,
            ReconciliationRecord(
                action_id=action_id,
                attempt=_payload_int(event, "attempt"),
                outcome=reconciliation_outcome,
                observed_target_fingerprint=_payload_string(
                    event, "observed_target_fingerprint"
                ),
                occurred_at=event.occurred_at,
            ),
        )
        statuses[action_id] = (
            ActionLifecycleStatus.SUCCEEDED
            if reconciliation_outcome is ReconciliationOutcome.APPLIED
            else (
                ActionLifecycleStatus.FAILED
                if reconciliation_outcome is ReconciliationOutcome.NOT_APPLIED
                else ActionLifecycleStatus.AMBIGUOUS
            )
        )
    verifications = state.verifications
    if event_type is DomainEventType.ACTION_VERIFICATION_COMPLETED:
        verification_outcome = VerificationOutcome(_payload_string(event, "outcome"))
        action = state.plan.action(action_id)
        verifications = (
            *verifications,
            VerificationRecord(
                action_id=action_id,
                outcome=verification_outcome,
                checked_conditions=action.postconditions,
                evidence_ids=tuple(_payload_strings(event, "evidence_ids")),
                occurred_at=event.occurred_at,
            ),
        )
        statuses[action_id] = {
            VerificationOutcome.SUCCESS: ActionLifecycleStatus.VERIFIED,
            VerificationOutcome.FAILURE: ActionLifecycleStatus.VERIFICATION_FAILED,
            VerificationOutcome.PARTIAL: ActionLifecycleStatus.VERIFICATION_PARTIAL,
            VerificationOutcome.UNKNOWN: ActionLifecycleStatus.VERIFICATION_UNKNOWN,
        }[verification_outcome]
    return replace(
        state,
        action_statuses=statuses,
        executions=executions,
        reconciliations=reconciliations,
        verifications=verifications,
    )


def _fold_approval_decision(
    state: RemediationState,
    event_type: DomainEventType,
    event: EventEnvelope,
) -> RemediationState:
    approval_id = UUID(_payload_string(event, "approval_id"))
    approvals = dict(state.approvals)
    try:
        current = approvals[approval_id]
    except KeyError as error:
        raise RemediationReplayError("approval decision has no request") from error
    allowed_statuses = (
        {ApprovalStatus.PENDING, ApprovalStatus.GRANTED}
        if event_type is DomainEventType.REMEDIATION_APPROVAL_REVOKED
        else {ApprovalStatus.PENDING}
    )
    if current.status not in allowed_statuses:
        raise RemediationReplayError("approval decision is terminal or replayed")
    statuses = dict(state.action_statuses)
    if event_type is DomainEventType.REMEDIATION_APPROVAL_GRANTED:
        approver_id = _payload_string(event, "approver_id")
        if approver_id in current.approver_ids:
            raise RemediationReplayError("approver decision was replayed")
        approvers = (*current.approver_ids, approver_id)
        decision_ids = (*current.decision_event_ids, event.event_id)
        status = (
            ApprovalStatus.GRANTED
            if len(approvers) >= current.scope.required_quorum
            else ApprovalStatus.PENDING
        )
        approvals[approval_id] = replace(
            current,
            status=status,
            approver_ids=approvers,
            decision_event_ids=decision_ids,
            decided_at=event.occurred_at if status is ApprovalStatus.GRANTED else None,
            rationale_codes=(
                *current.rationale_codes,
                _payload_string(event, "rationale_code"),
            ),
        )
        if status is ApprovalStatus.GRANTED:
            statuses[current.scope.action_id] = ActionLifecycleStatus.APPROVED
    else:
        status = {
            DomainEventType.REMEDIATION_APPROVAL_DENIED: ApprovalStatus.DENIED,
            DomainEventType.REMEDIATION_APPROVAL_EXPIRED: ApprovalStatus.EXPIRED,
            DomainEventType.REMEDIATION_APPROVAL_REVOKED: ApprovalStatus.REVOKED,
        }[event_type]
        approvals[approval_id] = replace(
            current,
            status=status,
            decided_at=event.occurred_at,
            rationale_codes=(
                *current.rationale_codes,
                _payload_string(event, "rationale_code"),
            ),
        )
        if statuses[current.scope.action_id] in {
            ActionLifecycleStatus.PROPOSED,
            ActionLifecycleStatus.POLICY_DENIED,
            ActionLifecycleStatus.AWAITING_APPROVAL,
            ActionLifecycleStatus.APPROVED,
        }:
            statuses[current.scope.action_id] = ActionLifecycleStatus.AWAITING_APPROVAL
    return replace(state, approvals=approvals, action_statuses=statuses)


def _action_plain(action: ActionSpecification) -> dict[str, object]:
    return {
        "action_id": str(action.action_id),
        "blast_radius": int(action.blast_radius),
        "compensation_reference": action.compensation_reference,
        "dry_run_supported": action.dry_run_supported,
        "evidence_ids": list(action.evidence_ids),
        "idempotency_key": action.idempotency_key,
        "kind": action.kind.value,
        "parameters": thaw_json(action.parameters),
        "postconditions": [_condition_plain(item) for item in action.postconditions],
        "preconditions": [_condition_plain(item) for item in action.preconditions],
        "reconciliation_policy": {
            "escalate_on_unknown": (action.reconciliation_policy.escalate_on_unknown),
            "interval_seconds": action.reconciliation_policy.interval_seconds,
            "max_attempts": action.reconciliation_policy.max_attempts,
            "strategy": action.reconciliation_policy.strategy.value,
        },
        "retry_policy": {
            "initial_backoff_seconds": action.retry_policy.initial_backoff_seconds,
            "max_attempts": action.retry_policy.max_attempts,
            "maximum_backoff_seconds": action.retry_policy.maximum_backoff_seconds,
        },
        "risk": int(action.risk),
        "rollback_reference": action.rollback_reference,
        "schema_version": action.schema_version,
        "target": {
            "environment": action.target.environment,
            "provider": action.target.provider,
            "resource_id": action.target.resource_id,
            "resource_type": action.target.resource_type,
            "scope": action.target.scope,
        },
        "timeout_seconds": action.timeout_seconds,
    }


def _action_from_payload(value: Mapping[str, JsonValue]) -> ActionSpecification:
    target = _mapping(value["target"])
    retry = _mapping(value["retry_policy"])
    reconciliation = _mapping(value["reconciliation_policy"])
    parameters = _mapping(value["parameters"])
    return ActionSpecification(
        action_id=UUID(_string(value["action_id"])),
        kind=ActionKind(_string(value["kind"])),
        target=ActionTarget(
            provider=_string(target["provider"]),
            environment=_string(target["environment"]),
            resource_type=_string(target["resource_type"]),
            resource_id=_string(target["resource_id"]),
            scope=_string(target["scope"]),
        ),
        risk=RiskTier(_integer(value["risk"])),
        blast_radius=BlastRadius(_integer(value["blast_radius"])),
        preconditions=tuple(
            _condition_from_payload(_mapping(item))
            for item in _sequence(value["preconditions"])
        ),
        postconditions=tuple(
            _condition_from_payload(_mapping(item))
            for item in _sequence(value["postconditions"])
        ),
        evidence_ids=tuple(_string(item) for item in _sequence(value["evidence_ids"])),
        idempotency_key=_string(value["idempotency_key"]),
        timeout_seconds=_integer(value["timeout_seconds"]),
        retry_policy=RetryPolicy(
            max_attempts=_integer(retry["max_attempts"]),
            initial_backoff_seconds=_number(retry["initial_backoff_seconds"]),
            maximum_backoff_seconds=_number(retry["maximum_backoff_seconds"]),
        ),
        reconciliation_policy=ReconciliationPolicy(
            strategy=ReconciliationStrategy(_string(reconciliation["strategy"])),
            max_attempts=_integer(reconciliation["max_attempts"]),
            interval_seconds=_number(reconciliation["interval_seconds"]),
            escalate_on_unknown=_boolean(reconciliation["escalate_on_unknown"]),
        ),
        dry_run_supported=_boolean(value["dry_run_supported"]),
        parameters=parameters,
        rollback_reference=_optional_string(value["rollback_reference"]),
        compensation_reference=_optional_string(value["compensation_reference"]),
        schema_version=_integer(value["schema_version"]),
    )


def _policy_plain(policy: ApprovalPolicySnapshot) -> dict[str, object]:
    return {
        "allowed_action_kinds": sorted(
            item.value for item in policy.allowed_action_kinds
        ),
        "allowed_target_fingerprints": sorted(policy.allowed_target_fingerprints),
        "approval_from_risk": int(policy.approval_from_risk),
        "approval_ttl_seconds": policy.approval_ttl_seconds,
        "destructive_actions_enabled": policy.destructive_actions_enabled,
        "maintenance_windows": [
            {
                "ends_at": item.ends_at.isoformat(),
                "starts_at": item.starts_at.isoformat(),
            }
            for item in policy.maintenance_windows
        ],
        "max_actions_per_period": policy.max_actions_per_period,
        "max_actions_per_plan": policy.max_actions_per_plan,
        "max_concurrent_actions": policy.max_concurrent_actions,
        "maximum_blast_radius": int(policy.maximum_blast_radius),
        "maximum_risk": int(policy.maximum_risk),
        "policy_version": policy.policy_version,
        "prohibit_self_approval": policy.prohibit_self_approval,
        "require_critic_approval": policy.require_critic_approval,
        "require_evidence": policy.require_evidence,
        "required_approver_roles": sorted(policy.required_approver_roles),
        "required_quorum": policy.required_quorum,
        "schema_version": policy.schema_version,
        "tenant_id": policy.tenant_id,
    }


def _policy_from_payload(value: Mapping[str, JsonValue]) -> ApprovalPolicySnapshot:
    return ApprovalPolicySnapshot(
        tenant_id=_string(value["tenant_id"]),
        policy_version=_string(value["policy_version"]),
        allowed_action_kinds=frozenset(
            ActionKind(_string(item))
            for item in _sequence(value["allowed_action_kinds"])
        ),
        allowed_target_fingerprints=frozenset(
            _string(item) for item in _sequence(value["allowed_target_fingerprints"])
        ),
        required_approver_roles=frozenset(
            _string(item) for item in _sequence(value["required_approver_roles"])
        ),
        maintenance_windows=tuple(
            MaintenanceWindow(
                datetime.fromisoformat(_string(window["starts_at"])),
                datetime.fromisoformat(_string(window["ends_at"])),
            )
            for item in _sequence(value["maintenance_windows"])
            for window in (_mapping(item),)
        ),
        maximum_risk=RiskTier(_integer(value["maximum_risk"])),
        maximum_blast_radius=BlastRadius(_integer(value["maximum_blast_radius"])),
        approval_from_risk=RiskTier(_integer(value["approval_from_risk"])),
        required_quorum=_integer(value["required_quorum"]),
        prohibit_self_approval=_boolean(value["prohibit_self_approval"]),
        require_evidence=_boolean(value["require_evidence"]),
        require_critic_approval=_boolean(value["require_critic_approval"]),
        max_actions_per_plan=_integer(value["max_actions_per_plan"]),
        max_actions_per_period=_integer(value["max_actions_per_period"]),
        max_concurrent_actions=_integer(value["max_concurrent_actions"]),
        approval_ttl_seconds=_integer(value["approval_ttl_seconds"]),
        destructive_actions_enabled=_boolean(value["destructive_actions_enabled"]),
        schema_version=_integer(value["schema_version"]),
    )


def _plan_plain(plan: RemediationPlan) -> dict[str, object]:
    return {
        "actions": [_action_plain(item) for item in plan.actions],
        "approval_policy": _policy_plain(plan.approval_policy),
        "created_at": plan.created_at.isoformat(),
        "critic_approved": plan.critic_approved,
        "evidence": [
            {
                "confidence": item.confidence,
                "content_digest": item.content_digest,
                "evidence_id": item.evidence_id,
                "observed_at": item.observed_at.isoformat(),
                "source_reference": item.source_reference,
            }
            for item in plan.evidence
        ],
        "incident_id": plan.incident_id,
        "investigation_run_id": str(plan.investigation_run_id),
        "plan_id": str(plan.plan_id),
        "rationale": plan.rationale,
        "requested_by": plan.requested_by,
        "revision": plan.revision,
        "schema_version": plan.schema_version,
        "tenant_id": plan.tenant_id,
        "verification_artifact_reference": plan.verification_artifact_reference,
    }


def _condition_plain(condition: Condition) -> dict[str, object]:
    return {
        "evidence_id": condition.evidence_id,
        "expected": condition.expected,
        "operator": condition.operator.value,
        "signal": condition.signal,
    }


def _condition_from_payload(value: Mapping[str, JsonValue]) -> Condition:
    expected = value["expected"]
    if isinstance(expected, (Mapping, Sequence)) and not isinstance(expected, str):
        raise ValueError("condition expected value must be scalar")
    return Condition(
        signal=_string(value["signal"]),
        operator=ConditionOperator(_string(value["operator"])),
        expected=expected,
        evidence_id=_optional_string(value["evidence_id"]),
    )


def _mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ValueError("expected a JSON object")
    return value


def _sequence(value: JsonValue) -> Sequence[JsonValue]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError("expected a JSON array")
    return value


def _string(value: JsonValue) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("expected a non-empty string")
    return value


def _optional_string(value: JsonValue) -> str | None:
    if value is None:
        return None
    return _string(value)


def _integer(value: JsonValue) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("expected an integer")
    return value


def _number(value: JsonValue) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("expected a number")
    return float(value)


def _boolean(value: JsonValue) -> bool:
    if not isinstance(value, bool):
        raise ValueError("expected a boolean")
    return value


def _event_action_id(event: EventEnvelope) -> UUID | None:
    value = event.payload.get("action_id")
    if value is None:
        return None
    if not isinstance(value, str):
        raise RemediationReplayError("action_id must be a string")
    try:
        return UUID(value)
    except ValueError as error:
        raise RemediationReplayError("action_id is malformed") from error


def _payload_string(event: EventEnvelope, name: str) -> str:
    value = event.payload.get(name)
    if not isinstance(value, str) or not value:
        raise RemediationReplayError(f"event requires string {name}")
    if len(value.encode()) > MAX_EVENT_REASON_BYTES and name not in {
        "plan_digest",
        "action_digest",
        "policy_digest",
        "target_fingerprint",
        "observed_target_fingerprint",
    }:
        raise RemediationReplayError(f"event field {name} is oversized")
    return value


def _payload_optional_string(event: EventEnvelope, name: str) -> str | None:
    value = event.payload.get(name)
    if value is None:
        return None
    return _payload_string(event, name)


def _payload_int(event: EventEnvelope, name: str) -> int:
    value = event.payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RemediationReplayError(f"event requires integer {name}")
    return value


def _payload_bool(event: EventEnvelope, name: str, default: bool) -> bool:
    value = event.payload.get(name, default)
    if not isinstance(value, bool):
        raise RemediationReplayError(f"event requires boolean {name}")
    return value


def _payload_strings(event: EventEnvelope, name: str) -> tuple[str, ...]:
    value = event.payload.get(name)
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise RemediationReplayError(f"event requires array {name}")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise RemediationReplayError(f"event {name} contains invalid strings")
        result.append(item)
    return tuple(result)


__all__ = [
    "ActionKind",
    "ActionLifecycleStatus",
    "ActionSpecification",
    "ActionTarget",
    "ApprovalPolicySnapshot",
    "ApprovalScope",
    "ApprovalState",
    "ApprovalStatus",
    "BlastRadius",
    "Condition",
    "ConditionOperator",
    "EffectOutcome",
    "EvidenceCitation",
    "ExecutionRecord",
    "MaintenanceWindow",
    "PolicyEvaluationRecord",
    "PolicyOutcome",
    "ReconciliationOutcome",
    "ReconciliationPolicy",
    "ReconciliationRecord",
    "ReconciliationStrategy",
    "RemediationPlan",
    "RemediationReplayError",
    "RemediationState",
    "RetryPolicy",
    "RiskTier",
    "VerificationOutcome",
    "VerificationRecord",
    "plan_from_payload",
    "plan_to_payload",
    "replay_remediation",
]
