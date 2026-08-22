"""Immutable provider-neutral contracts for deterministic evaluation evidence."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

MAX_CASES = 512
MAX_FIXTURES = 256
MAX_INVARIANTS = 64
MAX_METRICS = 64
MAX_REFERENCES = 128
MAX_STRING_LENGTH = 2_048
MAX_TAGS = 32

type CanonicalScalar = str | int | float | bool | None
type CanonicalValue = (
    CanonicalScalar | Sequence["CanonicalValue"] | Mapping[str, "CanonicalValue"]
)


class EvaluationMode(StrEnum):
    """Execution modes with distinct trust and reproducibility properties."""

    DETERMINISTIC = "deterministic"
    INTEGRATION = "integration"
    LIVE = "live"


class ExpectedOutcome(StrEnum):
    """Provider-neutral outcome classes used by scenario assertions."""

    POSITIVE = "positive"
    DEGRADED = "degraded"
    DENIED = "denied"
    PARTIAL = "partial"
    AMBIGUOUS = "ambiguous"
    CANCELLED = "cancelled"
    RECOVERED = "recovered"
    SAFE_FAILURE = "safe_failure"
    QUARANTINED = "quarantined"
    ABSTAINED = "abstained"


class ResultStatus(StrEnum):
    """Evaluator disposition, separate from the system-under-evaluation outcome."""

    PASSED = "passed"
    FAILED = "failed"
    EVALUATOR_ERROR = "evaluator_error"
    CANCELLED = "cancelled"


class FailureTaxonomy(StrEnum):
    """Stable machine-readable evaluation failure categories."""

    NONE = "none"
    OUTCOME_MISMATCH = "outcome_mismatch"
    SAFETY_INVARIANT = "safety_invariant"
    POLICY_VIOLATION = "policy_violation"
    TENANT_LEAKAGE = "tenant_leakage"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    CITATION_INVALID = "citation_invalid"
    CONTRADICTION_MISSED = "contradiction_missed"
    APPROVAL_INCORRECT = "approval_incorrect"
    EFFECT_INCORRECT = "effect_incorrect"
    RECOVERY_DIVERGED = "recovery_diverged"
    BUDGET_EXCEEDED = "budget_exceeded"
    TIMEOUT = "timeout"
    FIXTURE_REJECTED = "fixture_rejected"
    EVALUATOR_FAILURE = "evaluator_failure"


class MetricDirection(StrEnum):
    """Whether a metric improves upward, downward, or must remain exact."""

    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"
    EXACT = "exact"


class FixtureClassification(StrEnum):
    """Dataset classification accepted by required evaluation infrastructure."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class FixtureDisposition(StrEnum):
    """Whether a fixture may execute or is retained only as quarantined input."""

    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DELETED = "deleted"


class InvariantSeverity(StrEnum):
    """Regression severity; hard safety invariants cannot be averaged away."""

    HARD_SAFETY = "hard_safety"
    REQUIRED = "required"
    QUALITY = "quality"


@dataclass(frozen=True, slots=True)
class DeterminismContract:
    """All entropy and time inputs needed to reproduce a run."""

    seed: int
    clock: datetime
    id_namespace: UUID
    concurrency: int = 1
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.clock.tzinfo is None:
            raise ValueError("deterministic clock must be timezone-aware")
        if not 0 <= self.seed <= 2**63 - 1:
            raise ValueError("seed is outside the supported range")
        if not 1 <= self.concurrency <= 32:
            raise ValueError("concurrency must be between 1 and 32")
        if not 1 <= self.timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be between 1 and 600")


@dataclass(frozen=True, slots=True)
class SystemFingerprint:
    """Digest-addressed versions that materially affect an evaluation result."""

    source_revision: str
    system_digest: str
    config_digest: str
    policy_digest: str
    model_digest: str
    provider_digest: str
    prompt_digest: str
    schema_digest: str
    evaluator_version: str
    python_version: str

    def __post_init__(self) -> None:
        _require_texts(
            self.source_revision,
            self.system_digest,
            self.config_digest,
            self.policy_digest,
            self.model_digest,
            self.provider_digest,
            self.prompt_digest,
            self.schema_digest,
            self.evaluator_version,
            self.python_version,
        )
        for value in (
            self.system_digest,
            self.config_digest,
            self.policy_digest,
            self.model_digest,
            self.provider_digest,
            self.prompt_digest,
            self.schema_digest,
        ):
            _require_digest(value)


@dataclass(frozen=True, slots=True)
class FixtureProvenance:
    """Governance metadata for one exact fixture snapshot."""

    fixture_id: str
    path: str
    content_digest: str
    source: str
    license: str
    consent: str
    classification: FixtureClassification
    retention_days: int
    synthetic: bool
    redacted: bool
    disposition: FixtureDisposition = FixtureDisposition.ACTIVE
    deletion_reference: str | None = None

    def __post_init__(self) -> None:
        _require_texts(
            self.fixture_id,
            self.path,
            self.source,
            self.license,
            self.consent,
        )
        _require_digest(self.content_digest)
        if self.path.startswith("/") or ".." in self.path.split("/"):
            raise ValueError("fixture path must be repository-relative and contained")
        if not 1 <= self.retention_days <= 3_650:
            raise ValueError("fixture retention_days must be between 1 and 3650")
        if (
            self.disposition is FixtureDisposition.DELETED
            and not self.deletion_reference
        ):
            raise ValueError("deleted fixtures require a deletion reference")
        if (
            not self.synthetic
            and self.classification is FixtureClassification.RESTRICTED
        ):
            raise ValueError("restricted non-synthetic fixtures cannot be checked in")


@dataclass(frozen=True, slots=True)
class DatasetManifest:
    """Versioned dataset identity plus provenance for exact fixture snapshots."""

    dataset_id: str
    schema_version: int
    version: str
    description: str
    created_at: datetime
    fixtures: tuple[FixtureProvenance, ...]
    case_ids: tuple[str, ...]
    migration_from: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "fixtures",
            tuple(sorted(self.fixtures, key=lambda item: item.fixture_id)),
        )
        object.__setattr__(self, "case_ids", tuple(sorted(self.case_ids)))
        _require_texts(self.dataset_id, self.version, self.description)
        if self.schema_version != 1:
            raise ValueError("unsupported dataset schema version")
        if self.created_at.tzinfo is None:
            raise ValueError("dataset created_at must be timezone-aware")
        _require_bounded_unique(self.fixtures, MAX_FIXTURES, "fixtures")
        _require_bounded_unique(self.case_ids, MAX_CASES, "dataset case_ids")
        fixture_ids = tuple(item.fixture_id for item in self.fixtures)
        if len(fixture_ids) != len(set(fixture_ids)):
            raise ValueError("fixture identifiers must be unique")

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class ExpectedInvariant:
    """One exact assertion expected from the system under evaluation."""

    invariant_id: str
    description: str
    severity: InvariantSeverity
    reason_code: str

    def __post_init__(self) -> None:
        _require_texts(
            self.invariant_id,
            self.description,
            self.reason_code,
        )


@dataclass(frozen=True, slots=True)
class ScorerDefinition:
    """Versioned deterministic scorer contract and denominator policy."""

    scorer_id: str
    version: str
    metric_name: str
    direction: MetricDirection
    denominator: str
    edge_case_policy: str
    tolerance: Decimal
    hard_safety: bool = False

    def __post_init__(self) -> None:
        _require_texts(
            self.scorer_id,
            self.version,
            self.metric_name,
            self.denominator,
            self.edge_case_policy,
        )
        if self.tolerance < 0:
            raise ValueError("scorer tolerance cannot be negative")


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    """One immutable scenario case dispatched only to a registered executor."""

    case_id: str
    title: str
    layer: str
    executor: str
    parameters: Mapping[str, CanonicalValue]
    expected_outcome: ExpectedOutcome
    invariants: tuple[ExpectedInvariant, ...]
    scorer_ids: tuple[str, ...]
    fixture_ids: tuple[str, ...]
    tags: tuple[str, ...]
    weight: Decimal = Decimal("1")
    timeout_seconds: int = 10

    def __post_init__(self) -> None:
        _require_texts(self.case_id, self.title, self.layer, self.executor)
        if not 1 <= len(self.invariants) <= MAX_INVARIANTS:
            raise ValueError("case invariants are outside supported bounds")
        _require_bounded_unique(self.scorer_ids, MAX_METRICS, "case scorer_ids")
        _require_bounded_unique(self.fixture_ids, MAX_FIXTURES, "case fixture_ids")
        _require_bounded_unique(self.tags, MAX_TAGS, "case tags")
        if self.weight <= 0 or self.weight > 100:
            raise ValueError("case weight must be greater than zero and at most 100")
        if not 1 <= self.timeout_seconds <= 120:
            raise ValueError("case timeout_seconds must be between 1 and 120")
        object.__setattr__(self, "parameters", _freeze_mapping(self.parameters))

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class EvaluationScenario:
    """A bounded group of cases representing one operational scenario."""

    scenario_id: str
    version: str
    description: str
    case_ids: tuple[str, ...]
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_texts(self.scenario_id, self.version, self.description)
        _require_bounded_unique(self.case_ids, MAX_CASES, "scenario case_ids")
        _require_bounded_unique(self.tags, MAX_TAGS, "scenario tags")


@dataclass(frozen=True, slots=True)
class EvaluationSuite:
    """Complete immutable execution catalog and dataset binding."""

    suite_id: str
    version: str
    description: str
    dataset: DatasetManifest
    determinism: DeterminismContract
    scenarios: tuple[EvaluationScenario, ...]
    cases: tuple[EvaluationCase, ...]
    scorers: tuple[ScorerDefinition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scenarios",
            tuple(sorted(self.scenarios, key=lambda item: item.scenario_id)),
        )
        object.__setattr__(
            self,
            "cases",
            tuple(sorted(self.cases, key=lambda item: item.case_id)),
        )
        object.__setattr__(
            self,
            "scorers",
            tuple(sorted(self.scorers, key=lambda item: item.scorer_id)),
        )
        _require_texts(self.suite_id, self.version, self.description)
        _require_bounded_unique(self.scenarios, MAX_CASES, "suite scenarios")
        if not 1 <= len(self.cases) <= MAX_CASES:
            raise ValueError("suite cases are outside supported bounds")
        _require_bounded_unique(self.scorers, MAX_METRICS, "suite scorers")
        case_ids = tuple(item.case_id for item in self.cases)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("suite case identifiers must be unique")
        scorer_ids = tuple(item.scorer_id for item in self.scorers)
        if len(scorer_ids) != len(set(scorer_ids)):
            raise ValueError("suite scorer identifiers must be unique")
        if set(case_ids) != set(self.dataset.case_ids):
            raise ValueError("dataset and suite case identifiers must match exactly")
        if any(set(case.scorer_ids) - set(scorer_ids) for case in self.cases):
            raise ValueError("case references an unknown scorer")
        fixture_ids = {item.fixture_id for item in self.dataset.fixtures}
        if any(set(case.fixture_ids) - fixture_ids for case in self.cases):
            raise ValueError("case references an unknown fixture")
        referenced_fixture_ids = {
            fixture_id for case in self.cases for fixture_id in case.fixture_ids
        }
        if referenced_fixture_ids != fixture_ids:
            raise ValueError("every governed fixture must be referenced by a case")
        flattened_scenario_case_ids = tuple(
            case_id for scenario in self.scenarios for case_id in scenario.case_ids
        )
        scenario_case_ids = set(flattened_scenario_case_ids)
        exact_coverage = len(flattened_scenario_case_ids) == len(self.cases)
        if scenario_case_ids != set(case_ids) or not exact_coverage:
            raise ValueError("scenarios must cover every case exactly by identifier")

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class ExecutionTraceReference:
    """Bounded reference into evaluator traces without raw case content."""

    phase: str
    ordinal: int
    event_type: str | None = None
    artifact_reference: str | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        _require_texts(self.phase)
        if self.ordinal < 0:
            raise ValueError("trace ordinal cannot be negative")
        for value in (self.event_type, self.artifact_reference, self.reason_code):
            if value is not None:
                _require_texts(value)


@dataclass(frozen=True, slots=True)
class CitationResult:
    """Deterministic citation validity assessment."""

    citation_id: str
    source_digest: str
    valid: bool
    reason_code: str

    def __post_init__(self) -> None:
        _require_texts(self.citation_id, self.reason_code)
        _require_digest(self.source_digest)


@dataclass(frozen=True, slots=True)
class MetricResult:
    """One machine-readable metric result with an explicit denominator."""

    metric_name: str
    scorer_id: str
    scorer_version: str
    value: Decimal | None
    numerator: Decimal
    denominator: Decimal
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_texts(self.metric_name, self.scorer_id, self.scorer_version)
        if self.numerator < 0 or self.denominator < 0:
            raise ValueError("metric numerator and denominator cannot be negative")
        if self.value is not None and not self.value.is_finite():
            raise ValueError("metric value must be finite")
        _require_bounded_unique(self.reason_codes, MAX_REFERENCES, "metric reasons")


@dataclass(frozen=True, slots=True)
class CaseResult:
    """Deterministic result for exactly one immutable case."""

    case_id: str
    case_digest: str
    status: ResultStatus
    observed_outcome: ExpectedOutcome
    failure: FailureTaxonomy
    reason_codes: tuple[str, ...]
    invariant_results: Mapping[str, bool]
    metrics: tuple[MetricResult, ...]
    citations: tuple[CitationResult, ...]
    trace: tuple[ExecutionTraceReference, ...]
    steps: int
    token_count: int
    cost_usd: Decimal
    duration_ms: int

    def __post_init__(self) -> None:
        _require_texts(self.case_id)
        _require_digest(self.case_digest)
        _require_bounded_unique(self.reason_codes, MAX_REFERENCES, "result reasons")
        if len(self.metrics) > MAX_METRICS or len(self.trace) > MAX_REFERENCES:
            raise ValueError("case result exceeds metric or trace bounds")
        if len(self.citations) > MAX_REFERENCES:
            raise ValueError("case result exceeds citation bounds")
        if any(value < 0 for value in (self.steps, self.token_count, self.duration_ms)):
            raise ValueError("case accounting cannot be negative")
        if self.cost_usd < 0:
            raise ValueError("case cost cannot be negative")
        object.__setattr__(
            self,
            "invariant_results",
            MappingProxyType(dict(sorted(self.invariant_results.items()))),
        )


@dataclass(frozen=True, slots=True)
class AppliedWaiver:
    """Report reference to a separately reviewed, scoped, unexpired waiver."""

    waiver_id: str
    owner: str
    reason: str
    case_id: str
    metric_name: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_texts(
            self.waiver_id,
            self.owner,
            self.reason,
            self.case_id,
            self.metric_name,
        )
        if self.expires_at.tzinfo is None:
            raise ValueError("waiver expiry must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Hash/signature metadata; signatures are optional but never implicit."""

    report_id: UUID
    generated_at: datetime
    suite_digest: str
    dataset_digest: str
    baseline_digest: str | None
    comparison_id: str | None
    content_digest: str
    signature_algorithm: str | None = None
    signer: str | None = None
    signature: str | None = None

    def __post_init__(self) -> None:
        if self.generated_at.tzinfo is None:
            raise ValueError("report generated_at must be timezone-aware")
        for value in (
            self.suite_digest,
            self.dataset_digest,
            self.content_digest,
        ):
            _require_digest(value)
        if self.baseline_digest is not None:
            _require_digest(self.baseline_digest)
        signature_values = (
            self.signature_algorithm,
            self.signer,
            self.signature,
        )
        if any(value is not None for value in signature_values) and not all(
            value is not None for value in signature_values
        ):
            raise ValueError("report signature metadata must be complete or absent")


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Bounded evaluation evidence that never becomes runtime authority."""

    schema_version: int
    mode: EvaluationMode
    reproducible: bool
    production_truth: bool
    fingerprint: SystemFingerprint
    results: tuple[CaseResult, ...]
    waivers: tuple[AppliedWaiver, ...]
    metadata: ReportMetadata

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported report schema version")
        if self.production_truth:
            raise ValueError("evaluation reports cannot be production truth")
        if not 1 <= len(self.results) <= MAX_CASES:
            raise ValueError("report results are outside supported bounds")
        case_ids = tuple(item.case_id for item in self.results)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("report case identifiers must be unique")
        if self.mode is EvaluationMode.DETERMINISTIC and not self.reproducible:
            raise ValueError("deterministic reports must be reproducible")
        if self.mode is EvaluationMode.LIVE and self.reproducible:
            raise ValueError("live reports must be labeled non-reproducible")

    @property
    def passed(self) -> bool:
        return all(item.status is ResultStatus.PASSED for item in self.results)


def canonical_data(value: object) -> CanonicalValue:
    """Convert supported values to deterministic JSON-compatible containers."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical floats must be finite")
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("canonical decimals must be finite")
        return format(value, "f")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("canonical datetimes must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if is_dataclass(value) and not isinstance(value, type):
        instance = cast(Any, value)
        return {
            item.name: canonical_data(getattr(instance, item.name))
            for item in fields(instance)
        }
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical mapping keys must be strings")
        return {
            str(key): canonical_data(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [canonical_data(item) for item in value]
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: object) -> str:
    """Serialize with fixed ordering and separators for stable hashing."""
    return json.dumps(
        canonical_data(value),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: object) -> str:
    """Return a lowercase SHA-256 digest of canonical serialized content."""
    return sha256(canonical_json(value).encode()).hexdigest()


def _freeze_mapping(
    value: Mapping[str, CanonicalValue],
) -> Mapping[str, CanonicalValue]:
    return MappingProxyType(
        {
            key: _freeze_value(item)
            for key, item in sorted(value.items(), key=lambda pair: pair[0])
        }
    )


def _freeze_value(value: CanonicalValue) -> CanonicalValue:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(_freeze_value(item) for item in value)
    return value


def _require_texts(*values: str) -> None:
    if any(not value or len(value) > MAX_STRING_LENGTH for value in values):
        raise ValueError("required text is empty or exceeds the supported bound")


def _require_digest(value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("digest must be lowercase SHA-256 hexadecimal")


def _require_bounded_unique(
    values: Sequence[object],
    maximum: int,
    name: str,
) -> None:
    if len(values) > maximum:
        raise ValueError(f"{name} exceeds supported bounds")
    canonical = tuple(canonical_json(item) for item in values)
    if len(canonical) != len(set(canonical)):
        raise ValueError(f"{name} must not contain duplicates")


__all__ = [
    "MAX_CASES",
    "AppliedWaiver",
    "CanonicalValue",
    "CaseResult",
    "CitationResult",
    "DatasetManifest",
    "DeterminismContract",
    "EvaluationCase",
    "EvaluationMode",
    "EvaluationReport",
    "EvaluationScenario",
    "EvaluationSuite",
    "ExecutionTraceReference",
    "ExpectedInvariant",
    "ExpectedOutcome",
    "FailureTaxonomy",
    "FixtureClassification",
    "FixtureDisposition",
    "FixtureProvenance",
    "InvariantSeverity",
    "MetricDirection",
    "MetricResult",
    "ReportMetadata",
    "ResultStatus",
    "ScorerDefinition",
    "SystemFingerprint",
    "canonical_data",
    "canonical_digest",
    "canonical_json",
]
