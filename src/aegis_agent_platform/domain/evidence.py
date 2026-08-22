"""Pure immutable contracts for untrusted incident evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType

from aegis_agent_platform.domain.events import JsonValue, freeze_json_mapping


def _identifier(value: str, name: str, *, maximum: int = 256) -> None:
    if not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name} must be a normalized non-empty identifier")


@dataclass(frozen=True, slots=True, order=True)
class EvidenceId:
    value: str

    def __post_init__(self) -> None:
        _identifier(self.value, "evidence_id", maximum=80)

    def __str__(self) -> str:
        return self.value


class EvidenceSourceKind(StrEnum):
    DYNATRACE = "dynatrace"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    RUNBOOK = "runbook"


class EvidenceKind(StrEnum):
    LOG = "log"
    METRIC = "metric"
    TRACE = "trace"
    SPAN = "span"
    PROBLEM = "problem"
    EVENT = "event"
    ENTITY = "entity"
    TOPOLOGY = "topology"
    CHANGE = "change"
    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    REVIEW = "review"
    CHECK = "check"
    WORKFLOW = "workflow"
    DEPLOYMENT = "deployment"
    RELEASE = "release"
    TAG = "tag"
    WORKLOAD = "workload"
    POD = "pod"
    REPLICA_SET = "replica_set"
    RUNBOOK = "runbook"


class EvidenceSeverity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class RetentionClass(StrEnum):
    TRANSIENT = "transient"
    INCIDENT = "incident"
    AUDIT = "audit"
    LEGAL_HOLD = "legal_hold"


class TrustStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    UNTRUSTED = "untrusted"


class CorrelationLinkKind(StrEnum):
    EXACT_IDENTIFIER = "exact_identifier"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    RESOURCE_MATCH = "resource_match"
    DEPLOYMENT_CHANGE = "deployment_change"
    RUNBOOK_APPLICABILITY = "runbook_applicability"
    SOURCE_CONFLICT = "source_conflict"


@dataclass(frozen=True, slots=True, order=True)
class EnvironmentIdentity:
    name: str

    def __post_init__(self) -> None:
        _identifier(self.name, "environment")


@dataclass(frozen=True, slots=True, order=True)
class ServiceIdentity:
    name: str

    def __post_init__(self) -> None:
        _identifier(self.name, "service")


@dataclass(frozen=True, slots=True, order=True)
class ResourceIdentity:
    kind: str
    name: str
    namespace: str | None = None
    cluster: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.kind, "resource kind")
        _identifier(self.name, "resource name")
        if self.namespace is not None:
            _identifier(self.namespace, "namespace")
        if self.cluster is not None:
            _identifier(self.cluster, "cluster")


@dataclass(frozen=True, slots=True)
class QueryWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("query window timestamps must be timezone-aware")
        if self.end <= self.start:
            raise ValueError("query window end must follow start")


@dataclass(frozen=True, slots=True, order=True)
class TraceReference:
    trace_id: str

    def __post_init__(self) -> None:
        _identifier(self.trace_id, "trace_id")


@dataclass(frozen=True, slots=True, order=True)
class SpanReference:
    trace_id: str
    span_id: str

    def __post_init__(self) -> None:
        _identifier(self.trace_id, "trace_id")
        _identifier(self.span_id, "span_id")


@dataclass(frozen=True, slots=True, order=True)
class LogReference:
    log_id: str

    def __post_init__(self) -> None:
        _identifier(self.log_id, "log_id")


@dataclass(frozen=True, slots=True, order=True)
class MetricReference:
    metric_key: str

    def __post_init__(self) -> None:
        _identifier(self.metric_key, "metric_key")


@dataclass(frozen=True, slots=True, order=True)
class ChangeReference:
    commit_sha: str
    repository: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.commit_sha, "commit_sha")
        if self.repository is not None:
            _identifier(self.repository, "repository")


@dataclass(frozen=True, slots=True, order=True)
class DeploymentReference:
    revision: str
    image_digest: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.revision, "deployment revision")
        if self.image_digest is not None:
            _identifier(self.image_digest, "image digest")


@dataclass(frozen=True, slots=True, order=True)
class ProblemReference:
    problem_id: str

    def __post_init__(self) -> None:
        _identifier(self.problem_id, "problem_id")


@dataclass(frozen=True, slots=True, order=True)
class RunbookReference:
    path: str
    version: str

    def __post_init__(self) -> None:
        _identifier(self.path, "runbook path", maximum=1024)
        _identifier(self.version, "runbook version")


type EvidenceReference = (
    TraceReference
    | SpanReference
    | LogReference
    | MetricReference
    | ChangeReference
    | DeploymentReference
    | ProblemReference
    | RunbookReference
)


@dataclass(frozen=True, slots=True)
class Provenance:
    uri: str
    source_record_id: str
    retrieved_at: datetime
    trust: TrustStatus = TrustStatus.UNVERIFIED

    def __post_init__(self) -> None:
        if not self.uri.startswith(
            ("https://", "aegis-object://", "git+https://", "file://")
        ):
            raise ValueError("provenance URI uses an unsupported scheme")
        _identifier(self.source_record_id, "source record id", maximum=1024)
        if self.retrieved_at.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class RedactionMetadata:
    applied: bool
    rule_ids: Sequence[str] = ()
    removed_bytes: int = 0

    def __post_init__(self) -> None:
        if self.removed_bytes < 0:
            raise ValueError("removed bytes cannot be negative")
        rules = tuple(self.rule_ids)
        if self.applied != bool(rules):
            raise ValueError("redaction state must match rule identifiers")
        object.__setattr__(self, "rule_ids", rules)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: EvidenceId
    tenant_id: str
    source: EvidenceSourceKind
    kind: EvidenceKind
    environment: EnvironmentIdentity
    observed_at: datetime
    ingested_at: datetime
    query_window: QueryWindow
    summary: str
    fields: Mapping[str, JsonValue]
    provenance: Provenance
    content_digest: str
    classification: DataClassification
    retention: RetentionClass
    redaction: RedactionMetadata
    service: ServiceIdentity | None = None
    resource: ResourceIdentity | None = None
    severity: EvidenceSeverity = EvidenceSeverity.UNKNOWN
    source_confidence: float | None = None
    references: Sequence[EvidenceReference] = ()
    raw_payload_reference: str | None = None
    knowledge: bool = False

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        if self.observed_at.tzinfo is None or self.ingested_at.tzinfo is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        if not self.summary or len(self.summary.encode()) > 4096:
            raise ValueError("evidence summary must be between 1 and 4096 bytes")
        if len(self.content_digest) != 64 or any(
            value not in "0123456789abcdef" for value in self.content_digest
        ):
            raise ValueError("content digest must be lowercase SHA-256")
        if self.source_confidence is not None and not 0 <= self.source_confidence <= 1:
            raise ValueError("source confidence must be between 0 and 1")
        if (
            self.raw_payload_reference is not None
            and not self.raw_payload_reference.startswith("aegis-object://")
        ):
            raise ValueError("raw payloads require an encrypted object reference")
        if self.knowledge != (self.kind is EvidenceKind.RUNBOOK):
            raise ValueError("only runbooks are retrieved knowledge")
        object.__setattr__(self, "fields", freeze_json_mapping(self.fields))
        object.__setattr__(self, "references", tuple(self.references))


@dataclass(frozen=True, slots=True)
class PaginationCursor:
    value: str

    def __post_init__(self) -> None:
        _identifier(self.value, "pagination cursor", maximum=2048)


@dataclass(frozen=True, slots=True)
class PartialResult:
    partial: bool
    truncated: bool
    reasons: Sequence[str] = ()
    omitted_records: int = 0
    omitted_bytes: int = 0

    def __post_init__(self) -> None:
        if self.omitted_records < 0 or self.omitted_bytes < 0:
            raise ValueError("omission counts cannot be negative")
        reasons = tuple(self.reasons)
        if (self.partial or self.truncated) and not reasons:
            raise ValueError("partial results require explicit reasons")
        object.__setattr__(self, "reasons", reasons)


@dataclass(frozen=True, slots=True)
class CorrelationLink:
    left: EvidenceId
    right: EvidenceId
    kind: CorrelationLinkKind
    confidence: float
    rationale: str
    ambiguous: bool = False

    def __post_init__(self) -> None:
        if self.left == self.right:
            raise ValueError("correlation link endpoints must differ")
        if not 0 <= self.confidence <= 1 or not self.rationale:
            raise ValueError("correlation requires confidence and rationale")


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    occurred_at: datetime
    evidence_ids: Sequence[EvidenceId]
    summary: str

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None or not self.summary:
            raise ValueError("timeline entry requires time and summary")
        identifiers = tuple(sorted(set(self.evidence_ids)))
        if not identifiers:
            raise ValueError("timeline entry requires evidence")
        object.__setattr__(self, "evidence_ids", identifiers)


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    bundle_id: str
    tenant_id: str
    environment: EnvironmentIdentity
    generated_at: datetime
    evidence: Sequence[EvidenceRecord]
    timeline: Sequence[TimelineEntry]
    links: Sequence[CorrelationLink]
    source_conflicts: Sequence[CorrelationLink] = ()
    clock_skew_seconds: int = 120
    metadata: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        _identifier(self.bundle_id, "bundle_id")
        _identifier(self.tenant_id, "tenant_id")
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        if not 0 <= self.clock_skew_seconds <= 3600:
            raise ValueError("clock skew tolerance must be between 0 and 3600")
        evidence = tuple(sorted(self.evidence, key=lambda item: str(item.evidence_id)))
        timeline = tuple(sorted(self.timeline, key=lambda item: item.occurred_at))
        links = tuple(
            sorted(
                self.links,
                key=lambda item: (str(item.left), str(item.right), item.kind.value),
            )
        )
        conflicts = tuple(
            link for link in links if link.kind is CorrelationLinkKind.SOURCE_CONFLICT
        )
        if tuple(self.source_conflicts) != conflicts:
            raise ValueError("source conflicts must be preserved explicitly")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "timeline", timeline)
        object.__setattr__(self, "links", links)
        object.__setattr__(self, "source_conflicts", conflicts)
        object.__setattr__(self, "metadata", freeze_json_mapping(self.metadata))


__all__ = [
    "ChangeReference",
    "CorrelationLink",
    "CorrelationLinkKind",
    "DataClassification",
    "DeploymentReference",
    "EnvironmentIdentity",
    "EvidenceBundle",
    "EvidenceId",
    "EvidenceKind",
    "EvidenceRecord",
    "EvidenceReference",
    "EvidenceSeverity",
    "EvidenceSourceKind",
    "LogReference",
    "MetricReference",
    "PaginationCursor",
    "PartialResult",
    "ProblemReference",
    "Provenance",
    "QueryWindow",
    "RedactionMetadata",
    "ResourceIdentity",
    "RetentionClass",
    "RunbookReference",
    "ServiceIdentity",
    "SpanReference",
    "TimelineEntry",
    "TraceReference",
    "TrustStatus",
]
