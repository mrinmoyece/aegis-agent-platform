"""Versioned provider-neutral observability semantic conventions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

SEMANTIC_SCHEMA_VERSION = "1.0.0"


class TelemetryStatus(StrEnum):
    """Stable lifecycle outcomes shared by spans, logs, and metrics."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    DEGRADED = "degraded"
    PARTIAL = "partial"
    AMBIGUOUS = "ambiguous"
    QUARANTINED = "quarantined"
    ABSTAINED = "abstained"


class ErrorClass(StrEnum):
    """Secret-safe failure classes; exception messages are never attributes."""

    NONE = "none"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY = "policy"
    CONFLICT = "conflict"
    FENCING = "fencing"
    RATE_LIMIT = "rate_limit"
    BUDGET = "budget"
    TIMEOUT = "timeout"
    DEPENDENCY = "dependency"
    PROVIDER = "provider"
    CORRUPTION = "corruption"
    INTERNAL = "internal"


class Retryability(StrEnum):
    """Whether a classified failure may be retried."""

    NOT_APPLICABLE = "not_applicable"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"
    UNKNOWN = "unknown"


class Ambiguity(StrEnum):
    """Whether an external effect outcome is known."""

    NONE = "none"
    CONFIRMED = "confirmed"
    POSSIBLE = "possible"
    REQUIRES_RECONCILIATION = "requires_reconciliation"


class RecoveryOutcome(StrEnum):
    """Stable reconciliation disposition."""

    NOT_ATTEMPTED = "not_attempted"
    RECOVERED = "recovered"
    UNCHANGED = "unchanged"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class MetricKind(StrEnum):
    """Supported metric instrument kinds."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    """Reviewed metric contract with a bounded label and unit surface."""

    name: str
    kind: MetricKind
    unit: str
    owner: str
    description: str
    labels: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()
    business_outcome: bool = False

    def __post_init__(self) -> None:
        if not self.name.startswith("aegis_") or not self.owner:
            raise ValueError("metric name and owner are required")
        if self.kind is MetricKind.HISTOGRAM and not self.buckets:
            raise ValueError("histograms require explicit buckets")
        if self.kind is not MetricKind.HISTOGRAM and self.buckets:
            raise ValueError("only histograms may define buckets")
        if any(label not in ALLOWED_METRIC_LABELS for label in self.labels):
            raise ValueError("metric contains a forbidden label")


ALLOWED_METRIC_LABELS = frozenset(
    {
        "service.name",
        "deployment.environment",
        "aegis.component",
        "aegis.operation",
        "aegis.status",
        "aegis.error.class",
        "aegis.retryability",
        "aegis.risk.class",
        "aegis.provider.family",
        "aegis.connector.family",
        "aegis.backend.family",
        "aegis.queue.state",
        "aegis.work.state",
        "aegis.agent.role",
    }
)

FORBIDDEN_METRIC_LABEL_FRAGMENTS = (
    "tenant",
    "user",
    "principal",
    "run_id",
    "incident",
    "artifact",
    "target",
    "correlation",
    "trace_id",
    "span_id",
    "message",
    "prompt",
    "evidence",
    "url",
    "exception",
)

STANDARD_ATTRIBUTES = frozenset(
    ALLOWED_METRIC_LABELS
    | {
        "aegis.schema.version",
        "aegis.lifecycle.status",
        "aegis.ambiguity",
        "aegis.recovery.outcome",
        "aegis.sampled",
    }
)

OPERATIONS = frozenset(
    {
        "api.request",
        "ledger.append",
        "ledger.read",
        "ledger.replay",
        "outbox.publish",
        "queue.consume",
        "work.claim",
        "work.execute",
        "work.reconcile",
        "model.route",
        "model.attempt",
        "connector.query",
        "evidence.connector.query",
        "evidence.correlation",
        "evidence.ingest",
        "evidence.correlate",
        "specialist.execute",
        "coordinator.aggregate",
        "approval.decide",
        "action.preflight",
        "action.execute",
        "action.reconcile",
        "action.verify",
        "remediation.preflight",
        "remediation.dry_run",
        "remediation.execute",
        "remediation.reconcile",
        "remediation.verify",
        "sandbox.policy",
        "sandbox.provision",
        "sandbox.execute",
        "sandbox.start",
        "sandbox.collect",
        "sandbox.reconcile",
        "sandbox.scan",
        "sandbox.cleanup",
        "memory.ingest",
        "memory.retrieve",
        "memory.index",
        "memory.retain",
        "eval.run",
        "eval.case",
        "eval.compare",
        "observability.timeline",
        "observability.support_report",
        "replay.validate",
        "replay.fold",
        "replay.diff",
        "projection.rebuild",
    }
)

LOG_EVENTS = frozenset(
    {
        f"{operation}.{status.value}.v1"
        for operation in OPERATIONS
        for status in TelemetryStatus
    }
)

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
_LAG_BUCKETS = (0.1, 0.5, 1, 5, 15, 30, 60, 300, 900, 3600)
_SIZE_BUCKETS = (256, 1024, 4096, 16384, 65536, 262144, 1048576)


def _counter(
    name: str,
    owner: str,
    description: str,
    labels: tuple[str, ...] = (),
    *,
    unit: str = "{event}",
    business_outcome: bool = False,
) -> MetricDefinition:
    return MetricDefinition(
        name,
        MetricKind.COUNTER,
        unit,
        owner,
        description,
        labels,
        business_outcome=business_outcome,
    )


def _gauge(
    name: str,
    unit: str,
    owner: str,
    description: str,
    labels: tuple[str, ...] = (),
) -> MetricDefinition:
    return MetricDefinition(name, MetricKind.GAUGE, unit, owner, description, labels)


def _histogram(
    name: str,
    unit: str,
    owner: str,
    description: str,
    buckets: tuple[float, ...],
    labels: tuple[str, ...] = (),
) -> MetricDefinition:
    return MetricDefinition(
        name,
        MetricKind.HISTOGRAM,
        unit,
        owner,
        description,
        labels,
        buckets,
    )


_STATUS_LABEL = ("aegis.status",)
_COMPONENT_LABEL = ("aegis.component",)
_PROVIDER_LABEL = ("aegis.provider.family",)
_CONNECTOR_LABEL = ("aegis.connector.family",)
_ROLE_LABEL = ("aegis.agent.role",)
_BACKEND_LABEL = ("aegis.backend.family",)

_METRIC_DEFINITIONS = (
    _histogram(
        "aegis_api_request_duration_seconds",
        "s",
        "control-plane",
        "Authenticated API request latency.",
        _LATENCY_BUCKETS,
        _STATUS_LABEL,
    ),
    _counter(
        "aegis_api_requests_total",
        "control-plane",
        "Bounded API outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_tenant_access_denials_total",
        "identity",
        "Tenant authorization denials.",
        ("aegis.error.class",),
        business_outcome=True,
    ),
    _histogram(
        "aegis_ledger_append_duration_seconds",
        "s",
        "storage",
        "Committed event append latency.",
        _LATENCY_BUCKETS,
    ),
    _counter(
        "aegis_ledger_events_appended_total",
        "storage",
        "Events committed to the ledger.",
        business_outcome=True,
    ),
    _counter(
        "aegis_ledger_append_conflicts_total",
        "storage",
        "Optimistic append conflicts.",
    ),
    _counter(
        "aegis_ledger_replay_corruption_total",
        "storage",
        "Replay integrity failures.",
    ),
    _histogram(
        "aegis_outbox_lag_seconds",
        "s",
        "runtime",
        "Age of publishable outbox work.",
        _LAG_BUCKETS,
    ),
    _gauge(
        "aegis_queue_pending_messages",
        "{message}",
        "runtime",
        "Pending queue delivery count.",
        ("aegis.queue.state",),
    ),
    _histogram(
        "aegis_queue_oldest_pending_age_seconds",
        "s",
        "runtime",
        "Oldest pending delivery age.",
        _LAG_BUCKETS,
    ),
    _gauge(
        "aegis_worker_active_leases",
        "{lease}",
        "runtime",
        "Active fenced work leases.",
        _STATUS_LABEL,
    ),
    _counter(
        "aegis_worker_fence_rejections_total",
        "runtime",
        "Rejected stale lease writes.",
        business_outcome=True,
    ),
    _counter(
        "aegis_worker_retries_total",
        "runtime",
        "Scheduled work retries.",
        ("aegis.retryability",),
    ),
    _counter(
        "aegis_worker_outcomes_total",
        "runtime",
        "Terminal work outcomes.",
        ("aegis.work.state",),
        business_outcome=True,
    ),
    _gauge(
        "aegis_worker_dlq_messages",
        "{message}",
        "runtime",
        "Dead-letter work depth.",
    ),
    _counter(
        "aegis_worker_redrive_total",
        "runtime",
        "Approved dead-letter redrives.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _histogram(
        "aegis_provider_request_duration_seconds",
        "s",
        "model-gateway",
        "Model provider attempt latency.",
        _LATENCY_BUCKETS,
        _PROVIDER_LABEL + _STATUS_LABEL,
    ),
    _counter(
        "aegis_provider_tokens_total",
        "model-gateway",
        "Provider token usage recorded once from durable usage outcomes.",
        _PROVIDER_LABEL,
        unit="{token}",
        business_outcome=True,
    ),
    _counter(
        "aegis_provider_cost_microusd_total",
        "model-gateway",
        "Provider cost in integer micro-US dollars.",
        _PROVIDER_LABEL,
        unit="uUSD",
        business_outcome=True,
    ),
    _counter(
        "aegis_provider_fallbacks_total",
        "model-gateway",
        "Gateway fallback decisions.",
        _PROVIDER_LABEL,
    ),
    _counter(
        "aegis_provider_budget_denials_total",
        "model-gateway",
        "Budget enforcement denials.",
        _PROVIDER_LABEL,
        business_outcome=True,
    ),
    _gauge(
        "aegis_provider_circuit_state",
        "{state}",
        "model-gateway",
        "Provider circuit state encoded as 0 closed, 1 open, 2 half-open.",
        _PROVIDER_LABEL,
    ),
    _histogram(
        "aegis_connector_freshness_seconds",
        "s",
        "evidence",
        "Age of newest accepted source evidence.",
        _LAG_BUCKETS,
        _CONNECTOR_LABEL,
    ),
    _histogram(
        "aegis_connector_cursor_lag_seconds",
        "s",
        "evidence",
        "Source cursor wall-clock lag.",
        _LAG_BUCKETS,
        _CONNECTOR_LABEL,
    ),
    _counter(
        "aegis_connector_quarantines_total",
        "evidence",
        "Quarantined connector records.",
        _CONNECTOR_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_specialist_tasks_total",
        "coordinator",
        "Terminal specialist outcomes.",
        _ROLE_LABEL + _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_specialist_abstentions_total",
        "coordinator",
        "Grounded specialist abstentions.",
        _ROLE_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_specialist_critic_outcomes_total",
        "coordinator",
        "Critic review outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_approval_outcomes_total",
        "remediation",
        "Approval lifecycle outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_action_outcomes_total",
        "remediation",
        "Controlled action outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_action_reconciliation_total",
        "remediation",
        "Ambiguous action reconciliation outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_action_verification_total",
        "remediation",
        "Post-action verification outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _histogram(
        "aegis_sandbox_provision_duration_seconds",
        "s",
        "sandbox",
        "Sandbox provisioning latency.",
        _LATENCY_BUCKETS,
        _BACKEND_LABEL + _STATUS_LABEL,
    ),
    _histogram(
        "aegis_sandbox_runtime_seconds",
        "s",
        "sandbox",
        "Sandbox execution duration.",
        _LAG_BUCKETS,
        _BACKEND_LABEL + _STATUS_LABEL,
    ),
    _histogram(
        "aegis_sandbox_resource_bytes",
        "By",
        "sandbox",
        "Bounded sandbox resource observations.",
        _SIZE_BUCKETS,
        _BACKEND_LABEL,
    ),
    _counter(
        "aegis_sandbox_cleanup_total",
        "sandbox",
        "Sandbox cleanup outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _gauge(
        "aegis_sandbox_quarantined",
        "{sandbox}",
        "sandbox",
        "Quarantined sandbox projection count.",
        _BACKEND_LABEL,
    ),
    _counter(
        "aegis_memory_ingest_total",
        "memory",
        "Terminal memory ingestion outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _histogram(
        "aegis_memory_retrieval_duration_seconds",
        "s",
        "memory",
        "Authorized memory retrieval latency.",
        _LATENCY_BUCKETS,
        _STATUS_LABEL,
    ),
    _counter(
        "aegis_memory_cache_outcomes_total",
        "memory",
        "Memory cache hit and miss outcomes.",
        _STATUS_LABEL,
    ),
    _histogram(
        "aegis_memory_index_lag_seconds",
        "s",
        "memory",
        "Lag between accepted memory and index completion.",
        _LAG_BUCKETS,
        _BACKEND_LABEL,
    ),
    _counter(
        "aegis_memory_retention_total",
        "memory",
        "Memory retention and deletion outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_eval_cases_total",
        "evaluation",
        "Deterministic evaluation outcomes.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_eval_regressions_total",
        "evaluation",
        "Reviewed baseline regressions.",
        _STATUS_LABEL,
        business_outcome=True,
    ),
    _counter(
        "aegis_eval_safety_violations_total",
        "evaluation",
        "Hard safety invariant violations.",
        business_outcome=True,
    ),
    _counter(
        "aegis_telemetry_dropped_total",
        "observability",
        "Telemetry rejected, rate-limited, or dropped by reason.",
        ("aegis.error.class",),
    ),
    _gauge(
        "aegis_telemetry_exporter_healthy",
        "{state}",
        "observability",
        "Exporter health: 1 healthy, 0 unavailable.",
        _COMPONENT_LABEL,
    ),
    _counter(
        "aegis_telemetry_export_failures_total",
        "observability",
        "Bounded exporter failures.",
        _COMPONENT_LABEL,
    ),
)

METRICS = MappingProxyType(
    {definition.name: definition for definition in _METRIC_DEFINITIONS}
)


def validate_metric_labels(labels: tuple[str, ...]) -> None:
    """Reject identifiers, free text, and undeclared metric dimensions."""
    for label in labels:
        normalized = label.lower()
        if label not in ALLOWED_METRIC_LABELS or any(
            fragment in normalized for fragment in FORBIDDEN_METRIC_LABEL_FRAGMENTS
        ):
            raise ValueError(f"forbidden metric label: {label}")


def require_operation(operation: str) -> str:
    """Return a registered stable operation name."""
    if operation not in OPERATIONS:
        raise ValueError("unrecognized observability operation")
    return operation


__all__ = [
    "ALLOWED_METRIC_LABELS",
    "FORBIDDEN_METRIC_LABEL_FRAGMENTS",
    "LOG_EVENTS",
    "METRICS",
    "OPERATIONS",
    "SEMANTIC_SCHEMA_VERSION",
    "STANDARD_ATTRIBUTES",
    "Ambiguity",
    "ErrorClass",
    "MetricDefinition",
    "MetricKind",
    "RecoveryOutcome",
    "Retryability",
    "TelemetryStatus",
    "require_operation",
    "validate_metric_labels",
]
