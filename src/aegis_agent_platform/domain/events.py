"""Provider-neutral, additive event contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Self, cast
from uuid import UUID

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | Sequence[JsonValue] | Mapping[str, JsonValue]


class ActorKind(StrEnum):
    """Stable categories for the principal that caused an event."""

    USER = "user"
    SERVICE = "service"
    SYSTEM = "system"


class DomainEventType(StrEnum):
    """Implemented additive event names; existing meanings are never repurposed."""

    INVESTIGATION_REQUESTED = "investigation.requested.v1"
    RUN_STARTED = "run.started.v1"
    RUN_STATUS_CHANGED = "run.status_changed.v1"
    RUN_COMPLETED = "run.completed.v1"
    RUN_FAILED = "run.failed.v1"
    ARTIFACT_RECORDED = "artifact.recorded.v1"
    APPROVAL_REQUESTED = "approval.requested.v1"
    APPROVAL_DECIDED = "approval.decided.v1"
    USAGE_RECORDED = "usage.recorded.v1"
    SIDE_EFFECT_INTENT_RECORDED = "effect.intent_recorded.v1"
    SIDE_EFFECT_COMPLETED = "effect.completed.v1"
    SIDE_EFFECT_FAILED = "effect.failed.v1"
    OUTBOX_DEAD_LETTERED = "delivery.outbox_dead_lettered.v1"
    TENANT_REGISTERED = "tenant.registered.v1"
    WORK_REQUESTED = "work.requested.v1"
    WORK_PUBLISHED = "work.published.v1"
    WORK_CLAIMED = "work.claimed.v1"
    WORK_STARTED = "work.started.v1"
    WORK_HEARTBEAT = "work.heartbeat.v1"
    WORK_LEASE_EXPIRED = "work.lease_expired.v1"
    WORK_SUCCEEDED = "work.succeeded.v1"
    WORK_FAILED = "work.failed.v1"
    WORK_RETRY_SCHEDULED = "work.retry_scheduled.v1"
    WORK_CANCEL_REQUESTED = "work.cancel_requested.v1"
    WORK_CANCELLED = "work.cancelled.v1"
    WORK_DEAD_LETTERED = "work.dead_lettered.v1"
    WORK_RECONCILED = "work.reconciled.v1"
    MODEL_CALL_REQUESTED = "model.call_requested.v1"
    MODEL_CALL_STARTED = "model.call_started.v1"
    MODEL_CALL_ATTEMPTED = "model.call_attempted.v1"
    MODEL_CALL_SUCCEEDED = "model.call_succeeded.v1"
    MODEL_CALL_FAILED = "model.call_failed.v1"
    MODEL_CALL_TIMED_OUT = "model.call_timed_out.v1"
    MODEL_CALL_RATE_LIMITED = "model.call_rate_limited.v1"
    MODEL_CALL_CANCELLED = "model.call_cancelled.v1"
    MODEL_USAGE_RECORDED = "model.usage_recorded.v1"
    MODEL_ROUTE_DECIDED = "model.route_decided.v1"
    MODEL_FALLBACK_SELECTED = "model.fallback_selected.v1"
    MODEL_BUDGET_RESERVED = "model.budget_reserved.v1"
    MODEL_BUDGET_RELEASED = "model.budget_released.v1"
    MODEL_BUDGET_CHARGED = "model.budget_charged.v1"


@dataclass(frozen=True, slots=True)
class ActorReference:
    """Provider-neutral reference to an authenticated actor."""

    actor_id: str
    kind: ActorKind

    def __post_init__(self) -> None:
        if not self.actor_id:
            raise ValueError("actor_id is required")


@dataclass(frozen=True, slots=True)
class TraceContext:
    """W3C trace context carried as diagnostic metadata, never as truth."""

    traceparent: str
    tracestate: str | None = None

    def __post_init__(self) -> None:
        if not self.traceparent:
            raise ValueError("traceparent is required")


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Deeply immutable metadata shared by every additive event schema.

    Fields through ``payload`` are the original Layer 1 contract. All later fields
    have defaults so previously serialized fixtures remain readable.
    """

    event_id: UUID
    tenant_id: str
    aggregate_id: str
    event_type: str
    schema_version: int
    occurred_at: datetime
    payload: Mapping[str, JsonValue]
    correlation_id: UUID | None = None
    causation_id: UUID | None = None
    aggregate_sequence: int = 0
    global_position: int | None = None
    recorded_at: datetime | None = None
    actor: ActorReference | None = None
    identity_reference: str | None = None
    policy_reference: str | None = None
    audit_reference: UUID | None = None
    idempotency_key: str | None = None
    trace_context: TraceContext | None = None
    metadata: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        """Enforce universal envelope invariants."""
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        if not self.tenant_id or not self.aggregate_id or not self.event_type:
            raise ValueError("tenant, aggregate, and event type are required")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.recorded_at is not None and self.recorded_at.tzinfo is None:
            raise ValueError("recorded_at must be timezone-aware")
        if self.aggregate_sequence < 0:
            raise ValueError("aggregate_sequence cannot be negative")
        if self.global_position is not None and self.global_position < 1:
            raise ValueError("global_position must be positive")
        if self.idempotency_key is not None and not self.idempotency_key:
            raise ValueError("idempotency_key cannot be empty")
        object.__setattr__(self, "payload", freeze_json_mapping(self.payload))
        object.__setattr__(self, "metadata", freeze_json_mapping(self.metadata))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        """Decode current and legacy serialized envelopes without changing history."""
        actor_value = value.get("actor")
        actor = (
            ActorReference(
                actor_id=str(actor_value["actor_id"]),
                kind=ActorKind(str(actor_value["kind"])),
            )
            if isinstance(actor_value, Mapping)
            else None
        )
        trace_value = value.get("trace_context")
        trace_context = (
            TraceContext(
                traceparent=str(trace_value["traceparent"]),
                tracestate=(
                    str(trace_value["tracestate"])
                    if trace_value.get("tracestate") is not None
                    else None
                ),
            )
            if isinstance(trace_value, Mapping)
            else None
        )
        payload = value.get("payload")
        metadata = value.get("metadata", {})
        if not isinstance(payload, Mapping) or not isinstance(metadata, Mapping):
            raise ValueError("event payload and metadata must be mappings")
        recorded_at = value.get("recorded_at")
        audit_reference = value.get("audit_reference")
        return cls(
            event_id=UUID(str(value["event_id"])),
            tenant_id=str(value["tenant_id"]),
            aggregate_id=str(value["aggregate_id"]),
            event_type=str(value["event_type"]),
            schema_version=int(str(value["schema_version"])),
            occurred_at=datetime.fromisoformat(str(value["occurred_at"])),
            payload=cast(Mapping[str, JsonValue], payload),
            correlation_id=_optional_uuid(value.get("correlation_id")),
            causation_id=_optional_uuid(value.get("causation_id")),
            aggregate_sequence=int(str(value.get("aggregate_sequence", 0))),
            global_position=(
                int(str(value["global_position"]))
                if value.get("global_position") is not None
                else None
            ),
            recorded_at=(
                datetime.fromisoformat(str(recorded_at))
                if recorded_at is not None
                else None
            ),
            actor=actor,
            identity_reference=_optional_string(value.get("identity_reference")),
            policy_reference=_optional_string(value.get("policy_reference")),
            audit_reference=_optional_uuid(audit_reference),
            idempotency_key=_optional_string(value.get("idempotency_key")),
            trace_context=trace_context,
            metadata=cast(Mapping[str, JsonValue], metadata),
        )


def freeze_json_mapping(value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    """Snapshot a JSON mapping so committed values cannot be aliased."""
    return MappingProxyType({key: freeze_json(item) for key, item in value.items()})


def freeze_json(value: JsonValue) -> JsonValue:
    """Recursively convert mutable JSON containers to immutable values."""
    if isinstance(value, Mapping):
        return freeze_json_mapping(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(freeze_json(item) for item in value)
    return value


def thaw_json(value: JsonValue) -> JsonScalar | list[object] | dict[str, object]:
    """Return JSON-serializable containers at an infrastructure boundary."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str):
        return [thaw_json(item) for item in value]
    return value


def _optional_uuid(value: object) -> UUID | None:
    return UUID(str(value)) if value is not None else None


def _optional_string(value: object) -> str | None:
    return str(value) if value is not None else None
