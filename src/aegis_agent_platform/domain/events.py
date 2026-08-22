"""Provider-neutral, additive event contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from math import isfinite
from types import MappingProxyType
from typing import ClassVar, Self, cast
from uuid import UUID

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | Sequence[JsonValue] | Mapping[str, JsonValue]


class _StringConstant(str):
    _values: ClassVar[dict[str, Self]]

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        cls._values = {}

    def __new__(cls, value: str) -> Self:
        try:
            return cls._values[value]
        except KeyError as error:
            raise ValueError(f"{value!r} is not a valid {cls.__name__}") from error

    @classmethod
    def _define(cls, value: str) -> Self:
        member: Self = str.__new__(cls, value)
        cls._values[value] = member
        return member


class ActorKind(_StringConstant):
    """Stable categories for the principal that caused an event."""

    USER: ClassVar[ActorKind]
    SERVICE: ClassVar[ActorKind]
    SYSTEM: ClassVar[ActorKind]


ActorKind.USER = ActorKind._define("user")
ActorKind.SERVICE = ActorKind._define("service")
ActorKind.SYSTEM = ActorKind._define("system")


class DomainEventType(_StringConstant):
    """Implemented additive event names; existing meanings are never repurposed."""

    INVESTIGATION_REQUESTED: ClassVar[DomainEventType]
    RUN_STARTED: ClassVar[DomainEventType]
    RUN_STATUS_CHANGED: ClassVar[DomainEventType]
    RUN_COMPLETED: ClassVar[DomainEventType]
    RUN_FAILED: ClassVar[DomainEventType]
    ARTIFACT_RECORDED: ClassVar[DomainEventType]
    APPROVAL_REQUESTED: ClassVar[DomainEventType]
    APPROVAL_DECIDED: ClassVar[DomainEventType]
    USAGE_RECORDED: ClassVar[DomainEventType]
    SIDE_EFFECT_INTENT_RECORDED: ClassVar[DomainEventType]
    SIDE_EFFECT_COMPLETED: ClassVar[DomainEventType]
    SIDE_EFFECT_FAILED: ClassVar[DomainEventType]
    OUTBOX_DEAD_LETTERED: ClassVar[DomainEventType]
    TENANT_REGISTERED: ClassVar[DomainEventType]


DomainEventType.INVESTIGATION_REQUESTED = DomainEventType._define(
    "investigation.requested.v1"
)
DomainEventType.RUN_STARTED = DomainEventType._define("run.started.v1")
DomainEventType.RUN_STATUS_CHANGED = DomainEventType._define("run.status_changed.v1")
DomainEventType.RUN_COMPLETED = DomainEventType._define("run.completed.v1")
DomainEventType.RUN_FAILED = DomainEventType._define("run.failed.v1")
DomainEventType.ARTIFACT_RECORDED = DomainEventType._define("artifact.recorded.v1")
DomainEventType.APPROVAL_REQUESTED = DomainEventType._define("approval.requested.v1")
DomainEventType.APPROVAL_DECIDED = DomainEventType._define("approval.decided.v1")
DomainEventType.USAGE_RECORDED = DomainEventType._define("usage.recorded.v1")
DomainEventType.SIDE_EFFECT_INTENT_RECORDED = DomainEventType._define(
    "effect.intent_recorded.v1"
)
DomainEventType.SIDE_EFFECT_COMPLETED = DomainEventType._define("effect.completed.v1")
DomainEventType.SIDE_EFFECT_FAILED = DomainEventType._define("effect.failed.v1")
DomainEventType.OUTBOX_DEAD_LETTERED = DomainEventType._define(
    "delivery.outbox_dead_lettered.v1"
)
DomainEventType.TENANT_REGISTERED = DomainEventType._define("tenant.registered.v1")


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
    previous_aggregate_sequence: int | None = None
    metadata: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        """Enforce universal envelope invariants."""
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        if (
            not self.tenant_id.strip()
            or not self.aggregate_id.strip()
            or not self.event_type.strip()
        ):
            raise ValueError("tenant, aggregate, and event type are required")
        require_aware_datetime(self.occurred_at, field_name="occurred_at")
        if self.recorded_at is not None:
            require_aware_datetime(self.recorded_at, field_name="recorded_at")
        if self.aggregate_sequence < 0:
            raise ValueError("aggregate_sequence cannot be negative")
        if self.global_position is not None and self.global_position < 1:
            raise ValueError("global_position must be positive")
        if (
            self.previous_aggregate_sequence is not None
            and self.previous_aggregate_sequence < 0
        ):
            raise ValueError("previous_aggregate_sequence cannot be negative")
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
            previous_aggregate_sequence=(
                int(str(value["previous_aggregate_sequence"]))
                if value.get("previous_aggregate_sequence") is not None
                else None
            ),
            metadata=cast(Mapping[str, JsonValue], metadata),
        )


def require_aware_datetime(value: datetime, *, field_name: str) -> None:
    """Reject timestamps that cannot participate in deterministic ordering."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def freeze_json_mapping(value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    """Snapshot a JSON mapping so committed values cannot be aliased."""
    frozen: dict[str, JsonValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("JSON object keys must be strings")
        frozen[key] = freeze_json(item)
    return MappingProxyType(frozen)


def freeze_json(value: JsonValue) -> JsonValue:
    """Recursively convert mutable JSON containers to immutable values."""
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        return freeze_json_mapping(value)
    if isinstance(value, Sequence) and not isinstance(
        value,
        bytes | bytearray | memoryview | str,
    ):
        return tuple(freeze_json(item) for item in value)
    raise ValueError(f"unsupported JSON value type: {type(value).__name__}")


def thaw_json(value: JsonValue) -> JsonScalar | list[object] | dict[str, object]:
    """Return JSON-serializable containers at an infrastructure boundary."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(
        value,
        bytes | bytearray | memoryview | str,
    ):
        return [thaw_json(item) for item in value]
    return cast(JsonScalar, value)


def _optional_uuid(value: object) -> UUID | None:
    return UUID(str(value)) if value is not None else None


def _optional_string(value: object) -> str | None:
    return str(value) if value is not None else None
