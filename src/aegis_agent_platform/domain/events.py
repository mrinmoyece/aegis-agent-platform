"""Provider-neutral event contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from types import MappingProxyType
from uuid import UUID

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | Sequence[JsonValue] | Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Immutable metadata shared by every additive event schema."""

    event_id: UUID
    tenant_id: str
    aggregate_id: str
    event_type: str
    schema_version: int
    occurred_at: datetime
    payload: Mapping[str, JsonValue]
    correlation_id: UUID | None = None
    causation_id: UUID | None = None

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
        object.__setattr__(self, "payload", _freeze_json_mapping(self.payload))


def require_aware_datetime(value: datetime, *, field_name: str) -> None:
    """Reject timestamps that cannot participate in deterministic ordering."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def _freeze_json_mapping(
    value: Mapping[str, JsonValue],
) -> Mapping[str, JsonValue]:
    """Snapshot an event payload so committed event values cannot be aliased."""
    frozen: dict[str, JsonValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("JSON object keys must be strings")
        frozen[key] = _freeze_json(item)
    return MappingProxyType(frozen)


def _freeze_json(value: JsonValue) -> JsonValue:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        return _freeze_json_mapping(value)
    if isinstance(value, Sequence) and not isinstance(
        value,
        bytes | bytearray | memoryview,
    ):
        return tuple(_freeze_json(item) for item in value)
    raise ValueError(f"unsupported JSON value type: {type(value).__name__}")
