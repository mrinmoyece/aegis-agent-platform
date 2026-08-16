"""Provider-neutral event contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
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
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        object.__setattr__(self, "payload", _freeze_json_mapping(self.payload))


def _freeze_json_mapping(
    value: Mapping[str, JsonValue],
) -> Mapping[str, JsonValue]:
    """Snapshot an event payload so committed event values cannot be aliased."""
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _freeze_json(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return _freeze_json_mapping(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(_freeze_json(item) for item in value)
    return value
