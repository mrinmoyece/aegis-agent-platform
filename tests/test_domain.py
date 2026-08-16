"""Pure domain contract tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from uuid import uuid4

import pytest

from aegis_agent_platform.domain import EventEnvelope, JsonValue
from aegis_agent_platform.tenancy import TenantContext


def test_event_envelope_accepts_additive_payload() -> None:
    envelope = EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-1",
        aggregate_id="run-1",
        event_type="RunRequested",
        schema_version=1,
        occurred_at=datetime.now(UTC),
        payload={"input": {"kind": "text"}, "tags": ["learning"]},
    )

    assert envelope.schema_version == 1


def test_event_envelope_snapshots_mutable_payloads() -> None:
    tags = ["learning"]
    payload: dict[str, JsonValue] = {"tags": tags}
    envelope = EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-1",
        aggregate_id="run-1",
        event_type="RunRequested",
        schema_version=1,
        occurred_at=datetime.now(UTC),
        payload=payload,
    )

    tags.append("mutated")
    payload["added"] = True

    assert envelope.payload == {"tags": ("learning",)}


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"schema_version": 0}, "schema_version"),
        ({"tenant_id": ""}, "tenant"),
        ({"occurred_at": datetime.now()}, "timezone-aware"),
    ],
)
def test_event_envelope_rejects_invalid_universal_fields(
    changes: dict[str, object],
    message: str,
) -> None:
    values = {
        "event_id": uuid4(),
        "tenant_id": "tenant-1",
        "aggregate_id": "run-1",
        "event_type": "RunRequested",
        "schema_version": 1,
        "occurred_at": datetime.now(UTC),
        "payload": {},
    }
    values.update(changes)

    with pytest.raises(ValueError, match=message):
        EventEnvelope(**values)  # type: ignore[arg-type]


def test_tenant_context_is_explicit() -> None:
    for tenant_id in ("", "   "):
        with pytest.raises(ValueError, match="tenant_id"):
            TenantContext(tenant_id)


class NaiveTimezone(tzinfo):
    """Timezone object that deliberately reports no UTC offset."""

    def utcoffset(self, dt: datetime | None) -> None:
        del dt
        return None

    def dst(self, dt: datetime | None) -> timedelta:
        del dt
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        del dt
        return "naive-offset"


def test_event_rejects_timezone_without_utc_offset() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        EventEnvelope(
            event_id=uuid4(),
            tenant_id="tenant-1",
            aggregate_id="run-1",
            event_type="RunRequested",
            schema_version=1,
            occurred_at=datetime(2026, 8, 16, tzinfo=NaiveTimezone()),
            payload={},
        )
