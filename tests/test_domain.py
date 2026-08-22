"""Pure domain contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    EventEnvelope,
    JsonValue,
    TraceContext,
)
from aegis_agent_platform.domain.events import thaw_json
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


def test_event_envelope_deeply_freezes_metadata_and_trace_identity() -> None:
    metadata: dict[str, JsonValue] = {"labels": [{"safe": True}]}
    envelope = EventEnvelope(
        event_id=uuid4(),
        tenant_id="tenant-1",
        aggregate_id="run-1",
        event_type="run.started.v1",
        schema_version=1,
        occurred_at=datetime.now(UTC),
        payload={},
        actor=ActorReference("service-runtime", ActorKind.SERVICE),
        trace_context=TraceContext("00-a-b-01"),
        metadata=metadata,
    )

    nested = metadata["labels"]
    assert isinstance(nested, list)
    nested.append({"safe": False})

    assert envelope.metadata == {"labels": ({"safe": True},)}
    assert envelope.actor == ActorReference("service-runtime", ActorKind.SERVICE)


def test_legacy_serialized_event_fixture_remains_replayable() -> None:
    event_id = uuid4()
    envelope = EventEnvelope.from_mapping(
        {
            "event_id": str(event_id),
            "tenant_id": "tenant-1",
            "aggregate_id": "run-legacy",
            "event_type": "RunRequested",
            "schema_version": 1,
            "occurred_at": "2025-01-01T00:00:00+00:00",
            "payload": {"legacy": True},
            "correlation_id": None,
            "causation_id": None,
        }
    )

    assert envelope.event_id == event_id
    assert envelope.aggregate_sequence == 0
    assert envelope.recorded_at is None
    assert envelope.metadata == {}


def test_current_serialized_event_restores_optional_references() -> None:
    audit_reference = uuid4()
    envelope = EventEnvelope.from_mapping(
        {
            "event_id": str(uuid4()),
            "tenant_id": "tenant-1",
            "aggregate_id": "run-current",
            "event_type": "run.started.v1",
            "schema_version": 1,
            "occurred_at": "2025-01-01T00:00:00+00:00",
            "recorded_at": "2025-01-01T00:00:01+00:00",
            "payload": {},
            "metadata": {"tags": ["safe"]},
            "actor": {"actor_id": "service-a", "kind": "service"},
            "trace_context": {
                "traceparent": "00-a-b-01",
                "tracestate": "vendor=value",
            },
            "audit_reference": str(audit_reference),
            "aggregate_sequence": 1,
            "global_position": 2,
            "idempotency_key": "request-1",
        }
    )

    assert envelope.actor == ActorReference("service-a", ActorKind.SERVICE)
    assert envelope.audit_reference == audit_reference
    assert envelope.trace_context == TraceContext("00-a-b-01", "vendor=value")
    assert thaw_json(envelope.metadata) == {"tags": ["safe"]}


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"recorded_at": datetime.now()}, "recorded_at"),
        ({"aggregate_sequence": -1}, "aggregate_sequence"),
        ({"global_position": 0}, "global_position"),
        ({"idempotency_key": ""}, "idempotency_key"),
    ],
)
def test_event_envelope_rejects_invalid_durable_fields(
    changes: dict[str, object],
    message: str,
) -> None:
    values = {
        "event_id": uuid4(),
        "tenant_id": "tenant-1",
        "aggregate_id": "run-1",
        "event_type": "run.started.v1",
        "schema_version": 1,
        "occurred_at": datetime.now(UTC),
        "payload": {},
    }
    values.update(changes)

    with pytest.raises(ValueError, match=message):
        EventEnvelope(**values)  # type: ignore[arg-type]


def test_actor_and_trace_references_require_identifiers() -> None:
    with pytest.raises(ValueError, match="actor_id"):
        ActorReference("", ActorKind.SYSTEM)
    with pytest.raises(ValueError, match="traceparent"):
        TraceContext("")


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
    with pytest.raises(ValueError, match="tenant_id"):
        TenantContext("")  # type: ignore[arg-type]
