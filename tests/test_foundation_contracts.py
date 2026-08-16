"""Cross-boundary foundation contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from math import inf, nan
from uuid import uuid4

import pytest
from scripts.check_manifests import dockerfile_final_user

from aegis_agent_platform.domain import EventEnvelope
from aegis_agent_platform.integrations.dynatrace import (
    SignalKind,
    TelemetryEvidence,
)
from aegis_agent_platform.integrations.github import ChangeEvidence, ChangeKind
from aegis_agent_platform.providers import ModelMessage, ModelRequest
from aegis_agent_platform.queueing import Lease


@pytest.mark.parametrize("value", [nan, inf, -inf])
def test_event_payload_rejects_non_json_numbers(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        EventEnvelope(
            event_id=uuid4(),
            tenant_id="tenant-1",
            aggregate_id="incident-1",
            event_type="EvidenceRecorded",
            schema_version=1,
            occurred_at=datetime.now(UTC),
            payload={"value": value},
        )


def test_evidence_and_lease_timestamps_must_be_aware() -> None:
    timestamp = datetime.now()
    with pytest.raises(ValueError, match="timezone-aware"):
        TelemetryEvidence(
            reference="dt:problem-1",
            kind=SignalKind.PROBLEM,
            observed_at=timestamp,
            summary="Checkout failures",
            attributes={},
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        ChangeEvidence(
            reference="gh:deployment-1",
            repository="example/checkout",
            revision="abc123",
            kind=ChangeKind.DEPLOYMENT,
            observed_at=timestamp,
            summary="Checkout deployment",
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        Lease(
            lease_id=uuid4(),
            tenant_id="tenant-1",
            work_id=uuid4(),
            expires_at=timestamp,
            attempt=1,
            fence=1,
        )


def test_model_request_uses_validated_portable_options() -> None:
    request = ModelRequest(
        model="reasoning-model",
        messages=(ModelMessage(role="user", content="Investigate"),),
        temperature=0.2,
        max_output_tokens=1_000,
    )

    assert request.temperature == 0.2
    with pytest.raises(ValueError, match="temperature"):
        ModelRequest(model="model", messages=(), temperature=3.0)


def test_final_docker_stage_user_parser_ignores_comments_and_prior_stages() -> None:
    dockerfile = """
    FROM python AS builder
    USER 10001:10001
    # USER 10001:10001
    FROM python AS runtime
    USER root
    """

    assert dockerfile_final_user(dockerfile) == (2, "root")


def test_final_docker_stage_user_parser_accepts_docker_whitespace() -> None:
    dockerfile = "FROM python AS builder\nFROM python AS runtime\nUSER\troot\n"

    assert dockerfile_final_user(dockerfile) == (2, "root")
