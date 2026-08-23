"""Cross-boundary foundation contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from math import inf, nan
from typing import Any
from uuid import uuid4

import pytest
from scripts.check_manifests import (
    dockerfile_final_user,
    keycloak_mapper_matches,
    unpinned_workflow_actions,
)

import aegis_agent_platform.providers as providers
from aegis_agent_platform.domain import EventEnvelope
from aegis_agent_platform.domain import ModelRequest as DomainModelRequest
from aegis_agent_platform.integrations.dynatrace import (
    SignalKind,
    TelemetryEvidence,
)
from aegis_agent_platform.integrations.github import ChangeEvidence, ChangeKind
from aegis_agent_platform.providers import (
    LegacyModelMessage,
    LegacyModelRequest,
    LegacyModelResponse,
)
from aegis_agent_platform.queueing import Lease


def test_keycloak_mapper_validation_checks_security_configuration() -> None:
    mapper: dict[str, Any] = {
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.client.audience": "aegis-control-plane",
            "access.token.claim": "true",
        },
    }

    assert keycloak_mapper_matches(
        mapper,
        mapper_type="oidc-audience-mapper",
        required_config={
            "included.client.audience": "aegis-control-plane",
            "access.token.claim": "true",
        },
    )
    mapper["config"]["access.token.claim"] = "false"
    assert not keycloak_mapper_matches(
        mapper,
        mapper_type="oidc-audience-mapper",
        required_config={
            "included.client.audience": "aegis-control-plane",
            "access.token.claim": "true",
        },
    )


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


def test_event_payload_rejects_unsupported_mutable_values() -> None:
    with pytest.raises(ValueError, match="unsupported JSON"):
        EventEnvelope(
            event_id=uuid4(),
            tenant_id="tenant-1",
            aggregate_id="incident-1",
            event_type="EvidenceRecorded",
            schema_version=1,
            occurred_at=datetime.now(UTC),
            payload={"value": {1, 2}},  # type: ignore[dict-item]
        )


def test_event_payload_rejects_non_string_object_keys() -> None:
    with pytest.raises(ValueError, match="keys must be strings"):
        EventEnvelope(
            event_id=uuid4(),
            tenant_id="tenant-1",
            aggregate_id="incident-1",
            event_type="EvidenceRecorded",
            schema_version=1,
            occurred_at=datetime.now(UTC),
            payload={1: "value"},  # type: ignore[dict-item]
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
    request = LegacyModelRequest(
        model="reasoning-model",
        messages=(LegacyModelMessage(role="user", content="Investigate"),),
        temperature=0.2,
        max_output_tokens=1_000,
    )

    assert request.temperature == 0.2
    with pytest.raises(ValueError, match="temperature"):
        LegacyModelRequest(model="model", messages=(), temperature=3.0)


@pytest.mark.parametrize(
    ("input_tokens", "output_tokens"),
    [(-1, 0), (0, -1)],
)
def test_model_response_rejects_negative_usage(
    input_tokens: int,
    output_tokens: int,
) -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        LegacyModelResponse(
            content="result",
            finish_reason="stop",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )


def test_providers_model_request_export_points_to_domain_contract() -> None:
    assert providers.ModelRequest is DomainModelRequest


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


def test_reusable_workflow_must_be_sha_pinned() -> None:
    workflow = {
        "jobs": {
            "reusable": {
                "uses": "example/automation/.github/workflows/build.yml@main",
            }
        }
    }

    assert unpinned_workflow_actions(workflow) == [
        "example/automation/.github/workflows/build.yml@main"
    ]


def test_local_reusable_workflow_does_not_require_sha() -> None:
    workflow = {
        "jobs": {
            "reusable": {
                "uses": "./.github/workflows/build.yml",
            }
        }
    }

    assert unpinned_workflow_actions(workflow) == []
