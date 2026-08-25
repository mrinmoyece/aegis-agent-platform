"""Deterministic no-network protocol demonstration coverage."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

import pytest

from aegis_agent_platform.protocols.__main__ import (
    ProtocolDemoScenario,
    run_protocol_demo,
)


@pytest.mark.parametrize(
    ("scenario", "expected_status"),
    [
        (ProtocolDemoScenario.SAFE_RETRIEVAL, "completed"),
        (ProtocolDemoScenario.ARTIFACT_EXCHANGE, "completed"),
        (ProtocolDemoScenario.REMEDIATION_PROPOSAL, "completed"),
        (ProtocolDemoScenario.CANCELLATION, "cancelled"),
        (ProtocolDemoScenario.AMBIGUOUS_RECONCILIATION, "completed"),
        (ProtocolDemoScenario.CAPABILITY_DRIFT, "quarantined"),
        (ProtocolDemoScenario.MALICIOUS_CONTENT, "quarantined"),
        (ProtocolDemoScenario.TENANT_ATTACK, "denied"),
        (ProtocolDemoScenario.REVOCATION, "denied"),
    ],
)
def test_protocol_demo_scenarios_are_fake_only_and_fail_closed(
    scenario: ProtocolDemoScenario,
    expected_status: str,
) -> None:
    result = asyncio.run(run_protocol_demo(scenario))

    assert result["status"] == expected_status
    assert result["network"] == "deterministic-fake-only"
    assert result["raw_content_persisted"] is False
    assert result["production_ready"] is False
    event_types = result["event_types"]
    assert isinstance(event_types, Sequence)
    assert not isinstance(event_types, str)
    if scenario is ProtocolDemoScenario.ARTIFACT_EXCHANGE:
        assert "a2a.artifact_recorded.v1" in event_types
    if scenario is ProtocolDemoScenario.REMEDIATION_PROPOSAL:
        assert "mcp.invocation_completed.v1" in event_types
