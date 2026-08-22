"""Deterministic behavioral evaluations for approval-gated remediation."""

from __future__ import annotations

import asyncio

import pytest

from aegis_agent_platform.remediation.__main__ import (
    RemediationScenario,
    run_remediation_demo,
)


@pytest.mark.parametrize(
    ("scenario", "expected_status", "required_event"),
    [
        (
            RemediationScenario.APPROVED_SUCCESS,
            "verified",
            "action.verification_completed.v1",
        ),
        (
            RemediationScenario.DENIED,
            "policy_denied",
            "remediation.policy_evaluated.v1",
        ),
        (
            RemediationScenario.EXPIRED,
            "expired",
            "remediation.approval_expired.v1",
        ),
        (
            RemediationScenario.AMBIGUOUS_RECONCILED,
            "verified",
            "action.reconciliation_completed.v1",
        ),
        (
            RemediationScenario.VERIFICATION_FAILURE,
            "verification_failed",
            "action.verification_completed.v1",
        ),
        (
            RemediationScenario.POLICY_ATTACK,
            "policy_denied",
            "remediation.policy_evaluated.v1",
        ),
        (
            RemediationScenario.CRASH_RECOVERY,
            "verified",
            "action.execution_failed.v1",
        ),
    ],
)
def test_layer8_behavioral_scenarios(
    scenario: RemediationScenario,
    expected_status: str,
    required_event: str,
) -> None:
    result = asyncio.run(run_remediation_demo(scenario))

    assert result["status"] == expected_status
    assert required_event in result["event_types"]
    assert result["demo_only"] is True
    assert result["uses_live_network"] is False
    assert result["uses_production_credentials"] is False
    assert result["at_least_once"] is True
    assert result["claims_exactly_once"] is False
    assert result["redacted"] is True


def test_policy_attack_never_reaches_adapter() -> None:
    result = asyncio.run(run_remediation_demo(RemediationScenario.POLICY_ATTACK))

    assert result["adapter_calls"] == ()
    assert not any(
        event.startswith("action.execution") for event in result["event_types"]
    )
