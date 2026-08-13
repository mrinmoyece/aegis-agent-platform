"""Deterministic behavioral evaluations for Layer 9 sandbox execution."""

from __future__ import annotations

import asyncio

import pytest

from aegis_agent_platform.sandbox.__main__ import (
    SandboxScenario,
    run_sandbox_demo,
)


@pytest.mark.parametrize(
    ("scenario", "expected_status", "required_event"),
    [
        (
            SandboxScenario.APPROVED_ANALYSIS,
            "cleaned",
            "sandbox.attested.v1",
        ),
        (
            SandboxScenario.POLICY_DENIED,
            "policy_denied",
            "sandbox.policy_evaluated.v1",
        ),
        (SandboxScenario.PROMPT_INJECTION, "rejected", None),
        (SandboxScenario.MALICIOUS_ARCHIVE, "rejected", None),
        (SandboxScenario.TIMEOUT, "cleaned", "sandbox.timed_out.v1"),
        (SandboxScenario.OOM, "cleaned", "sandbox.oom_killed.v1"),
        (
            SandboxScenario.CANCELLATION,
            "cleaned",
            "sandbox.cancelled.v1",
        ),
        (
            SandboxScenario.AMBIGUOUS_PROVISIONING,
            "cleaned",
            "sandbox.reconciled.v1",
        ),
        (
            SandboxScenario.OUTPUT_QUARANTINE,
            "cleaned",
            "sandbox.quarantined.v1",
        ),
        (
            SandboxScenario.CLEANUP_RECOVERY,
            "cleaned",
            "sandbox.reconciled.v1",
        ),
    ],
)
def test_layer9_behavioral_scenarios(
    scenario: SandboxScenario,
    expected_status: str,
    required_event: str | None,
) -> None:
    result = asyncio.run(run_sandbox_demo(scenario))

    assert result["status"] == expected_status
    if required_event is not None:
        assert required_event in result["event_types"]
    assert result["demo_only"] is True
    assert result["uses_live_network"] is False
    assert result["uses_production_credentials"] is False
    assert result["at_least_once"] is True
    assert result["claims_exactly_once"] is False
    assert result["unrestricted_exec"] is False
    assert result["redacted"] is True


def test_policy_denial_never_reaches_backend() -> None:
    result = asyncio.run(run_sandbox_demo(SandboxScenario.POLICY_DENIED))

    assert result["backend_calls"] == ()
    assert "sandbox.provisioning_requested.v1" not in result["event_types"]
