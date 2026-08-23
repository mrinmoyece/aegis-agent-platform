"""CI-gated deterministic behavioral evaluations for Layer 7."""

from __future__ import annotations

import asyncio
from typing import cast

import pytest

from aegis_agent_platform.agents import CanonicalScenario
from aegis_agent_platform.agents.__main__ import run_canonical_demo


@pytest.mark.parametrize(
    ("scenario", "expected_status"),
    [
        (CanonicalScenario.SUCCESS, "succeeded"),
        (CanonicalScenario.AMBIGUITY, "abstained"),
        (CanonicalScenario.CONTRADICTION, "abstained"),
        (CanonicalScenario.BUDGET_EXHAUSTION, "budget_exhausted"),
        (CanonicalScenario.RECOVERY, "succeeded"),
    ],
)
def test_checkout_specialist_behavioral_eval(
    scenario: CanonicalScenario,
    expected_status: str,
) -> None:
    result = asyncio.run(run_canonical_demo(scenario))

    assert result["demo_only"] is True
    assert result["uses_live_network"] is False
    assert result["executes_remediation"] is False
    assert result["status"] == expected_status
    artifacts = cast(tuple[dict[str, object], ...], result["artifacts"])
    if scenario is CanonicalScenario.BUDGET_EXHAUSTION:
        assert all(item["role"] != "change_investigator" for item in artifacts)
    else:
        assert artifacts[-1]["kind"] == "final_incident_assessment"
        assert artifacts[-1]["redacted"] is True
