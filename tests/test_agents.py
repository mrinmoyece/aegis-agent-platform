"""Multi-agent artifact and coordination contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aegis_agent_platform.agents import (
    AgentRole,
    FindingArtifact,
    SpecialistAssignment,
    SpecialistBudget,
)


def test_finding_requires_cited_evidence() -> None:
    with pytest.raises(ValueError, match="evidence citations"):
        FindingArtifact(
            artifact_id=uuid4(),
            tenant_id="tenant-1",
            incident_id="incident-1",
            produced_by=AgentRole.TELEMETRY_INVESTIGATOR,
            created_at=datetime.now(UTC),
            statement="Checkout errors began after the deployment.",
            evidence_ids=(),
            confidence=0.8,
        )


def test_assignment_carries_explicit_limits_and_capabilities() -> None:
    assignment = SpecialistAssignment(
        assignment_id=uuid4(),
        role=AgentRole.CHANGE_INVESTIGATOR,
        depends_on=(),
        capabilities=frozenset({"github:read"}),
        budget=SpecialistBudget(
            max_steps=8,
            max_input_tokens=20_000,
            timeout_seconds=120,
        ),
        read_only=True,
    )

    assert assignment.read_only
    assert assignment.capabilities == {"github:read"}
