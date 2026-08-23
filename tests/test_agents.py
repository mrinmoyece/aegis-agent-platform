"""Multi-agent artifact and coordination contract tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from uuid import uuid4

import pytest

from aegis_agent_platform.agents import (
    AgentRole,
    FindingArtifact,
    SpecialistAssignment,
    SpecialistBudget,
    VerificationArtifact,
)


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


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"max_steps": 0, "max_input_tokens": 1, "timeout_seconds": 1}, "between"),
        ({"max_steps": 1, "max_input_tokens": -1, "timeout_seconds": 1}, "between"),
        ({"max_steps": 1, "max_input_tokens": 1, "timeout_seconds": 0}, "between"),
    ],
)
def test_specialist_budget_requires_positive_limits(
    values: dict[str, int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        SpecialistBudget(**values)


def test_verification_requires_evidence_and_positive_window() -> None:
    with pytest.raises(ValueError, match="evidence citations"):
        VerificationArtifact(
            artifact_id=uuid4(),
            tenant_id="tenant-1",
            incident_id="incident-1",
            produced_by=AgentRole.VERIFICATION_AGENT,
            created_at=datetime.now(UTC),
            recovered=True,
            evidence_ids=(),
            observation_window_seconds=60,
        )
    with pytest.raises(ValueError, match="window must be positive"):
        VerificationArtifact(
            artifact_id=uuid4(),
            tenant_id="tenant-1",
            incident_id="incident-1",
            produced_by=AgentRole.VERIFICATION_AGENT,
            created_at=datetime.now(UTC),
            recovered=True,
            evidence_ids=(uuid4(),),
            observation_window_seconds=0,
        )


def test_artifact_rejects_timezone_without_utc_offset() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        FindingArtifact(
            artifact_id=uuid4(),
            tenant_id="tenant-1",
            incident_id="incident-1",
            produced_by=AgentRole.TELEMETRY_INVESTIGATOR,
            created_at=datetime(2026, 8, 16, tzinfo=NaiveTimezone()),
            statement="Checkout errors began after the deployment.",
            evidence_ids=(uuid4(),),
            confidence=0.8,
        )
