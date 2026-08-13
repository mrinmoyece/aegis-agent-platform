"""Coordinator-owned plans, limits, and durable artifact ledger port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.agents.artifacts import AgentArtifact, AgentRole


@dataclass(frozen=True, slots=True)
class SpecialistBudget:
    """Hard execution limits assigned by the incident coordinator."""

    max_steps: int
    max_input_tokens: int
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class SpecialistAssignment:
    """A statically planned DAG node with least-privilege capabilities."""

    assignment_id: UUID
    role: AgentRole
    depends_on: tuple[UUID, ...]
    capabilities: frozenset[str]
    budget: SpecialistBudget
    read_only: bool


@dataclass(frozen=True, slots=True)
class InvestigationPlan:
    """Coordinator-owned immutable investigation DAG."""

    incident_id: str
    assignments: tuple[SpecialistAssignment, ...]


class ArtifactLedger(Protocol):
    """Only communication channel between incident specialists."""

    async def record(self, artifact: AgentArtifact) -> None:
        """Persist a typed artifact as an event before it is consumed."""
        ...

    async def read_incident(
        self, tenant_id: str, incident_id: str
    ) -> tuple[
        AgentArtifact,
        ...,
    ]:
        """Read committed artifacts in deterministic ledger order."""
        ...
