"""Coordinator-owned plans, limits, and durable artifact ledger port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.agents.artifacts import AgentArtifact, AgentRole
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class SpecialistBudget:
    """Hard execution limits assigned by the incident coordinator."""

    max_steps: int
    max_input_tokens: int
    timeout_seconds: int

    def __post_init__(self) -> None:
        """Reject disabled or nonsensical execution limits."""
        if min(self.max_steps, self.max_input_tokens, self.timeout_seconds) <= 0:
            raise ValueError("specialist budget limits must be positive")


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

    async def record(
        self,
        tenant: TenantContext,
        artifact: AgentArtifact,
    ) -> None:
        """Persist one tenant's typed artifact before it is consumed.

        Implementations must reject artifacts whose tenant ID does not match
        the validated context.
        """
        ...

    async def read_incident(
        self, tenant: TenantContext, incident_id: str
    ) -> tuple[
        AgentArtifact,
        ...,
    ]:
        """Read committed artifacts in deterministic ledger order."""
        ...
