"""Typed specialist roles and ledger-mediated coordination artifacts."""

from aegis_agent_platform.agents.artifacts import (
    AgentArtifact,
    AgentRole,
    EvidenceArtifact,
    FindingArtifact,
    HypothesisArtifact,
    RemediationProposal,
    VerificationArtifact,
)
from aegis_agent_platform.agents.coordination import (
    ArtifactLedger,
    InvestigationPlan,
    SpecialistAssignment,
    SpecialistBudget,
)

__all__ = [
    "AgentArtifact",
    "AgentRole",
    "ArtifactLedger",
    "EvidenceArtifact",
    "FindingArtifact",
    "HypothesisArtifact",
    "InvestigationPlan",
    "RemediationProposal",
    "SpecialistAssignment",
    "SpecialistBudget",
    "VerificationArtifact",
]
