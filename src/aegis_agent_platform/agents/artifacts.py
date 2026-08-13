"""Typed artifacts exchanged through the durable event ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class AgentRole(StrEnum):
    """Fixed roles in the incident-response investigation graph."""

    INCIDENT_COORDINATOR = "incident_coordinator"
    TELEMETRY_INVESTIGATOR = "telemetry_investigator"
    CHANGE_INVESTIGATOR = "change_investigator"
    RUNTIME_INVESTIGATOR = "runtime_investigator"
    KNOWLEDGE_INVESTIGATOR = "knowledge_investigator"
    HYPOTHESIS_REVIEWER = "hypothesis_reviewer"
    REMEDIATION_PLANNER = "remediation_planner"
    VERIFICATION_AGENT = "verification_agent"


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactMetadata:
    """Identity and provenance required for every specialist artifact."""

    artifact_id: UUID
    tenant_id: str
    incident_id: str
    produced_by: AgentRole
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.incident_id:
            raise ValueError("tenant_id and incident_id are required")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceArtifact(ArtifactMetadata):
    """A fact tied to an immutable source reference."""

    source: str
    source_reference: str
    summary: str


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingArtifact(ArtifactMetadata):
    """A specialist conclusion supported by evidence citations."""

    statement: str
    evidence_ids: tuple[UUID, ...]
    confidence: float

    def __post_init__(self) -> None:
        ArtifactMetadata.__post_init__(self)
        _validate_supported_claim(self.evidence_ids, self.confidence)


@dataclass(frozen=True, slots=True, kw_only=True)
class HypothesisArtifact(ArtifactMetadata):
    """A causal hypothesis with supporting and conflicting evidence."""

    statement: str
    supporting_evidence_ids: tuple[UUID, ...]
    conflicting_evidence_ids: tuple[UUID, ...]
    confidence: float

    def __post_init__(self) -> None:
        ArtifactMetadata.__post_init__(self)
        _validate_supported_claim(self.supporting_evidence_ids, self.confidence)


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationProposal(ArtifactMetadata):
    """An exact proposed action that cannot itself confer approval."""

    action: str
    target: str
    hypothesis_id: UUID
    risk: str


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationArtifact(ArtifactMetadata):
    """Post-action recovery result tied to observed evidence."""

    recovered: bool
    evidence_ids: tuple[UUID, ...]
    observation_window_seconds: int


type AgentArtifact = (
    EvidenceArtifact
    | FindingArtifact
    | HypothesisArtifact
    | RemediationProposal
    | VerificationArtifact
)


def _validate_supported_claim(
    evidence_ids: tuple[UUID, ...],
    confidence: float,
) -> None:
    if not evidence_ids:
        raise ValueError("supported claims require evidence citations")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
