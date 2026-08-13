"""Immutable provider-neutral artifacts committed through the event ledger."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TypedDict
from uuid import UUID

from aegis_agent_platform.domain import JsonValue

MAX_ARTIFACT_SUMMARY_BYTES = 4_096
MAX_ARTIFACT_TEXT_BYTES = 16_384
MAX_ARTIFACT_ITEMS = 64


class AgentRole(StrEnum):
    """Fixed roles in the incident-response investigation graph."""

    INCIDENT_COORDINATOR = "incident_coordinator"
    TELEMETRY_INVESTIGATOR = "telemetry_investigator"
    CHANGE_INVESTIGATOR = "change_investigator"
    RUNTIME_INVESTIGATOR = "runtime_investigator"
    KNOWLEDGE_INVESTIGATOR = "knowledge_investigator"
    CRITIC_REVIEWER = "critic_reviewer"
    HYPOTHESIS_REVIEWER = "critic_reviewer"
    REMEDIATION_PLANNER = "remediation_planner"
    VERIFICATION_AGENT = "verification_agent"


class ArtifactKind(StrEnum):
    EVIDENCE_ASSESSMENT = "evidence_assessment"
    HYPOTHESIS = "hypothesis"
    ALTERNATIVE_HYPOTHESIS = "alternative_hypothesis"
    CONTRADICTION = "contradiction"
    CRITIQUE = "critique"
    CAUSAL_GRAPH_REFERENCE = "causal_graph_reference"
    TIMELINE_REFERENCE = "timeline_reference"
    REMEDIATION_RECOMMENDATION = "remediation_recommendation"
    VERIFICATION_PLAN = "verification_plan"
    COORDINATOR_DECISION = "coordinator_decision"
    FINAL_INCIDENT_ASSESSMENT = "final_incident_assessment"


class ConfidenceCalibration(StrEnum):
    DIRECT = "direct"
    INFERRED = "inferred"
    CONTESTED = "contested"
    INSUFFICIENT = "insufficient"


class CoordinatorOutcome(StrEnum):
    FINALIZE = "finalize"
    ABSTAIN = "abstain"
    ESCALATE = "escalate"


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """Immutable citation to bounded, already-ingested evidence."""

    evidence_id: str
    source_uri: str
    content_digest: str

    def __post_init__(self) -> None:
        _bounded_text(self.evidence_id, "evidence_id", 128)
        _bounded_text(self.source_uri, "source_uri", 2_048)
        if not self.source_uri.startswith(
            ("https://", "git+https://", "file://", "aegis-object://")
        ):
            raise ValueError("citation source URI uses an unsupported scheme")
        if len(self.content_digest) != 64 or any(
            value not in "0123456789abcdef" for value in self.content_digest
        ):
            raise ValueError("citation digest must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class CalibratedConfidence:
    score: float
    calibration: ConfidenceCalibration
    rationale: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("confidence score must be between 0 and 1")
        _bounded_text(self.rationale, "confidence rationale", 1_024)


@dataclass(frozen=True, slots=True, kw_only=True)
class DurableArtifactMetadata:
    """Required identity, linkage, provenance, and event-supplied timestamp."""

    artifact_id: UUID
    tenant_id: str
    incident_id: str
    run_id: UUID
    task_id: UUID
    produced_by: AgentRole
    created_at: datetime
    provenance_artifact_ids: tuple[UUID, ...] = ()
    citations: tuple[EvidenceCitation, ...] = ()
    schema_version: int = 1
    redacted: bool = True

    def __post_init__(self) -> None:
        _bounded_text(self.tenant_id, "tenant_id", 128)
        _bounded_text(self.incident_id, "incident_id", 256)
        if self.run_id.int == 0 or self.task_id.int == 0 or self.artifact_id.int == 0:
            raise ValueError("artifact, run, and task identifiers must be non-zero")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be supplied by a timezone-aware event")
        if self.schema_version < 1:
            raise ValueError("artifact schema version must be positive")
        if not self.redacted:
            raise ValueError("durable reasoning artifacts must be redacted")
        provenance = tuple(sorted(set(self.provenance_artifact_ids), key=str))
        citations = tuple(
            sorted(set(self.citations), key=lambda item: item.evidence_id)
        )
        if len(provenance) > MAX_ARTIFACT_ITEMS or len(citations) > MAX_ARTIFACT_ITEMS:
            raise ValueError("artifact provenance and citations are bounded")
        object.__setattr__(self, "provenance_artifact_ids", provenance)
        object.__setattr__(self, "citations", citations)


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceAssessmentArtifact(DurableArtifactMetadata):
    assessment: str
    limitations: tuple[str, ...]
    confidence: CalibratedConfidence

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_text(self.assessment, "assessment", MAX_ARTIFACT_TEXT_BYTES)
        _bounded_strings(self.limitations, "limitations")
        if not self.citations:
            raise ValueError("evidence assessments require citations")


@dataclass(frozen=True, slots=True, kw_only=True)
class HypothesisArtifact(DurableArtifactMetadata):
    statement: str
    conflicting_evidence_ids: tuple[str, ...]
    confidence: CalibratedConfidence

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_text(self.statement, "hypothesis", MAX_ARTIFACT_TEXT_BYTES)
        _bounded_strings(self.conflicting_evidence_ids, "conflicting evidence")
        if not self.citations:
            raise ValueError("hypotheses require evidence citations")


@dataclass(frozen=True, slots=True, kw_only=True)
class AlternativeHypothesisArtifact(DurableArtifactMetadata):
    statement: str
    distinguishing_evidence: tuple[str, ...]
    confidence: CalibratedConfidence

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_text(self.statement, "alternative hypothesis", MAX_ARTIFACT_TEXT_BYTES)
        _bounded_strings(self.distinguishing_evidence, "distinguishing evidence")
        if not self.citations:
            raise ValueError("alternative hypotheses require evidence citations")


@dataclass(frozen=True, slots=True, kw_only=True)
class ContradictionArtifact(DurableArtifactMetadata):
    claim: str
    counterclaim: str
    unresolved: bool

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_text(self.claim, "claim", MAX_ARTIFACT_TEXT_BYTES)
        _bounded_text(self.counterclaim, "counterclaim", MAX_ARTIFACT_TEXT_BYTES)
        if len(self.provenance_artifact_ids) < 2 or len(self.citations) < 2:
            raise ValueError("contradictions require two artifacts and cited evidence")


@dataclass(frozen=True, slots=True, kw_only=True)
class CritiqueArtifact(DurableArtifactMetadata):
    accepted: bool
    unsupported_claims: tuple[str, ...]
    evidence_gaps: tuple[str, ...]
    unresolved_contradiction_ids: tuple[UUID, ...]
    confidence: CalibratedConfidence

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_strings(self.unsupported_claims, "unsupported claims")
        _bounded_strings(self.evidence_gaps, "evidence gaps")
        contradictions = tuple(sorted(set(self.unresolved_contradiction_ids), key=str))
        if len(contradictions) > MAX_ARTIFACT_ITEMS:
            raise ValueError("unresolved contradiction list is bounded")
        if self.accepted and (
            self.unsupported_claims or self.unresolved_contradiction_ids
        ):
            raise ValueError("accepted critique cannot retain unsupported claims")
        object.__setattr__(self, "unresolved_contradiction_ids", contradictions)


@dataclass(frozen=True, slots=True, kw_only=True)
class CausalGraphReferenceArtifact(DurableArtifactMetadata):
    reference: str
    content_digest: str
    caveat: str

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _artifact_reference(self.reference)
        _digest(self.content_digest)
        _bounded_text(self.caveat, "causal graph caveat", 2_048)


@dataclass(frozen=True, slots=True, kw_only=True)
class TimelineReferenceArtifact(DurableArtifactMetadata):
    reference: str
    content_digest: str
    clock_skew_seconds: int

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _artifact_reference(self.reference)
        _digest(self.content_digest)
        if not 0 <= self.clock_skew_seconds <= 3_600:
            raise ValueError("timeline clock skew must be between 0 and 3600")


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationRecommendationArtifact(DurableArtifactMetadata):
    action: str
    target: str
    expected_result: str
    risk: str
    rollback: str
    hypothesis_id: UUID
    proposal_only: bool = True

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        for value, name, maximum in (
            (self.action, "action", 2_048),
            (self.target, "target", 1_024),
            (self.expected_result, "expected result", 2_048),
            (self.risk, "risk", 2_048),
            (self.rollback, "rollback", 2_048),
        ):
            _bounded_text(value, name, maximum)
        if not self.proposal_only:
            raise ValueError("Layer 7 remediation artifacts are proposal-only")
        if self.hypothesis_id not in self.provenance_artifact_ids:
            raise ValueError("remediation must cite its hypothesis artifact")


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationPlanArtifact(DurableArtifactMetadata):
    signals: tuple[str, ...]
    success_criteria: tuple[str, ...]
    observation_window_seconds: int

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_strings(self.signals, "verification signals")
        _bounded_strings(self.success_criteria, "success criteria")
        if not self.signals or not self.success_criteria:
            raise ValueError("verification requires signals and success criteria")
        if not 60 <= self.observation_window_seconds <= 86_400:
            raise ValueError("verification window must be between 60 and 86400")


@dataclass(frozen=True, slots=True, kw_only=True)
class CoordinatorDecisionArtifact(DurableArtifactMetadata):
    outcome: CoordinatorOutcome
    rationale: str
    selected_hypothesis_id: UUID | None
    unresolved_questions: tuple[str, ...]

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_text(self.rationale, "decision rationale", MAX_ARTIFACT_TEXT_BYTES)
        _bounded_strings(self.unresolved_questions, "unresolved questions")
        if self.outcome is CoordinatorOutcome.FINALIZE:
            if self.selected_hypothesis_id is None or self.unresolved_questions:
                raise ValueError("finalization requires one resolved hypothesis")
        elif not self.unresolved_questions:
            raise ValueError("abstention and escalation require unresolved questions")


@dataclass(frozen=True, slots=True, kw_only=True)
class FinalIncidentAssessmentArtifact(DurableArtifactMetadata):
    outcome: CoordinatorOutcome
    conclusion: str
    selected_hypothesis_id: UUID | None
    recommendation_id: UUID | None
    decision_id: UUID
    remaining_ambiguities: tuple[str, ...]
    confidence: CalibratedConfidence

    def __post_init__(self) -> None:
        DurableArtifactMetadata.__post_init__(self)
        _bounded_text(self.conclusion, "final conclusion", MAX_ARTIFACT_TEXT_BYTES)
        _bounded_strings(self.remaining_ambiguities, "remaining ambiguities")
        if self.decision_id not in self.provenance_artifact_ids:
            raise ValueError("final assessment must cite the coordinator decision")
        if self.outcome is CoordinatorOutcome.FINALIZE:
            if (
                self.selected_hypothesis_id is None
                or self.recommendation_id is None
                or self.remaining_ambiguities
            ):
                raise ValueError("finalized assessment requires resolved artifacts")
        elif not self.remaining_ambiguities:
            raise ValueError("non-final assessment must preserve ambiguity")


type DurableAgentArtifact = (
    EvidenceAssessmentArtifact
    | HypothesisArtifact
    | AlternativeHypothesisArtifact
    | ContradictionArtifact
    | CritiqueArtifact
    | CausalGraphReferenceArtifact
    | TimelineReferenceArtifact
    | RemediationRecommendationArtifact
    | VerificationPlanArtifact
    | CoordinatorDecisionArtifact
    | FinalIncidentAssessmentArtifact
)


def artifact_kind(artifact: DurableAgentArtifact) -> ArtifactKind:
    """Return the stable discriminator for the typed artifact union."""
    mapping: dict[type[object], ArtifactKind] = {
        EvidenceAssessmentArtifact: ArtifactKind.EVIDENCE_ASSESSMENT,
        HypothesisArtifact: ArtifactKind.HYPOTHESIS,
        AlternativeHypothesisArtifact: ArtifactKind.ALTERNATIVE_HYPOTHESIS,
        ContradictionArtifact: ArtifactKind.CONTRADICTION,
        CritiqueArtifact: ArtifactKind.CRITIQUE,
        CausalGraphReferenceArtifact: ArtifactKind.CAUSAL_GRAPH_REFERENCE,
        TimelineReferenceArtifact: ArtifactKind.TIMELINE_REFERENCE,
        RemediationRecommendationArtifact: ArtifactKind.REMEDIATION_RECOMMENDATION,
        VerificationPlanArtifact: ArtifactKind.VERIFICATION_PLAN,
        CoordinatorDecisionArtifact: ArtifactKind.COORDINATOR_DECISION,
        FinalIncidentAssessmentArtifact: ArtifactKind.FINAL_INCIDENT_ASSESSMENT,
    }
    return mapping[type(artifact)]


def artifact_summary(artifact: DurableAgentArtifact) -> str:
    """Return a bounded redacted summary suitable for projections and prompts."""
    if isinstance(artifact, EvidenceAssessmentArtifact):
        summary = artifact.assessment
    elif isinstance(artifact, (HypothesisArtifact, AlternativeHypothesisArtifact)):
        summary = artifact.statement
    elif isinstance(artifact, ContradictionArtifact):
        summary = f"{artifact.claim} / {artifact.counterclaim}"
    elif isinstance(artifact, CritiqueArtifact):
        summary = "accepted" if artifact.accepted else "rejected"
    elif isinstance(
        artifact,
        (CausalGraphReferenceArtifact, TimelineReferenceArtifact),
    ):
        summary = artifact.reference
    elif isinstance(artifact, RemediationRecommendationArtifact):
        summary = f"{artifact.action} on {artifact.target}"
    elif isinstance(artifact, VerificationPlanArtifact):
        summary = "; ".join(artifact.success_criteria)
    elif isinstance(artifact, CoordinatorDecisionArtifact):
        summary = artifact.rationale
    else:
        summary = artifact.conclusion
    encoded = summary.encode()
    if len(encoded) <= MAX_ARTIFACT_SUMMARY_BYTES:
        return summary
    return encoded[:MAX_ARTIFACT_SUMMARY_BYTES].decode("utf-8", errors="ignore")


def artifact_confidence(artifact: DurableAgentArtifact) -> float | None:
    confidence = getattr(artifact, "confidence", None)
    return confidence.score if isinstance(confidence, CalibratedConfidence) else None


def artifact_to_payload(artifact: DurableAgentArtifact) -> Mapping[str, JsonValue]:
    """Encode an artifact into bounded JSON for one additive event schema."""
    body: dict[str, JsonValue]
    if isinstance(artifact, EvidenceAssessmentArtifact):
        body = {
            "assessment": artifact.assessment,
            "limitations": artifact.limitations,
            "confidence": _confidence_payload(artifact.confidence),
        }
    elif isinstance(artifact, HypothesisArtifact):
        body = {
            "statement": artifact.statement,
            "conflicting_evidence_ids": artifact.conflicting_evidence_ids,
            "confidence": _confidence_payload(artifact.confidence),
        }
    elif isinstance(artifact, AlternativeHypothesisArtifact):
        body = {
            "statement": artifact.statement,
            "distinguishing_evidence": artifact.distinguishing_evidence,
            "confidence": _confidence_payload(artifact.confidence),
        }
    elif isinstance(artifact, ContradictionArtifact):
        body = {
            "claim": artifact.claim,
            "counterclaim": artifact.counterclaim,
            "unresolved": artifact.unresolved,
        }
    elif isinstance(artifact, CritiqueArtifact):
        body = {
            "accepted": artifact.accepted,
            "unsupported_claims": artifact.unsupported_claims,
            "evidence_gaps": artifact.evidence_gaps,
            "unresolved_contradiction_ids": tuple(
                str(value) for value in artifact.unresolved_contradiction_ids
            ),
            "confidence": _confidence_payload(artifact.confidence),
        }
    elif isinstance(artifact, CausalGraphReferenceArtifact):
        body = {
            "reference": artifact.reference,
            "content_digest": artifact.content_digest,
            "caveat": artifact.caveat,
        }
    elif isinstance(artifact, TimelineReferenceArtifact):
        body = {
            "reference": artifact.reference,
            "content_digest": artifact.content_digest,
            "clock_skew_seconds": artifact.clock_skew_seconds,
        }
    elif isinstance(artifact, RemediationRecommendationArtifact):
        body = {
            "action": artifact.action,
            "target": artifact.target,
            "expected_result": artifact.expected_result,
            "risk": artifact.risk,
            "rollback": artifact.rollback,
            "hypothesis_id": str(artifact.hypothesis_id),
            "proposal_only": artifact.proposal_only,
        }
    elif isinstance(artifact, VerificationPlanArtifact):
        body = {
            "signals": artifact.signals,
            "success_criteria": artifact.success_criteria,
            "observation_window_seconds": artifact.observation_window_seconds,
        }
    elif isinstance(artifact, CoordinatorDecisionArtifact):
        body = {
            "outcome": artifact.outcome.value,
            "rationale": artifact.rationale,
            "selected_hypothesis_id": (
                str(artifact.selected_hypothesis_id)
                if artifact.selected_hypothesis_id is not None
                else None
            ),
            "unresolved_questions": artifact.unresolved_questions,
        }
    else:
        body = {
            "outcome": artifact.outcome.value,
            "conclusion": artifact.conclusion,
            "selected_hypothesis_id": (
                str(artifact.selected_hypothesis_id)
                if artifact.selected_hypothesis_id is not None
                else None
            ),
            "recommendation_id": (
                str(artifact.recommendation_id)
                if artifact.recommendation_id is not None
                else None
            ),
            "decision_id": str(artifact.decision_id),
            "remaining_ambiguities": artifact.remaining_ambiguities,
            "confidence": _confidence_payload(artifact.confidence),
        }
    payload: dict[str, JsonValue] = {
        "kind": artifact_kind(artifact).value,
        "artifact_id": str(artifact.artifact_id),
        "tenant_id": artifact.tenant_id,
        "incident_id": artifact.incident_id,
        "run_id": str(artifact.run_id),
        "task_id": str(artifact.task_id),
        "produced_by": artifact.produced_by.value,
        "created_at": artifact.created_at.isoformat(),
        "schema_version": artifact.schema_version,
        "redacted": artifact.redacted,
        "provenance_artifact_ids": tuple(
            str(value) for value in artifact.provenance_artifact_ids
        ),
        "citations": tuple(
            {
                "evidence_id": citation.evidence_id,
                "source_uri": citation.source_uri,
                "content_digest": citation.content_digest,
            }
            for citation in artifact.citations
        ),
        "body": body,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_ARTIFACT_TEXT_BYTES * 4:
        raise ValueError("serialized artifact exceeds the durable event cap")
    return payload


def artifact_from_payload(value: Mapping[str, JsonValue]) -> DurableAgentArtifact:
    """Decode and fully validate the current additive artifact schema."""
    kind = ArtifactKind(str(value["kind"]))
    body = _mapping(value["body"])
    metadata = _metadata_values(value)
    if kind is ArtifactKind.EVIDENCE_ASSESSMENT:
        return EvidenceAssessmentArtifact(
            **metadata,
            assessment=str(body["assessment"]),
            limitations=_strings(body["limitations"]),
            confidence=_confidence(body["confidence"]),
        )
    if kind is ArtifactKind.HYPOTHESIS:
        return HypothesisArtifact(
            **metadata,
            statement=str(body["statement"]),
            conflicting_evidence_ids=_strings(body["conflicting_evidence_ids"]),
            confidence=_confidence(body["confidence"]),
        )
    if kind is ArtifactKind.ALTERNATIVE_HYPOTHESIS:
        return AlternativeHypothesisArtifact(
            **metadata,
            statement=str(body["statement"]),
            distinguishing_evidence=_strings(body["distinguishing_evidence"]),
            confidence=_confidence(body["confidence"]),
        )
    if kind is ArtifactKind.CONTRADICTION:
        return ContradictionArtifact(
            **metadata,
            claim=str(body["claim"]),
            counterclaim=str(body["counterclaim"]),
            unresolved=bool(body["unresolved"]),
        )
    if kind is ArtifactKind.CRITIQUE:
        return CritiqueArtifact(
            **metadata,
            accepted=bool(body["accepted"]),
            unsupported_claims=_strings(body["unsupported_claims"]),
            evidence_gaps=_strings(body["evidence_gaps"]),
            unresolved_contradiction_ids=tuple(
                UUID(item) for item in _strings(body["unresolved_contradiction_ids"])
            ),
            confidence=_confidence(body["confidence"]),
        )
    if kind is ArtifactKind.CAUSAL_GRAPH_REFERENCE:
        return CausalGraphReferenceArtifact(
            **metadata,
            reference=str(body["reference"]),
            content_digest=str(body["content_digest"]),
            caveat=str(body["caveat"]),
        )
    if kind is ArtifactKind.TIMELINE_REFERENCE:
        return TimelineReferenceArtifact(
            **metadata,
            reference=str(body["reference"]),
            content_digest=str(body["content_digest"]),
            clock_skew_seconds=int(str(body["clock_skew_seconds"])),
        )
    if kind is ArtifactKind.REMEDIATION_RECOMMENDATION:
        return RemediationRecommendationArtifact(
            **metadata,
            action=str(body["action"]),
            target=str(body["target"]),
            expected_result=str(body["expected_result"]),
            risk=str(body["risk"]),
            rollback=str(body["rollback"]),
            hypothesis_id=UUID(str(body["hypothesis_id"])),
            proposal_only=bool(body["proposal_only"]),
        )
    if kind is ArtifactKind.VERIFICATION_PLAN:
        return VerificationPlanArtifact(
            **metadata,
            signals=_strings(body["signals"]),
            success_criteria=_strings(body["success_criteria"]),
            observation_window_seconds=int(str(body["observation_window_seconds"])),
        )
    if kind is ArtifactKind.COORDINATOR_DECISION:
        return CoordinatorDecisionArtifact(
            **metadata,
            outcome=CoordinatorOutcome(str(body["outcome"])),
            rationale=str(body["rationale"]),
            selected_hypothesis_id=_optional_uuid(body["selected_hypothesis_id"]),
            unresolved_questions=_strings(body["unresolved_questions"]),
        )
    return FinalIncidentAssessmentArtifact(
        **metadata,
        outcome=CoordinatorOutcome(str(body["outcome"])),
        conclusion=str(body["conclusion"]),
        selected_hypothesis_id=_optional_uuid(body["selected_hypothesis_id"]),
        recommendation_id=_optional_uuid(body["recommendation_id"]),
        decision_id=UUID(str(body["decision_id"])),
        remaining_ambiguities=_strings(body["remaining_ambiguities"]),
        confidence=_confidence(body["confidence"]),
    )


# Layer 1 compatibility types remain readable; Layer 7 runtime accepts only the
# durable union above.
@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactMetadata:
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
    source: str
    source_reference: str
    summary: str


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingArtifact(ArtifactMetadata):
    statement: str
    evidence_ids: tuple[UUID, ...]
    confidence: float

    def __post_init__(self) -> None:
        ArtifactMetadata.__post_init__(self)
        _validate_supported_claim(self.evidence_ids, self.confidence)


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationProposal(ArtifactMetadata):
    action: str
    target: str
    hypothesis_id: UUID
    risk: str


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationArtifact(ArtifactMetadata):
    recovered: bool
    evidence_ids: tuple[UUID, ...]
    observation_window_seconds: int


type AgentArtifact = (
    EvidenceArtifact
    | FindingArtifact
    | DurableAgentArtifact
    | RemediationProposal
    | VerificationArtifact
)


def _confidence_payload(value: CalibratedConfidence) -> Mapping[str, JsonValue]:
    return {
        "score": value.score,
        "calibration": value.calibration.value,
        "rationale": value.rationale,
    }


class _MetadataValues(TypedDict):
    artifact_id: UUID
    tenant_id: str
    incident_id: str
    run_id: UUID
    task_id: UUID
    produced_by: AgentRole
    created_at: datetime
    provenance_artifact_ids: tuple[UUID, ...]
    citations: tuple[EvidenceCitation, ...]
    schema_version: int
    redacted: bool


def _metadata_values(value: Mapping[str, JsonValue]) -> _MetadataValues:
    citations: list[EvidenceCitation] = []
    for item in _json_sequence(value["citations"]):
        item_mapping = _mapping(item)
        citations.append(
            EvidenceCitation(
                evidence_id=str(item_mapping["evidence_id"]),
                source_uri=str(item_mapping["source_uri"]),
                content_digest=str(item_mapping["content_digest"]),
            )
        )
    return {
        "artifact_id": UUID(str(value["artifact_id"])),
        "tenant_id": str(value["tenant_id"]),
        "incident_id": str(value["incident_id"]),
        "run_id": UUID(str(value["run_id"])),
        "task_id": UUID(str(value["task_id"])),
        "produced_by": AgentRole(str(value["produced_by"])),
        "created_at": datetime.fromisoformat(str(value["created_at"])),
        "provenance_artifact_ids": tuple(
            UUID(str(item)) for item in _json_sequence(value["provenance_artifact_ids"])
        ),
        "citations": tuple(citations),
        "schema_version": int(str(value["schema_version"])),
        "redacted": bool(value["redacted"]),
    }


def _confidence(value: JsonValue) -> CalibratedConfidence:
    item = _mapping(value)
    return CalibratedConfidence(
        score=float(str(item["score"])),
        calibration=ConfidenceCalibration(str(item["calibration"])),
        rationale=str(item["rationale"]),
    )


def _mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ValueError("artifact value must be an object")
    return value


def _json_sequence(value: JsonValue) -> Sequence[JsonValue]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError("artifact value must be an array")
    return value


def _strings(value: JsonValue) -> tuple[str, ...]:
    return tuple(str(item) for item in _json_sequence(value))


def _optional_uuid(value: JsonValue) -> UUID | None:
    return UUID(str(value)) if value is not None else None


def _validate_supported_claim(
    evidence_ids: tuple[UUID, ...],
    confidence: float,
) -> None:
    if not evidence_ids:
        raise ValueError("supported claims require evidence citations")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")


def _bounded_text(value: str, name: str, maximum: int) -> None:
    if not value or value != value.strip() or len(value.encode()) > maximum:
        raise ValueError(f"{name} must be normalized and at most {maximum} bytes")


def _bounded_strings(values: Sequence[str], name: str) -> None:
    normalized = tuple(values)
    if len(normalized) > MAX_ARTIFACT_ITEMS:
        raise ValueError(f"{name} contains too many values")
    for value in normalized:
        _bounded_text(value, name, 2_048)


def _artifact_reference(value: str) -> None:
    _bounded_text(value, "artifact reference", 2_048)
    if not value.startswith("aegis-artifact://"):
        raise ValueError("derived references require aegis-artifact://")


def _digest(value: str) -> None:
    if len(value) != 64 or any(item not in "0123456789abcdef" for item in value):
        raise ValueError("content digest must be lowercase SHA-256")


__all__ = [
    "AgentArtifact",
    "AgentRole",
    "AlternativeHypothesisArtifact",
    "ArtifactKind",
    "ArtifactMetadata",
    "CalibratedConfidence",
    "CausalGraphReferenceArtifact",
    "ConfidenceCalibration",
    "ContradictionArtifact",
    "CoordinatorDecisionArtifact",
    "CoordinatorOutcome",
    "CritiqueArtifact",
    "DurableAgentArtifact",
    "DurableArtifactMetadata",
    "EvidenceArtifact",
    "EvidenceAssessmentArtifact",
    "EvidenceCitation",
    "FinalIncidentAssessmentArtifact",
    "FindingArtifact",
    "HypothesisArtifact",
    "RemediationProposal",
    "RemediationRecommendationArtifact",
    "TimelineReferenceArtifact",
    "VerificationArtifact",
    "VerificationPlanArtifact",
    "artifact_confidence",
    "artifact_from_payload",
    "artifact_kind",
    "artifact_summary",
    "artifact_to_payload",
]
