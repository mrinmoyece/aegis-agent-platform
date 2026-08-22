"""Deterministic non-LLM evidence timeline correlation."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from itertools import combinations

from aegis_agent_platform.domain import (
    CorrelationLink,
    CorrelationLinkKind,
    EvidenceBundle,
    EvidenceId,
    EvidenceKind,
    EvidenceRecord,
    TimelineEntry,
)


class CorrelationEngine:
    """Link immutable evidence without inferring or fabricating causality."""

    def correlate(
        self,
        *,
        bundle_id: str,
        tenant_id: str,
        environment: object,
        generated_at: object,
        evidence: tuple[EvidenceRecord, ...],
        clock_skew_seconds: int = 120,
    ) -> EvidenceBundle:
        from datetime import datetime

        from aegis_agent_platform.domain import EnvironmentIdentity

        if not isinstance(environment, EnvironmentIdentity) or not isinstance(
            generated_at, datetime
        ):
            raise TypeError("invalid correlation inputs")
        if any(record.tenant_id != tenant_id for record in evidence):
            raise PermissionError("cross_tenant_correlation")
        if any(record.environment != environment for record in evidence):
            raise PermissionError("cross_environment_correlation")
        links: dict[
            tuple[EvidenceId, EvidenceId, CorrelationLinkKind], CorrelationLink
        ] = {}
        reference_index: dict[object, list[EvidenceRecord]] = defaultdict(list)
        for record in evidence:
            for reference in record.references:
                reference_index[reference].append(record)
        for records in reference_index.values():
            for index, left in enumerate(records):
                for right in records[index + 1 :]:
                    _add(
                        links,
                        left,
                        right,
                        CorrelationLinkKind.EXACT_IDENTIFIER,
                        1.0,
                        "records share an immutable typed source identifier",
                    )
        ordered = sorted(
            evidence,
            key=lambda item: (item.observed_at, str(item.evidence_id)),
        )
        tolerance = timedelta(seconds=clock_skew_seconds)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                delta = right.observed_at - left.observed_at
                if delta > tolerance:
                    break
                if left.service is not None and left.service == right.service:
                    _add(
                        links,
                        left,
                        right,
                        CorrelationLinkKind.TEMPORAL_PROXIMITY,
                        0.65,
                        f"same service within {clock_skew_seconds}s clock-skew window",
                        ambiguous=True,
                    )
                if left.resource is not None and left.resource == right.resource:
                    _add(
                        links,
                        left,
                        right,
                        CorrelationLinkKind.RESOURCE_MATCH,
                        0.9,
                        "same normalized resource identity",
                    )
        runbooks = [item for item in ordered if item.kind is EvidenceKind.RUNBOOK]
        for runbook in runbooks:
            for record in ordered:
                if runbook == record or runbook.service is None:
                    continue
                if runbook.service == record.service:
                    _add(
                        links,
                        runbook,
                        record,
                        CorrelationLinkKind.RUNBOOK_APPLICABILITY,
                        0.8,
                        "versioned runbook declares the same service applicability",
                    )
        conflicts: list[CorrelationLink] = []
        by_source_record: dict[tuple[str, str], list[EvidenceRecord]] = defaultdict(
            list
        )
        for record in ordered:
            key = (record.source.value, record.provenance.source_record_id)
            by_source_record[key].append(record)
        for records in by_source_record.values():
            versions = {
                item.content_digest: item
                for item in sorted(records, key=lambda value: str(value.evidence_id))
            }
            for left, right in combinations(versions.values(), 2):
                conflict = _add(
                    links,
                    left,
                    right,
                    CorrelationLinkKind.SOURCE_CONFLICT,
                    1.0,
                    "same source record identifier has conflicting immutable content",
                    ambiguous=True,
                )
                conflicts.append(conflict)
        timeline = tuple(
            TimelineEntry(item.observed_at, (item.evidence_id,), item.summary)
            for item in ordered
        )
        ordered_links = tuple(
            sorted(
                links.values(),
                key=lambda item: (str(item.left), str(item.right), item.kind.value),
            )
        )
        return EvidenceBundle(
            bundle_id=bundle_id,
            tenant_id=tenant_id,
            environment=environment,
            generated_at=generated_at,
            evidence=evidence,
            timeline=timeline,
            links=ordered_links,
            source_conflicts=tuple(
                link
                for link in ordered_links
                if link.kind is CorrelationLinkKind.SOURCE_CONFLICT
            ),
            clock_skew_seconds=clock_skew_seconds,
            metadata={
                "causality_inferred": False,
                "timezone": "UTC",
                "ambiguities_preserved": True,
            },
        )


def _add(
    links: dict[tuple[EvidenceId, EvidenceId, CorrelationLinkKind], CorrelationLink],
    left: EvidenceRecord,
    right: EvidenceRecord,
    kind: CorrelationLinkKind,
    confidence: float,
    rationale: str,
    *,
    ambiguous: bool = False,
) -> CorrelationLink:
    first, second = sorted((left.evidence_id, right.evidence_id))
    key = (first, second, kind)
    link = CorrelationLink(first, second, kind, confidence, rationale, ambiguous)
    links[key] = link
    return link


__all__ = ["CorrelationEngine"]
