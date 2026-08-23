"""Authorized bounded evidence control-plane operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol, cast
from uuid import UUID

from aegis_agent_platform.domain import EvidenceBundle, EvidenceRecord, JsonValue
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.evidence.ingestion import (
    StoredEvidencePage,
    render_citation,
)
from aegis_agent_platform.evidence.ports import EvidenceQuery
from aegis_agent_platform.evidence.service import (
    EvidenceQueryService,
    EvidenceRequestResult,
)
from aegis_agent_platform.identity import AuthorizationService, Permission, Principal
from aegis_agent_platform.observability.context import PropagationContext
from aegis_agent_platform.policy import TenantPolicy
from aegis_agent_platform.tenancy import TenantContext


class EvidenceBundleReader(Protocol):
    def get(self, context: TenantContext, bundle_id: str) -> EvidenceBundle | None: ...


class EvidenceRecordReader(Protocol):
    def list(
        self,
        context: TenantContext,
        *,
        offset: int = 0,
        limit: int = 100,
        ingested_before: datetime | None = None,
    ) -> tuple[EvidenceRecord, ...]: ...

    def page(
        self,
        context: TenantContext,
        *,
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
    ) -> StoredEvidencePage: ...


class InMemoryEvidenceBundleStore:
    def __init__(self) -> None:
        self._bundles: dict[tuple[str, str], EvidenceBundle] = {}

    def put(self, context: TenantContext, bundle: EvidenceBundle) -> None:
        if str(context.tenant_id) != bundle.tenant_id:
            raise PermissionError("cross_tenant_bundle")
        self._bundles[(bundle.tenant_id, bundle.bundle_id)] = bundle

    def get(self, context: TenantContext, bundle_id: str) -> EvidenceBundle | None:
        return self._bundles.get((str(context.tenant_id), bundle_id))


class EvidenceOperations:
    def __init__(
        self,
        service: EvidenceQueryService,
        records: EvidenceRecordReader,
        bundles: EvidenceBundleReader,
        authorization: AuthorizationService | None = None,
    ) -> None:
        self._service = service
        self._records = records
        self._bundles = bundles
        self._authorization = authorization or AuthorizationService()

    async def request(
        self,
        principal: Principal,
        context: TenantContext,
        query: EvidenceQuery,
        policy: TenantPolicy,
        *,
        at: datetime,
        propagation: PropagationContext | None = None,
    ) -> EvidenceRequestResult:
        self._require(principal, context, Permission.EVIDENCE_QUERY, at)
        return await self._service.request(
            context,
            query,
            policy,
            actor_id=principal.actor_id,
            propagation=propagation,
        )

    async def status(
        self,
        principal: Principal,
        context: TenantContext,
        query_id: UUID,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        return await self._service.status(context, query_id)

    def capabilities(
        self,
        principal: Principal,
        context: TenantContext,
        policy: TenantPolicy,
        *,
        at: datetime,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        return tuple(
            {
                "source": source,
                "enabled": source in policy.allowed_connectors,
                "health": "configured",
            }
            for source in self._service.capabilities()
        )

    def evidence(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        cursor: int = 0,
        limit: int = 100,
        snapshot_at: datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        return tuple(
            _record(item)
            for item in self._records.list(
                context,
                offset=cursor,
                limit=limit,
                ingested_before=snapshot_at or at,
            )
        )

    def citations(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        cursor: int = 0,
        limit: int = 100,
        snapshot_at: datetime | None = None,
    ) -> tuple[str, ...]:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        return tuple(
            render_citation(item)
            for item in self._records.list(
                context,
                offset=cursor,
                limit=limit,
                ingested_before=snapshot_at or at,
            )
        )

    def evidence_page(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], tuple[int, int] | None]:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        page = self._records.page(context, cursor=cursor, limit=limit)
        return tuple(_record(item) for item in page.records), page.next_cursor

    def citation_page(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
    ) -> tuple[tuple[str, ...], tuple[int, int] | None]:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        page = self._records.page(context, cursor=cursor, limit=limit)
        return tuple(render_citation(item) for item in page.records), page.next_cursor

    def bundle(
        self,
        principal: Principal,
        context: TenantContext,
        bundle_id: str,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, Permission.EVIDENCE_READ, at)
        bundle = self._bundles.get(context, bundle_id)
        if bundle is None:
            return None
        return {
            "bundle_id": bundle.bundle_id,
            "environment": bundle.environment.name,
            "generated_at": bundle.generated_at.isoformat(),
            "evidence_ids": tuple(str(item.evidence_id) for item in bundle.evidence),
            "timeline": tuple(
                {
                    "occurred_at": item.occurred_at.isoformat(),
                    "evidence_ids": tuple(str(value) for value in item.evidence_ids),
                    "summary": item.summary,
                }
                for item in bundle.timeline
            ),
            "links": tuple(
                {
                    "left": str(item.left),
                    "right": str(item.right),
                    "kind": item.kind.value,
                    "confidence": item.confidence,
                    "rationale": item.rationale,
                    "ambiguous": item.ambiguous,
                }
                for item in bundle.links
            ),
            "conflict_count": len(bundle.source_conflicts),
            "causality_inferred": False,
        }

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        permission: Permission,
        at: datetime,
    ) -> None:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=permission,
            at=at,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)


def _record(item: object) -> Mapping[str, JsonValue]:
    from aegis_agent_platform.domain import EvidenceRecord

    if not isinstance(item, EvidenceRecord):
        raise TypeError("item must be EvidenceRecord")
    return {
        "evidence_id": str(item.evidence_id),
        "source": item.source.value,
        "kind": item.kind.value,
        "environment": item.environment.name,
        "service": item.service.name if item.service else None,
        "observed_at": item.observed_at.isoformat(),
        "summary": item.summary,
        "fields": cast(JsonValue, thaw_json(item.fields)),
        "severity": item.severity.value,
        "classification": item.classification.value,
        "retention": item.retention.value,
        "digest": item.content_digest,
        "provenance_uri": item.provenance.uri,
        "redacted": item.redaction.applied,
        "knowledge": item.knowledge,
    }


__all__ = [
    "EvidenceBundleReader",
    "EvidenceOperations",
    "InMemoryEvidenceBundleStore",
]
