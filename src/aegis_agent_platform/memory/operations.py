"""Authenticated tenant-scoped memory operations with redacted read models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from hashlib import sha256
from uuid import UUID

from aegis_agent_platform.domain import (
    ContextBudget,
    EpisodicMemoryReference,
    JsonValue,
    MemoryContext,
    MemoryRetention,
    RetrievalQuery,
    RetrievalResult,
    SemanticMemory,
    WorkingMemoryItem,
    WorkLease,
    replay_memory,
)
from aegis_agent_platform.identity import AuthorizationService, Permission, Principal
from aegis_agent_platform.memory.context import ContextBuilder
from aegis_agent_platform.memory.ingestion import (
    MemoryIngestionResult,
    MemoryIngestionService,
    MemoryProposalResult,
)
from aegis_agent_platform.memory.lifecycle import MemoryLifecycleService
from aegis_agent_platform.memory.repository import MemoryIndex, MemoryLedger
from aegis_agent_platform.memory.retrieval import HybridRetriever
from aegis_agent_platform.tenancy import TenantContext


class MemoryOperations:
    """Deny-by-default façade for ingest, retrieval, context, and privacy flows."""

    def __init__(
        self,
        ledger: MemoryLedger,
        index: MemoryIndex,
        ingestion: MemoryIngestionService,
        retriever: HybridRetriever,
        context_builder: ContextBuilder,
        lifecycle: MemoryLifecycleService,
        *,
        authorization: AuthorizationService | None = None,
    ) -> None:
        self._ledger = ledger
        self._index = index
        self._ingestion = ingestion
        self._retriever = retriever
        self._context_builder = context_builder
        self._lifecycle = lifecycle
        self._authorization = authorization or AuthorizationService()

    async def propose(
        self,
        principal: Principal,
        context: TenantContext,
        memory: SemanticMemory,
        source_text: str,
        *,
        at: datetime,
        idempotency_key: str,
    ) -> MemoryProposalResult:
        self._require(principal, context, Permission.MEMORY_INGEST, at)
        return await self._ingestion.propose(
            context,
            memory,
            source_text,
            proposed_by=principal.actor_id,
            idempotency_key=idempotency_key,
        )

    async def accept(
        self,
        principal: Principal,
        context: TenantContext,
        memory: SemanticMemory,
        lease: WorkLease,
        *,
        at: datetime,
        idempotency_key: str,
        acceptance_kind: str = "human",
        contradiction_ids: Sequence[UUID] = (),
    ) -> MemoryIngestionResult:
        self._require(principal, context, Permission.MEMORY_ACCEPT, at)
        if principal.actor_id != memory.accepted_by:
            raise PermissionError("memory acceptor does not match reviewed contract")
        return await self._ingestion.accept_and_process(
            context,
            memory,
            lease,
            accepted_by=principal.actor_id,
            acceptance_kind=acceptance_kind,
            idempotency_key=idempotency_key,
            contradiction_ids=contradiction_ids,
        )

    async def reject(
        self,
        principal: Principal,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        at: datetime,
        reason_code: str,
        idempotency_key: str,
    ) -> None:
        self._require(principal, context, Permission.MEMORY_ACCEPT, at)
        await self._ingestion.reject(
            context,
            memory,
            rejected_by=principal.actor_id,
            reason_code=reason_code,
            idempotency_key=idempotency_key,
        )

    async def retrieve(
        self,
        principal: Principal,
        context: TenantContext,
        query: RetrievalQuery,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> RetrievalResult:
        self._require(principal, context, Permission.MEMORY_RETRIEVE, at)
        if query.principal_id != principal.actor_id:
            raise PermissionError("retrieval principal does not match authentication")
        trusted_roles = frozenset(
            binding.role.value
            for binding in principal.role_bindings
            if binding.is_active(at)
        )
        trusted_query = replace(
            query,
            service_id=(
                str(principal.service_identity)
                if principal.service_identity is not None
                else None
            ),
            roles=trusted_roles,
            purpose="incident-investigation",
            as_of=at,
        )
        return await self._retriever.retrieve(context, trusted_query, lease)

    async def context(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        run_id: UUID,
        task_id: UUID,
        lease: WorkLease,
        budget: ContextBudget,
        working: Sequence[WorkingMemoryItem],
        episodic: Sequence[EpisodicMemoryReference],
        semantic: RetrievalResult,
        at: datetime,
    ) -> MemoryContext:
        self._require(principal, context, Permission.MEMORY_RETRIEVE, at)
        trusted_roles = frozenset(
            binding.role.value
            for binding in principal.role_bindings
            if binding.is_active(at)
        )
        expected_service = (
            str(principal.service_identity)
            if principal.service_identity is not None
            else None
        )
        if (
            semantic.scope.tenant_id != str(context.tenant_id)
            or semantic.scope.principal_id != principal.actor_id
            or semantic.scope.service_id != expected_service
            or semantic.scope.roles != trusted_roles
            or semantic.scope.purpose != "incident-investigation"
        ):
            raise PermissionError("memory context retrieval scope is not authorized")
        return await self._context_builder.build(
            context,
            run_id=run_id,
            task_id=task_id,
            actor_id=principal.actor_id,
            lease=lease,
            budget=budget,
            working=working,
            episodic=episodic,
            semantic=semantic,
        )

    async def status(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, Permission.MEMORY_READ, at)
        events = await self._ledger.load(context, memory_id)
        if not events:
            return None
        state = replay_memory(events)
        return {
            "candidate_status": (
                state.candidate_status.value
                if state.candidate_status is not None
                else None
            ),
            "chunking_status": state.chunking.value,
            "embedding_status": state.embedding.value,
            "indexing_status": state.indexing.value,
            "legal_hold": state.legal_hold,
            "lifecycle_status": state.lifecycle_status.value,
            "memory_id": str(memory_id),
            "redacted": True,
            "scan_status": state.scan.value,
            "version": state.version,
        }

    async def provenance(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, Permission.MEMORY_READ, at)
        memory = await self._index.provenance(context, memory_id)
        if memory is None:
            return None
        show_location = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=Permission.MEMORY_ADMIN,
            at=at,
        ).allowed
        return _provenance(memory, show_location=show_location)

    async def page(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        after_memory_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        self._require(principal, context, Permission.MEMORY_READ, at)
        show_location = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=Permission.MEMORY_ADMIN,
            at=at,
        ).allowed
        rows, cursor = await self._index.page(
            context,
            after_memory_id=after_memory_id,
            limit=limit,
        )
        return (
            tuple(_provenance(memory, show_location=show_location) for memory in rows),
            cursor,
        )

    async def feedback(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        *,
        at: datetime,
        rating: float,
        relevant: bool,
        reason_code: str,
    ) -> float:
        self._require(principal, context, Permission.MEMORY_FEEDBACK, at)
        return await self._lifecycle.feedback(
            context,
            memory_id,
            actor_id=principal.actor_id,
            rating=rating,
            relevant=relevant,
            reason_code=reason_code,
        )

    async def tombstone(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        *,
        at: datetime,
        reason_code: str,
    ) -> None:
        self._require(principal, context, Permission.MEMORY_ADMIN, at)
        await self._lifecycle.tombstone(
            context,
            memory_id,
            actor_id=principal.actor_id,
            reason_code=reason_code,
        )

    async def retention(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        retention: MemoryRetention,
        *,
        at: datetime,
        policy_reference: str,
    ) -> None:
        self._require(principal, context, Permission.MEMORY_ADMIN, at)
        await self._lifecycle.retention(
            context,
            memory_id,
            retention,
            actor_id=principal.actor_id,
            policy_reference=policy_reference,
        )

    async def legal_hold(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        *,
        at: datetime,
        hold_reference: str,
        enabled: bool,
    ) -> None:
        self._require(principal, context, Permission.MEMORY_ADMIN, at)
        await self._lifecycle.legal_hold(
            context,
            memory_id,
            actor_id=principal.actor_id,
            hold_reference=hold_reference,
            enabled=enabled,
        )

    async def delete(
        self,
        principal: Principal,
        context: TenantContext,
        memory_id: UUID,
        *,
        at: datetime,
        request_reference: str,
    ) -> int:
        self._require(principal, context, Permission.MEMORY_ADMIN, at)
        return await self._lifecycle.delete(
            context,
            memory_id,
            actor_id=principal.actor_id,
            request_reference=request_reference,
        )

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


def _provenance(
    memory: SemanticMemory, *, show_location: bool = False
) -> Mapping[str, JsonValue]:
    return {
        "accepted_by": memory.accepted_by,
        "citation_references": tuple(
            {
                "artifact_id": (
                    str(citation.artifact_id)
                    if citation.artifact_id is not None
                    else None
                ),
                "content_digest": citation.content_digest,
                "event_id": (
                    str(citation.event_id) if citation.event_id is not None else None
                ),
                "source_id": citation.source_id,
                "source_uri": citation.source_uri if show_location else None,
            }
            for citation in memory.snapshot.citations
        ),
        "content_reference_digest": sha256(
            memory.snapshot.content_reference.encode()
        ).hexdigest(),
        "created_at": memory.created_at.isoformat(),
        "embedding_dimension": memory.embedding_dimension,
        "embedding_model": memory.embedding_model,
        "embedder_version": memory.embedder_version,
        "memory_id": str(memory.memory_id),
        "policy_reference": memory.policy_reference,
        "quality": memory.quality,
        "redacted": True,
        "schema_version": memory.schema_version,
        "security_label": memory.security_label.value,
        "source_digest": memory.snapshot.content_digest,
        "source_kind": memory.snapshot.source_kind.value,
        "source_reference": memory.snapshot.source_reference if show_location else None,
        "source_version": memory.snapshot.source_version,
        "version_key": memory.version_key,
    }


__all__ = ["MemoryOperations"]
