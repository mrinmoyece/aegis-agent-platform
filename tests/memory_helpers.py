"""Deterministic Layer 10 fixtures shared by unit, eval, and integration tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid5

from aegis_agent_platform.domain import (
    DataClassification,
    MemoryAcl,
    MemoryCitation,
    MemoryRetention,
    MemorySourceKind,
    SemanticMemory,
    SourceSnapshot,
    SourceTrustTier,
    WorkLease,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.memory.ingestion import MemoryIngestionService
from aegis_agent_platform.memory.ports import (
    DeterministicEmbeddingProvider,
    RegexMemoryScanner,
)
from aegis_agent_platform.memory.repository import (
    InMemoryHybridIndex,
    InMemoryMemoryBlobStore,
    InMemoryMemoryLedger,
)
from aegis_agent_platform.tenancy import TenantContext

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
NAMESPACE = UUID("5d3a657d-7b42-4d18-b495-501579ab68e5")


def identifier(name: str) -> UUID:
    return uuid5(NAMESPACE, name)


def lease(
    work_id: UUID,
    tenant_id: str = "tenant-a",
    *,
    generation: int = 1,
) -> WorkLease:
    return WorkLease(
        work_id=work_id,
        tenant_id=tenant_id,
        token=identifier(f"lease:{tenant_id}:{work_id}:{generation}"),
        generation=generation,
        owner="memory-worker",
        attempt=1,
        acquired_at=NOW,
        heartbeat_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def semantic_memory(
    name: str,
    text: str,
    *,
    tenant_id: str = "tenant-a",
    accepted_by: str = "admin-a",
    users: tuple[str, ...] = ("investigator-a",),
    roles: tuple[str, ...] = ("investigator",),
    purposes: tuple[str, ...] = ("incident-investigation",),
    created_at: datetime = NOW,
    expires_at: datetime | None = None,
    quality: float = 0.8,
    trust: SourceTrustTier = SourceTrustTier.REVIEWED,
    source_kind: MemorySourceKind = MemorySourceKind.INCIDENT,
    supersedes: tuple[UUID, ...] = (),
    deletion_scope: str = "derived_and_referenced_blob",
) -> SemanticMemory:
    canonical = " ".join(text.split())
    digest = sha256(canonical.encode()).hexdigest()
    memory_id = identifier(f"memory:{tenant_id}:{name}")
    event_id = identifier(f"event:{tenant_id}:{name}")
    citation = MemoryCitation(
        source_id=f"source-{name}",
        source_uri=f"https://evidence.example/{tenant_id}/{name}",
        content_digest=digest,
        event_id=event_id,
    )
    snapshot = SourceSnapshot(
        snapshot_id=identifier(f"snapshot:{tenant_id}:{name}"),
        tenant_id=tenant_id,
        source_kind=source_kind,
        source_reference=f"source-{name}",
        source_version="v1",
        content_digest=digest,
        content_reference=f"aegis-object://{tenant_id}/{memory_id}",
        occurred_at=created_at,
        captured_at=created_at,
        citations=(citation,),
        trust=trust,
    )
    return SemanticMemory(
        memory_id=memory_id,
        tenant_id=tenant_id,
        snapshot=snapshot,
        incident_id=f"incident-{name}",
        run_id=identifier(f"run:{tenant_id}:{name}"),
        acl=MemoryAcl(
            user_ids=users,
            roles=roles,
            purposes=purposes,
        ),
        security_label=DataClassification.INTERNAL,
        schema_version="semantic-memory-v1",
        chunker_version="bounded-words-v1",
        embedder_version="v1",
        embedding_model="aegis-deterministic-embedding",
        embedding_dimension=8,
        confidence=0.9,
        quality=quality,
        retention=MemoryRetention(
            retention_class="incident",
            expires_at=expires_at,
            deletion_scope=deletion_scope,
        ),
        accepted_by=accepted_by,
        policy_reference="memory-policy-v1",
        created_at=created_at,
        supersedes_memory_ids=supersedes,
    )


@dataclass(slots=True)
class MemoryHarness:
    ledger: InMemoryMemoryLedger
    blobs: InMemoryMemoryBlobStore
    index: InMemoryHybridIndex
    ingestion: MemoryIngestionService

    @classmethod
    def create(cls) -> MemoryHarness:
        ledger = InMemoryMemoryLedger()
        blobs = InMemoryMemoryBlobStore()
        index = InMemoryHybridIndex()
        ingestion = MemoryIngestionService(
            ledger,
            blobs,
            index,
            DeterministicEmbeddingProvider(),
            RegexMemoryScanner(),
            clock=lambda: NOW,
        )
        return cls(ledger, blobs, index, ingestion)

    async def ingest(
        self,
        memory: SemanticMemory,
        text: str,
        *,
        contradiction_ids: tuple[UUID, ...] = (),
    ) -> None:
        context = TenantContext(TenantId(memory.tenant_id))
        result = await self.ingestion.propose(
            context,
            memory,
            text,
            proposed_by=memory.accepted_by,
            idempotency_key=f"proposal-{memory.memory_id}",
        )
        if not result.created:
            return
        active_lease = lease(memory.memory_id, memory.tenant_id)
        self.ledger.register_lease(active_lease)
        await self.ingestion.accept_and_process(
            context,
            memory,
            active_lease,
            accepted_by=memory.accepted_by,
            acceptance_kind="human",
            idempotency_key=f"accept-{memory.memory_id}",
            contradiction_ids=contradiction_ids,
        )


__all__ = [
    "NOW",
    "MemoryHarness",
    "identifier",
    "lease",
    "semantic_memory",
]
