"""Authorized ledger-first semantic memory ingestion and reconciliation."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EmbeddingRequest,
    EmbeddingResponse,
    EventEnvelope,
    JsonValue,
    MemoryCandidateStatus,
    MemoryChunk,
    MemoryJobStatus,
    MemoryLifecycleStatus,
    SemanticMemory,
    WorkLease,
    canonical_text,
    memory_event_payload,
    replay_memory,
)
from aegis_agent_platform.event_store import StorageError
from aegis_agent_platform.memory.ports import (
    EmbeddingProvider,
    MemoryProviderError,
    MemoryProviderErrorClass,
    MemoryScanError,
    MemoryScanner,
    ScanDisposition,
    validate_embedding_response,
)
from aegis_agent_platform.memory.quota import (
    InMemoryMemoryQuota,
    MemoryQuota,
    MemoryQuotaExceededError,
    MemoryQuotaKind,
)
from aegis_agent_platform.memory.repository import (
    MemoryBlobStore,
    MemoryIndex,
    MemoryLedger,
)
from aegis_agent_platform.memory.serialization import (
    memory_from_document,
    memory_to_document,
)
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class ChunkingPolicy:
    version: str = "bounded-words-v1"
    max_tokens: int = 192
    overlap_tokens: int = 24
    max_chunks: int = 128

    def __post_init__(self) -> None:
        if not self.version or len(self.version) > 128:
            raise ValueError("chunking policy version is required")
        if not 16 <= self.max_tokens <= 4_096:
            raise ValueError("chunk token limit is outside the bound")
        if not 0 <= self.overlap_tokens <= min(256, self.max_tokens // 4):
            raise ValueError("chunk overlap is outside the bound")
        if not 1 <= self.max_chunks <= 512:
            raise ValueError("chunk count is outside the bound")


@dataclass(frozen=True, slots=True)
class MemoryProviderPolicy:
    max_batch_items: int = 128
    max_input_tokens: int = 64_000
    max_attempts: int = 2
    max_concurrency: int = 4
    circuit_failure_threshold: int = 3

    def __post_init__(self) -> None:
        if not 1 <= self.max_batch_items <= 128:
            raise ValueError("embedding batch limit is outside the bound")
        if not 256 <= self.max_input_tokens <= 1_000_000:
            raise ValueError("embedding token budget is outside the bound")
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("embedding attempt limit is outside the bound")
        if not 1 <= self.max_concurrency <= 64:
            raise ValueError("embedding concurrency is outside the bound")
        if not 1 <= self.circuit_failure_threshold <= 20:
            raise ValueError("embedding circuit threshold is outside the bound")


@dataclass(frozen=True, slots=True)
class MemoryProposalResult:
    created: bool
    memory_id: UUID


@dataclass(frozen=True, slots=True)
class MemoryIngestionResult:
    memory_id: UUID
    status: str
    chunks: tuple[MemoryChunk, ...]
    duplicate_of: UUID | None = None
    quarantine_reason: str | None = None


def deterministic_chunks(
    memory: SemanticMemory,
    text: str,
    policy: ChunkingPolicy,
) -> tuple[MemoryChunk, ...]:
    """Split canonical text at word boundaries with deterministic bounded overlap."""
    value = canonical_text(text)
    words = value.split()
    if not words:
        raise ValueError("memory source text is empty")
    step = policy.max_tokens - policy.overlap_tokens
    chunks: list[MemoryChunk] = []
    search_offset = 0
    for ordinal, start in enumerate(range(0, len(words), step)):
        if ordinal >= policy.max_chunks:
            raise ValueError("memory source exceeds the deterministic chunk bound")
        selected = words[start : start + policy.max_tokens]
        if not selected:
            break
        chunk_text = " ".join(selected)
        first_word = selected[0]
        start_offset = value.find(first_word, search_offset)
        if start_offset < 0:
            raise ValueError("memory chunk offset could not be determined")
        end_offset = start_offset + len(chunk_text)
        digest = sha256(chunk_text.encode()).hexdigest()
        chunk_id = uuid5(
            NAMESPACE_URL,
            f"aegis-memory:{memory.memory_id}:{policy.version}:{ordinal}:{digest}",
        )
        chunks.append(
            MemoryChunk(
                chunk_id=chunk_id,
                memory_id=memory.memory_id,
                tenant_id=memory.tenant_id,
                ordinal=ordinal,
                text=chunk_text,
                content_digest=digest,
                token_count=len(selected),
                byte_count=len(chunk_text.encode()),
                start_offset=start_offset,
                end_offset=end_offset,
                citations=memory.snapshot.citations,
            )
        )
        if start + policy.max_tokens >= len(words):
            break
        search_offset = max(
            0, end_offset - len(" ".join(selected[-policy.overlap_tokens :]))
        )
    return tuple(chunks)


class MemoryIngestionService:
    """Persist intent before source, embedding, and derived-index side effects."""

    def __init__(
        self,
        ledger: MemoryLedger,
        blobs: MemoryBlobStore,
        index: MemoryIndex,
        embedder: EmbeddingProvider,
        scanner: MemoryScanner,
        *,
        chunking: ChunkingPolicy | None = None,
        provider_policy: MemoryProviderPolicy | None = None,
        quota: MemoryQuota | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
        sleep: Callable[[float], object] | None = None,
    ) -> None:
        self._ledger = ledger
        self._blobs = blobs
        self._index = index
        self._embedder = embedder
        self._scanner = scanner
        self._chunking = chunking or ChunkingPolicy()
        self._provider_policy = provider_policy or MemoryProviderPolicy()
        self._quota = quota or InMemoryMemoryQuota()
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._sleep = sleep
        self._semaphore = asyncio.Semaphore(self._provider_policy.max_concurrency)
        self._provider_failures = 0

    async def propose(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        source_text: str,
        *,
        proposed_by: str,
        idempotency_key: str,
    ) -> MemoryProposalResult:
        self._tenant(context, memory)
        if not proposed_by or not idempotency_key:
            raise ValueError("memory proposal actor and idempotency key are required")
        canonical = canonical_text(source_text)
        if sha256(canonical.encode()).hexdigest() != memory.snapshot.content_digest:
            raise ValueError("memory source digest does not match canonical content")
        duplicate = await self._index.find_version(context, memory.version_key)
        if duplicate is not None:
            return MemoryProposalResult(False, duplicate)
        contract_document = json.dumps(
            memory_to_document(memory),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        contract_document_digest = sha256(contract_document.encode()).hexdigest()
        payload = dict(memory_event_payload(memory))
        payload.update(
            {
                "contract_reference": memory.contract_reference,
                "contract_document_digest": contract_document_digest,
            }
        )
        event = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_CANDIDATE_PROPOSED,
            payload,
            actor_id=proposed_by,
            idempotency_key=f"{idempotency_key}:proposed",
        )
        await self._ledger.append(
            context,
            memory.memory_id,
            (event,),
            expected_version=0,
        )
        try:
            await self._quota.reserve(
                context,
                MemoryQuotaKind.INGESTED_BYTES,
                len(canonical.encode()),
                at=self._clock(),
            )
        except MemoryQuotaExceededError:
            rejected = self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_CANDIDATE_REJECTED,
                {"reason_code": "tenant_ingestion_quota_exhausted"},
                actor_id=proposed_by,
                idempotency_key=f"{idempotency_key}:quota-rejected",
            )
            await self._ledger.append(
                context,
                memory.memory_id,
                (rejected,),
                expected_version=1,
            )
            raise
        await self._blobs.put(context, memory.snapshot, canonical)
        await self._blobs.put(
            context,
            replace(
                memory.snapshot,
                content_digest=contract_document_digest,
                content_reference=memory.contract_reference,
            ),
            contract_document,
        )
        return MemoryProposalResult(True, memory.memory_id)

    async def accept_and_process(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        lease: WorkLease,
        *,
        accepted_by: str,
        acceptance_kind: str,
        idempotency_key: str,
        contradiction_ids: Sequence[UUID] = (),
    ) -> MemoryIngestionResult:
        self._tenant(context, memory)
        if lease.tenant_id != memory.tenant_id:
            raise PermissionError("memory processing lease is not tenant bound")
        if accepted_by != memory.accepted_by or acceptance_kind not in {
            "human",
            "policy",
        }:
            raise PermissionError("semantic memory requires human or policy acceptance")
        events = await self._ledger.load(context, memory.memory_id)
        state = replay_memory(events)
        if state.candidate_status is None:
            raise ValueError("memory candidate was not proposed")
        if events[0].payload.get("contract_digest") != memory.contract_digest:
            raise ValueError("accepted memory contract does not match its proposal")
        contract_document = await self._blobs.get(context, memory.contract_reference)
        expected_contract_digest = events[0].payload.get("contract_document_digest")
        if (
            contract_document is None
            or not isinstance(expected_contract_digest, str)
            or sha256(contract_document.encode()).hexdigest()
            != expected_contract_digest
            or memory_from_document(json.loads(contract_document)).contract_digest
            != memory.contract_digest
        ):
            raise ValueError("accepted memory contract blob failed verification")
        source_text = await self._blobs.get(context, memory.snapshot.content_reference)
        if source_text is None:
            raise ValueError("memory source blob is unavailable")
        if (
            sha256(canonical_text(source_text).encode()).hexdigest()
            != memory.snapshot.content_digest
        ):
            raise ValueError("memory source blob failed digest verification")
        now = self._clock()
        await self._ledger.assert_fence(
            context,
            memory.memory_id,
            lease,
            at=now,
        )
        if state.candidate_status is MemoryCandidateStatus.PROPOSED:
            initial = (
                self._event(
                    memory.memory_id,
                    memory.tenant_id,
                    DomainEventType.MEMORY_CANDIDATE_ACCEPTED,
                    {
                        "accepted_by": accepted_by,
                        "acceptance_kind": acceptance_kind,
                        "policy_reference": memory.policy_reference,
                    },
                    actor_id=accepted_by,
                    idempotency_key=f"{idempotency_key}:accepted",
                    lease=lease,
                ),
                self._event(
                    memory.memory_id,
                    memory.tenant_id,
                    DomainEventType.MEMORY_SOURCE_SNAPSHOT_RECORDED,
                    {
                        "snapshot_id": str(memory.snapshot.snapshot_id),
                        "source_digest": memory.snapshot.content_digest,
                        "source_reference": memory.snapshot.source_reference,
                        "source_version": memory.snapshot.source_version,
                        "citation_ids": tuple(
                            item.source_id for item in memory.snapshot.citations
                        ),
                    },
                    actor_id=accepted_by,
                    idempotency_key=f"{idempotency_key}:snapshot",
                    lease=lease,
                ),
            )
            version = await self._ledger.append_fenced(
                context,
                memory.memory_id,
                lease,
                initial,
                expected_version=len(events),
            )
        elif (
            state.candidate_status is MemoryCandidateStatus.ACCEPTED
            and state.source_snapshot_recorded
        ):
            version = len(events)
        else:
            raise ValueError("memory candidate cannot resume processing")
        if state.indexing is MemoryJobStatus.COMPLETED:
            existing = await self._index.find_version(context, memory.version_key)
            if existing == memory.memory_id:
                return MemoryIngestionResult(memory.memory_id, "active", ())
            raise ValueError("completed memory requires derived-index rebuild")
        recorded_scan = _recorded_scan_outcome(events)
        attempt = (
            sum(
                event.event_type == DomainEventType.MEMORY_SCAN_REQUESTED
                for event in events
            )
            + 1
        )
        attempt_key = f"{idempotency_key}:processing:{attempt}"
        scan_requested = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_SCAN_REQUESTED,
            {
                "source_digest": memory.snapshot.content_digest,
                "scanner_policy": "memory-scan-v1",
            },
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:scan-requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (scan_requested,),
            expected_version=version,
        )
        try:
            scan = await self._scanner.scan(source_text)
        except MemoryScanError as error:
            failed = self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_SCAN_FAILED,
                {
                    "error_code": error.code,
                    "retryable": error.retryable,
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:scan-failed",
                lease=lease,
            )
            await self._ledger.append_fenced(
                context,
                memory.memory_id,
                lease,
                (failed,),
                expected_version=version,
            )
            raise
        if recorded_scan is not None and recorded_scan != (
            scan.disposition.value,
            sha256(scan.redacted_text.encode()).hexdigest(),
            "memory-scan-v1",
            scan.rule_ids,
            scan.prompt_injection_marked,
            scan.poisoning_suspected,
        ):
            drift = MemoryScanError("scanner_result_drift", retryable=False)
            failed = self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_SCAN_FAILED,
                {
                    "error_code": drift.code,
                    "retryable": drift.retryable,
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:scan-drift",
                lease=lease,
            )
            await self._ledger.append_fenced(
                context,
                memory.memory_id,
                lease,
                (failed,),
                expected_version=version,
            )
            raise drift
        scan_events = (
            self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_REDACTION_COMPLETED,
                {
                    "applied": scan.disposition is not ScanDisposition.ALLOW,
                    "rule_ids": scan.rule_ids,
                    "redacted_digest": sha256(scan.redacted_text.encode()).hexdigest(),
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:redaction",
                lease=lease,
            ),
            self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_CLASSIFICATION_COMPLETED,
                {"security_label": memory.security_label.value},
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:classification",
                lease=lease,
            ),
            self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_SCAN_COMPLETED,
                {
                    "disposition": scan.disposition.value,
                    "prompt_injection_marked": scan.prompt_injection_marked,
                    "poisoning_suspected": scan.poisoning_suspected,
                    "rule_ids": scan.rule_ids,
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:scan",
                lease=lease,
            ),
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            scan_events,
            expected_version=version,
        )
        if scan.disposition is ScanDisposition.QUARANTINE:
            quarantine = self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_QUARANTINED,
                {
                    "reason_code": "poisoning_or_prompt_injection",
                    "source_digest": memory.snapshot.content_digest,
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:quarantine",
                lease=lease,
            )
            await self._ledger.append_fenced(
                context,
                memory.memory_id,
                lease,
                (quarantine,),
                expected_version=version,
            )
            return MemoryIngestionResult(
                memory.memory_id,
                "quarantined",
                (),
                quarantine_reason="poisoning_or_prompt_injection",
            )
        chunk_request = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_CHUNKING_REQUESTED,
            {"chunker_version": self._chunking.version},
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:chunk-requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (chunk_request,),
            expected_version=version,
        )
        chunks = deterministic_chunks(memory, scan.redacted_text, self._chunking)
        chunk_complete = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_CHUNKING_COMPLETED,
            {
                "chunk_count": len(chunks),
                "chunk_references": tuple(
                    {
                        "chunk_id": str(chunk.chunk_id),
                        "content_digest": chunk.content_digest,
                        "ordinal": chunk.ordinal,
                    }
                    for chunk in chunks
                ),
            },
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:chunk-completed",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (chunk_complete,),
            expected_version=version,
        )
        total_tokens = sum(chunk.token_count for chunk in chunks)
        provider_idempotency_key = f"{idempotency_key}:embedding"
        embedding_request = EmbeddingRequest(
            request_id=uuid5(
                NAMESPACE_URL,
                f"{memory.tenant_id}:{memory.memory_id}:{provider_idempotency_key}",
            ),
            tenant_id=memory.tenant_id,
            texts=tuple(chunk.text for chunk in chunks),
            model=memory.embedding_model,
            dimension=memory.embedding_dimension,
            model_version=memory.embedder_version,
            timeout_seconds=min(
                60.0, float(lease.expires_at.timestamp() - now.timestamp())
            ),
            idempotency_key=provider_idempotency_key,
        )
        embedding_intent = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_EMBEDDING_REQUESTED,
            {
                "request_id": str(embedding_request.request_id),
                "input_digest": embedding_request.input_digest,
                "model": embedding_request.model,
                "model_version": embedding_request.model_version,
                "dimension": embedding_request.dimension,
                "chunk_count": len(chunks),
            },
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:embedding-requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (embedding_intent,),
            expected_version=version,
        )
        try:
            if (
                len(chunks) > self._provider_policy.max_batch_items
                or total_tokens > self._provider_policy.max_input_tokens
            ):
                raise MemoryProviderError(
                    MemoryProviderErrorClass.RATE_LIMIT,
                    "memory_embedding_request_budget_exhausted",
                    retryable=False,
                )
            try:
                await self._quota.reserve(
                    context,
                    MemoryQuotaKind.EMBEDDED_TOKENS,
                    total_tokens,
                    at=now,
                )
            except MemoryQuotaExceededError as error:
                raise MemoryProviderError(
                    MemoryProviderErrorClass.RATE_LIMIT,
                    "memory_embedding_tenant_quota_exhausted",
                    retryable=False,
                ) from error
            response = await self._embed(embedding_request)
            validate_embedding_response(embedding_request, response)
        except MemoryProviderError as error:
            failed = self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_EMBEDDING_FAILED,
                {
                    "request_id": str(embedding_request.request_id),
                    "error_class": error.error_class.value,
                    "error_code": error.code,
                    "result_ambiguous": error.result_ambiguous,
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:embedding-failed",
                lease=lease,
            )
            await self._ledger.append_fenced(
                context,
                memory.memory_id,
                lease,
                (failed,),
                expected_version=version,
            )
            raise
        completed_chunks = tuple(
            replace(
                chunk,
                embedding_reference=(
                    f"aegis-embedding://{memory.tenant_id}/"
                    f"{embedding_request.request_id}/{chunk.ordinal}"
                ),
                embedding=vector,
            )
            for chunk, vector in zip(chunks, response.vectors, strict=True)
        )
        embedding_completed = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_EMBEDDING_COMPLETED,
            {
                "request_id": str(response.request_id),
                "embedding_references": tuple(
                    chunk.embedding_reference for chunk in completed_chunks
                ),
                "model": response.model,
                "model_version": response.model_version,
                "dimension": response.dimension,
                "provider_request_reference": response.provider_request_id,
            },
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:embedding-completed",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (embedding_completed,),
            expected_version=version,
        )
        indexing_intent = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_INDEXING_REQUESTED,
            {
                "version_key": memory.version_key,
                "chunk_ids": tuple(str(chunk.chunk_id) for chunk in completed_chunks),
                "index_version": "hybrid-index-v1",
                "contradiction_ids": tuple(
                    str(identifier)
                    for identifier in sorted(set(contradiction_ids), key=str)
                ),
            },
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:indexing-requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (indexing_intent,),
            expected_version=version,
        )
        try:
            await self._ledger.assert_fence(
                context,
                memory.memory_id,
                lease,
                at=self._clock(),
            )
            await self._index.upsert(
                context,
                memory,
                completed_chunks,
                indexed_at=self._clock(),
                contradiction_ids=contradiction_ids,
                aggregate_version=version,
            )
        except (StorageError, PermissionError, ValueError) as error:
            failed = self._event(
                memory.memory_id,
                memory.tenant_id,
                DomainEventType.MEMORY_INDEXING_FAILED,
                {
                    "error_code": type(error).__name__,
                    "result_ambiguous": True,
                },
                actor_id=accepted_by,
                idempotency_key=f"{attempt_key}:indexing-failed",
                lease=lease,
            )
            await self._ledger.append_fenced(
                context,
                memory.memory_id,
                lease,
                (failed,),
                expected_version=version,
            )
            raise
        indexed = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_INDEXING_COMPLETED,
            {
                "version_key": memory.version_key,
                "chunk_count": len(completed_chunks),
                "index_version": "hybrid-index-v1",
            },
            actor_id=accepted_by,
            idempotency_key=f"{attempt_key}:indexing-completed",
            lease=lease,
        )
        await self._ledger.append_fenced(
            context,
            memory.memory_id,
            lease,
            (indexed,),
            expected_version=version,
        )
        for superseded_id in memory.supersedes_memory_ids:
            await self._supersede(
                context,
                superseded_id,
                memory.memory_id,
                actor_id=accepted_by,
                idempotency_key=idempotency_key,
            )
        return MemoryIngestionResult(memory.memory_id, "active", completed_chunks)

    async def reject(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        rejected_by: str,
        reason_code: str,
        idempotency_key: str,
    ) -> None:
        """Reject a proposed candidate and erase its unaccepted source blob."""
        self._tenant(context, memory)
        if not rejected_by or not reason_code or len(reason_code) > 128:
            raise ValueError("memory rejection requires bounded actor and reason")
        events = await self._ledger.load(context, memory.memory_id)
        state = replay_memory(events)
        if (
            state.candidate_status is None
            or events[0].payload.get("contract_digest") != memory.contract_digest
        ):
            raise ValueError("rejected memory contract does not match its proposal")
        event = self._event(
            memory.memory_id,
            memory.tenant_id,
            DomainEventType.MEMORY_CANDIDATE_REJECTED,
            {
                "reason_code": reason_code,
                "source_digest": memory.snapshot.content_digest,
            },
            actor_id=rejected_by,
            idempotency_key=f"{idempotency_key}:rejected",
        )
        await self._ledger.append(
            context,
            memory.memory_id,
            (event,),
            expected_version=len(events),
        )
        await self._blobs.delete(context, memory.snapshot.content_reference)
        await self._blobs.delete(context, memory.contract_reference)

    async def reconcile(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        chunks: Sequence[MemoryChunk],
        lease: WorkLease,
    ) -> str:
        """Observe derived index state before retrying ambiguous index delivery."""
        await self._ledger.assert_fence(
            context,
            memory.memory_id,
            lease,
            at=self._clock(),
        )
        existing = await self._index.find_version(context, memory.version_key)
        if existing == memory.memory_id:
            events = await self._ledger.load(context, memory.memory_id)
            state = replay_memory(events)
            if state.indexing is not MemoryJobStatus.COMPLETED:
                completion = self._event(
                    memory.memory_id,
                    memory.tenant_id,
                    DomainEventType.MEMORY_INDEXING_COMPLETED,
                    {
                        "version_key": memory.version_key,
                        "chunk_count": len(chunks),
                        "index_version": "hybrid-index-v1",
                        "observed_during_reconciliation": True,
                    },
                    actor_id=lease.owner,
                    idempotency_key=(
                        f"memory-reconcile:{memory.memory_id}:{len(events)}:completed"
                    ),
                    lease=lease,
                )
                batch: tuple[EventEnvelope, ...]
                if state.indexing is MemoryJobStatus.FAILED:
                    requested = self._event(
                        memory.memory_id,
                        memory.tenant_id,
                        DomainEventType.MEMORY_INDEXING_REQUESTED,
                        {
                            "version_key": memory.version_key,
                            "chunk_ids": tuple(str(chunk.chunk_id) for chunk in chunks),
                            "index_version": "hybrid-index-v1",
                            "reconciliation": True,
                        },
                        actor_id=lease.owner,
                        idempotency_key=(
                            f"memory-reconcile:{memory.memory_id}:{len(events)}:requested"
                        ),
                        lease=lease,
                    )
                    batch = (requested, completion)
                elif state.indexing is MemoryJobStatus.REQUESTED:
                    batch = (completion,)
                else:
                    raise ValueError("memory index observation has no durable intent")
                await self._ledger.append_fenced(
                    context,
                    memory.memory_id,
                    lease,
                    batch,
                    expected_version=len(events),
                )
            return "indexed"
        if existing is not None:
            return "conflict"
        if not chunks:
            return "missing_chunks"
        return "retry_indexing"

    async def _supersede(
        self,
        context: TenantContext,
        old_memory_id: UUID,
        new_memory_id: UUID,
        *,
        actor_id: str,
        idempotency_key: str,
    ) -> None:
        events = await self._ledger.load(context, old_memory_id)
        if not events:
            raise ValueError("superseded memory does not exist")
        state = replay_memory(events)
        if state.lifecycle_status is not MemoryLifecycleStatus.ACTIVE:
            raise ValueError("only active memory may be superseded")
        requested = self._event(
            old_memory_id,
            str(context.tenant_id),
            DomainEventType.MEMORY_SUPERSESSION_REQUESTED,
            {"superseded_by": str(new_memory_id)},
            actor_id=actor_id,
            idempotency_key=f"{idempotency_key}:supersede-requested:{old_memory_id}",
        )
        version = await self._ledger.append(
            context,
            old_memory_id,
            (requested,),
            expected_version=len(events),
        )
        await self._index.set_lifecycle(
            context,
            old_memory_id,
            MemoryLifecycleStatus.SUPERSEDED,
            aggregate_version=version,
        )
        completed = self._event(
            old_memory_id,
            str(context.tenant_id),
            DomainEventType.MEMORY_SUPERSEDED,
            {"superseded_by": str(new_memory_id)},
            actor_id=actor_id,
            idempotency_key=f"{idempotency_key}:superseded:{old_memory_id}",
        )
        await self._ledger.append(
            context,
            old_memory_id,
            (completed,),
            expected_version=version,
        )

    async def _embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        if self._provider_failures >= self._provider_policy.circuit_failure_threshold:
            raise MemoryProviderError(
                MemoryProviderErrorClass.PROVIDER_UNAVAILABLE,
                "embedding_circuit_open",
                retryable=True,
            )
        last_error: MemoryProviderError | None = None
        for attempt in range(1, self._provider_policy.max_attempts + 1):
            try:
                async with self._semaphore:
                    response = await asyncio.wait_for(
                        self._embedder.embed(request),
                        timeout=request.timeout_seconds,
                    )
                self._provider_failures = 0
                return response
            except TimeoutError:
                last_error = MemoryProviderError(
                    MemoryProviderErrorClass.TIMEOUT,
                    "embedding_timeout",
                    retryable=True,
                    result_ambiguous=True,
                )
            except MemoryProviderError as error:
                last_error = error
            if last_error is None or not last_error.retryable:
                break
            self._provider_failures += 1
            if attempt < self._provider_policy.max_attempts:
                await asyncio.sleep(0)
        if last_error is None:
            last_error = MemoryProviderError(
                MemoryProviderErrorClass.PROVIDER_BUG,
                "embedding_provider_failed_without_error",
                retryable=False,
            )
        raise last_error

    def _event(
        self,
        aggregate_id: UUID,
        tenant_id: str,
        event_type: DomainEventType,
        payload: dict[str, JsonValue],
        *,
        actor_id: str,
        idempotency_key: str,
        lease: WorkLease | None = None,
    ) -> EventEnvelope:
        if lease is not None:
            payload["lease_token"] = str(lease.token)
            payload["lease_generation"] = lease.generation
        return EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=tenant_id,
            aggregate_id=str(aggregate_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=self._clock(),
            payload=payload,
            correlation_id=aggregate_id,
            actor=ActorReference(actor_id, ActorKind.USER),
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _tenant(context: TenantContext, memory: SemanticMemory) -> None:
        if str(context.tenant_id) != memory.tenant_id:
            raise PermissionError("cross_tenant_memory_ingestion")


def _recorded_scan_outcome(
    events: Sequence[EventEnvelope],
) -> tuple[str, str, str, tuple[str, ...], bool, bool] | None:
    disposition: str | None = None
    redacted_digest: str | None = None
    scanner_policy: str | None = None
    rule_ids: tuple[str, ...] | None = None
    prompt_injection_marked: bool | None = None
    poisoning_suspected: bool | None = None
    for event in events:
        if event.event_type == DomainEventType.MEMORY_SCAN_REQUESTED:
            policy = event.payload.get("scanner_policy")
            scanner_policy = policy if isinstance(policy, str) else None
        elif event.event_type == DomainEventType.MEMORY_REDACTION_COMPLETED:
            digest = event.payload.get("redacted_digest")
            redacted_digest = digest if isinstance(digest, str) else None
        elif event.event_type == DomainEventType.MEMORY_SCAN_COMPLETED:
            value = event.payload.get("disposition")
            disposition = value if isinstance(value, str) else None
            rules = event.payload.get("rule_ids")
            rule_ids = (
                tuple(str(rule) for rule in rules)
                if isinstance(rules, Sequence) and not isinstance(rules, str)
                else None
            )
            prompt = event.payload.get("prompt_injection_marked")
            prompt_injection_marked = prompt if isinstance(prompt, bool) else None
            poisoning = event.payload.get("poisoning_suspected")
            poisoning_suspected = poisoning if isinstance(poisoning, bool) else None
    if disposition is None:
        return None
    if (
        disposition is None
        or redacted_digest is None
        or scanner_policy is None
        or rule_ids is None
        or prompt_injection_marked is None
        or poisoning_suspected is None
    ):
        raise ValueError("memory scan history is corrupt")
    return (
        disposition,
        redacted_digest,
        scanner_policy,
        rule_ids,
        prompt_injection_marked,
        poisoning_suspected,
    )


__all__ = [
    "ChunkingPolicy",
    "MemoryIngestionResult",
    "MemoryIngestionService",
    "MemoryProposalResult",
    "MemoryProviderPolicy",
    "deterministic_chunks",
]
