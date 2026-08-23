"""Retention, feedback, tombstone, erasure, and deterministic rebuild workflows."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EmbeddingRequest,
    EventEnvelope,
    JsonValue,
    MemoryJobStatus,
    MemoryLifecycleStatus,
    MemoryReplayState,
    MemoryRetention,
    SemanticMemory,
    normalized_vector,
    replay_memory,
)
from aegis_agent_platform.memory.cache import MemoryCache
from aegis_agent_platform.memory.ingestion import ChunkingPolicy, deterministic_chunks
from aegis_agent_platform.memory.ports import (
    EmbeddingProvider,
    MemoryScanner,
    ScanDisposition,
    validate_embedding_response,
)
from aegis_agent_platform.memory.repository import (
    IndexedMemoryChunk,
    MemoryBlobStore,
    MemoryIndex,
    MemoryLedger,
)
from aegis_agent_platform.memory.serialization import memory_from_document
from aegis_agent_platform.tenancy import TenantContext


class MemoryLifecycleService:
    """Keep ledger transitions authoritative while purging derived state."""

    def __init__(
        self,
        ledger: MemoryLedger,
        blobs: MemoryBlobStore,
        index: MemoryIndex,
        *,
        cache: MemoryCache | None = None,
        rebuild_embedder: EmbeddingProvider | None = None,
        rebuild_scanner: MemoryScanner | None = None,
        rebuild_chunking: ChunkingPolicy | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._ledger = ledger
        self._blobs = blobs
        self._index = index
        self._cache = cache
        self._rebuild_embedder = rebuild_embedder
        self._rebuild_scanner = rebuild_scanner
        self._rebuild_chunking = rebuild_chunking or ChunkingPolicy()
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def feedback(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        actor_id: str,
        rating: float,
        relevant: bool,
        reason_code: str,
    ) -> float:
        if not 0 <= rating <= 1:
            raise ValueError("memory feedback rating must be between 0 and 1")
        if not actor_id or not reason_code or len(reason_code) > 128:
            raise ValueError("memory feedback requires bounded actor and reason")
        state, events = await self._state(context, memory_id)
        if state.lifecycle_status is not MemoryLifecycleStatus.ACTIVE:
            raise ValueError("feedback requires active memory")
        memory = await self._authoritative_memory(context, memory_id, events)
        quality = max(
            0.0,
            min(
                1.0,
                memory.quality * 0.8 + rating * 0.2
                if relevant
                else memory.quality * 0.8,
            ),
        )
        batch = (
            self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_FEEDBACK_RECORDED,
                {
                    "rating": rating,
                    "relevant": relevant,
                    "reason_code": reason_code,
                },
                actor_id=actor_id,
                suffix=f"feedback:{len(events)}",
            ),
            self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_QUALITY_UPDATED,
                {
                    "previous_quality": memory.quality,
                    "quality": quality,
                    "policy_version": "quality-ewma-v1",
                },
                actor_id=actor_id,
                suffix=f"quality:{len(events)}",
            ),
        )
        version = await self._ledger.append(
            context,
            memory_id,
            batch,
            expected_version=len(events),
        )
        await self._index.update_quality(
            context,
            replace(memory, quality=quality),
            aggregate_version=version,
        )
        await self._invalidate(context)
        return quality

    async def tombstone(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        actor_id: str,
        reason_code: str,
    ) -> None:
        state, events = await self._state(context, memory_id)
        if state.legal_hold:
            raise PermissionError("legal_hold_blocks_tombstone")
        if state.lifecycle_status not in {
            MemoryLifecycleStatus.ACTIVE,
            MemoryLifecycleStatus.SUPERSEDED,
        }:
            raise ValueError("only active or superseded memory may be tombstoned")
        if state.tombstone_requested:
            version = len(events)
        else:
            requested = self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_TOMBSTONE_REQUESTED,
                {"reason_code": reason_code},
                actor_id=actor_id,
                suffix="tombstone-requested",
            )
            version = await self._ledger.append(
                context,
                memory_id,
                (requested,),
                expected_version=len(events),
            )
        await self._index.set_lifecycle(
            context,
            memory_id,
            MemoryLifecycleStatus.TOMBSTONED,
            aggregate_version=version,
        )
        completed = self._event(
            context,
            memory_id,
            DomainEventType.MEMORY_TOMBSTONED,
            {"reason_code": reason_code},
            actor_id=actor_id,
            suffix="tombstoned",
        )
        await self._ledger.append(
            context,
            memory_id,
            (completed,),
            expected_version=version,
        )
        await self._invalidate(context)

    async def retention(
        self,
        context: TenantContext,
        memory_id: UUID,
        retention: MemoryRetention,
        *,
        actor_id: str,
        policy_reference: str,
    ) -> None:
        state, events = await self._state(context, memory_id)
        if state.deletion_requested:
            raise ValueError("retention cannot change after deletion intent")
        memory = await self._authoritative_memory(context, memory_id, events)
        if (
            retention.legal_hold != memory.retention.legal_hold
            or retention.legal_hold_reference != memory.retention.legal_hold_reference
        ):
            raise ValueError("retention updates cannot change legal-hold state")
        payload: dict[str, JsonValue] = {
            "retention_class": retention.retention_class,
            "expires_at": (
                retention.expires_at.isoformat()
                if retention.expires_at is not None
                else None
            ),
            "deletion_scope": retention.deletion_scope,
            "policy_reference": policy_reference,
        }
        batch = (
            self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_RETENTION_UPDATE_REQUESTED,
                payload,
                actor_id=actor_id,
                suffix=f"retention-requested:{len(events)}",
            ),
            self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_RETENTION_UPDATED,
                payload,
                actor_id=actor_id,
                suffix=f"retention-updated:{len(events)}",
            ),
        )
        version = await self._ledger.append(
            context,
            memory_id,
            batch,
            expected_version=len(events),
        )
        await self._index.update_retention(
            context,
            replace(memory, retention=retention),
            aggregate_version=version,
        )
        await self._invalidate(context)

    async def legal_hold(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        actor_id: str,
        hold_reference: str,
        enabled: bool,
    ) -> None:
        state, events = await self._state(context, memory_id)
        if state.deletion_requested:
            raise ValueError("legal hold cannot change after deletion intent")
        if enabled == state.legal_hold:
            raise ValueError("memory legal hold already has the requested state")
        memory = await self._authoritative_memory(context, memory_id, events)
        event_type = (
            DomainEventType.MEMORY_LEGAL_HOLD_PLACED
            if enabled
            else DomainEventType.MEMORY_LEGAL_HOLD_RELEASED
        )
        batch = (
            self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_LEGAL_HOLD_UPDATE_REQUESTED,
                {"hold_reference": hold_reference, "enabled": enabled},
                actor_id=actor_id,
                suffix=f"legal-hold-requested:{len(events)}",
            ),
            self._event(
                context,
                memory_id,
                event_type,
                {"hold_reference": hold_reference},
                actor_id=actor_id,
                suffix=f"legal-hold-updated:{len(events)}",
            ),
        )
        version = await self._ledger.append(
            context,
            memory_id,
            batch,
            expected_version=len(events),
        )
        updated = replace(
            memory.retention,
            legal_hold=enabled,
            legal_hold_reference=hold_reference if enabled else None,
        )
        await self._index.update_retention(
            context,
            replace(memory, retention=updated),
            aggregate_version=version,
        )
        await self._invalidate(context)

    async def delete(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        actor_id: str,
        request_reference: str,
    ) -> int:
        state, events = await self._state(context, memory_id)
        if state.legal_hold:
            raise PermissionError("legal_hold_blocks_deletion")
        if state.lifecycle_status is MemoryLifecycleStatus.DELETED:
            await self._index.delete_metadata(
                context,
                memory_id,
                aggregate_version=len(events),
            )
            contract_reference, _contract_digest = _contract_reference(events)
            await self._blobs.delete(context, contract_reference)
            await self._invalidate(context)
            return 0
        memory = await self._authoritative_memory(context, memory_id, events)
        if state.deletion_requested:
            version = len(events)
        else:
            requested = self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_DELETION_REQUESTED,
                {
                    "request_reference": request_reference,
                    "deletion_scope": memory.retention.deletion_scope,
                },
                actor_id=actor_id,
                suffix="deletion-requested",
            )
            version = await self._ledger.append(
                context,
                memory_id,
                (requested,),
                expected_version=len(events),
            )
        crypto = memory.retention.deletion_scope == "crypto_erasure"
        if crypto and not state.crypto_erasure_requested:
            erasure_requested = self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_CRYPTO_ERASURE_REQUESTED,
                {
                    "content_reference_digest": _reference_digest(
                        memory.snapshot.content_reference
                    ),
                    "key_reference": "deployment-managed",
                },
                actor_id=actor_id,
                suffix="crypto-erasure-requested",
            )
            version = await self._ledger.append(
                context,
                memory_id,
                (erasure_requested,),
                expected_version=version,
            )
        deleted_chunks = await self._index.purge_chunks(context, memory_id)
        blob_deleted = False
        if memory.retention.deletion_scope != "derived_only":
            blob_deleted = await self._blobs.delete(
                context,
                memory.snapshot.content_reference,
            )
        completion: list[EventEnvelope] = []
        if crypto:
            completion.append(
                self._event(
                    context,
                    memory_id,
                    DomainEventType.MEMORY_CRYPTO_ERASURE_COMPLETED,
                    {
                        "content_reference_digest": _reference_digest(
                            memory.snapshot.content_reference
                        ),
                        "reference_removed": blob_deleted,
                        "boundary": "referenced_blob_only",
                    },
                    actor_id=actor_id,
                    suffix="crypto-erasure-completed",
                )
            )
        completion.append(
            self._event(
                context,
                memory_id,
                DomainEventType.MEMORY_DELETION_COMPLETED,
                {
                    "derived_chunks_deleted": deleted_chunks,
                    "referenced_blob_deleted": blob_deleted,
                    "immutable_ledger_retained": True,
                },
                actor_id=actor_id,
                suffix="deletion-completed",
            )
        )
        completed_version = await self._ledger.append(
            context,
            memory_id,
            tuple(completion),
            expected_version=version,
        )
        await self._index.delete_metadata(
            context,
            memory_id,
            aggregate_version=completed_version,
        )
        if memory.retention.deletion_scope != "derived_only":
            await self._blobs.delete(context, memory.contract_reference)
        await self._invalidate(context)
        return deleted_chunks

    async def rebuild(
        self,
        context: TenantContext,
        records: Sequence[IndexedMemoryChunk],
        *,
        actor_id: str,
        checkpoint_position: int,
    ) -> UUID:
        if checkpoint_position < 1:
            raise ValueError("memory rebuild checkpoint must be positive")
        rebuild_id = self._uuid_factory()
        requested = self._event(
            context,
            rebuild_id,
            DomainEventType.MEMORY_REBUILD_REQUESTED,
            {
                "source": "event_ledger_and_referenced_blobs",
                "record_count": len(records),
            },
            actor_id=actor_id,
            suffix="rebuild-requested",
        )
        version = await self._ledger.append(
            context,
            rebuild_id,
            (requested,),
            expected_version=0,
        )
        await self._index.rebuild(context, records)
        completed = self._event(
            context,
            rebuild_id,
            DomainEventType.MEMORY_REBUILD_COMPLETED,
            {"record_count": len(records), "index_version": "hybrid-index-v1"},
            actor_id=actor_id,
            suffix="rebuild-completed",
        )
        checkpoint = self._event(
            context,
            rebuild_id,
            DomainEventType.MEMORY_CHECKPOINT_RECORDED,
            {"position": checkpoint_position, "index_version": "hybrid-index-v1"},
            actor_id=actor_id,
            suffix="checkpoint",
        )
        await self._ledger.append(
            context,
            rebuild_id,
            (completed, checkpoint),
            expected_version=version,
        )
        await self._invalidate(context)
        return rebuild_id

    async def rebuild_from_ledger(
        self,
        context: TenantContext,
        *,
        actor_id: str,
        checkpoint_position: int,
    ) -> UUID:
        """Rebuild derived records from event truth and digest-bound source blobs."""
        if self._rebuild_embedder is None or self._rebuild_scanner is None:
            raise ValueError("memory rebuild providers are not configured")
        if checkpoint_position < 1:
            raise ValueError("memory rebuild checkpoint must be positive")
        streams = await self._candidate_streams(context)
        rebuild_id = self._uuid_factory()
        requested = self._event(
            context,
            rebuild_id,
            DomainEventType.MEMORY_REBUILD_REQUESTED,
            {
                "source": "event_ledger_and_referenced_blobs",
                "record_count": len(streams),
                "chunker_version": self._rebuild_chunking.version,
            },
            actor_id=actor_id,
            suffix="rebuild-requested",
        )
        version = await self._ledger.append(
            context,
            rebuild_id,
            (requested,),
            expected_version=0,
        )
        records: list[IndexedMemoryChunk] = []
        tombstones: dict[UUID, int] = {}
        for memory_id, events in sorted(streams.items(), key=lambda item: str(item[0])):
            state = replay_memory(events)
            if state.lifecycle_status is MemoryLifecycleStatus.DELETED:
                tombstones[memory_id] = state.version
                continue
            if state.indexing is not MemoryJobStatus.COMPLETED:
                continue
            proposal = events[0]
            memory = await self._authoritative_memory(context, memory_id, events)
            if (
                memory.contract_digest != proposal.payload.get("contract_digest")
                or memory.chunker_version != self._rebuild_chunking.version
            ):
                raise ValueError("memory rebuild contract does not match event truth")
            source = await self._blobs.get(
                context,
                memory.snapshot.content_reference,
            )
            if (
                source is None
                or sha256(source.encode()).hexdigest() != memory.snapshot.content_digest
            ):
                raise ValueError("memory rebuild source blob failed verification")
            scan = await self._rebuild_scanner.scan(source)
            if scan.disposition is ScanDisposition.QUARANTINE:
                raise ValueError("memory rebuild scanner quarantined indexed content")
            recorded_scan = _scan_outcome(events)
            if recorded_scan != (
                scan.disposition.value,
                sha256(scan.redacted_text.encode()).hexdigest(),
                "memory-scan-v1",
                scan.rule_ids,
                scan.prompt_injection_marked,
                scan.poisoning_suspected,
            ):
                raise ValueError(
                    "memory rebuild scanner output changed from event truth"
                )
            chunks = deterministic_chunks(
                memory,
                scan.redacted_text,
                self._rebuild_chunking,
            )
            embedding_request = EmbeddingRequest(
                request_id=uuid5(NAMESPACE_URL, f"rebuild:{rebuild_id}:{memory_id}"),
                tenant_id=memory.tenant_id,
                texts=tuple(chunk.text for chunk in chunks),
                model=memory.embedding_model,
                dimension=memory.embedding_dimension,
                model_version=memory.embedder_version,
                timeout_seconds=60,
                idempotency_key=f"rebuild:{rebuild_id}:{memory_id}:embedding",
            )
            response = await self._rebuild_embedder.embed(embedding_request)
            validate_embedding_response(embedding_request, response)
            contradictions = _contradiction_ids(events)
            indexed_at = max(event.occurred_at for event in events)
            records.extend(
                IndexedMemoryChunk(
                    memory,
                    replace(
                        chunk,
                        embedding_reference=(
                            f"aegis-embedding://{memory.tenant_id}/"
                            f"{embedding_request.request_id}/{chunk.ordinal}"
                        ),
                        embedding=normalized_vector(vector),
                    ),
                    indexed_at,
                    lifecycle=state.lifecycle_status,
                    contradiction_ids=contradictions,
                    aggregate_version=state.version,
                )
                for chunk, vector in zip(chunks, response.vectors, strict=True)
            )
        await self._index.rebuild(context, records, tombstones=tombstones)
        completed = self._event(
            context,
            rebuild_id,
            DomainEventType.MEMORY_REBUILD_COMPLETED,
            {"record_count": len(records), "index_version": "hybrid-index-v1"},
            actor_id=actor_id,
            suffix="rebuild-completed",
        )
        checkpoint = self._event(
            context,
            rebuild_id,
            DomainEventType.MEMORY_CHECKPOINT_RECORDED,
            {"position": checkpoint_position, "index_version": "hybrid-index-v1"},
            actor_id=actor_id,
            suffix="checkpoint",
        )
        await self._ledger.append(
            context,
            rebuild_id,
            (completed, checkpoint),
            expected_version=version,
        )
        await self._invalidate(context)
        return rebuild_id

    async def _candidate_streams(
        self,
        context: TenantContext,
    ) -> dict[UUID, tuple[EventEnvelope, ...]]:
        candidate_ids: set[UUID] = set()
        after_position = 0
        while True:
            page, cursor = await self._ledger.scan(
                context,
                after_position=after_position,
                limit=500,
            )
            candidate_ids.update(
                UUID(event.aggregate_id)
                for event in page
                if event.event_type == DomainEventType.MEMORY_CANDIDATE_PROPOSED
            )
            if cursor is None:
                break
            after_position = cursor
        return {
            memory_id: await self._ledger.load(context, memory_id)
            for memory_id in candidate_ids
        }

    async def _state(
        self,
        context: TenantContext,
        memory_id: UUID,
    ) -> tuple[MemoryReplayState, tuple[EventEnvelope, ...]]:
        events = await self._ledger.load(context, memory_id)
        if not events:
            raise ValueError("memory does not exist")
        return replay_memory(events), events

    async def _authoritative_memory(
        self,
        context: TenantContext,
        memory_id: UUID,
        events: Sequence[EventEnvelope],
    ) -> SemanticMemory:
        contract_reference, contract_digest = _contract_reference(events)
        document = await self._blobs.get(context, contract_reference)
        if document is None or sha256(document.encode()).hexdigest() != contract_digest:
            raise ValueError("memory contract blob failed verification")
        memory = memory_from_document(json.loads(document))
        if memory.memory_id != memory_id or memory.tenant_id != str(context.tenant_id):
            raise ValueError("memory contract does not match event truth")
        return _apply_event_overrides(memory, events, replay_memory(events))

    async def _invalidate(self, context: TenantContext) -> None:
        if self._cache is not None:
            await self._cache.invalidate_tenant(context)

    def _event(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        event_type: DomainEventType,
        payload: dict[str, JsonValue],
        *,
        actor_id: str,
        suffix: str,
    ) -> EventEnvelope:
        return EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=str(context.tenant_id),
            aggregate_id=str(aggregate_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=self._clock(),
            payload=payload,
            correlation_id=aggregate_id,
            actor=ActorReference(actor_id, ActorKind.USER),
            idempotency_key=f"memory:{aggregate_id}:{suffix}",
        )


def _reference_digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _contract_reference(events: Sequence[EventEnvelope]) -> tuple[str, str]:
    proposals = [
        event
        for event in events
        if event.event_type == DomainEventType.MEMORY_CANDIDATE_PROPOSED
    ]
    if len(proposals) != 1:
        raise ValueError("memory contract event history is corrupt")
    reference = proposals[0].payload.get("contract_reference")
    digest = proposals[0].payload.get("contract_document_digest")
    if not isinstance(reference, str) or not isinstance(digest, str):
        raise ValueError("memory contract reference is missing")
    return reference, digest


def _contradiction_ids(events: Sequence[EventEnvelope]) -> tuple[UUID, ...]:
    values: set[UUID] = set()
    for event in events:
        if event.event_type != DomainEventType.MEMORY_INDEXING_REQUESTED:
            continue
        identifiers = event.payload.get("contradiction_ids", ())
        if not isinstance(identifiers, Sequence) or isinstance(identifiers, str):
            raise ValueError("memory contradiction references are corrupt")
        values.update(UUID(str(identifier)) for identifier in identifiers)
    return tuple(sorted(values, key=str))


def _scan_outcome(
    events: Sequence[EventEnvelope],
) -> tuple[str, str, str, tuple[str, ...], bool, bool]:
    disposition: str | None = None
    redacted_digest: str | None = None
    policy: str | None = None
    rule_ids: tuple[str, ...] | None = None
    prompt_injection_marked: bool | None = None
    poisoning_suspected: bool | None = None
    for event in events:
        if event.event_type == DomainEventType.MEMORY_SCAN_REQUESTED:
            value = event.payload.get("scanner_policy")
            policy = value if isinstance(value, str) else None
        elif event.event_type == DomainEventType.MEMORY_REDACTION_COMPLETED:
            value = event.payload.get("redacted_digest")
            redacted_digest = value if isinstance(value, str) else None
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
    if (
        disposition is None
        or redacted_digest is None
        or policy is None
        or rule_ids is None
        or prompt_injection_marked is None
        or poisoning_suspected is None
    ):
        raise ValueError("memory rebuild scan history is corrupt")
    return (
        disposition,
        redacted_digest,
        policy,
        rule_ids,
        prompt_injection_marked,
        poisoning_suspected,
    )


def _apply_event_overrides(
    memory: SemanticMemory,
    events: Sequence[EventEnvelope],
    state: MemoryReplayState,
) -> SemanticMemory:
    updated = memory
    for event in events:
        if event.event_type == DomainEventType.MEMORY_QUALITY_UPDATED:
            quality = event.payload.get("quality")
            if not isinstance(quality, (int, float)) or isinstance(quality, bool):
                raise ValueError("memory quality event is corrupt")
            updated = replace(updated, quality=float(quality))
        elif event.event_type == DomainEventType.MEMORY_RETENTION_UPDATED:
            expires_at = event.payload.get("expires_at")
            updated = replace(
                updated,
                retention=replace(
                    updated.retention,
                    retention_class=str(event.payload["retention_class"]),
                    expires_at=(
                        datetime.fromisoformat(expires_at)
                        if isinstance(expires_at, str)
                        else None
                    ),
                    deletion_scope=str(event.payload["deletion_scope"]),
                ),
            )
        elif event.event_type == DomainEventType.MEMORY_LEGAL_HOLD_PLACED:
            updated = replace(
                updated,
                retention=replace(
                    updated.retention,
                    legal_hold=True,
                    legal_hold_reference=str(event.payload["hold_reference"]),
                ),
            )
        elif event.event_type == DomainEventType.MEMORY_LEGAL_HOLD_RELEASED:
            updated = replace(
                updated,
                retention=replace(
                    updated.retention,
                    legal_hold=False,
                    legal_hold_reference=None,
                ),
            )
    if updated.retention.legal_hold != state.legal_hold:
        raise ValueError("memory legal-hold replay does not match its contract")
    return updated


__all__ = ["MemoryLifecycleService"]
