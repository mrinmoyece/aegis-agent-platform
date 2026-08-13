"""Ledger-first memory repositories and disposable in-memory hybrid index."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import (
    EventEnvelope,
    MemoryChunk,
    MemoryLifecycleStatus,
    RetrievalQuery,
    SemanticMemory,
    SourceSnapshot,
    WorkLease,
    replay_memory,
)
from aegis_agent_platform.event_store import ConcurrencyError, FencingError
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class IndexedMemoryChunk:
    memory: SemanticMemory
    chunk: MemoryChunk
    indexed_at: datetime
    lifecycle: MemoryLifecycleStatus = MemoryLifecycleStatus.ACTIVE
    contradiction_ids: tuple[UUID, ...] = ()
    aggregate_version: int = 1

    def __post_init__(self) -> None:
        if (
            self.memory.memory_id != self.chunk.memory_id
            or self.memory.tenant_id != self.chunk.tenant_id
        ):
            raise ValueError("indexed chunk linkage does not match memory")
        if self.indexed_at.tzinfo is None:
            raise ValueError("indexed_at must be timezone-aware")
        if self.aggregate_version < 1:
            raise ValueError("indexed memory aggregate version must be positive")
        object.__setattr__(
            self,
            "contradiction_ids",
            tuple(sorted(set(self.contradiction_ids), key=str)),
        )


class MemoryLedger(Protocol):
    async def append(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int: ...

    async def append_fenced(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int: ...

    async def assert_fence(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None: ...

    async def load(
        self,
        context: TenantContext,
        aggregate_id: UUID,
    ) -> tuple[EventEnvelope, ...]: ...

    async def scan(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 500,
    ) -> tuple[tuple[EventEnvelope, ...], int | None]: ...


class MemoryBlobStore(Protocol):
    async def put(
        self,
        context: TenantContext,
        snapshot: SourceSnapshot,
        text: str,
    ) -> bool: ...

    async def get(self, context: TenantContext, reference: str) -> str | None: ...

    async def delete(self, context: TenantContext, reference: str) -> bool: ...


class MemoryIndex(Protocol):
    async def upsert(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        chunks: Sequence[MemoryChunk],
        *,
        indexed_at: datetime,
        contradiction_ids: Sequence[UUID] = (),
        aggregate_version: int,
        lifecycle: MemoryLifecycleStatus = MemoryLifecycleStatus.ACTIVE,
    ) -> None: ...

    async def candidates(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        *,
        query_vector: Sequence[float] | None = None,
    ) -> tuple[IndexedMemoryChunk, ...]: ...

    async def find_version(
        self,
        context: TenantContext,
        version_key: str,
    ) -> UUID | None: ...

    async def set_lifecycle(
        self,
        context: TenantContext,
        memory_id: UUID,
        lifecycle: MemoryLifecycleStatus,
        *,
        aggregate_version: int,
    ) -> None: ...

    async def update_quality(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        aggregate_version: int,
    ) -> None: ...

    async def update_retention(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        aggregate_version: int,
    ) -> None: ...

    async def purge_chunks(self, context: TenantContext, memory_id: UUID) -> int: ...

    async def delete_metadata(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        aggregate_version: int,
    ) -> None: ...

    async def provenance(
        self,
        context: TenantContext,
        memory_id: UUID,
    ) -> SemanticMemory | None: ...

    async def page(
        self,
        context: TenantContext,
        *,
        after_memory_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[SemanticMemory, ...], UUID | None]: ...

    async def rebuild(
        self,
        context: TenantContext,
        records: Sequence[IndexedMemoryChunk],
        *,
        tombstones: Mapping[UUID, int] | None = None,
    ) -> None: ...


class InMemoryMemoryLedger(MemoryLedger):
    """Race-safe event truth with explicit worker fencing."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._events: dict[tuple[str, UUID], list[EventEnvelope]] = {}
        self._global_events: list[EventEnvelope] = []
        self._leases: dict[tuple[str, UUID], WorkLease] = {}

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(self._global_events)

    def register_lease(self, lease: WorkLease) -> None:
        self._leases[(lease.tenant_id, lease.work_id)] = lease

    def replace_lease(self, lease: WorkLease) -> None:
        self.register_lease(lease)

    async def append(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        async with self._lock:
            return self._append_locked(
                str(context.tenant_id),
                aggregate_id,
                events,
                expected_version=expected_version,
            )

    async def append_fenced(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not events:
            raise ValueError("fenced memory append requires events")
        async with self._lock:
            self._assert_fence_locked(
                str(context.tenant_id),
                lease.work_id,
                lease,
                at=events[0].occurred_at,
            )
            if any(
                event.payload.get("lease_token") != str(lease.token)
                or event.payload.get("lease_generation") != lease.generation
                for event in events
            ):
                raise ValueError("memory event does not match the active fence")
            return self._append_locked(
                str(context.tenant_id),
                aggregate_id,
                events,
                expected_version=expected_version,
            )

    async def assert_fence(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        del aggregate_id
        async with self._lock:
            self._assert_fence_locked(
                str(context.tenant_id),
                lease.work_id,
                lease,
                at=at,
            )

    async def load(
        self,
        context: TenantContext,
        aggregate_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        return tuple(self._events.get((str(context.tenant_id), aggregate_id), ()))

    async def scan(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 500,
    ) -> tuple[tuple[EventEnvelope, ...], int | None]:
        if after_position < 0 or not 1 <= limit <= 1_000:
            raise ValueError("memory scan cursor or limit is invalid")
        tenant_events = tuple(
            event
            for event in self._global_events
            if event.tenant_id == str(context.tenant_id)
            and (event.global_position or 0) > after_position
        )
        page = tenant_events[:limit]
        next_position = (
            page[-1].global_position if len(tenant_events) > limit and page else None
        )
        return page, next_position

    def _append_locked(
        self,
        tenant_id: str,
        aggregate_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not events:
            raise ValueError("memory append requires events")
        stream = self._events.setdefault((tenant_id, aggregate_id), [])
        if len(stream) != expected_version:
            raise ConcurrencyError(expected_version, len(stream))
        if any(
            event.tenant_id != tenant_id or event.aggregate_id != str(aggregate_id)
            for event in events
        ):
            raise ValueError("memory events must match trusted tenant and aggregate")
        prepared = [
            replace(
                event,
                aggregate_sequence=expected_version + position,
                global_position=len(self._global_events) + position,
            )
            for position, event in enumerate(events, start=1)
        ]
        replay_memory((*stream, *prepared))
        stream.extend(prepared)
        self._global_events.extend(prepared)
        return len(stream)

    def _assert_fence_locked(
        self,
        tenant_id: str,
        work_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        current = self._leases.get((tenant_id, work_id))
        if (
            lease.tenant_id != tenant_id
            or current is None
            or current.token != lease.token
            or current.generation != lease.generation
            or current.expires_at <= at
        ):
            raise FencingError(
                lease.generation,
                current.generation if current is not None else 0,
            )


class InMemoryMemoryBlobStore(MemoryBlobStore):
    """Tenant-bound erasable source blobs for deterministic tests."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], tuple[str, str]] = {}

    async def put(
        self,
        context: TenantContext,
        snapshot: SourceSnapshot,
        text: str,
    ) -> bool:
        tenant_id = str(context.tenant_id)
        if snapshot.tenant_id != tenant_id or not snapshot.content_reference.startswith(
            f"aegis-object://{tenant_id}/"
        ):
            raise PermissionError("cross_tenant_memory_blob")
        key = (tenant_id, snapshot.content_reference)
        existing = self._values.get(key)
        if existing is not None:
            if existing != (snapshot.content_digest, text):
                raise ValueError("memory blob reference was rebound")
            return False
        self._values[key] = (snapshot.content_digest, text)
        return True

    async def get(self, context: TenantContext, reference: str) -> str | None:
        value = self._values.get((str(context.tenant_id), reference))
        return value[1] if value is not None else None

    async def delete(self, context: TenantContext, reference: str) -> bool:
        return self._values.pop((str(context.tenant_id), reference), None) is not None


class InMemoryHybridIndex(MemoryIndex):
    """Disposable tenant/ACL-filtered keyword/vector index."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, UUID], IndexedMemoryChunk] = {}
        self._versions: dict[tuple[str, str], UUID] = {}
        self._memories: dict[tuple[str, UUID], SemanticMemory] = {}
        self._aggregate_versions: dict[tuple[str, UUID], int] = {}
        self._tombstones: dict[tuple[str, UUID], int] = {}

    @property
    def records(self) -> Mapping[tuple[str, UUID], IndexedMemoryChunk]:
        return MappingProxyType(dict(self._records))

    async def upsert(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        chunks: Sequence[MemoryChunk],
        *,
        indexed_at: datetime,
        contradiction_ids: Sequence[UUID] = (),
        aggregate_version: int,
        lifecycle: MemoryLifecycleStatus = MemoryLifecycleStatus.ACTIVE,
    ) -> None:
        tenant_id = str(context.tenant_id)
        tombstone_version = self._tombstones.get((tenant_id, memory.memory_id), 0)
        if aggregate_version <= tombstone_version:
            raise ValueError("deleted memory projection cannot be resurrected")
        if memory.tenant_id != tenant_id:
            raise PermissionError("cross_tenant_memory_index")
        version_key = (tenant_id, memory.version_key)
        existing = self._versions.get(version_key)
        if existing is not None and existing != memory.memory_id:
            raise ValueError("memory version already belongs to another identifier")
        for chunk in chunks:
            if chunk.tenant_id != tenant_id or chunk.memory_id != memory.memory_id:
                raise PermissionError("cross_tenant_memory_chunk")
        current_version = self._aggregate_versions.get((tenant_id, memory.memory_id), 0)
        if aggregate_version < current_version:
            return
        for chunk in chunks:
            self._records[(tenant_id, chunk.chunk_id)] = IndexedMemoryChunk(
                memory,
                chunk,
                indexed_at,
                lifecycle=lifecycle,
                contradiction_ids=tuple(contradiction_ids),
                aggregate_version=aggregate_version,
            )
        self._versions[version_key] = memory.memory_id
        self._memories[(tenant_id, memory.memory_id)] = memory
        self._aggregate_versions[(tenant_id, memory.memory_id)] = aggregate_version

    async def candidates(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        *,
        query_vector: Sequence[float] | None = None,
    ) -> tuple[IndexedMemoryChunk, ...]:
        del query_vector
        tenant_id = str(context.tenant_id)
        if query.tenant_id != tenant_id:
            raise PermissionError("cross_tenant_memory_retrieval")
        values = tuple(
            record
            for (row_tenant, _), record in self._records.items()
            if row_tenant == tenant_id
            and record.lifecycle is MemoryLifecycleStatus.ACTIVE
            and record.memory.embedding_model == query.embedding_model
            and record.memory.embedder_version == query.embedding_model_version
            and record.memory.embedding_dimension == query.embedding_dimension
            and record.memory.quality >= query.minimum_quality
            and record.memory.acl.allows(
                principal_id=query.principal_id,
                service_id=query.service_id,
                roles=query.roles,
                purpose=query.purpose,
            )
            and (
                record.memory.retention.expires_at is None
                or query.as_of is None
                or record.memory.retention.expires_at > query.as_of
            )
        )
        return tuple(
            sorted(
                values,
                key=lambda item: (
                    item.memory.created_at,
                    str(item.memory.memory_id),
                    item.chunk.ordinal,
                ),
                reverse=True,
            )[: query.candidate_limit]
        )

    async def find_version(
        self,
        context: TenantContext,
        version_key: str,
    ) -> UUID | None:
        return self._versions.get((str(context.tenant_id), version_key))

    async def set_lifecycle(
        self,
        context: TenantContext,
        memory_id: UUID,
        lifecycle: MemoryLifecycleStatus,
        *,
        aggregate_version: int,
    ) -> None:
        tenant_id = str(context.tenant_id)
        key = (tenant_id, memory_id)
        current = self._aggregate_versions.get(key)
        if current is None:
            raise ValueError("memory does not exist")
        if aggregate_version <= current:
            return
        for key, record in tuple(self._records.items()):
            if key[0] == tenant_id and record.memory.memory_id == memory_id:
                self._records[key] = replace(
                    record,
                    lifecycle=lifecycle,
                    aggregate_version=aggregate_version,
                )
        self._aggregate_versions[(tenant_id, memory_id)] = aggregate_version

    async def purge_chunks(self, context: TenantContext, memory_id: UUID) -> int:
        tenant_id = str(context.tenant_id)
        keys = [
            key
            for key, record in self._records.items()
            if key[0] == tenant_id and record.memory.memory_id == memory_id
        ]
        for key in keys:
            del self._records[key]
        return len(keys)

    async def delete_metadata(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        aggregate_version: int,
    ) -> None:
        tenant_id = str(context.tenant_id)
        key = (tenant_id, memory_id)
        self._tombstones[key] = max(
            aggregate_version,
            self._tombstones.get(key, 0),
        )
        memory = self._memories.pop((tenant_id, memory_id), None)
        if memory is not None:
            self._versions.pop((tenant_id, memory.version_key), None)
        self._aggregate_versions.pop((tenant_id, memory_id), None)

    async def update_quality(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        aggregate_version: int,
    ) -> None:
        tenant_id = str(context.tenant_id)
        if memory.tenant_id != tenant_id:
            raise PermissionError("cross_tenant_memory_index")
        current = self._memories.get((tenant_id, memory.memory_id))
        if current is None:
            raise ValueError("memory does not exist")
        if aggregate_version <= self._aggregate_versions[(tenant_id, memory.memory_id)]:
            return
        self._memories[(tenant_id, memory.memory_id)] = memory
        for key, record in tuple(self._records.items()):
            if key[0] == tenant_id and record.memory.memory_id == memory.memory_id:
                self._records[key] = replace(record, memory=memory)
        self._aggregate_versions[(tenant_id, memory.memory_id)] = aggregate_version

    async def update_retention(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        aggregate_version: int,
    ) -> None:
        tenant_id = str(context.tenant_id)
        if memory.tenant_id != tenant_id:
            raise PermissionError("cross_tenant_memory_index")
        current = self._memories.get((tenant_id, memory.memory_id))
        if current is None:
            raise ValueError("memory does not exist")
        if aggregate_version <= self._aggregate_versions[(tenant_id, memory.memory_id)]:
            return
        self._memories[(tenant_id, memory.memory_id)] = memory
        for key, record in tuple(self._records.items()):
            if key[0] == tenant_id and record.memory.memory_id == memory.memory_id:
                self._records[key] = replace(record, memory=memory)
        self._aggregate_versions[(tenant_id, memory.memory_id)] = aggregate_version

    async def provenance(
        self,
        context: TenantContext,
        memory_id: UUID,
    ) -> SemanticMemory | None:
        return self._memories.get((str(context.tenant_id), memory_id))

    async def page(
        self,
        context: TenantContext,
        *,
        after_memory_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[SemanticMemory, ...], UUID | None]:
        if not 1 <= limit <= 100:
            raise ValueError("memory page limit must be between 1 and 100")
        tenant_id = str(context.tenant_id)
        rows = tuple(
            memory
            for (row_tenant, memory_id), memory in sorted(
                self._memories.items(),
                key=lambda item: str(item[0][1]),
            )
            if row_tenant == tenant_id
            and (after_memory_id is None or str(memory_id) > str(after_memory_id))
        )
        page = rows[:limit]
        cursor = page[-1].memory_id if len(rows) > limit and page else None
        return page, cursor

    async def rebuild(
        self,
        context: TenantContext,
        records: Sequence[IndexedMemoryChunk],
        *,
        tombstones: Mapping[UUID, int] | None = None,
    ) -> None:
        tenant_id = str(context.tenant_id)
        self._records = {
            key: value for key, value in self._records.items() if key[0] != tenant_id
        }
        self._versions = {
            key: value for key, value in self._versions.items() if key[0] != tenant_id
        }
        self._memories = {
            key: value for key, value in self._memories.items() if key[0] != tenant_id
        }
        self._aggregate_versions = {
            key: value
            for key, value in self._aggregate_versions.items()
            if key[0] != tenant_id
        }
        if tombstones is not None:
            self._tombstones = {
                key: value
                for key, value in self._tombstones.items()
                if key[0] != tenant_id
            }
            self._tombstones.update(
                ((tenant_id, memory_id), version)
                for memory_id, version in tombstones.items()
            )
        grouped: dict[UUID, list[MemoryChunk]] = {}
        memories: dict[UUID, SemanticMemory] = {}
        timestamps: dict[UUID, datetime] = {}
        contradictions: dict[UUID, tuple[UUID, ...]] = {}
        aggregate_versions: dict[UUID, int] = {}
        lifecycles: dict[UUID, MemoryLifecycleStatus] = {}
        for record in records:
            if record.memory.tenant_id != tenant_id:
                raise PermissionError("cross_tenant_memory_rebuild")
            grouped.setdefault(record.memory.memory_id, []).append(record.chunk)
            memories[record.memory.memory_id] = record.memory
            timestamps[record.memory.memory_id] = record.indexed_at
            contradictions[record.memory.memory_id] = record.contradiction_ids
            aggregate_versions[record.memory.memory_id] = record.aggregate_version
            lifecycles[record.memory.memory_id] = record.lifecycle
        for memory_id in sorted(grouped, key=str):
            await self.upsert(
                context,
                memories[memory_id],
                grouped[memory_id],
                indexed_at=timestamps[memory_id],
                contradiction_ids=contradictions[memory_id],
                aggregate_version=aggregate_versions[memory_id],
                lifecycle=lifecycles[memory_id],
            )


__all__ = [
    "InMemoryHybridIndex",
    "InMemoryMemoryBlobStore",
    "InMemoryMemoryLedger",
    "IndexedMemoryChunk",
    "MemoryBlobStore",
    "MemoryIndex",
    "MemoryLedger",
]
