"""PostgreSQL ledger fencing and pgvector-derived memory index adapters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from aegis_agent_platform.domain import (
    EventEnvelope,
    MemoryChunk,
    MemoryCitation,
    MemoryLifecycleStatus,
    RetrievalQuery,
    SemanticMemory,
    WorkLease,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    classify_storage_error,
    postgres_connection_lock,
)
from aegis_agent_platform.memory.quota import (
    MemoryQuota,
    MemoryQuotaExceededError,
    MemoryQuotaKind,
    MemoryQuotaLimits,
)
from aegis_agent_platform.memory.repository import (
    IndexedMemoryChunk,
    MemoryIndex,
    MemoryLedger,
)
from aegis_agent_platform.memory.serialization import (
    memory_from_document,
    memory_to_document,
)
from aegis_agent_platform.tenancy import TenantContext

_QUOTA_SQL = {
    MemoryQuotaKind.INGESTED_BYTES: """
        UPDATE memory_quota_projection
        SET ingested_bytes = ingested_bytes + %s, updated_at = %s
        WHERE tenant_id = %s AND usage_period = %s
          AND ingested_bytes + %s <= %s
        RETURNING ingested_bytes
    """,
    MemoryQuotaKind.EMBEDDED_TOKENS: """
        UPDATE memory_quota_projection
        SET embedded_tokens = embedded_tokens + %s, updated_at = %s
        WHERE tenant_id = %s AND usage_period = %s
          AND embedded_tokens + %s <= %s
        RETURNING embedded_tokens
    """,
    MemoryQuotaKind.RETRIEVALS: """
        UPDATE memory_quota_projection
        SET retrieval_count = retrieval_count + %s, updated_at = %s
        WHERE tenant_id = %s AND usage_period = %s
          AND retrieval_count + %s <= %s
        RETURNING retrieval_count
    """,
    MemoryQuotaKind.SUMMARY_TOKENS: """
        UPDATE memory_quota_projection
        SET summary_tokens = summary_tokens + %s, updated_at = %s
        WHERE tenant_id = %s AND usage_period = %s
          AND summary_tokens + %s <= %s
        RETURNING summary_tokens
    """,
}

_CANDIDATE_COLUMNS = """
SELECT c.memory_document, c.lifecycle_status,
    m.chunk_id, m.memory_id, m.ordinal, m.content,
    m.content_digest, m.token_count, m.byte_count,
    m.start_offset, m.end_offset, m.citation_metadata,
    m.embedding_reference, m.embedding::text,
    m.contradiction_ids, m.indexed_at, c.aggregate_version
FROM memory_candidate_projection AS c
JOIN memory_chunk_projection AS m
  ON m.tenant_id = c.tenant_id
 AND m.memory_id = c.memory_id
WHERE c.tenant_id = %s
  AND c.candidate_status = 'accepted'
  AND c.lifecycle_status = 'active'
  AND c.quality >= %s
  AND c.embedding_model = %s
  AND c.embedder_version = %s
  AND c.embedding_dimension = %s
  AND (c.expires_at IS NULL OR c.expires_at > %s)
  AND c.memory_document->'acl'->'purposes' ? %s
  AND (
    c.memory_document->'acl'->'user_ids' ? %s
    OR (
        %s::text IS NOT NULL
        AND c.memory_document->'acl'->'service_ids' ? %s
    )
    OR c.memory_document->'acl'->'roles' ?| %s::text[]
  )
"""
_LEXICAL_CANDIDATES_SQL = (
    _CANDIDATE_COLUMNS
    + """
ORDER BY ts_rank_cd(
    m.search_document, plainto_tsquery('simple', %s)
) DESC, c.quality DESC, c.created_at DESC, c.memory_id, m.ordinal
LIMIT %s
"""
)
_HYBRID_CANDIDATES_SQL = (
    _CANDIDATE_COLUMNS
    + """
ORDER BY (
    0.5 * ts_rank_cd(
        m.search_document, plainto_tsquery('simple', %s)
    ) + 0.5 * (1 - (m.embedding <=> %s::vector))
) DESC, c.quality DESC, c.created_at DESC, c.memory_id, m.ordinal
LIMIT %s
"""
)


class PostgresMemoryLedger(MemoryLedger):
    """Append memory events through the ledger under an independent work fence."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
    ) -> None:
        self._connection = connection
        self._event_store = event_store
        self._lock = postgres_connection_lock(connection)

    async def append(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if any(event.aggregate_id != str(aggregate_id) for event in events):
            raise ValueError("memory events do not match their aggregate")
        return await self._event_store.append(
            context,
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
        if not events or any(
            event.aggregate_id != str(aggregate_id) for event in events
        ):
            raise ValueError("fenced memory events do not match their aggregate")
        if any(
            event.payload.get("lease_token") != str(lease.token)
            or event.payload.get("lease_generation") != lease.generation
            for event in events
        ):
            raise ValueError("memory event does not match the active fence")

        async def assert_fence(connection: psycopg.AsyncConnection[Any]) -> None:
            await _assert_fence(connection, context, lease)

        return await self._event_store.append_atomic(
            context,
            events,
            expected_version=expected_version,
            mutation=assert_fence,
        )

    async def assert_fence(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        del aggregate_id, at
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                await _assert_fence(self._connection, context, lease)
        except FencingError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def load(
        self,
        context: TenantContext,
        aggregate_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        events: list[EventEnvelope] = []
        after_version = 0
        while True:
            page = [
                event
                async for event in self._event_store.read_stream(
                    context,
                    str(aggregate_id),
                    after_version=after_version,
                    limit=1_000,
                )
            ]
            events.extend(page)
            if len(page) < 1_000:
                return tuple(events)
            after_version += len(page)

    async def scan(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 500,
    ) -> tuple[tuple[EventEnvelope, ...], int | None]:
        page = await self._event_store.read_all(
            context,
            after_position=after_position,
            limit=limit,
        )
        return page.events, page.next_cursor


class PostgresMemoryIndex(MemoryIndex):
    """Forced-RLS pgvector/lexical read model; the event ledger remains truth."""

    def __init__(self, connection: psycopg.AsyncConnection[Any]) -> None:
        self._connection = connection
        self._lock = postgres_connection_lock(connection)

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
        if memory.tenant_id != tenant_id or any(
            chunk.tenant_id != tenant_id or chunk.memory_id != memory.memory_id
            for chunk in chunks
        ):
            raise PermissionError("cross_tenant_pgvector_memory")
        if memory.embedding_dimension != 8:
            raise ValueError("Layer 10 pgvector schema requires dimension 8")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                await self._connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:{memory.memory_id}",),
                )
                tombstone_cursor = await self._connection.execute(
                    """
                    SELECT aggregate_version
                    FROM memory_projection_tombstones
                    WHERE tenant_id = %s AND memory_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, memory.memory_id),
                )
                tombstone = await tombstone_cursor.fetchone()
                if tombstone is not None and aggregate_version <= int(tombstone[0]):
                    raise ValueError("deleted memory projection cannot be resurrected")
                await self._connection.execute(
                    """
                    INSERT INTO memory_source_snapshots (
                        tenant_id, snapshot_id, memory_id, source_kind,
                        source_reference, source_version, content_digest,
                        content_reference, citation_metadata, trust_tier,
                        occurred_at, captured_at, recorded_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, snapshot_id) DO NOTHING
                    """,
                    (
                        tenant_id,
                        memory.snapshot.snapshot_id,
                        memory.memory_id,
                        memory.snapshot.source_kind.value,
                        memory.snapshot.source_reference,
                        memory.snapshot.source_version,
                        memory.snapshot.content_digest,
                        memory.snapshot.content_reference,
                        Jsonb(_citations(memory.snapshot.citations)),
                        memory.snapshot.trust.value,
                        memory.snapshot.occurred_at,
                        memory.snapshot.captured_at,
                        indexed_at,
                    ),
                )
                candidate_cursor = await self._connection.execute(
                    """
                    INSERT INTO memory_candidate_projection (
                        tenant_id, memory_id, version_key, source_snapshot_id,
                        source_kind, candidate_status, lifecycle_status,
                        security_label, schema_version, chunker_version,
                        embedder_version, embedding_model, embedding_dimension,
                        confidence, quality, retention_class, expires_at,
                        legal_hold, legal_hold_reference, deletion_scope,
                        policy_reference, accepted_by, memory_document,
                        aggregate_version, created_at, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, 'accepted', %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, memory_id) DO UPDATE SET
                        candidate_status = EXCLUDED.candidate_status,
                        lifecycle_status = EXCLUDED.lifecycle_status,
                        quality = EXCLUDED.quality,
                        retention_class = EXCLUDED.retention_class,
                        expires_at = EXCLUDED.expires_at,
                        legal_hold = EXCLUDED.legal_hold,
                        legal_hold_reference = EXCLUDED.legal_hold_reference,
                        deletion_scope = EXCLUDED.deletion_scope,
                        memory_document = EXCLUDED.memory_document,
                        aggregate_version = EXCLUDED.aggregate_version,
                        updated_at = EXCLUDED.updated_at
                    WHERE memory_candidate_projection.aggregate_version
                        <= EXCLUDED.aggregate_version
                    """,
                    (
                        tenant_id,
                        memory.memory_id,
                        memory.version_key,
                        memory.snapshot.snapshot_id,
                        memory.snapshot.source_kind.value,
                        lifecycle.value,
                        memory.security_label.value,
                        memory.schema_version,
                        memory.chunker_version,
                        memory.embedder_version,
                        memory.embedding_model,
                        memory.embedding_dimension,
                        memory.confidence,
                        memory.quality,
                        memory.retention.retention_class,
                        memory.retention.expires_at,
                        memory.retention.legal_hold,
                        memory.retention.legal_hold_reference,
                        memory.retention.deletion_scope,
                        memory.policy_reference,
                        memory.accepted_by,
                        Jsonb(memory_to_document(memory)),
                        aggregate_version,
                        memory.created_at,
                        indexed_at,
                    ),
                )
                if candidate_cursor.rowcount == 0:
                    return
                await self._connection.execute(
                    """
                    DELETE FROM memory_chunk_projection
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (tenant_id, memory.memory_id),
                )
                for chunk in chunks:
                    if chunk.embedding is None or chunk.embedding_reference is None:
                        raise ValueError(
                            "pgvector chunks require normalized embeddings"
                        )
                    await self._connection.execute(
                        """
                        INSERT INTO memory_chunk_projection (
                            tenant_id, chunk_id, memory_id, ordinal, content,
                            content_digest, token_count, byte_count, start_offset,
                            end_offset, citation_metadata, embedding_reference,
                            embedding_model, embedder_version, embedding,
                            contradiction_ids, indexed_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s::vector, %s, %s
                        )
                        """,
                        (
                            tenant_id,
                            chunk.chunk_id,
                            memory.memory_id,
                            chunk.ordinal,
                            chunk.text,
                            chunk.content_digest,
                            chunk.token_count,
                            chunk.byte_count,
                            chunk.start_offset,
                            chunk.end_offset,
                            Jsonb(_citations(chunk.citations)),
                            chunk.embedding_reference,
                            memory.embedding_model,
                            memory.embedder_version,
                            _vector_literal(chunk.embedding),
                            list(contradiction_ids),
                            indexed_at,
                        ),
                    )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def candidates(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        *,
        query_vector: Sequence[float] | None = None,
    ) -> tuple[IndexedMemoryChunk, ...]:
        tenant_id = str(context.tenant_id)
        if query.tenant_id != tenant_id:
            raise PermissionError("cross_tenant_pgvector_retrieval")
        as_of = query.as_of or datetime.max.replace(tzinfo=UTC)
        parameters: list[object] = [
            tenant_id,
            query.minimum_quality,
            query.embedding_model,
            query.embedding_model_version,
            query.embedding_dimension,
            as_of,
            query.purpose,
            query.principal_id,
            query.service_id,
            query.service_id,
            list(query.roles),
            query.text,
        ]
        if query_vector is not None:
            if len(query_vector) != 8:
                raise ValueError("Layer 10 pgvector query requires dimension 8")
            parameters.append(_vector_literal(query_vector))
        parameters.append(query.candidate_limit)
        statement = (
            _HYBRID_CANDIDATES_SQL
            if query_vector is not None
            else _LEXICAL_CANDIDATES_SQL
        )
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                if query_vector is not None:
                    await self._connection.execute(
                        "SELECT set_config('hnsw.iterative_scan', 'strict_order', true)"
                    )
                    await self._connection.execute(
                        "SELECT set_config('hnsw.max_scan_tuples', %s, true)",
                        (str(max(query.candidate_limit * 50, 5_000)),),
                    )
                cursor = await self._connection.execute(
                    statement,
                    tuple(parameters),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        values: list[IndexedMemoryChunk] = []
        for row in rows:
            memory = memory_from_document(row[0])
            values.append(
                IndexedMemoryChunk(
                    memory,
                    MemoryChunk(
                        chunk_id=row[2],
                        memory_id=row[3],
                        tenant_id=tenant_id,
                        ordinal=row[4],
                        text=row[5],
                        content_digest=row[6],
                        token_count=row[7],
                        byte_count=row[8],
                        start_offset=row[9],
                        end_offset=row[10],
                        citations=_citations_from_json(row[11]),
                        embedding_reference=row[12],
                        embedding=_vector(row[13]),
                    ),
                    row[15],
                    lifecycle=MemoryLifecycleStatus(row[1]),
                    contradiction_ids=tuple(row[14]),
                    aggregate_version=row[16],
                )
            )
        return tuple(values)

    async def find_version(
        self,
        context: TenantContext,
        version_key: str,
    ) -> UUID | None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT memory_id FROM memory_candidate_projection
                    WHERE tenant_id = %s AND version_key = %s
                    """,
                    (str(context.tenant_id), version_key),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return row[0] if row is not None else None

    async def set_lifecycle(
        self,
        context: TenantContext,
        memory_id: UUID,
        lifecycle: MemoryLifecycleStatus,
        *,
        aggregate_version: int,
    ) -> None:
        await self._update(
            context,
            """
            UPDATE memory_candidate_projection
            SET lifecycle_status = CASE
                    WHEN aggregate_version < %s THEN %s ELSE lifecycle_status END,
                aggregate_version = GREATEST(aggregate_version, %s),
                updated_at = CASE WHEN aggregate_version < %s
                    THEN clock_timestamp() ELSE updated_at END
            WHERE tenant_id = %s AND memory_id = %s
            """,
            (
                aggregate_version,
                lifecycle.value,
                aggregate_version,
                aggregate_version,
                str(context.tenant_id),
                memory_id,
            ),
        )

    async def update_quality(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        aggregate_version: int,
    ) -> None:
        if memory.tenant_id != str(context.tenant_id):
            raise PermissionError("cross_tenant_memory_index")
        await self._update(
            context,
            """
            UPDATE memory_candidate_projection
            SET quality = CASE WHEN aggregate_version < %s THEN %s ELSE quality END,
                memory_document = CASE WHEN aggregate_version < %s
                    THEN %s ELSE memory_document END,
                aggregate_version = GREATEST(aggregate_version, %s),
                updated_at = CASE WHEN aggregate_version < %s
                    THEN clock_timestamp() ELSE updated_at END
            WHERE tenant_id = %s AND memory_id = %s
            """,
            (
                aggregate_version,
                memory.quality,
                aggregate_version,
                Jsonb(memory_to_document(memory)),
                aggregate_version,
                aggregate_version,
                str(context.tenant_id),
                memory.memory_id,
            ),
        )

    async def update_retention(
        self,
        context: TenantContext,
        memory: SemanticMemory,
        *,
        aggregate_version: int,
    ) -> None:
        if memory.tenant_id != str(context.tenant_id):
            raise PermissionError("cross_tenant_memory_index")
        await self._update(
            context,
            """
            UPDATE memory_candidate_projection
            SET retention_class = CASE WHEN aggregate_version < %s
                    THEN %s ELSE retention_class END,
                expires_at = CASE WHEN aggregate_version < %s
                    THEN %s ELSE expires_at END,
                legal_hold = CASE WHEN aggregate_version < %s
                    THEN %s ELSE legal_hold END,
                legal_hold_reference = CASE WHEN aggregate_version < %s
                    THEN %s ELSE legal_hold_reference END,
                deletion_scope = CASE WHEN aggregate_version < %s
                    THEN %s ELSE deletion_scope END,
                memory_document = CASE WHEN aggregate_version < %s
                    THEN %s ELSE memory_document END,
                aggregate_version = GREATEST(aggregate_version, %s),
                updated_at = CASE WHEN aggregate_version < %s
                    THEN clock_timestamp() ELSE updated_at END
            WHERE tenant_id = %s AND memory_id = %s
            """,
            (
                aggregate_version,
                memory.retention.retention_class,
                aggregate_version,
                memory.retention.expires_at,
                aggregate_version,
                memory.retention.legal_hold,
                aggregate_version,
                memory.retention.legal_hold_reference,
                aggregate_version,
                memory.retention.deletion_scope,
                aggregate_version,
                Jsonb(memory_to_document(memory)),
                aggregate_version,
                aggregate_version,
                str(context.tenant_id),
                memory.memory_id,
            ),
        )

    async def purge_chunks(self, context: TenantContext, memory_id: UUID) -> int:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    DELETE FROM memory_chunk_projection
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (str(context.tenant_id), memory_id),
                )
                return cursor.rowcount or 0
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def delete_metadata(
        self,
        context: TenantContext,
        memory_id: UUID,
        *,
        aggregate_version: int,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                await self._connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{context.tenant_id}:{memory_id}",),
                )
                await self._connection.execute(
                    """
                    INSERT INTO memory_projection_tombstones (
                        tenant_id, memory_id, aggregate_version, deleted_at
                    ) VALUES (%s, %s, %s, clock_timestamp())
                    ON CONFLICT (tenant_id, memory_id) DO UPDATE SET
                        aggregate_version = GREATEST(
                            memory_projection_tombstones.aggregate_version,
                            EXCLUDED.aggregate_version
                        ),
                        deleted_at = CASE
                            WHEN memory_projection_tombstones.aggregate_version
                                < EXCLUDED.aggregate_version
                            THEN EXCLUDED.deleted_at
                            ELSE memory_projection_tombstones.deleted_at
                        END
                    """,
                    (str(context.tenant_id), memory_id, aggregate_version),
                )
                await self._connection.execute(
                    """
                    DELETE FROM memory_candidate_projection
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (str(context.tenant_id), memory_id),
                )
                await self._connection.execute(
                    """
                    DELETE FROM memory_source_snapshots
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (str(context.tenant_id), memory_id),
                )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def provenance(
        self,
        context: TenantContext,
        memory_id: UUID,
    ) -> SemanticMemory | None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT memory_document FROM memory_candidate_projection
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (str(context.tenant_id), memory_id),
                )
                row = await cursor.fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return memory_from_document(row[0]) if row is not None else None

    async def page(
        self,
        context: TenantContext,
        *,
        after_memory_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[SemanticMemory, ...], UUID | None]:
        if not 1 <= limit <= 100:
            raise ValueError("memory page limit must be between 1 and 100")
        after = after_memory_id or UUID(int=0)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT memory_id, memory_document
                    FROM memory_candidate_projection
                    WHERE tenant_id = %s AND memory_id::text > %s
                    ORDER BY memory_id::text
                    LIMIT %s
                    """,
                    (str(context.tenant_id), str(after), limit + 1),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        page = tuple(memory_from_document(row[1]) for row in rows[:limit])
        cursor_value = page[-1].memory_id if len(rows) > limit and page else None
        return page, cursor_value

    async def rebuild(
        self,
        context: TenantContext,
        records: Sequence[IndexedMemoryChunk],
        *,
        tombstones: Mapping[UUID, int] | None = None,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                await self._connection.execute(
                    "DELETE FROM memory_chunk_projection WHERE tenant_id = %s",
                    (str(context.tenant_id),),
                )
                await self._connection.execute(
                    "DELETE FROM memory_candidate_projection WHERE tenant_id = %s",
                    (str(context.tenant_id),),
                )
                await self._connection.execute(
                    "DELETE FROM memory_source_snapshots WHERE tenant_id = %s",
                    (str(context.tenant_id),),
                )
                if tombstones is not None:
                    await self._connection.execute(
                        "DELETE FROM memory_projection_tombstones WHERE tenant_id = %s",
                        (str(context.tenant_id),),
                    )
                    for memory_id, aggregate_version in sorted(
                        tombstones.items(), key=lambda item: str(item[0])
                    ):
                        await self._connection.execute(
                            """
                            INSERT INTO memory_projection_tombstones (
                                tenant_id, memory_id, aggregate_version, deleted_at
                            ) VALUES (%s, %s, %s, clock_timestamp())
                            """,
                            (
                                str(context.tenant_id),
                                memory_id,
                                aggregate_version,
                            ),
                        )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        grouped: dict[UUID, list[MemoryChunk]] = {}
        metadata: dict[UUID, IndexedMemoryChunk] = {}
        for record in records:
            grouped.setdefault(record.memory.memory_id, []).append(record.chunk)
            metadata[record.memory.memory_id] = record
        for memory_id in sorted(grouped, key=str):
            record = metadata[memory_id]
            await self.upsert(
                context,
                record.memory,
                grouped[memory_id],
                indexed_at=record.indexed_at,
                contradiction_ids=record.contradiction_ids,
                aggregate_version=record.aggregate_version,
                lifecycle=record.lifecycle,
            )

    async def _update(
        self,
        context: TenantContext,
        statement: str,
        parameters: tuple[object, ...],
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(statement, parameters)
                if cursor.rowcount != 1:
                    raise ValueError("memory does not exist")
        except psycopg.Error as error:
            raise classify_storage_error(error) from error


async def _assert_fence(
    connection: psycopg.AsyncConnection[Any],
    context: TenantContext,
    lease: WorkLease,
) -> None:
    cursor = await connection.execute(
        """
        SELECT generation
        FROM work_leases
        WHERE tenant_id = %s AND work_id = %s
          AND lease_token = %s AND generation = %s
          AND released_at IS NULL
          AND expires_at > clock_timestamp()
        FOR UPDATE
        """,
        (
            str(context.tenant_id),
            lease.work_id,
            lease.token,
            lease.generation,
        ),
    )
    if await cursor.fetchone() is None:
        raise FencingError(lease.generation, 0)


@asynccontextmanager
async def _tenant_transaction(
    connection: psycopg.AsyncConnection[Any],
    lock: asyncio.Lock,
    context: TenantContext,
) -> AsyncIterator[None]:
    async with lock, connection.transaction():
        await connection.execute(
            "SELECT set_config('aegis.tenant_id', %s, true)",
            (str(context.tenant_id),),
        )
        yield


def _citations(values: Sequence[MemoryCitation]) -> list[dict[str, object]]:
    return [
        {
            "artifact_id": (
                str(item.artifact_id) if item.artifact_id is not None else None
            ),
            "content_digest": item.content_digest,
            "event_id": str(item.event_id) if item.event_id is not None else None,
            "source_id": item.source_id,
            "source_uri": item.source_uri,
        }
        for item in values
    ]


def _citations_from_json(value: object) -> tuple[MemoryCitation, ...]:
    if not isinstance(value, list):
        raise ValueError("memory citations must be an array")
    citations: list[MemoryCitation] = []
    for item in value:
        row = _dict(item)
        citations.append(
            MemoryCitation(
                source_id=str(row["source_id"]),
                source_uri=str(row["source_uri"]),
                content_digest=str(row["content_digest"]),
                event_id=(
                    UUID(str(row["event_id"]))
                    if row.get("event_id") is not None
                    else None
                ),
                artifact_id=(
                    UUID(str(row["artifact_id"]))
                    if row.get("artifact_id") is not None
                    else None
                ),
            )
        )
    return tuple(citations)


def _vector_literal(values: Sequence[float]) -> str:
    return "[" + ",".join(format(value, ".17g") for value in values) + "]"


def _vector(value: object) -> tuple[float, ...]:
    if (
        not isinstance(value, str)
        or not value.startswith("[")
        or not value.endswith("]")
    ):
        raise ValueError("pgvector value has an invalid representation")
    return tuple(float(item) for item in value[1:-1].split(","))


def _dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("memory JSON value must be an object")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("memory JSON value must be an array")
    return tuple(str(item) for item in value)


class PostgresMemoryQuota(MemoryQuota):
    """Forced-RLS atomic quota reservations; projections remain rebuildable."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        limits: MemoryQuotaLimits,
    ) -> None:
        self._connection = connection
        self._limits = limits
        self._lock = postgres_connection_lock(connection)

    async def reserve(
        self,
        context: TenantContext,
        kind: MemoryQuotaKind,
        amount: int,
        *,
        at: datetime,
    ) -> int:
        if amount < 1:
            raise ValueError("memory quota reservation must be positive")
        if at.tzinfo is None:
            raise ValueError("memory quota timestamp must be timezone-aware")
        tenant_id = str(context.tenant_id)
        period = at.date().isoformat()
        try:
            async with self._lock, self._connection.transaction():
                await self._connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    (tenant_id,),
                )
                await self._connection.execute(
                    """
                    INSERT INTO memory_quota_projection (
                        tenant_id, usage_period, updated_at
                    ) VALUES (%s, %s, %s)
                    ON CONFLICT (tenant_id, usage_period) DO NOTHING
                    """,
                    (tenant_id, period, at),
                )
                cursor = await self._connection.execute(
                    _QUOTA_SQL[kind],
                    (
                        amount,
                        at,
                        tenant_id,
                        period,
                        amount,
                        self._limits.limit(kind),
                    ),
                )
                row = await cursor.fetchone()
                if row is None:
                    raise MemoryQuotaExceededError(kind)
                return int(row[0])
        except MemoryQuotaExceededError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error


__all__ = [
    "PostgresMemoryIndex",
    "PostgresMemoryLedger",
    "PostgresMemoryQuota",
]
