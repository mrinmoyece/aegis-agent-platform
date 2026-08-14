"""Live pgvector, forced-RLS, Redis, fencing, rebuild, and purge evidence."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from redis.asyncio import Redis

from aegis_agent_platform.domain import RetrievalQuery, WorkLease, WorkRequest
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.memory.ingestion import MemoryIngestionService
from aegis_agent_platform.memory.lifecycle import MemoryLifecycleService
from aegis_agent_platform.memory.ports import (
    DeterministicEmbeddingProvider,
    RegexMemoryScanner,
)
from aegis_agent_platform.memory.postgres import (
    PostgresMemoryIndex,
    PostgresMemoryLedger,
    PostgresMemoryQuota,
)
from aegis_agent_platform.memory.quota import MemoryQuotaLimits
from aegis_agent_platform.memory.redis_cache import RedisMemoryCache
from aegis_agent_platform.memory.repository import InMemoryMemoryBlobStore
from aegis_agent_platform.memory.retrieval import HybridRetriever
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext
from integration_helpers import integration_writer_fences
from memory_helpers import semantic_memory

DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("AEGIS_TEST_REDIS_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.redis_integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="PostgreSQL and Redis integration URLs are required",
    ),
]


async def _insert_lease(
    connection: psycopg.AsyncConnection[Any],
    event_store: PostgresEventStore,
    lease: WorkLease,
) -> None:
    outbox_message_id = uuid4()
    await PostgresWorkRepository(connection, event_store).register(
        TenantContext(TenantId(lease.tenant_id)),
        WorkRequest(
            work_id=lease.work_id,
            tenant_id=lease.tenant_id,
            work_kind="memory.integration",
            idempotency_key=f"memory-integration:{lease.work_id}",
            correlation_id=lease.work_id,
            requested_at=lease.acquired_at,
            payload={},
            max_attempts=3,
            timeout_seconds=600,
        ),
        requested_event_id=uuid4(),
        outbox_message_id=outbox_message_id,
    )
    async with connection.transaction():
        await connection.execute(
            "SELECT set_config('aegis.tenant_id', %s, true)",
            (lease.tenant_id,),
        )
        await connection.execute(
            """
            UPDATE outbox_messages
            SET status = 'published', published_at = %s
            WHERE tenant_id = %s AND message_id = %s
            """,
            (lease.acquired_at, lease.tenant_id, outbox_message_id),
        )
        await connection.execute(
            """
            INSERT INTO work_leases (
                tenant_id, work_id, lease_token, generation, owner,
                acquired_at, heartbeat_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                lease.tenant_id,
                lease.work_id,
                lease.token,
                lease.generation,
                lease.owner,
                lease.acquired_at,
                lease.heartbeat_at,
                lease.expires_at,
            ),
        )


async def _replace_vector(
    connection: psycopg.AsyncConnection[Any],
    memory_id: UUID,
    value: str,
) -> None:
    async with connection.transaction():
        await connection.execute(
            "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
        )
        await connection.execute(
            """
            UPDATE memory_chunk_projection
            SET embedding = %s::vector
            WHERE tenant_id = 'tenant-a' AND memory_id = %s
            """,
            (value, memory_id),
        )


def _lease(work_id: UUID, tenant_id: str, at: datetime) -> WorkLease:
    return WorkLease(
        work_id,
        tenant_id,
        uuid4(),
        1,
        "memory-integration",
        1,
        at,
        at,
        at + timedelta(minutes=10),
    )


def test_pgvector_rls_cache_fencing_rebuild_and_purge() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        assert REDIS_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        redis = Redis.from_url(REDIS_URL)
        await redis.flushdb()
        await connection.execute("SET ROLE aegis_app")
        event_store = PostgresEventStore(
            connection,
            writer_fence_resolver=integration_writer_fences("local-test", 1),
        )
        ledger = PostgresMemoryLedger(connection, event_store)
        index = PostgresMemoryIndex(connection)
        blobs = InMemoryMemoryBlobStore()
        cache = RedisMemoryCache(redis)
        at = datetime.now(UTC)
        embedder = DeterministicEmbeddingProvider()
        quota = PostgresMemoryQuota(connection, MemoryQuotaLimits())
        ingestion = MemoryIngestionService(
            ledger,
            blobs,
            index,
            embedder,
            RegexMemoryScanner(),
            quota=quota,
            clock=lambda: at,
        )
        retriever = HybridRetriever(
            ledger,
            index,
            embedder,
            cache=cache,
            quota=quota,
            clock=lambda: at,
        )
        lifecycle = MemoryLifecycleService(
            ledger,
            blobs,
            index,
            cache=cache,
            clock=lambda: at,
        )
        text = "Database failover recovered by promoting the healthy replica."
        memory = semantic_memory("postgres-memory", text, created_at=at)
        context = TenantContext(TenantId("tenant-a"))
        await ingestion.propose(
            context,
            memory,
            text,
            proposed_by="admin-a",
            idempotency_key="postgres-memory-proposal",
        )
        memory_lease = _lease(uuid4(), "tenant-a", at)
        await _insert_lease(connection, event_store, memory_lease)
        accepted = await ingestion.accept_and_process(
            context,
            memory,
            memory_lease,
            accepted_by="admin-a",
            acceptance_kind="human",
            idempotency_key="postgres-memory-accept",
        )
        assert accepted.chunks
        for invalid_vector in (
            "[NaN,0,0,0,0,0,0,0]",
            "[1,0]",
        ):
            with pytest.raises(psycopg.Error):
                await _replace_vector(
                    connection,
                    memory.memory_id,
                    invalid_vector,
                )

        retrieval_id = uuid4()
        retrieval_lease = _lease(uuid4(), "tenant-a", at)
        await _insert_lease(connection, event_store, retrieval_lease)
        request = RetrievalQuery(
            retrieval_id,
            "tenant-a",
            "investigator-a",
            None,
            frozenset({"investigator"}),
            "incident-investigation",
            "healthy replica database failover",
            top_k=5,
            candidate_limit=20,
            max_context_bytes=8_192,
            max_context_tokens=2_048,
            as_of=at,
        )
        result = await retriever.retrieve(context, request, retrieval_lease)
        assert result.hits[0].chunk.memory_id == memory.memory_id
        assert result.hits[0].chunk.embedding is not None
        assert await cache.get(context, request) is not None
        async with connection.transaction():
            await connection.execute(
                "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
            )
            cursor = await connection.execute(
                """
                SELECT ingested_bytes, embedded_tokens, retrieval_count
                FROM memory_quota_projection
                WHERE tenant_id = 'tenant-a'
                """
            )
            quota_row = await cursor.fetchone()
        assert quota_row == (len(text.encode()), len(text.split()), 1)

        other_context = TenantContext(TenantId("tenant-b"))
        other_request = RetrievalQuery(
            uuid4(),
            "tenant-b",
            "investigator-a",
            None,
            frozenset({"investigator"}),
            "incident-investigation",
            "healthy replica database failover",
            top_k=5,
            candidate_limit=20,
            max_context_bytes=8_192,
            max_context_tokens=2_048,
            as_of=at,
        )
        assert not await index.candidates(other_context, other_request)
        assert await cache.get(other_context, other_request) is None

        stale = WorkLease(
            memory_lease.work_id,
            memory_lease.tenant_id,
            uuid4(),
            memory_lease.generation + 1,
            memory_lease.owner,
            memory_lease.attempt,
            memory_lease.acquired_at,
            memory_lease.heartbeat_at,
            memory_lease.expires_at,
        )
        with pytest.raises(FencingError):
            await ledger.assert_fence(
                context,
                memory.memory_id,
                stale,
                at=at,
            )
        existing_events = await ledger.load(context, memory.memory_id)
        false_fence_event = replace(
            existing_events[0],
            event_id=uuid4(),
            payload={
                "lease_token": str(uuid4()),
                "lease_generation": memory_lease.generation,
            },
            idempotency_key=f"false-fence:{memory.memory_id}",
        )
        with pytest.raises(ValueError, match="active fence"):
            await ledger.append_fenced(
                context,
                memory.memory_id,
                memory_lease,
                (false_fence_event,),
                expected_version=len(existing_events),
            )

        records = await index.candidates(
            context,
            request,
            query_vector=result.hits[0].chunk.embedding,
        )
        rebuild_id = await lifecycle.rebuild(
            context,
            records,
            actor_id="admin-a",
            checkpoint_position=100,
        )
        assert await ledger.load(context, rebuild_id)
        assert await index.provenance(context, memory.memory_id) is not None

        deleted = await lifecycle.delete(
            context,
            memory.memory_id,
            actor_id="admin-a",
            request_reference="postgres-delete-request",
        )
        assert deleted == len(accepted.chunks)
        assert await index.provenance(context, memory.memory_id) is None
        assert await cache.get(context, request) is None
        with pytest.raises(ValueError, match="cannot be resurrected"):
            await index.upsert(
                context,
                memory,
                tuple(record.chunk for record in records),
                indexed_at=at,
                aggregate_version=max(record.aggregate_version for record in records),
            )
        async with connection.transaction():
            await connection.execute(
                "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
            )
            cursor = await connection.execute(
                """
                SELECT count(*) FROM memory_source_snapshots
                WHERE memory_id = %s
                """,
                (memory.memory_id,),
            )
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] == 0

        await redis.aclose()
        await connection.close()

    asyncio.run(scenario())
