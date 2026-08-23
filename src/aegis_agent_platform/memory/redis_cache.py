"""Redis adapter for reference-only derived memory selections."""

from __future__ import annotations

import json
from collections.abc import Awaitable
from hashlib import sha256
from typing import cast
from uuid import UUID

from redis.asyncio import Redis

from aegis_agent_platform.domain import RetrievalQuery
from aegis_agent_platform.memory.cache import (
    CachedSelection,
    MemoryCache,
    memory_cache_key,
)
from aegis_agent_platform.tenancy import TenantContext


class RedisMemoryCache(MemoryCache):
    """Redis acceleration with tenant-digested keys and reference-only values."""

    def __init__(self, client: Redis, *, ttl_seconds: int = 300) -> None:
        if not 1 <= ttl_seconds <= 86_400:
            raise ValueError("memory cache TTL is outside the bound")
        self._client = client
        self._ttl_seconds = ttl_seconds

    async def get(
        self,
        context: TenantContext,
        query: RetrievalQuery,
    ) -> CachedSelection | None:
        key = memory_cache_key(context, query)
        raw = await self._client.get(key)
        if raw is None:
            return None
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise ValueError("memory cache entry is malformed")
        chunk_ids = decoded.get("chunk_ids")
        scores = decoded.get("scores")
        policy = decoded.get("retrieval_policy")
        if (
            not isinstance(chunk_ids, list)
            or not isinstance(scores, list)
            or not isinstance(policy, str)
        ):
            raise ValueError("memory cache entry has an invalid schema")
        return CachedSelection(
            policy,
            tuple(UUID(str(item)) for item in chunk_ids),
            tuple(float(item) for item in scores),
        )

    async def set(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        value: CachedSelection,
    ) -> None:
        key = memory_cache_key(context, query)
        tenant_digest = sha256(str(context.tenant_id).encode()).hexdigest()[:16]
        payload = json.dumps(
            {
                "chunk_ids": tuple(str(item) for item in value.chunk_ids),
                "retrieval_policy": value.retrieval_policy,
                "scores": value.scores,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        async with self._client.pipeline(transaction=True) as pipeline:
            pipeline.set(key, payload, ex=self._ttl_seconds)
            pipeline.sadd(f"aegis:memory:keys:{tenant_digest}", key)
            pipeline.expire(
                f"aegis:memory:keys:{tenant_digest}",
                self._ttl_seconds,
            )
            await pipeline.execute()

    async def invalidate_tenant(self, context: TenantContext) -> int:
        tenant_digest = sha256(str(context.tenant_id).encode()).hexdigest()[:16]
        set_key = f"aegis:memory:keys:{tenant_digest}"
        raw_keys = await cast(
            Awaitable[set[bytes | str]],
            self._client.smembers(set_key),
        )
        keys = [
            item.decode() if isinstance(item, bytes) else str(item) for item in raw_keys
        ]
        if not keys:
            await self._client.delete(set_key)
            return 0
        async with self._client.pipeline(transaction=True) as pipeline:
            pipeline.delete(*keys)
            pipeline.delete(set_key)
            await pipeline.execute()
        return len(keys)


__all__ = ["RedisMemoryCache"]
