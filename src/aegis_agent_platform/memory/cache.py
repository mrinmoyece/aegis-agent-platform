"""Tenant-bound derived retrieval caches containing references, never raw text."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import RetrievalQuery
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class CachedSelection:
    retrieval_policy: str
    chunk_ids: tuple[UUID, ...]
    scores: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.chunk_ids) != len(self.scores):
            raise ValueError("cached chunk identifiers and scores must align")
        if any(not 0 <= score <= 1 for score in self.scores):
            raise ValueError("cached retrieval scores must be normalized")


class MemoryCache(Protocol):
    async def get(
        self,
        context: TenantContext,
        query: RetrievalQuery,
    ) -> CachedSelection | None: ...

    async def set(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        value: CachedSelection,
    ) -> None: ...

    async def invalidate_tenant(self, context: TenantContext) -> int: ...


def memory_cache_key(context: TenantContext, query: RetrievalQuery) -> str:
    tenant_id = str(context.tenant_id)
    if query.tenant_id != tenant_id:
        raise PermissionError("cross_tenant_memory_cache")
    service_id = query.service_id or ""
    digest = sha256(
        (
            f"{tenant_id}|{query.query_digest}|{query.policy_version}|{query.purpose}|"
            f"{','.join(sorted(query.roles))}|{query.principal_id}|{service_id}|"
            f"{query.top_k}|{query.candidate_limit}|{query.max_context_bytes}|"
            f"{query.max_context_tokens}|{query.minimum_quality:.12f}|"
            f"{query.as_of.isoformat() if query.as_of is not None else ''}|"
            f"{query.embedding_model}|{query.embedding_model_version}|"
            f"{query.embedding_dimension}"
        ).encode()
    ).hexdigest()
    tenant_digest = sha256(tenant_id.encode()).hexdigest()[:16]
    return f"aegis:memory:{tenant_digest}:{digest}"


class InMemoryMemoryCache(MemoryCache):
    def __init__(self) -> None:
        self._values: dict[str, CachedSelection] = {}
        self._tenant_keys: dict[str, set[str]] = {}

    async def get(
        self,
        context: TenantContext,
        query: RetrievalQuery,
    ) -> CachedSelection | None:
        return self._values.get(memory_cache_key(context, query))

    async def set(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        value: CachedSelection,
    ) -> None:
        key = memory_cache_key(context, query)
        self._values[key] = value
        self._tenant_keys.setdefault(str(context.tenant_id), set()).add(key)

    async def invalidate_tenant(self, context: TenantContext) -> int:
        tenant_id = str(context.tenant_id)
        keys = self._tenant_keys.pop(tenant_id, set())
        for key in keys:
            self._values.pop(key, None)
        return len(keys)


__all__ = [
    "CachedSelection",
    "InMemoryMemoryCache",
    "MemoryCache",
    "memory_cache_key",
]
