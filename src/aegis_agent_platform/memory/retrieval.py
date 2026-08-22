"""Deterministic tenant-filtered hybrid retrieval with exact citations."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EmbeddingRequest,
    EventEnvelope,
    JsonValue,
    RetrievalFreshness,
    RetrievalHit,
    RetrievalQuery,
    RetrievalResult,
    WorkLease,
)
from aegis_agent_platform.memory.cache import CachedSelection, MemoryCache
from aegis_agent_platform.memory.ports import (
    EmbeddingProvider,
    MemoryProviderError,
    MemoryProviderErrorClass,
    validate_embedding_response,
)
from aegis_agent_platform.memory.quota import (
    InMemoryMemoryQuota,
    MemoryQuota,
    MemoryQuotaExceededError,
    MemoryQuotaKind,
)
from aegis_agent_platform.memory.repository import (
    IndexedMemoryChunk,
    MemoryIndex,
    MemoryLedger,
)
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class RetrievalPolicy:
    version: str = "hybrid-v1"
    lexical_weight: float = 0.35
    vector_weight: float = 0.35
    recency_weight: float = 0.10
    quality_weight: float = 0.20
    diversity_lambda: float = 0.75
    stale_after_days: int = 180
    exclude_stale: bool = True
    embedding_model: str = "aegis-deterministic-embedding"
    embedding_model_version: str = "v1"
    embedding_dimension: int = 8

    def __post_init__(self) -> None:
        weights = (
            self.lexical_weight,
            self.vector_weight,
            self.recency_weight,
            self.quality_weight,
        )
        if not self.version or not math.isclose(sum(weights), 1.0):
            raise ValueError("retrieval score weights must sum to one")
        if any(not 0 <= value <= 1 for value in (*weights, self.diversity_lambda)):
            raise ValueError("retrieval weights must be normalized")
        if not 1 <= self.stale_after_days <= 3_650:
            raise ValueError("retrieval freshness bound is invalid")
        if (
            not self.embedding_model
            or not self.embedding_model_version
            or not 1 <= self.embedding_dimension <= 4_096
        ):
            raise ValueError("retrieval embedding contract is invalid")


class HybridRetriever:
    """Persist query intent, prefilter, rank, diversify, and record references."""

    def __init__(
        self,
        ledger: MemoryLedger,
        index: MemoryIndex,
        embedder: EmbeddingProvider,
        *,
        policy: RetrievalPolicy | None = None,
        cache: MemoryCache | None = None,
        quota: MemoryQuota | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._ledger = ledger
        self._index = index
        self._embedder = embedder
        self._policy = policy or RetrievalPolicy()
        self._cache = cache
        self._quota = quota or InMemoryMemoryQuota()
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def retrieve(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        lease: WorkLease,
    ) -> RetrievalResult:
        tenant_id = str(context.tenant_id)
        if query.tenant_id != tenant_id or query.policy_version != self._policy.version:
            raise PermissionError("retrieval tenant or policy mismatch")
        if lease.tenant_id != tenant_id:
            raise PermissionError("retrieval lease is not tenant bound")
        query = dataclass_replace(
            query,
            as_of=self._clock(),
            embedding_model=self._policy.embedding_model,
            embedding_model_version=self._policy.embedding_model_version,
            embedding_dimension=self._policy.embedding_dimension,
        )
        as_of = query.as_of
        if as_of is None:
            raise ValueError("retrieval as-of timestamp is required")
        requested = self._event(
            query,
            DomainEventType.MEMORY_RETRIEVAL_REQUESTED,
            {
                "query_digest": query.query_digest,
                "purpose": query.purpose,
                "policy_version": query.policy_version,
                "top_k": query.top_k,
                "candidate_limit": query.candidate_limit,
                "max_context_bytes": query.max_context_bytes,
                "max_context_tokens": query.max_context_tokens,
                "as_of": query.as_of.isoformat() if query.as_of is not None else None,
                "embedding_model": query.embedding_model,
                "embedding_model_version": query.embedding_model_version,
                "embedding_dimension": query.embedding_dimension,
            },
            suffix="requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            query.retrieval_id,
            lease,
            (requested,),
            expected_version=0,
        )
        try:
            await self._quota.reserve(
                context,
                MemoryQuotaKind.RETRIEVALS,
                1,
                at=as_of,
            )
        except MemoryQuotaExceededError as error:
            failure = MemoryProviderError(
                MemoryProviderErrorClass.RATE_LIMIT,
                "memory_retrieval_tenant_quota_exhausted",
                retryable=False,
            )
            await self._fail(context, query, lease, failure, version)
            raise error
        candidates = self._compatible_candidates(
            await self._index.candidates(context, query)
        )
        cached = (
            await self._cache.get(context, query) if self._cache is not None else None
        )
        if cached is not None:
            result = self._from_cache(query, candidates, cached)
            if result is not None:
                await self._complete(context, query, lease, result, version)
                return result
        embedding_request = EmbeddingRequest(
            request_id=self._uuid_factory(),
            tenant_id=tenant_id,
            texts=(query.text,),
            model=self._policy.embedding_model,
            dimension=self._policy.embedding_dimension,
            model_version=self._policy.embedding_model_version,
            timeout_seconds=30,
            idempotency_key=f"retrieval:{query.retrieval_id}:embedding",
        )
        embedding_intent = self._event(
            query,
            DomainEventType.MEMORY_EMBEDDING_REQUESTED,
            {
                "request_id": str(embedding_request.request_id),
                "input_digest": embedding_request.input_digest,
                "model": embedding_request.model,
                "model_version": embedding_request.model_version,
                "dimension": embedding_request.dimension,
                "query_embedding": True,
            },
            suffix="embedding-requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            query.retrieval_id,
            lease,
            (embedding_intent,),
            expected_version=version,
        )
        try:
            response = await asyncio.wait_for(
                self._embedder.embed(embedding_request),
                timeout=embedding_request.timeout_seconds,
            )
            validate_embedding_response(embedding_request, response)
        except TimeoutError as error:
            failure = MemoryProviderError(
                MemoryProviderErrorClass.TIMEOUT,
                "retrieval_embedding_timeout",
                retryable=True,
                result_ambiguous=True,
            )
            await self._fail(context, query, lease, failure, version)
            raise failure from error
        except MemoryProviderError as error:
            await self._fail(context, query, lease, error, version)
            raise
        embedding_complete = self._event(
            query,
            DomainEventType.MEMORY_EMBEDDING_COMPLETED,
            {
                "request_id": str(response.request_id),
                "model": response.model,
                "model_version": response.model_version,
                "dimension": response.dimension,
                "query_embedding": True,
            },
            suffix="embedding-completed",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            query.retrieval_id,
            lease,
            (embedding_complete,),
            expected_version=version,
        )
        candidates = self._compatible_candidates(
            await self._index.candidates(
                context,
                query,
                query_vector=response.vectors[0],
            )
        )
        result = self._rank(query, candidates, response.vectors[0])
        await self._complete(context, query, lease, result, version)
        if self._cache is not None:
            await self._cache.set(
                context,
                query,
                CachedSelection(
                    query.policy_version,
                    tuple(hit.chunk.chunk_id for hit in result.hits),
                    tuple(hit.final_score for hit in result.hits),
                ),
            )
        return result

    def _rank(
        self,
        query: RetrievalQuery,
        candidates: Sequence[IndexedMemoryChunk],
        query_vector: Sequence[float],
    ) -> RetrievalResult:
        as_of = query.as_of or self._clock()
        candidates = tuple(
            item
            for item in candidates
            if not self._policy.exclude_stale
            or (as_of - item.memory.created_at).total_seconds()
            <= self._policy.stale_after_days * 86_400
        )
        query_terms = _terms(query.text)
        lexical_raw = [
            len(query_terms.intersection(_terms(item.chunk.text)))
            / max(1, len(query_terms.union(_terms(item.chunk.text))))
            for item in candidates
        ]
        vector_raw = [
            _cosine(query_vector, item.chunk.embedding or ()) for item in candidates
        ]
        lexical = _normalize(lexical_raw)
        vector = _normalize(tuple((score + 1) / 2 for score in vector_raw))
        ranked: list[tuple[IndexedMemoryChunk, RetrievalHit]] = []
        for item, lexical_score, vector_score in zip(
            candidates,
            lexical,
            vector,
            strict=True,
        ):
            age_days = max(
                0.0, (as_of - item.memory.created_at).total_seconds() / 86_400
            )
            recency = 1 / (1 + age_days / 30)
            final = (
                self._policy.lexical_weight * lexical_score
                + self._policy.vector_weight * vector_score
                + self._policy.recency_weight * recency
                + self._policy.quality_weight * item.memory.quality
            )
            freshness = (
                RetrievalFreshness.STALE
                if age_days > self._policy.stale_after_days
                else RetrievalFreshness.CURRENT
            )
            ranked.append(
                (
                    item,
                    RetrievalHit(
                        item.chunk,
                        lexical_score,
                        vector_score,
                        recency,
                        item.memory.quality,
                        min(1.0, max(0.0, final)),
                        freshness,
                        item.contradiction_ids,
                    ),
                )
            )
        selected = _mmr(
            ranked,
            top_k=query.top_k,
            diversity_lambda=self._policy.diversity_lambda,
        )
        bounded: list[RetrievalHit] = []
        used_bytes = 0
        used_tokens = 0
        for hit in selected:
            if (
                used_bytes + hit.chunk.byte_count > query.max_context_bytes
                or used_tokens + hit.chunk.token_count > query.max_context_tokens
            ):
                continue
            bounded.append(hit)
            used_bytes += hit.chunk.byte_count
            used_tokens += hit.chunk.token_count
        return RetrievalResult(
            query.retrieval_id,
            query.query_digest,
            query.policy_version,
            query.scope,
            tuple(bounded),
            insufficient_context=not bounded,
        )

    def _from_cache(
        self,
        query: RetrievalQuery,
        candidates: Sequence[IndexedMemoryChunk],
        cached: CachedSelection,
    ) -> RetrievalResult | None:
        if cached.retrieval_policy != query.policy_version:
            return None
        by_id = {item.chunk.chunk_id: item for item in candidates}
        if any(identifier not in by_id for identifier in cached.chunk_ids):
            return None
        as_of = query.as_of or self._clock()
        hits: list[RetrievalHit] = []
        used_bytes = 0
        used_tokens = 0
        for identifier, score in zip(
            cached.chunk_ids,
            cached.scores,
            strict=True,
        ):
            item = by_id[identifier]
            age_days = max(
                0.0, (as_of - item.memory.created_at).total_seconds() / 86_400
            )
            if self._policy.exclude_stale and age_days > self._policy.stale_after_days:
                continue
            if len(hits) >= query.top_k:
                break
            if (
                used_bytes + item.chunk.byte_count > query.max_context_bytes
                or used_tokens + item.chunk.token_count > query.max_context_tokens
            ):
                continue
            hits.append(
                RetrievalHit(
                    item.chunk,
                    score,
                    score,
                    1 / (1 + age_days / 30),
                    item.memory.quality,
                    score,
                    (
                        RetrievalFreshness.STALE
                        if age_days > self._policy.stale_after_days
                        else RetrievalFreshness.CURRENT
                    ),
                    item.contradiction_ids,
                )
            )
            used_bytes += item.chunk.byte_count
            used_tokens += item.chunk.token_count
        return RetrievalResult(
            query.retrieval_id,
            query.query_digest,
            query.policy_version,
            query.scope,
            tuple(hits),
            insufficient_context=not hits,
        )

    def _compatible_candidates(
        self,
        candidates: Sequence[IndexedMemoryChunk],
    ) -> tuple[IndexedMemoryChunk, ...]:
        return tuple(
            item
            for item in candidates
            if item.memory.embedding_model == self._policy.embedding_model
            and item.memory.embedder_version == self._policy.embedding_model_version
            and item.memory.embedding_dimension == self._policy.embedding_dimension
            and item.chunk.embedding is not None
            and len(item.chunk.embedding) == self._policy.embedding_dimension
        )

    async def _complete(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        lease: WorkLease,
        result: RetrievalResult,
        expected_version: int,
    ) -> None:
        event = self._event(
            query,
            DomainEventType.MEMORY_RETRIEVAL_COMPLETED,
            {
                "query_digest": query.query_digest,
                "candidate_references": tuple(
                    {
                        "chunk_id": str(hit.chunk.chunk_id),
                        "memory_id": str(hit.chunk.memory_id),
                        "score": round(hit.final_score, 12),
                        "freshness": hit.freshness.value,
                        "contradiction_ids": tuple(
                            str(item) for item in hit.contradiction_ids
                        ),
                    }
                    for hit in result.hits
                ),
                "selected_count": len(result.hits),
                "insufficient_context": result.insufficient_context,
            },
            suffix="completed",
            lease=lease,
        )
        await self._ledger.append_fenced(
            context,
            query.retrieval_id,
            lease,
            (event,),
            expected_version=expected_version,
        )

    async def _fail(
        self,
        context: TenantContext,
        query: RetrievalQuery,
        lease: WorkLease,
        error: MemoryProviderError,
        expected_version: int,
    ) -> None:
        event = self._event(
            query,
            DomainEventType.MEMORY_RETRIEVAL_FAILED,
            {
                "query_digest": query.query_digest,
                "error_class": error.error_class.value,
                "error_code": error.code,
                "result_ambiguous": error.result_ambiguous,
            },
            suffix="failed",
            lease=lease,
        )
        await self._ledger.append_fenced(
            context,
            query.retrieval_id,
            lease,
            (event,),
            expected_version=expected_version,
        )

    def _event(
        self,
        query: RetrievalQuery,
        event_type: DomainEventType,
        payload: dict[str, JsonValue],
        *,
        suffix: str,
        lease: WorkLease,
    ) -> EventEnvelope:
        payload["lease_token"] = str(lease.token)
        payload["lease_generation"] = lease.generation
        return EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=query.tenant_id,
            aggregate_id=str(query.retrieval_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=self._clock(),
            payload=payload,
            correlation_id=query.retrieval_id,
            actor=ActorReference(query.principal_id, ActorKind.USER),
            idempotency_key=f"retrieval:{query.retrieval_id}:{suffix}",
        )


def _terms(value: str) -> frozenset[str]:
    return frozenset(
        token.strip(".,:;!?()[]{}\"'").casefold()
        for token in value.split()
        if token.strip(".,:;!?()[]{}\"'")
    )


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        return -1.0
    return max(-1.0, min(1.0, sum(a * b for a, b in zip(left, right, strict=True))))


def _normalize(values: Sequence[float]) -> tuple[float, ...]:
    if not values:
        return ()
    minimum = min(values)
    maximum = max(values)
    if math.isclose(minimum, maximum):
        return tuple(min(1.0, max(0.0, value)) for value in values)
    return tuple((value - minimum) / (maximum - minimum) for value in values)


def _mmr(
    ranked: Sequence[tuple[IndexedMemoryChunk, RetrievalHit]],
    *,
    top_k: int,
    diversity_lambda: float,
) -> tuple[RetrievalHit, ...]:
    remaining = list(ranked)
    selected: list[tuple[IndexedMemoryChunk, RetrievalHit]] = []
    while remaining and len(selected) < top_k:
        choices: list[tuple[float, str, int, IndexedMemoryChunk, RetrievalHit]] = []
        for item, hit in remaining:
            duplication = max(
                (
                    len(_terms(hit.chunk.text).intersection(_terms(chosen.chunk.text)))
                    / max(
                        1,
                        len(_terms(hit.chunk.text).union(_terms(chosen.chunk.text))),
                    )
                    for _, chosen in selected
                ),
                default=0.0,
            )
            mmr_score = (
                diversity_lambda * hit.final_score
                - (1 - diversity_lambda) * duplication
            )
            choices.append(
                (
                    mmr_score,
                    str(hit.chunk.memory_id),
                    -hit.chunk.ordinal,
                    item,
                    hit,
                )
            )
        _, _, _, chosen_item, chosen_hit = max(choices, key=lambda value: value[:3])
        selected.append((chosen_item, chosen_hit))
        remaining = [
            value
            for value in remaining
            if value[1].chunk.chunk_id != chosen_hit.chunk.chunk_id
        ]
    return tuple(hit for _, hit in selected)


__all__ = ["HybridRetriever", "RetrievalPolicy"]
