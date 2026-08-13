"""Citation-preserving context allocation and durable bounded compaction."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    ContextBudget,
    ContextSnippet,
    DomainEventType,
    EpisodicMemoryReference,
    EventEnvelope,
    JsonValue,
    MemoryContext,
    MemoryTier,
    RetrievalResult,
    SummarizationRequest,
    SummarizationResponse,
    WorkingMemoryItem,
    WorkLease,
)
from aegis_agent_platform.memory.ports import (
    MemoryProviderError,
    MemoryProviderErrorClass,
    SummarizationProvider,
)
from aegis_agent_platform.memory.repository import MemoryLedger
from aegis_agent_platform.tenancy import TenantContext


class ContextCompactor:
    """Persist summary intent, validate claims/citations, and fall back safely."""

    def __init__(
        self,
        ledger: MemoryLedger,
        summarizer: SummarizationProvider,
        *,
        model: str = "aegis-deterministic-summary",
        model_version: str = "v1",
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._ledger = ledger
        self._summarizer = summarizer
        self._model = model
        self._model_version = model_version
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def compact(
        self,
        context: TenantContext,
        source_items: Sequence[WorkingMemoryItem],
        lease: WorkLease,
        *,
        summary_id: UUID,
        actor_id: str,
        max_output_tokens: int,
        recursion_depth: int = 0,
    ) -> WorkingMemoryItem:
        if not source_items:
            raise ValueError("context compaction requires source items")
        request = SummarizationRequest(
            request_id=self._uuid_factory(),
            tenant_id=str(context.tenant_id),
            source_items=tuple(source_items),
            max_output_tokens=max_output_tokens,
            model=self._model,
            model_version=self._model_version,
            recursion_depth=recursion_depth,
            timeout_seconds=30,
            idempotency_key=f"summary:{summary_id}:{recursion_depth}",
        )
        intent = self._event(
            context,
            summary_id,
            DomainEventType.MEMORY_SUMMARY_REQUESTED,
            {
                "request_id": str(request.request_id),
                "model": request.model,
                "model_version": request.model_version,
                "recursion_depth": request.recursion_depth,
                "source_reference_ids": tuple(
                    item.reference_id for item in request.source_items
                ),
                "source_digest": _source_digest(request.source_items),
                "max_output_tokens": request.max_output_tokens,
            },
            actor_id=actor_id,
            suffix="requested",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            summary_id,
            lease,
            (intent,),
            expected_version=0,
        )
        try:
            response = await asyncio.wait_for(
                self._summarizer.summarize(request),
                timeout=request.timeout_seconds,
            )
            summary_text = _validate_summary(request, response)
        except (MemoryProviderError, TimeoutError, ValueError) as error:
            reason = (
                error.code
                if isinstance(error, MemoryProviderError)
                else "summary_timeout"
                if isinstance(error, TimeoutError)
                else "unsupported_summary_claim"
            )
            rejected = self._event(
                context,
                summary_id,
                DomainEventType.MEMORY_SUMMARY_REJECTED,
                {
                    "request_id": str(request.request_id),
                    "reason_code": reason,
                    "deterministic_fallback": True,
                },
                actor_id=actor_id,
                suffix="rejected",
                lease=lease,
            )
            version = await self._ledger.append_fenced(
                context,
                summary_id,
                lease,
                (rejected,),
                expected_version=version,
            )
            fallback = _fallback_summary(
                request.source_items,
                max_output_tokens=max_output_tokens,
                summary_id=summary_id,
            )
            compacted = self._event(
                context,
                summary_id,
                DomainEventType.MEMORY_CONTEXT_COMPACTED,
                {
                    "summary_reference": fallback.reference_id,
                    "source_reference_ids": tuple(
                        item.reference_id for item in request.source_items
                    ),
                    "citation_ids": tuple(
                        citation.source_id for citation in fallback.citations
                    ),
                    "fallback": True,
                },
                actor_id=actor_id,
                suffix="fallback",
                lease=lease,
            )
            await self._ledger.append_fenced(
                context,
                summary_id,
                lease,
                (compacted,),
                expected_version=version,
            )
            return fallback
        completed = self._event(
            context,
            summary_id,
            DomainEventType.MEMORY_SUMMARY_COMPLETED,
            {
                "request_id": str(response.request_id),
                "summary_digest": sha256(summary_text.encode()).hexdigest(),
                "covered_reference_ids": response.covered_reference_ids,
                "claim_count": len(response.claims),
                "model": response.model,
                "model_version": response.model_version,
            },
            actor_id=actor_id,
            suffix="completed",
            lease=lease,
        )
        version = await self._ledger.append_fenced(
            context,
            summary_id,
            lease,
            (completed,),
            expected_version=version,
        )
        citations = tuple(
            sorted(
                {
                    citation
                    for item in request.source_items
                    for citation in item.citations
                }
            )
        )
        item = WorkingMemoryItem(
            reference_id=f"summary:{summary_id}",
            text=summary_text,
            citations=citations,
            priority=max(source.priority for source in request.source_items),
            occurred_at=max(source.occurred_at for source in request.source_items),
            kind="citation_preserving_summary",
        )
        compacted = self._event(
            context,
            summary_id,
            DomainEventType.MEMORY_CONTEXT_COMPACTED,
            {
                "summary_reference": item.reference_id,
                "source_reference_ids": response.covered_reference_ids,
                "citation_ids": tuple(
                    citation.source_id for citation in item.citations
                ),
                "fallback": False,
            },
            actor_id=actor_id,
            suffix="compacted",
            lease=lease,
        )
        await self._ledger.append_fenced(
            context,
            summary_id,
            lease,
            (compacted,),
            expected_version=version,
        )
        return item

    def _event(
        self,
        context: TenantContext,
        aggregate_id: UUID,
        event_type: DomainEventType,
        payload: dict[str, JsonValue],
        *,
        actor_id: str,
        suffix: str,
        lease: WorkLease,
    ) -> EventEnvelope:
        payload["lease_token"] = str(lease.token)
        payload["lease_generation"] = lease.generation
        return EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=str(context.tenant_id),
            aggregate_id=str(aggregate_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=self._clock(),
            payload=payload,
            correlation_id=lease.work_id,
            actor=ActorReference(actor_id, ActorKind.USER),
            idempotency_key=f"summary:{aggregate_id}:{suffix}",
        )


class ContextBuilder:
    """Allocate working, episodic, and semantic memory under hard budgets."""

    def __init__(
        self,
        ledger: MemoryLedger,
        *,
        compactor: ContextCompactor | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._ledger = ledger
        self._compactor = compactor
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def build(
        self,
        context: TenantContext,
        *,
        run_id: UUID,
        task_id: UUID,
        actor_id: str,
        lease: WorkLease,
        budget: ContextBudget,
        working: Sequence[WorkingMemoryItem],
        episodic: Sequence[EpisodicMemoryReference],
        semantic: RetrievalResult,
        policy_version: str = "context-builder-v1",
        fence_work_id: UUID | None = None,
    ) -> MemoryContext:
        expected_work_id = fence_work_id or task_id
        if (
            lease.tenant_id != str(context.tenant_id)
            or lease.work_id != expected_work_id
        ):
            raise PermissionError("context lease is not tenant/task bound")
        if (
            semantic.scope.tenant_id != str(context.tenant_id)
            or semantic.scope.principal_id != actor_id
        ):
            raise PermissionError("retrieval result is not tenant/principal bound")
        context_id = self._uuid_factory()
        working_items = tuple(working)
        compacted = False
        if (
            self._compactor is not None
            and sum(_tokens(item.text) for item in working_items)
            > budget.working_tokens
            and working_items
        ):
            summary = await self._compactor.compact(
                context,
                working_items,
                lease,
                summary_id=self._uuid_factory(),
                actor_id=actor_id,
                max_output_tokens=max(64, budget.working_tokens),
            )
            working_items = (summary,)
            compacted = True
        candidates = {
            MemoryTier.WORKING: tuple(
                ContextSnippet(
                    item.reference_id,
                    MemoryTier.WORKING,
                    item.text,
                    item.citations,
                    item.priority,
                )
                for item in working_items
            ),
            MemoryTier.EPISODIC: tuple(
                ContextSnippet(
                    item.reference_id,
                    MemoryTier.EPISODIC,
                    item.cited_summary,
                    item.citations,
                    70,
                )
                for item in episodic
            ),
            MemoryTier.SEMANTIC: tuple(
                ContextSnippet(
                    str(hit.chunk.chunk_id),
                    MemoryTier.SEMANTIC,
                    hit.chunk.text,
                    hit.chunk.citations,
                    round(hit.final_score * 100),
                )
                for hit in semantic.hits
            ),
        }
        tier_limits = {
            MemoryTier.WORKING: budget.working_tokens,
            MemoryTier.EPISODIC: budget.episodic_tokens,
            MemoryTier.SEMANTIC: budget.semantic_tokens,
        }
        selected: list[ContextSnippet] = []
        used_tokens = budget.reserved_system_tokens + budget.reserved_safety_tokens
        used_bytes = 0
        seen: set[str] = set()
        for tier in (MemoryTier.WORKING, MemoryTier.EPISODIC, MemoryTier.SEMANTIC):
            tier_tokens = 0
            accepted: list[ContextSnippet] = []
            for item in sorted(
                candidates[tier],
                key=lambda value: (-value.priority, value.reference_id),
            ):
                digest = sha256(item.text.casefold().encode()).hexdigest()
                if digest in seen:
                    continue
                remaining_tier = tier_limits[tier] - tier_tokens
                remaining_total = budget.total_tokens - used_tokens
                remaining_bytes = budget.total_bytes - used_bytes
                if min(remaining_tier, remaining_total) <= 0 or remaining_bytes <= 0:
                    break
                bounded = _bound_snippet(
                    item,
                    max_tokens=min(remaining_tier, remaining_total),
                    max_bytes=remaining_bytes,
                )
                if bounded is None:
                    continue
                accepted.append(bounded)
                token_count = _tokens(bounded.text)
                tier_tokens += token_count
                used_tokens += token_count
                used_bytes += len(bounded.text.encode())
                seen.add(digest)
            selected.extend(_edge_order(accepted))
        contradictory = any(hit.contradiction_ids for hit in semantic.hits)
        insufficient = not selected or semantic.insufficient_context or contradictory
        abstention_reason = (
            "contradictory_memory_requires_critic"
            if contradictory
            else "no_authorized_cited_context"
            if insufficient
            else None
        )
        result = MemoryContext(
            context_id=context_id,
            tenant_id=str(context.tenant_id),
            run_id=run_id,
            task_id=task_id,
            snippets=tuple(selected),
            budget=budget,
            used_tokens=used_tokens,
            used_bytes=used_bytes,
            compacted=compacted,
            insufficient_context=insufficient,
            abstention_reason=abstention_reason,
            policy_version=policy_version,
        )
        event = EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=str(context.tenant_id),
            aggregate_id=str(context_id),
            event_type=DomainEventType.MEMORY_CONTEXT_SELECTED,
            schema_version=1,
            occurred_at=self._clock(),
            payload={
                "lease_token": str(lease.token),
                "lease_generation": lease.generation,
                "run_id": str(run_id),
                "task_id": str(task_id),
                "policy_version": policy_version,
                "selected_references": tuple(
                    {
                        "reference_id": item.reference_id,
                        "tier": item.tier.value,
                        "citation_ids": tuple(
                            citation.source_id for citation in item.citations
                        ),
                        "text_digest": sha256(item.text.encode()).hexdigest(),
                    }
                    for item in result.snippets
                ),
                "used_tokens": result.used_tokens,
                "used_bytes": result.used_bytes,
                "compacted": result.compacted,
                "insufficient_context": result.insufficient_context,
            },
            correlation_id=run_id,
            actor=ActorReference(actor_id, ActorKind.USER),
            idempotency_key=f"context:{context_id}:selected",
        )
        await self._ledger.append_fenced(
            context,
            context_id,
            lease,
            (event,),
            expected_version=0,
        )
        return result


def _validate_summary(
    request: SummarizationRequest,
    response: SummarizationResponse,
) -> str:
    if response.request_id != request.request_id:
        raise MemoryProviderError(
            MemoryProviderErrorClass.MALFORMED_RESPONSE,
            "summary_request_id_mismatch",
            retryable=False,
            result_ambiguous=True,
        )
    if (
        response.model != request.model
        or response.model_version != request.model_version
    ):
        raise MemoryProviderError(
            MemoryProviderErrorClass.MALFORMED_RESPONSE,
            "summary_model_version_mismatch",
            retryable=False,
            result_ambiguous=True,
        )
    sources = {item.reference_id: item for item in request.source_items}
    if set(response.covered_reference_ids) != set(sources):
        raise ValueError("summary did not preserve complete source-reference coverage")
    citation_text: dict[str, str] = {}
    for item in request.source_items:
        for citation in item.citations:
            citation_text[citation.source_id] = (
                citation_text.get(citation.source_id, "") + " " + item.text
            )
    for claim in response.claims:
        if any(identifier not in citation_text for identifier in claim.citation_ids):
            raise ValueError("summary contains an unknown citation")
        supported = " ".join(citation_text[item] for item in claim.citation_ids)
        claim_terms = _substantive_terms(claim.text)
        source_terms = _substantive_terms(supported)
        if (
            claim_terms
            and len(claim_terms.intersection(source_terms)) / len(claim_terms) < 0.8
        ):
            raise ValueError("summary contains an unsupported claim")
    rendered = "\n".join(
        f"{claim.text} [{' '.join(claim.citation_ids)}]" for claim in response.claims
    )
    if response.summary != rendered:
        raise ValueError("summary text is not the validated cited-claim rendering")
    if len(rendered.encode()) > request.max_output_tokens * 4:
        raise ValueError("summary exceeds its output budget")
    contradictions = [
        item for item in request.source_items if "contradiction" in item.kind.casefold()
    ]
    if contradictions and "contrad" not in rendered.casefold():
        raise ValueError("summary drifted by omitting an explicit contradiction")
    return rendered


def _fallback_summary(
    items: Sequence[WorkingMemoryItem],
    *,
    max_output_tokens: int,
    summary_id: UUID,
) -> WorkingMemoryItem:
    ordered = tuple(
        sorted(
            items,
            key=lambda item: (-item.priority, item.occurred_at, item.reference_id),
        )
    )
    max_bytes = max_output_tokens * 4
    lines: list[str] = []
    used = 0
    for item in ordered:
        line = f"{item.text} [{' '.join(c.source_id for c in item.citations)}]"
        if lines and used + len(line.encode()) > max_bytes:
            continue
        lines.append(line)
        used += len(line.encode())
    text = "\n".join(lines)
    if len(text.encode()) > max_bytes:
        text = text.encode()[:max_bytes].decode("utf-8", errors="ignore").rstrip()
    citations = tuple(
        sorted({citation for item in ordered for citation in item.citations})
    )
    return WorkingMemoryItem(
        reference_id=f"summary-fallback:{summary_id}",
        text=text,
        citations=citations,
        priority=max(item.priority for item in items),
        occurred_at=max(item.occurred_at for item in items),
        kind="deterministic_fallback_summary",
    )


def _source_digest(items: Sequence[WorkingMemoryItem]) -> str:
    value = "|".join(
        f"{item.reference_id}:{sha256(item.text.encode()).hexdigest()}"
        for item in items
    )
    return sha256(value.encode()).hexdigest()


def _tokens(value: str) -> int:
    return max(1, len(value.split()))


def _bound_snippet(
    item: ContextSnippet,
    *,
    max_tokens: int,
    max_bytes: int,
) -> ContextSnippet | None:
    if max_tokens < 1 or max_bytes < 1:
        return None
    words = item.text.split()
    selected: list[str] = []
    used = 0
    for word in words[:max_tokens]:
        added = len(word.encode()) + (1 if selected else 0)
        if used + added > max_bytes:
            break
        selected.append(word)
        used += added
    if not selected:
        return None
    text = " ".join(selected)
    return ContextSnippet(
        item.reference_id,
        item.tier,
        text,
        item.citations,
        item.priority,
    )


def _edge_order(items: Sequence[ContextSnippet]) -> tuple[ContextSnippet, ...]:
    left: list[ContextSnippet] = []
    right: list[ContextSnippet] = []
    for index, item in enumerate(items):
        (left if index % 2 == 0 else right).append(item)
    return (*left, *reversed(right))


def _substantive_terms(value: str) -> frozenset[str]:
    stop = {"a", "an", "and", "or", "the", "to", "of", "in", "on", "for", "is"}
    return frozenset(
        token.strip(".,:;!?()[]{}\"'").casefold()
        for token in value.split()
        if token.strip(".,:;!?()[]{}\"'").casefold() not in stop
    )


__all__ = ["ContextBuilder", "ContextCompactor"]
