"""Layer 7 specialist context composition backed by cited Layer 10 retrieval."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from aegis_agent_platform.agents.artifacts import (
    DurableAgentArtifact,
    EvidenceCitation,
)
from aegis_agent_platform.agents.coordination import SpecialistAssignment
from aegis_agent_platform.domain import (
    ContextBudget,
    MemoryContext,
    RetrievalQuery,
    WorkLease,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.memory.context import ContextBuilder
from aegis_agent_platform.memory.retrieval import HybridRetriever
from aegis_agent_platform.tenancy import TenantContext


class SpecialistMemoryProvider:
    """Retrieve read-only memory under the coordinator-owned specialist lease."""

    def __init__(
        self,
        retriever: HybridRetriever,
        context_builder: ContextBuilder,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._retriever = retriever
        self._context_builder = context_builder
        self._clock = clock
        self._uuid_factory = uuid_factory

    async def context_for(
        self,
        *,
        tenant_id: str,
        run_id: UUID,
        assignment: SpecialistAssignment,
        upstream_artifacts: tuple[DurableAgentArtifact, ...],
        evidence: tuple[EvidenceCitation, ...],
        lease: WorkLease,
    ) -> MemoryContext | None:
        del upstream_artifacts
        if lease.tenant_id != tenant_id or lease.work_id != run_id:
            raise PermissionError("specialist memory lease is not tenant/run bound")
        now = self._clock()
        query_text = " ".join(
            (
                assignment.role.value,
                *(kind.value for kind in assignment.output_kinds),
                *(item.evidence_id for item in evidence),
            )
        )
        query = RetrievalQuery(
            retrieval_id=self._uuid_factory(),
            tenant_id=tenant_id,
            principal_id=f"specialist:{assignment.role.value}",
            service_id="aegis-specialist",
            roles=frozenset({assignment.role.value}),
            purpose="incident-investigation",
            text=query_text,
            top_k=8,
            candidate_limit=64,
            max_context_bytes=min(
                assignment.budget.max_input_tokens * 4,
                1_000_000,
            ),
            max_context_tokens=min(
                assignment.budget.max_input_tokens,
                250_000,
            ),
            as_of=now,
        )
        retrieval = await self._retriever.retrieve(
            TenantContext(TenantId(tenant_id)),
            query,
            lease,
        )
        total = max(256, assignment.budget.max_input_tokens)
        system = min(256, total // 8)
        safety = min(256, total // 8)
        semantic = total - system - safety
        return await self._context_builder.build(
            TenantContext(TenantId(tenant_id)),
            run_id=run_id,
            task_id=assignment.assignment_id,
            actor_id=f"specialist:{assignment.role.value}",
            lease=lease,
            budget=ContextBudget(
                total_tokens=total,
                total_bytes=min(total * 4, 1_000_000),
                reserved_system_tokens=system,
                reserved_safety_tokens=safety,
                working_tokens=0,
                episodic_tokens=0,
                semantic_tokens=semantic,
            ),
            working=(),
            episodic=(),
            semantic=retrieval,
            policy_version="specialist-context-v1",
            fence_work_id=run_id,
        )


__all__ = ["SpecialistMemoryProvider"]
