"""Durable agent repository port and deterministic in-memory ledger adapter."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4

from aegis_agent_platform.agents.artifacts import (
    artifact_confidence,
    artifact_kind,
    artifact_summary,
)
from aegis_agent_platform.agents.coordination import (
    InvestigationState,
    replay_investigation,
)
from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    WorkLease,
    WorkRequest,
    WorkTransition,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import FencingError, OutboxMessage
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class InvestigationRequestResult:
    created: bool
    run_id: UUID


class InvestigationIdempotencyConflictError(ValueError):
    """An idempotency key is already bound to different investigation input."""


class AgentRepository(Protocol):
    """Ledger-authoritative writes and disposable tenant-scoped read models."""

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        agent_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> InvestigationRequestResult: ...

    async def load(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> tuple[EventEnvelope, ...]: ...

    async def append_fenced(
        self,
        context: TenantContext,
        run_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
    ) -> int: ...

    async def status(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> Mapping[str, JsonValue] | None: ...

    async def task_page(
        self,
        context: TenantContext,
        run_id: UUID,
        *,
        after_ordinal: int = -1,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]: ...

    async def artifact_page(
        self,
        context: TenantContext,
        run_id: UUID,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]: ...

    async def rebuild_projection(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> None: ...


class InMemoryAgentRepository(AgentRepository):
    """Event-first adapter with rebuildable projections and strict fencing."""

    def __init__(
        self,
        *,
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._uuid_factory = uuid_factory
        self._events: dict[tuple[str, UUID], list[EventEnvelope]] = {}
        self._requests: dict[tuple[str, str], tuple[UUID, str]] = {}
        self._leases: dict[tuple[str, UUID], WorkLease] = {}
        self._run_projection: dict[
            tuple[str, UUID],
            Mapping[str, JsonValue],
        ] = {}
        self._task_projection: dict[
            tuple[str, UUID],
            tuple[Mapping[str, JsonValue], ...],
        ] = {}
        self._artifact_projection: dict[
            tuple[str, UUID],
            tuple[Mapping[str, JsonValue], ...],
        ] = {}
        self.outbox: list[OutboxMessage] = []

    def register_lease(self, lease: WorkLease) -> None:
        self._leases[(lease.tenant_id, lease.work_id)] = lease

    def replace_lease(self, lease: WorkLease) -> None:
        self.register_lease(lease)

    def clear_projections(self) -> None:
        self._run_projection.clear()
        self._task_projection.clear()
        self._artifact_projection.clear()

    async def rebuild_projection(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> None:
        events = self._events.get((str(context.tenant_id), run_id))
        if events is None:
            return
        self._project(str(context.tenant_id), run_id, replay_investigation(events))

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        agent_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> InvestigationRequestResult:
        tenant_id = str(context.tenant_id)
        if request.tenant_id != tenant_id or request.work_id.int == 0:
            raise PermissionError("cross_tenant_investigation_request")
        fingerprint = _request_fingerprint(request)
        key = (tenant_id, request.idempotency_key)
        existing = self._requests.get(key)
        if existing is not None:
            if existing[1] != fingerprint:
                raise InvestigationIdempotencyConflictError(
                    "investigation_idempotency_key_reused"
                )
            return InvestigationRequestResult(False, existing[0])
        work_event = WorkTransition(
            DomainEventType.WORK_REQUESTED,
            request.requested_at,
            {
                "max_attempts": request.max_attempts,
                "timeout_seconds": request.timeout_seconds,
                "idempotency_key": request.idempotency_key,
                "request_payload": request.payload,
            },
        ).to_event(
            request,
            event_id=requested_event_id,
            causation_id=request.causation_id,
        )
        pending = (work_event, *agent_events)
        if any(
            event.tenant_id != tenant_id or event.aggregate_id != str(request.work_id)
            for event in pending
        ):
            raise ValueError("request events must match the tenant work aggregate")
        events = [
            replace(event, aggregate_sequence=position)
            for position, event in enumerate(pending, start=1)
        ]
        state = replay_investigation(events)
        self._events[(tenant_id, request.work_id)] = events
        self._requests[key] = (request.work_id, fingerprint)
        self.outbox.append(
            OutboxMessage(
                message_id=outbox_message_id,
                event_id=requested_event_id,
                destination="aegis.work.investigation",
                payload={
                    "tenant_id": tenant_id,
                    "run_id": str(request.work_id),
                    "work_kind": request.work_kind,
                },
                headers={"schema_version": 1},
                available_at=request.requested_at,
                max_attempts=request.max_attempts,
            )
        )
        self._project(tenant_id, request.work_id, state)
        return InvestigationRequestResult(True, request.work_id)

    async def load(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        return tuple(self._events.get((str(context.tenant_id), run_id), ()))

    async def append_fenced(
        self,
        context: TenantContext,
        run_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
    ) -> int:
        if not events:
            raise ValueError("fenced append requires events")
        tenant_id = str(context.tenant_id)
        current = self._leases.get((tenant_id, run_id))
        at = events[0].occurred_at
        if (
            lease.tenant_id != tenant_id
            or lease.work_id != run_id
            or current is None
            or current.token != lease.token
            or current.generation != lease.generation
            or current.expires_at <= at
        ):
            raise FencingError(lease.generation, current.generation if current else 0)
        stream = self._events.get((tenant_id, run_id))
        if stream is None:
            raise ValueError("investigation stream does not exist")
        existing_event_ids = {event.event_id for event in stream}
        existing_keys = {
            event.idempotency_key
            for event in stream
            if event.idempotency_key is not None
        }
        if any(
            event.event_id in existing_event_ids
            or (
                event.idempotency_key is not None
                and event.idempotency_key in existing_keys
            )
            for event in events
        ):
            raise ValueError("duplicate agent event append")
        prepared: list[EventEnvelope] = []
        for event in events:
            if (
                event.tenant_id != tenant_id
                or event.aggregate_id != str(run_id)
                or event.payload.get("lease_token") != str(lease.token)
                or event.payload.get("lease_generation") != lease.generation
            ):
                raise ValueError("event does not match the active investigation fence")
            prepared.append(
                replace(event, aggregate_sequence=len(stream) + len(prepared) + 1)
            )
        candidate = [*stream, *prepared]
        state = replay_investigation(candidate)
        stream.extend(prepared)
        self._project(tenant_id, run_id, state)
        return len(stream)

    async def status(
        self,
        context: TenantContext,
        run_id: UUID,
    ) -> Mapping[str, JsonValue] | None:
        return self._run_projection.get((str(context.tenant_id), run_id))

    async def task_page(
        self,
        context: TenantContext,
        run_id: UUID,
        *,
        after_ordinal: int = -1,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        _page_limit(limit)
        items = tuple(
            item
            for item in self._task_projection.get((str(context.tenant_id), run_id), ())
            if int(str(item["ordinal"])) > after_ordinal
        )
        page = items[:limit]
        next_cursor = (
            int(str(page[-1]["ordinal"])) if len(items) > len(page) and page else None
        )
        return page, next_cursor

    async def artifact_page(
        self,
        context: TenantContext,
        run_id: UUID,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        _page_limit(limit)
        items = tuple(
            item
            for item in self._artifact_projection.get(
                (str(context.tenant_id), run_id), ()
            )
            if int(str(item["position"])) > after_position
        )
        page = items[:limit]
        next_cursor = (
            int(str(page[-1]["position"])) if len(items) > len(page) and page else None
        )
        return page, next_cursor

    def _project(
        self,
        tenant_id: str,
        run_id: UUID,
        state: InvestigationState,
    ) -> None:
        key = (tenant_id, run_id)
        self._run_projection[key] = {
            "run_id": str(run_id),
            "incident_id": state.plan.incident_id,
            "plan_id": str(state.plan.plan_id),
            "plan_digest": state.plan.digest,
            "status": state.status.value,
            "version": state.version,
            "used_tokens": state.used_tokens,
            "reserved_tokens": state.reserved_tokens,
            "used_cost_usd": str(state.used_cost_usd),
            "reserved_cost_usd": str(state.reserved_cost_usd),
            "final_artifact_id": (
                str(state.final_artifact_id)
                if state.final_artifact_id is not None
                else None
            ),
            "terminal_reason": state.terminal_reason,
        }
        self._task_projection[key] = tuple(
            {
                "assignment_id": str(assignment.assignment_id),
                "ordinal": assignment.ordinal,
                "role": assignment.role.value,
                "status": state.tasks[assignment.assignment_id].status.value,
                "attempts": state.tasks[assignment.assignment_id].attempts,
                "used_tokens": state.tasks[assignment.assignment_id].used_tokens,
                "used_cost_usd": str(
                    state.tasks[assignment.assignment_id].used_cost_usd
                ),
                "artifact_count": len(
                    state.tasks[assignment.assignment_id].artifact_ids
                ),
                "last_error_code": (
                    state.tasks[assignment.assignment_id].last_error_code
                ),
            }
            for assignment in state.plan.assignments
        )
        self._artifact_projection[key] = tuple(
            {
                "position": position,
                "artifact_id": str(artifact.artifact_id),
                "task_id": str(artifact.task_id),
                "kind": artifact_kind(artifact).value,
                "role": artifact.produced_by.value,
                "summary": artifact_summary(artifact),
                "confidence": artifact_confidence(artifact),
                "citation_ids": tuple(
                    citation.evidence_id for citation in artifact.citations
                ),
                "created_at": artifact.created_at.isoformat(),
                "schema_version": artifact.schema_version,
                "redacted": True,
            }
            for position, artifact in enumerate(state.artifacts, start=1)
        )


def _request_fingerprint(request: WorkRequest) -> str:
    value = json.dumps(
        {
            "work_kind": request.work_kind,
            "payload": thaw_json(request.payload),
            "timeout_seconds": request.timeout_seconds,
            "max_attempts": request.max_attempts,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(value.encode()).hexdigest()


def _page_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("page limit must be between 1 and 100")


__all__ = [
    "AgentRepository",
    "InMemoryAgentRepository",
    "InvestigationIdempotencyConflictError",
    "InvestigationRequestResult",
]
