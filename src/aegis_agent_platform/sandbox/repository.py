"""Ledger-first sandbox repository port and deterministic in-memory adapter."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    SandboxState,
    SandboxStatus,
    WorkLease,
    WorkRequest,
    WorkTransition,
    replay_sandbox,
    thaw_json,
)
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    FencingError,
    OutboxMessage,
)
from aegis_agent_platform.sandbox.policy import SandboxQuotaUsage
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class SandboxRequestResult:
    created: bool
    sandbox_id: UUID


class SandboxIdempotencyConflictError(ValueError):
    """Tenant idempotency key was rebound to different immutable content."""


class SandboxRepository(Protocol):
    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        sandbox_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> SandboxRequestResult: ...

    async def load(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> tuple[EventEnvelope, ...]: ...

    async def append(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int: ...

    async def append_fenced(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int: ...

    async def assert_fence(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None: ...

    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> SandboxQuotaUsage: ...

    async def page(
        self,
        context: TenantContext,
        *,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]: ...

    async def artifact_page(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]: ...

    async def cleanup_page(
        self,
        context: TenantContext,
        *,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]: ...

    async def rebuild_projection(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> None: ...


class InMemorySandboxRepository(SandboxRepository):
    """Race-safe event truth with disposable tenant-scoped projections."""

    def __init__(self, *, uuid_factory: Callable[[], UUID] = uuid4) -> None:
        self._uuid_factory = uuid_factory
        self._lock = asyncio.Lock()
        self._events: dict[tuple[str, UUID], list[EventEnvelope]] = {}
        self._requests: dict[tuple[str, str], tuple[UUID, str]] = {}
        self._leases: dict[tuple[str, UUID], WorkLease] = {}
        self._projection: dict[tuple[str, UUID], Mapping[str, JsonValue]] = {}
        self.outbox: list[OutboxMessage] = []

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(
            event
            for key in sorted(self._events, key=lambda item: (item[0], str(item[1])))
            for event in self._events[key]
        )

    @property
    def projections(self) -> Mapping[tuple[str, UUID], Mapping[str, JsonValue]]:
        return MappingProxyType(dict(self._projection))

    def register_lease(self, lease: WorkLease) -> None:
        self._leases[(lease.tenant_id, lease.work_id)] = lease

    def replace_lease(self, lease: WorkLease) -> None:
        self.register_lease(lease)

    def clear_projections(self) -> None:
        self._projection.clear()

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        sandbox_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> SandboxRequestResult:
        tenant_id = str(context.tenant_id)
        if request.tenant_id != tenant_id or request.work_id.int == 0:
            raise PermissionError("cross_tenant_sandbox_request")
        fingerprint = _request_fingerprint(request)
        key = (tenant_id, request.idempotency_key)
        async with self._lock:
            existing = self._requests.get(key)
            if existing is not None:
                if existing[1] != fingerprint:
                    raise SandboxIdempotencyConflictError(
                        "sandbox_idempotency_key_reused"
                    )
                return SandboxRequestResult(False, existing[0])
            work_event = WorkTransition(
                DomainEventType.WORK_REQUESTED,
                request.requested_at,
                {
                    "idempotency_key": request.idempotency_key,
                    "max_attempts": request.max_attempts,
                    "request_payload": request.payload,
                    "timeout_seconds": request.timeout_seconds,
                },
            ).to_event(
                request,
                event_id=requested_event_id,
                causation_id=request.causation_id,
            )
            pending = (work_event, *sandbox_events)
            if any(
                event.tenant_id != tenant_id
                or event.aggregate_id != str(request.work_id)
                for event in pending
            ):
                raise ValueError("sandbox events must match the tenant work aggregate")
            prepared = [
                replace(event, aggregate_sequence=position)
                for position, event in enumerate(pending, start=1)
            ]
            state = replay_sandbox(prepared)
            self._events[(tenant_id, request.work_id)] = prepared
            self._requests[key] = (request.work_id, fingerprint)
            self.outbox.append(
                OutboxMessage(
                    message_id=outbox_message_id,
                    event_id=requested_event_id,
                    destination="aegis.work.sandbox",
                    payload={
                        "sandbox_id": str(request.work_id),
                        "tenant_id": tenant_id,
                        "work_kind": request.work_kind,
                    },
                    headers={"schema_version": 1},
                    available_at=request.requested_at,
                    max_attempts=request.max_attempts,
                )
            )
            self._project(state)
            return SandboxRequestResult(True, request.work_id)

    async def load(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        return tuple(self._events.get((str(context.tenant_id), sandbox_id), ()))

    async def append(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if any(_requires_fence(event) for event in events):
            raise FencingError(0, 0)
        async with self._lock:
            return self._append_locked(
                str(context.tenant_id),
                sandbox_id,
                events,
                expected_version=expected_version,
            )

    async def append_fenced(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not events:
            raise ValueError("fenced sandbox append requires events")
        async with self._lock:
            self._assert_fence_locked(
                str(context.tenant_id),
                sandbox_id,
                lease,
                at=events[0].occurred_at,
            )
            if any(
                event.payload.get("lease_token") != str(lease.token)
                or event.payload.get("lease_generation") != lease.generation
                for event in events
            ):
                raise ValueError("sandbox execution event does not match active fence")
            return self._append_locked(
                str(context.tenant_id),
                sandbox_id,
                events,
                expected_version=expected_version,
            )

    async def assert_fence(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        async with self._lock:
            self._assert_fence_locked(
                str(context.tenant_id),
                sandbox_id,
                lease,
                at=at,
            )

    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> SandboxQuotaUsage:
        tenant_id = str(context.tenant_id)
        states = [
            replay_sandbox(events)
            for (row_tenant, _sandbox_id), events in self._events.items()
            if row_tenant == tenant_id
        ]
        period_states = [
            state
            for state in states
            if state.request.requested_at.date() == at.date()
            and state.request.idempotency_key != exclude_idempotency_key
        ]
        active = {
            SandboxStatus.DISPATCHED,
            SandboxStatus.PROVISIONING,
            SandboxStatus.PROVISIONED,
            SandboxStatus.STARTING,
            SandboxStatus.RUNNING,
            SandboxStatus.CANCELLING,
            SandboxStatus.CLEANUP_PENDING,
        }
        return SandboxQuotaUsage(
            runs_in_period=len(period_states),
            active_runs=sum(state.status in active for state in period_states),
            cpu_millis_seconds=sum(
                state.request.spec.resources.cpu_millis
                * state.request.spec.resources.timeout_seconds
                for state in period_states
            ),
            artifact_bytes=sum(
                sum(output.max_bytes for output in state.request.spec.expected_outputs)
                for state in period_states
            ),
        )

    async def page(
        self,
        context: TenantContext,
        *,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        _page_limit(limit)
        tenant_id = str(context.tenant_id)
        rows = tuple(
            value
            for (row_tenant, sandbox_id), value in sorted(
                self._projection.items(),
                key=lambda item: str(item[0][1]),
            )
            if row_tenant == tenant_id
            and (after_sandbox_id is None or str(sandbox_id) > str(after_sandbox_id))
        )
        page = rows[:limit]
        cursor = (
            UUID(str(page[-1]["sandbox_id"])) if len(rows) > limit and page else None
        )
        return page, cursor

    async def artifact_page(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        _page_limit(limit)
        events = await self.load(context, sandbox_id)
        rows = tuple(
            {
                "position": event.aggregate_sequence,
                "artifact_id": event.payload.get("artifact_id"),
                "digest": event.payload.get("digest"),
                "media_type": event.payload.get("media_type"),
                "size_bytes": event.payload.get("size_bytes"),
                "quarantined": event.payload.get("quarantined", False),
                "redacted": True,
            }
            for event in events
            if event.aggregate_sequence > after_position
            and event.event_type == DomainEventType.SANDBOX_ARTIFACT_CAPTURED
        )
        page = rows[:limit]
        position = page[-1]["position"] if page else None
        cursor = (
            position
            if len(rows) > limit
            and isinstance(position, int)
            and not isinstance(position, bool)
            else None
        )
        return page, cursor

    async def cleanup_page(
        self,
        context: TenantContext,
        *,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        rows, cursor = await self.page(
            context,
            after_sandbox_id=after_sandbox_id,
            limit=limit,
        )
        return (
            tuple(
                row
                for row in rows
                if row["status"]
                in {
                    SandboxStatus.CLEANUP_PENDING.value,
                    SandboxStatus.CLEANUP_FAILED.value,
                    SandboxStatus.QUARANTINED.value,
                }
            ),
            cursor,
        )

    async def rebuild_projection(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> None:
        events = await self.load(context, sandbox_id)
        if events:
            self._project(replay_sandbox(events))

    def _append_locked(
        self,
        tenant_id: str,
        sandbox_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if not events:
            raise ValueError("sandbox append requires events")
        stream = self._events.get((tenant_id, sandbox_id))
        if stream is None:
            raise ValueError("sandbox stream does not exist")
        if len(stream) != expected_version:
            raise ConcurrencyError(expected_version, len(stream))
        prepared = [
            replace(event, aggregate_sequence=expected_version + position)
            for position, event in enumerate(events, start=1)
        ]
        state = replay_sandbox((*stream, *prepared))
        stream.extend(prepared)
        self._project(state)
        return len(stream)

    def _assert_fence_locked(
        self,
        tenant_id: str,
        sandbox_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        current = self._leases.get((tenant_id, sandbox_id))
        if (
            lease.tenant_id != tenant_id
            or lease.work_id != sandbox_id
            or current is None
            or current.token != lease.token
            or current.generation != lease.generation
            or current.expires_at <= at
        ):
            raise FencingError(
                lease.generation,
                current.generation if current is not None else 0,
            )

    def _project(self, state: SandboxState) -> None:
        request = state.request
        self._projection[(request.linkage.tenant_id, request.sandbox_id)] = (
            MappingProxyType(
                {
                    "sandbox_id": str(request.sandbox_id),
                    "run_id": str(request.linkage.run_id),
                    "task_id": str(request.linkage.task_id),
                    "remediation_plan_id": str(request.linkage.remediation_plan_id),
                    "remediation_action_id": str(request.linkage.remediation_action_id),
                    "approval_id": str(request.linkage.approval_id),
                    "purpose": request.purpose.value,
                    "risk": int(request.risk),
                    "spec_digest": request.spec.digest,
                    "image_digest": request.spec.image_digest,
                    "policy_digest": state.policy_digest,
                    "approval_scope_digest": state.approval_scope_digest,
                    "status": state.status.value,
                    "version": state.version,
                    "cleanup_attempts": state.cleanup_attempts,
                    "quarantined": state.quarantine_reason is not None,
                    "requested_at": request.requested_at.isoformat(),
                    "redacted": True,
                }
            )
        )


def _requires_fence(event: EventEnvelope) -> bool:
    return event.event_type in {
        DomainEventType.SANDBOX_DISPATCH_CLAIMED,
        DomainEventType.SANDBOX_PROVISIONING_REQUESTED,
        DomainEventType.SANDBOX_PROVISIONED,
        DomainEventType.SANDBOX_START_REQUESTED,
        DomainEventType.SANDBOX_STARTED,
        DomainEventType.SANDBOX_OUTPUT_CAPTURED,
        DomainEventType.SANDBOX_ARTIFACT_CAPTURED,
        DomainEventType.SANDBOX_COMPLETED,
        DomainEventType.SANDBOX_FAILED,
        DomainEventType.SANDBOX_TIMED_OUT,
        DomainEventType.SANDBOX_OOM_KILLED,
        DomainEventType.SANDBOX_POLICY_VIOLATION,
        DomainEventType.SANDBOX_CANCELLATION_REQUESTED,
        DomainEventType.SANDBOX_CANCELLED,
        DomainEventType.SANDBOX_ATTESTED,
        DomainEventType.SANDBOX_CLEANUP_REQUESTED,
        DomainEventType.SANDBOX_CLEANUP_COMPLETED,
        DomainEventType.SANDBOX_CLEANUP_FAILED,
        DomainEventType.SANDBOX_QUARANTINED,
        DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
        DomainEventType.SANDBOX_RECONCILED,
    }


def _request_fingerprint(request: WorkRequest) -> str:
    payload = json.dumps(
        thaw_json(request.payload),
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(
        (
            f"{request.tenant_id}|{request.work_id}|{request.work_kind}|"
            f"{request.timeout_seconds}|{payload}"
        ).encode()
    ).hexdigest()


def _page_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("sandbox page limit must be between 1 and 100")


__all__ = [
    "InMemorySandboxRepository",
    "SandboxIdempotencyConflictError",
    "SandboxRepository",
    "SandboxRequestResult",
]
