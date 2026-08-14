"""Ledger-first protocol operation repository with worker fencing."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import (
    EventEnvelope,
    ProtocolOperationState,
    WorkLease,
    replay_protocol_operation,
)
from aegis_agent_platform.event_store import ConcurrencyError, FencingError
from aegis_agent_platform.tenancy import TenantContext


class ProtocolLedger(Protocol):
    async def append(
        self,
        context: TenantContext,
        operation_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        lease: WorkLease | None = None,
    ) -> int: ...

    async def load(
        self,
        context: TenantContext,
        operation_id: UUID,
    ) -> tuple[EventEnvelope, ...]: ...

    async def by_idempotency_key(
        self,
        context: TenantContext,
        idempotency_key: str,
    ) -> ProtocolOperationState | None: ...

    async def page(
        self,
        context: TenantContext,
        *,
        after_operation_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[ProtocolOperationState, ...], UUID | None]: ...


class InMemoryProtocolLedger:
    """Deterministic event truth with optimistic concurrency and stale fences."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._events: dict[tuple[str, UUID], list[EventEnvelope]] = {}
        self._idempotency: dict[tuple[str, str], UUID] = {}
        self._leases: dict[tuple[str, UUID], WorkLease] = {}
        self._global_position = 0

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(event for events in self._events.values() for event in events)

    def register_lease(self, lease: WorkLease) -> None:
        self._leases[(lease.tenant_id, lease.work_id)] = lease

    async def append(
        self,
        context: TenantContext,
        operation_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        lease: WorkLease | None = None,
    ) -> int:
        if not events:
            raise ValueError("protocol append requires events")
        tenant_id = str(context.tenant_id)
        if any(
            event.tenant_id != tenant_id or event.aggregate_id != str(operation_id)
            for event in events
        ):
            raise PermissionError("cross_tenant_protocol_event")
        async with self._lock:
            stream = self._events.setdefault((tenant_id, operation_id), [])
            if len(stream) != expected_version:
                raise ConcurrencyError(expected_version, len(stream))
            event_keys = {
                event.idempotency_key
                for event in events
                if event.idempotency_key is not None
            }
            for idempotency_key in event_keys:
                existing = self._idempotency.get((tenant_id, idempotency_key))
                if existing is not None and existing != operation_id:
                    raise ConcurrencyError(expected_version, len(stream))
            if lease is not None:
                current = self._leases.get((tenant_id, lease.work_id))
                if current != lease or lease.expires_at <= events[0].occurred_at:
                    raise FencingError(
                        lease.generation,
                        current.generation if current else 0,
                    )
                if any(
                    event.payload.get("lease_token") != str(lease.token)
                    or event.payload.get("lease_generation") != lease.generation
                    for event in events
                ):
                    raise FencingError(lease.generation, 0)
            for event in events:
                self._global_position += 1
                positioned = replace(
                    event,
                    global_position=self._global_position,
                    recorded_at=event.occurred_at,
                    aggregate_sequence=len(stream) + 1,
                )
                stream.append(positioned)
                if positioned.idempotency_key is not None:
                    key = (tenant_id, positioned.idempotency_key)
                    self._idempotency[key] = operation_id
            return len(stream)

    async def load(
        self,
        context: TenantContext,
        operation_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        return tuple(self._events.get((str(context.tenant_id), operation_id), ()))

    async def by_idempotency_key(
        self,
        context: TenantContext,
        idempotency_key: str,
    ) -> ProtocolOperationState | None:
        operation_id = self._idempotency.get((str(context.tenant_id), idempotency_key))
        if operation_id is None:
            return None
        return replay_protocol_operation(await self.load(context, operation_id))

    async def page(
        self,
        context: TenantContext,
        *,
        after_operation_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[ProtocolOperationState, ...], UUID | None]:
        if not 1 <= limit <= 100:
            raise ValueError("protocol operation page limit is invalid")
        tenant_id = str(context.tenant_id)
        ids = tuple(
            operation_id
            for (candidate_tenant, operation_id) in sorted(
                self._events,
                key=lambda item: str(item[1]),
            )
            if candidate_tenant == tenant_id
            and (
                after_operation_id is None or operation_id.int > after_operation_id.int
            )
        )
        page_ids = ids[:limit]
        states = tuple(
            replay_protocol_operation(self._events[(tenant_id, operation_id)])
            for operation_id in page_ids
        )
        cursor = page_ids[-1] if len(ids) > limit else None
        return states, cursor
