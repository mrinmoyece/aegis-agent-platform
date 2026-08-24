"""Provider-neutral at-least-once delivery contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.domain.events import freeze_json_mapping
from aegis_agent_platform.tenancy import TenantContext


class QueueError(Exception):
    """Base secret-safe queue failure."""


class RetryableQueueError(QueueError):
    """Transport availability failure that may be retried."""


class PermanentQueueError(QueueError):
    """Invalid envelope or operation that must not be retried."""


class PoisonMessageError(PermanentQueueError):
    """Delivery cannot be safely deserialized and must be quarantined."""


@dataclass(frozen=True, slots=True)
class MessageEnvelope:
    """Tenant-bound transport envelope with deterministic message identity."""

    message_id: UUID
    tenant_id: str
    work_id: UUID
    event_id: UUID | None
    destination: str
    correlation_id: UUID
    causation_id: UUID | None
    occurred_at: datetime
    payload: Mapping[str, JsonValue]
    headers: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.destination:
            raise ValueError("message tenant and destination are required")
        if self.occurred_at.tzinfo is None:
            raise ValueError("message occurred_at must be timezone-aware")
        if self.schema_version != 1:
            raise ValueError("unsupported message schema version")
        object.__setattr__(self, "payload", freeze_json_mapping(self.payload))
        object.__setattr__(self, "headers", freeze_json_mapping(self.headers))


@dataclass(frozen=True, slots=True)
class QueueDelivery:
    """One explicit-ack delivery from a consumer group."""

    stream_entry_id: str
    envelope: MessageEnvelope
    delivery_count: int
    idle_milliseconds: int

    def __post_init__(self) -> None:
        if not self.stream_entry_id:
            raise ValueError("stream entry id is required")
        if self.delivery_count < 1 or self.idle_milliseconds < 0:
            raise ValueError("invalid delivery metadata")


@dataclass(frozen=True, slots=True)
class PendingEntry:
    """Bounded pending-entry-list inspection result."""

    stream_entry_id: str
    consumer: str
    idle_milliseconds: int
    delivery_count: int


class WorkQueue(Protocol):
    """At-least-once transport port; PostgreSQL remains authoritative."""

    async def publish(self, envelope: MessageEnvelope) -> str:
        """Publish an envelope and return its transport entry identifier."""
        ...

    async def read(
        self,
        *,
        consumer: str,
        count: int,
        block_milliseconds: int,
    ) -> tuple[QueueDelivery, ...]:
        """Read new messages for one consumer group."""
        ...

    async def acknowledge(self, delivery: QueueDelivery) -> None:
        """Explicitly acknowledge only after durable inbox/outcome commit."""
        ...

    async def quarantine(
        self,
        delivery: QueueDelivery,
        *,
        reason_code: str,
    ) -> None:
        """Record payload-free rejection evidence and remove one poison entry."""
        ...

    async def pending(
        self,
        *,
        count: int,
        minimum_idle_milliseconds: int = 0,
    ) -> tuple[PendingEntry, ...]:
        """Inspect a bounded pending page."""
        ...

    async def reclaim(
        self,
        *,
        consumer: str,
        minimum_idle_milliseconds: int,
        count: int,
    ) -> tuple[QueueDelivery, ...]:
        """Claim bounded orphaned pending entries after an idle threshold."""
        ...

    async def health(self) -> bool:
        """Return transport reachability without claiming correctness."""
        ...


class OutboxRepository(Protocol):
    """Layer 3 outbox operations used by the publisher."""

    async def claim_outbox(
        self,
        context: TenantContext,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        now: datetime,
        limit: int,
        destination: str | None = None,
    ) -> Sequence[object]:
        """Claim a bounded batch."""
        ...

    async def mark_outbox_published(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        published_at: datetime,
    ) -> None:
        """Acknowledge publication under the current database lease."""
        ...

    async def mark_outbox_failed(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        retry_at: datetime,
        error_code: str,
    ) -> None:
        """Release or dead-letter a failed publication."""
        ...


@dataclass(frozen=True, slots=True)
class Lease:
    """Time-bounded, tenant-scoped claim contract for at-least-once delivery."""

    lease_id: UUID
    tenant_id: str
    work_id: UUID
    expires_at: datetime
    attempt: int
    fence: int

    def __post_init__(self) -> None:
        if not self.tenant_id.strip():
            raise ValueError("tenant_id is required")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        if self.attempt < 1 or self.fence < 1:
            raise ValueError("attempt and fence must be positive")


__all__ = [
    "Lease",
    "MessageEnvelope",
    "OutboxRepository",
    "PendingEntry",
    "PermanentQueueError",
    "PoisonMessageError",
    "QueueDelivery",
    "QueueError",
    "RetryableQueueError",
    "WorkQueue",
]
