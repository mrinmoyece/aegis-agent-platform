"""Append-only event persistence contracts."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import EventEnvelope, JsonValue
from aegis_agent_platform.operations import WriterFence
from aegis_agent_platform.tenancy import TenantContext


class StorageError(Exception):
    """Base class for secret-safe, classified storage failures."""


class TransientStorageError(StorageError):
    """A retryable connectivity, serialization, or availability failure."""


class PermanentStorageError(StorageError):
    """A non-retryable schema, validation, or integrity failure."""


class ConcurrencyError(PermanentStorageError):
    """The aggregate version changed before an append committed."""

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"optimistic concurrency conflict: expected {expected}, actual {actual}"
        )
        self.expected = expected
        self.actual = actual


class ReplayCorruptionError(PermanentStorageError):
    """Committed ordering violates the gapless aggregate contract."""


class FencingError(ConcurrencyError):
    """A worker write used a stale, released, or expired lease token."""


class OutboxStatus(StrEnum):
    """Delivery projection states; event history remains authoritative."""

    PENDING = "pending"
    LEASED = "leased"
    PUBLISHED = "published"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    """Outgoing delivery committed atomically with its causing events."""

    message_id: UUID
    destination: str
    payload: Mapping[str, JsonValue]
    headers: Mapping[str, JsonValue]
    available_at: datetime
    max_attempts: int = 8
    event_id: UUID | None = None

    def __post_init__(self) -> None:
        if not self.destination:
            raise ValueError("outbox destination is required")
        if self.available_at.tzinfo is None:
            raise ValueError("outbox available_at must be timezone-aware")
        if self.max_attempts < 1:
            raise ValueError("outbox max_attempts must be positive")


@dataclass(frozen=True, slots=True)
class ClaimedOutboxMessage:
    """Leased outbox row returned to one publisher."""

    message: OutboxMessage
    attempt_count: int
    lease_owner: str
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class EventPage:
    """Bounded deterministic page in global commit order."""

    events: tuple[EventEnvelope, ...]
    next_cursor: int | None


@dataclass(frozen=True, slots=True)
class AppendResult:
    """Result of a normal or inbox-deduplicated append."""

    aggregate_version: int
    duplicate: bool = False


class EventStore(Protocol):
    """Tenant-scoped append, replay, and delivery contract."""

    async def append(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> int:
        """Append one aggregate batch and outgoing work atomically."""
        ...

    async def append_from_inbox(
        self,
        context: TenantContext,
        *,
        source: str,
        message_id: str,
        events: Sequence[EventEnvelope],
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> AppendResult:
        """Deduplicate one delivery and atomically commit resulting work."""
        ...

    def read_stream(
        self,
        context: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
        limit: int = 100,
    ) -> AsyncIterator[EventEnvelope]:
        """Read one aggregate in gapless committed order."""
        ...

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        """Read a bounded tenant page in global commit order."""
        ...


class WriterFenceResolver(Protocol):
    """Resolve deployment credentials from the trusted tenant context."""

    def resolve(self, context: TenantContext) -> WriterFence:
        """Return the tenant credential or fail closed."""
        ...


__all__ = [
    "AppendResult",
    "ClaimedOutboxMessage",
    "ConcurrencyError",
    "EventPage",
    "EventStore",
    "FencingError",
    "OutboxMessage",
    "OutboxStatus",
    "PermanentStorageError",
    "ReplayCorruptionError",
    "StorageError",
    "TransientStorageError",
    "WriterFenceResolver",
]
