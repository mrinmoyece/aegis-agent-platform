"""Append-only event persistence port."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Protocol

from aegis_agent_platform.domain import EventEnvelope


class EventStore(Protocol):
    """Tenant-scoped append and read contract."""

    async def append(
        self,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        """Append events atomically and return the new aggregate version."""
        ...

    def read_stream(
        self,
        tenant_id: str,
        aggregate_id: str,
        *,
        after_version: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        """Read an aggregate stream in committed order."""
        ...
