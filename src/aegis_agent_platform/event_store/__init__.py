"""Append-only event persistence port."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Protocol

from aegis_agent_platform.domain import EventEnvelope
from aegis_agent_platform.tenancy import TenantContext


class EventStore(Protocol):
    """Tenant-scoped append and read contract."""

    async def append(
        self,
        tenant: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        """Append one tenant's events atomically.

        Implementations must reject envelopes whose tenant ID does not match the
        validated context and return the new aggregate version.
        """
        ...

    def read_stream(
        self,
        tenant: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        """Read an aggregate stream in committed order."""
        ...
