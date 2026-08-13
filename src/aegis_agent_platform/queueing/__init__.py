"""Queue and recoverable lease contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class Lease:
    """A time-bounded, tenant-scoped claim on durable work."""

    lease_id: UUID
    tenant_id: str
    work_id: UUID
    expires_at: datetime
    attempt: int
    fence: int


class LeaseQueue(Protocol):
    """Port implemented by a durable queue adapter in a later layer."""

    async def acquire(
        self,
        worker_id: str,
        tenant: TenantContext,
    ) -> Lease | None:
        """Acquire available work without granting concurrent ownership."""
        ...

    async def renew(self, lease: Lease, *, extend_until: datetime) -> Lease:
        """Renew an active lease and return its current fencing token."""
        ...

    async def acknowledge(self, lease: Lease) -> None:
        """Acknowledge completed work using the active lease token."""
        ...

    async def release(self, lease: Lease, *, reason: str) -> None:
        """Release unfinished work with an auditable reason."""
        ...
