"""Tenant context contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Validated tenant identity propagated across every operation."""

    tenant_id: str

    def __post_init__(self) -> None:
        """Reject absent tenant context at the boundary."""
        if not self.tenant_id.strip():
            raise ValueError("tenant_id is required")
