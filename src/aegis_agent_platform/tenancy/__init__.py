"""Tenant context and tenant-scoped repository contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from aegis_agent_platform.identity.models import TenantId


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Validated tenant identity propagated across every operation."""

    tenant_id: TenantId

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, TenantId):
            raise ValueError("tenant_id must be a TenantId")


@dataclass(frozen=True, slots=True)
class Tenant:
    """Immutable tenant record."""

    tenant_id: TenantId
    display_name: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.display_name.strip():
            raise ValueError("display_name is required")


class TenantRepository(Protocol):
    """Tenant store that requires an explicit trusted tenant context."""

    def get(self, context: TenantContext) -> Tenant | None:
        """Return only the tenant named by the supplied context."""
        ...


class InMemoryTenantRepository:
    """Deterministic tenant-scoped store; never accepts a payload tenant."""

    def __init__(self, tenants: tuple[Tenant, ...]) -> None:
        self._tenants: dict[TenantId, Tenant] = {}
        for tenant in tenants:
            if tenant.tenant_id in self._tenants:
                raise ValueError("duplicate tenant records are not allowed")
            self._tenants[tenant.tenant_id] = tenant

    def get(self, context: TenantContext) -> Tenant | None:
        return self._tenants.get(context.tenant_id)


__all__ = [
    "InMemoryTenantRepository",
    "Tenant",
    "TenantContext",
    "TenantRepository",
]
