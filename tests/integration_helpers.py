"""Typed helpers shared by disposable integration tests."""

from aegis_agent_platform.event_store.fencing import TenantWriterFenceResolver
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.operations import WriterFence


def integration_writer_fences(
    home_region: str,
    generation: int,
) -> TenantWriterFenceResolver:
    """Return tenant-scoped credentials for the disposable integration tenants."""
    return TenantWriterFenceResolver(
        fences={
            TenantId(tenant): WriterFence(home_region, generation)
            for tenant in ("tenant-a", "tenant-b", "tenant-remediation")
        }
    )


__all__ = ["integration_writer_fences"]
