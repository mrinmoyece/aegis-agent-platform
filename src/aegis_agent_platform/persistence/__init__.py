"""Production persistence adapters live outside deterministic domain packages."""

from aegis_agent_platform.persistence.postgres import (
    PostgresAuditStore,
    PostgresIdentityDirectory,
    PostgresPolicyRepository,
    PostgresTenantRepository,
)

__all__ = [
    "PostgresAuditStore",
    "PostgresIdentityDirectory",
    "PostgresPolicyRepository",
    "PostgresTenantRepository",
]
