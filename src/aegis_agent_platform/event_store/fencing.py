"""Trusted tenant-scoped writer-fence credential adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.operations import WriterFence
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class TenantWriterFenceResolver:
    """Resolve credentials without inferring a tenant from mutable payload data."""

    fences: Mapping[TenantId, WriterFence]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fences", MappingProxyType(dict(self.fences)))

    def resolve(self, context: TenantContext) -> WriterFence:
        """Fail closed when the trusted tenant has no deployment credential."""
        fence = self.fences.get(context.tenant_id)
        if fence is None:
            raise FencingError(expected=1, actual=0)
        return fence

    @classmethod
    def from_json_file(cls, path: Path) -> TenantWriterFenceResolver:
        """Load an externally mounted credential map during process startup."""
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not document:
            raise ValueError("writer fence document must be a non-empty object")
        fences: dict[TenantId, WriterFence] = {}
        for tenant, raw_fence in document.items():
            if not isinstance(tenant, str) or not isinstance(raw_fence, dict):
                raise ValueError("writer fence entries must map tenant IDs to objects")
            region = raw_fence.get("home_region")
            generation = raw_fence.get("generation")
            if not isinstance(region, str) or not isinstance(generation, int):
                raise ValueError("writer fence entries require region and generation")
            fences[TenantId(tenant)] = WriterFence(
                home_region=region,
                generation=generation,
            )
        return cls(fences=fences)


@dataclass(frozen=True, slots=True)
class ReloadingTenantWriterFenceResolver:
    """Resolve every append against the latest atomically mounted secret file."""

    path: Path

    @property
    def fences(self) -> Mapping[TenantId, WriterFence]:
        """Return a validated point-in-time credential snapshot."""
        return TenantWriterFenceResolver.from_json_file(self.path).fences

    def resolve(self, context: TenantContext) -> WriterFence:
        """Reload the credential map so rotation does not retain stale authority."""
        return TenantWriterFenceResolver.from_json_file(self.path).resolve(context)


__all__ = [
    "ReloadingTenantWriterFenceResolver",
    "TenantWriterFenceResolver",
]
