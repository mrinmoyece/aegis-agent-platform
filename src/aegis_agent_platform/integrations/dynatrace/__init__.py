"""Read-only Dynatrace evidence contract for future adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.tenancy import TenantContext


class SignalKind(StrEnum):
    """Dynatrace evidence classes used during incident correlation."""

    LOG = "log"
    TRACE = "trace"
    METRIC = "metric"
    TOPOLOGY = "topology"
    PROBLEM = "problem"
    EVENT = "event"


@dataclass(frozen=True, slots=True)
class TelemetryEvidence:
    """Normalized evidence with an immutable vendor reference."""

    reference: str
    kind: SignalKind
    observed_at: datetime
    summary: str
    attributes: Mapping[str, JsonValue]


class DynatraceEvidenceReader(Protocol):
    """Tenant-scoped read port; implementations arrive in a later layer."""

    async def collect(
        self,
        *,
        tenant: TenantContext,
        query: str,
        start: datetime,
        end: datetime,
        kinds: Sequence[SignalKind],
    ) -> Sequence[TelemetryEvidence]:
        """Collect normalized incident evidence for a bounded time window."""
        ...
