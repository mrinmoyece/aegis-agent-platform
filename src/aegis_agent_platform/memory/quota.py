"""Atomic tenant memory quotas for nondeterministic and abuse-sensitive work."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from aegis_agent_platform.tenancy import TenantContext


class MemoryQuotaKind(StrEnum):
    INGESTED_BYTES = "ingested_bytes"
    EMBEDDED_TOKENS = "embedded_tokens"
    RETRIEVALS = "retrievals"
    SUMMARY_TOKENS = "summary_tokens"


class MemoryQuotaExceededError(RuntimeError):
    """A tenant reached a hard policy-derived memory budget."""

    def __init__(self, kind: MemoryQuotaKind) -> None:
        super().__init__(f"memory_{kind.value}_quota_exhausted")
        self.kind = kind


@dataclass(frozen=True, slots=True)
class MemoryQuotaLimits:
    max_ingested_bytes: int = 10_000_000
    max_embedded_tokens: int = 1_000_000
    max_retrievals: int = 10_000
    max_summary_tokens: int = 1_000_000

    def __post_init__(self) -> None:
        if any(
            value < 1
            for value in (
                self.max_ingested_bytes,
                self.max_embedded_tokens,
                self.max_retrievals,
                self.max_summary_tokens,
            )
        ):
            raise ValueError("memory quota limits must be positive")

    def limit(self, kind: MemoryQuotaKind) -> int:
        return {
            MemoryQuotaKind.INGESTED_BYTES: self.max_ingested_bytes,
            MemoryQuotaKind.EMBEDDED_TOKENS: self.max_embedded_tokens,
            MemoryQuotaKind.RETRIEVALS: self.max_retrievals,
            MemoryQuotaKind.SUMMARY_TOKENS: self.max_summary_tokens,
        }[kind]


class MemoryQuota(Protocol):
    async def reserve(
        self,
        context: TenantContext,
        kind: MemoryQuotaKind,
        amount: int,
        *,
        at: datetime,
    ) -> int: ...


class InMemoryMemoryQuota(MemoryQuota):
    """Race-safe deterministic quota authority for tests and local execution."""

    def __init__(self, limits: MemoryQuotaLimits | None = None) -> None:
        self._limits = limits or MemoryQuotaLimits()
        self._usage: dict[tuple[str, str, MemoryQuotaKind], int] = {}
        self._lock = asyncio.Lock()

    async def reserve(
        self,
        context: TenantContext,
        kind: MemoryQuotaKind,
        amount: int,
        *,
        at: datetime,
    ) -> int:
        _validate(amount, at)
        key = (str(context.tenant_id), at.date().isoformat(), kind)
        async with self._lock:
            updated = self._usage.get(key, 0) + amount
            if updated > self._limits.limit(kind):
                raise MemoryQuotaExceededError(kind)
            self._usage[key] = updated
            return updated


def _validate(amount: int, at: datetime) -> None:
    if amount < 1:
        raise ValueError("memory quota reservation must be positive")
    if at.tzinfo is None:
        raise ValueError("memory quota timestamp must be timezone-aware")


__all__ = [
    "InMemoryMemoryQuota",
    "MemoryQuota",
    "MemoryQuotaExceededError",
    "MemoryQuotaKind",
    "MemoryQuotaLimits",
]
