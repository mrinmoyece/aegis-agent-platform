"""Rebuildable projection contracts and deterministic replay coordinator."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from aegis_agent_platform.domain import EventEnvelope
from aegis_agent_platform.event_store import EventStore, ReplayCorruptionError
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class ProjectionCheckpoint:
    """Monotonic cursor for one disposable tenant projection."""

    projection_name: str
    last_global_position: int


_BUDGET_PROJECTIONS = frozenset({"model-usage"})
"""Projections whose rows drive budget admission and require rebuild isolation."""


class ProjectionRepository(Protocol):
    """Atomic read-model writer; implementations are never authoritative."""

    async def checkpoint(
        self, context: TenantContext, projection_name: str
    ) -> ProjectionCheckpoint:
        """Return the durable checkpoint, or position zero when absent."""
        ...

    async def apply(
        self,
        context: TenantContext,
        projection_name: str,
        events: Sequence[EventEnvelope],
        *,
        expected_checkpoint: int,
    ) -> int:
        """Idempotently apply events and advance the checkpoint atomically."""
        ...

    async def reset(self, context: TenantContext, projection_name: str) -> None:
        """Delete one tenant's disposable view and checkpoint."""
        ...

    async def begin_rebuild(self, context: TenantContext, projection_name: str) -> None:
        """Acquire an exclusive maintenance lock before reset+catch-up.

        For budget-admission projections (e.g. ``model-usage``) the
        implementation MUST hold a distributed lock for the duration of the
        rebuild so that concurrent admission queries fail closed rather than
        observing the empty view produced by ``reset``.
        """
        ...

    async def end_rebuild(self, context: TenantContext, projection_name: str) -> None:
        """Release the maintenance lock acquired by ``begin_rebuild``."""
        ...


class ProjectionEngine:
    """Replay global tenant history into an idempotent projection."""

    def __init__(
        self,
        event_store: EventStore,
        repository: ProjectionRepository,
        *,
        page_size: int = 100,
    ) -> None:
        if not 1 <= page_size <= 1_000:
            raise ValueError("projection page_size must be between 1 and 1000")
        self._event_store = event_store
        self._repository = repository
        self._page_size = page_size

    async def catch_up(
        self, context: TenantContext, projection_name: str
    ) -> ProjectionCheckpoint:
        """Apply committed events from the current checkpoint."""
        checkpoint = await self._repository.checkpoint(context, projection_name)
        cursor = checkpoint.last_global_position
        aggregate_versions: dict[str, int] = {}
        while True:
            page = await self._event_store.read_all(
                context,
                after_position=cursor,
                limit=self._page_size,
            )
            if not page.events:
                return ProjectionCheckpoint(projection_name, cursor)
            _validate_page(page.events, cursor, aggregate_versions)
            cursor = await self._repository.apply(
                context,
                projection_name,
                page.events,
                expected_checkpoint=cursor,
            )
            if page.next_cursor is None:
                return ProjectionCheckpoint(projection_name, cursor)

    async def rebuild(
        self, context: TenantContext, projection_name: str
    ) -> ProjectionCheckpoint:
        """Discard and deterministically recreate one tenant projection.

        For budget-admission projections (``model-usage``) this method holds a
        distributed maintenance lock for the entire reset→catch-up window so
        that concurrent admission queries fail closed instead of observing the
        empty view exposed between the two transactions.
        """
        if projection_name in _BUDGET_PROJECTIONS:
            await self._repository.begin_rebuild(context, projection_name)
        try:
            await self._repository.reset(context, projection_name)
            return await self.catch_up(context, projection_name)
        finally:
            if projection_name in _BUDGET_PROJECTIONS:
                await self._repository.end_rebuild(context, projection_name)


def _validate_page(
    events: Sequence[EventEnvelope],
    cursor: int,
    aggregate_versions: dict[str, int],
) -> None:
    positions = [event.global_position for event in events]
    if any(position is None for position in positions):
        raise ReplayCorruptionError("projection replay requires global positions")
    numeric_positions = [position for position in positions if position is not None]
    if numeric_positions != sorted(set(numeric_positions)):
        raise ReplayCorruptionError("global event positions are not strictly monotonic")
    if numeric_positions and numeric_positions[0] <= cursor:
        raise ReplayCorruptionError("projection page overlaps its checkpoint")

    for event in events:
        previous = aggregate_versions.get(
            event.aggregate_id, event.previous_aggregate_sequence
        )
        if previous is not None and event.aggregate_sequence != previous + 1:
            raise ReplayCorruptionError("aggregate sequence gap detected during replay")
        aggregate_versions[event.aggregate_id] = event.aggregate_sequence


__all__ = ["ProjectionCheckpoint", "ProjectionEngine", "ProjectionRepository"]
