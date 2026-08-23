"""Deterministic fault injection at explicit durable-execution cut points."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FaultCutPoint(StrEnum):
    """Named barriers around durable intents, effects, delivery, and derived state."""

    BEFORE_INTENT_APPEND = "before_intent_append"
    AFTER_INTENT_APPEND = "after_intent_append"
    BEFORE_SIDE_EFFECT = "before_side_effect"
    AFTER_SIDE_EFFECT = "after_side_effect"
    BEFORE_RESULT_APPEND = "before_result_append"
    AFTER_RESULT_APPEND = "after_result_append"
    BEFORE_PROJECTION_UPDATE = "before_projection_update"
    AFTER_PROJECTION_UPDATE = "after_projection_update"
    BEFORE_QUEUE_DELIVERY = "before_queue_delivery"
    AFTER_QUEUE_DELIVERY = "after_queue_delivery"
    BEFORE_QUEUE_ACK = "before_queue_ack"
    AFTER_QUEUE_ACK = "after_queue_ack"
    LEASE_EXPIRY = "lease_expiry"
    PROVIDER_TIMEOUT = "provider_timeout"
    CONNECTOR_PAGE = "connector_page"
    CONNECTOR_CURSOR = "connector_cursor"
    ACTION_AMBIGUITY = "action_ambiguity"
    SANDBOX_PROVISION = "sandbox_provision"
    SANDBOX_DELETE = "sandbox_delete"
    MEMORY_EMBEDDING = "memory_embedding"
    MEMORY_INDEXING = "memory_indexing"
    MEMORY_CACHE = "memory_cache"


class FaultAction(StrEnum):
    """Controlled outcome injected when a cut point is reached."""

    RAISE = "raise"
    CANCEL = "cancel"
    TIMEOUT = "timeout"
    AMBIGUOUS = "ambiguous"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class FaultPlan:
    """One exact, bounded fault occurrence."""

    cut_point: FaultCutPoint
    action: FaultAction
    occurrence: int = 1
    reason_code: str = "injected_fault"

    def __post_init__(self) -> None:
        if not 1 <= self.occurrence <= 100:
            raise ValueError("fault occurrence must be between 1 and 100")
        if not self.reason_code or len(self.reason_code) > 128:
            raise ValueError("fault reason code is required and bounded")


class FaultInjectedError(RuntimeError):
    """Explicit fault signal raised instead of relying on nondeterministic timing."""

    def __init__(self, plan: FaultPlan) -> None:
        self.plan = plan
        super().__init__(
            f"{plan.cut_point.value}:{plan.action.value}:{plan.reason_code}"
        )


class DeterministicFaultInjector:
    """Synchronous barrier/hook object suitable for fakes and service adapters."""

    def __init__(self, plans: tuple[FaultPlan, ...]) -> None:
        identities = tuple((plan.cut_point, plan.occurrence) for plan in plans)
        if len(identities) != len(set(identities)):
            raise ValueError("fault plans must target unique cut-point occurrences")
        self._plans = {(plan.cut_point, plan.occurrence): plan for plan in plans}
        self._counts: dict[FaultCutPoint, int] = {}
        self._triggered: list[FaultPlan] = []
        self._visited: list[FaultCutPoint] = []

    def visit(self, cut_point: FaultCutPoint) -> FaultAction | None:
        """Reach a barrier and either continue or return/raise its exact action."""
        self._visited.append(cut_point)
        occurrence = self._counts.get(cut_point, 0) + 1
        self._counts[cut_point] = occurrence
        plan = self._plans.get((cut_point, occurrence))
        if plan is None:
            return None
        self._triggered.append(plan)
        if plan.action is FaultAction.RAISE:
            raise FaultInjectedError(plan)
        return plan.action

    @property
    def visited(self) -> tuple[FaultCutPoint, ...]:
        return tuple(self._visited)

    @property
    def triggered(self) -> tuple[FaultPlan, ...]:
        return tuple(self._triggered)

    def assert_complete(self) -> None:
        """Fail when a configured fault hook was silently skipped."""
        missing = tuple(
            plan for plan in self._plans.values() if plan not in self._triggered
        )
        if missing:
            names = ",".join(plan.cut_point.value for plan in missing)
            raise AssertionError(f"configured fault hooks were not reached: {names}")


__all__ = [
    "DeterministicFaultInjector",
    "FaultAction",
    "FaultCutPoint",
    "FaultInjectedError",
    "FaultPlan",
]
