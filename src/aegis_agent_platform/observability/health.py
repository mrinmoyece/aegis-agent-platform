"""Component health with cached probes and readiness hysteresis."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class HealthStatus(StrEnum):
    """Stable component and aggregate health states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class DependencyCriticality(StrEnum):
    """Whether a dependency gates correctness or only optional capability."""

    CORRECTNESS = "correctness"
    OPTIONAL = "optional"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Payload-free result from one bounded component probe."""

    status: HealthStatus
    reason_code: str

    def __post_init__(self) -> None:
        if (
            not self.reason_code
            or len(self.reason_code) > 64
            or not self.reason_code.replace("_", "").isalnum()
        ):
            raise ValueError("health reason_code must be a bounded identifier")


@dataclass(frozen=True, slots=True)
class ComponentProbe:
    """Named probe with explicit readiness impact."""

    component: str
    criticality: DependencyCriticality
    check: Callable[[], Awaitable[ProbeResult]]

    def __post_init__(self) -> None:
        if (
            not self.component
            or len(self.component) > 64
            or not self.component.replace("_", "").replace("-", "").isalnum()
        ):
            raise ValueError("health component must be a bounded identifier")


@dataclass(frozen=True, slots=True)
class HealthReport:
    """Aggregate readiness and honest degraded reasons."""

    live: bool
    ready: bool
    status: HealthStatus
    components: Mapping[str, ProbeResult]


@dataclass(slots=True)
class _ProbeState:
    result: ProbeResult
    expires_at: float
    consecutive_successes: int
    consecutive_failures: int


class HealthRegistry:
    """Run cached probes and require repeated transitions to avoid flapping."""

    def __init__(
        self,
        probes: tuple[ComponentProbe, ...],
        *,
        cache_seconds: float = 5,
        transition_threshold: int = 2,
        probe_timeout_seconds: float = 1.0,
    ) -> None:
        if not 0 <= cache_seconds <= 60:
            raise ValueError("cache_seconds must be between 0 and 60")
        if not 1 <= transition_threshold <= 5:
            raise ValueError("transition_threshold must be between 1 and 5")
        if not 0.05 <= probe_timeout_seconds <= 30:
            raise ValueError("probe_timeout_seconds must be between 0.05 and 30")
        if len({probe.component for probe in probes}) != len(probes):
            raise ValueError("health probe names must be unique")
        self._probes = probes
        self._cache_seconds = cache_seconds
        self._threshold = transition_threshold
        self._probe_timeout_seconds = probe_timeout_seconds
        self._state: dict[str, _ProbeState] = {}

    async def report(self, *, monotonic_time: float) -> HealthReport:
        """Return liveness plus correctness-gated readiness."""
        results: dict[str, ProbeResult] = {}
        critical_unavailable = False
        degraded = False
        for probe in self._probes:
            result = await self._result(probe, monotonic_time)
            results[probe.component] = result
            if (
                probe.criticality is DependencyCriticality.CORRECTNESS
                and result.status is HealthStatus.UNAVAILABLE
            ):
                critical_unavailable = True
            if result.status is not HealthStatus.HEALTHY:
                degraded = True
        status = (
            HealthStatus.UNAVAILABLE
            if critical_unavailable
            else HealthStatus.DEGRADED
            if degraded
            else HealthStatus.HEALTHY
        )
        return HealthReport(
            live=True,
            ready=not critical_unavailable,
            status=status,
            components=MappingProxyType(results),
        )

    async def _result(
        self,
        probe: ComponentProbe,
        monotonic_time: float,
    ) -> ProbeResult:
        previous = self._state.get(probe.component)
        if previous is not None and monotonic_time < previous.expires_at:
            return previous.result
        observed = await self._observe(probe)
        state = _ProbeState(observed, 0, 0, 0) if previous is None else previous
        is_success = observed.status is HealthStatus.HEALTHY
        state.consecutive_successes = (
            state.consecutive_successes + 1 if is_success else 0
        )
        state.consecutive_failures = (
            state.consecutive_failures + 1 if not is_success else 0
        )
        should_transition = (
            state.result.status is observed.status
            or state.consecutive_successes >= self._threshold
            or state.consecutive_failures >= self._threshold
        )
        if should_transition:
            state.result = observed
            state.consecutive_successes = 0
            state.consecutive_failures = 0
        state.expires_at = monotonic_time + self._cache_seconds
        self._state[probe.component] = state
        return state.result

    async def _observe(self, probe: ComponentProbe) -> ProbeResult:
        try:
            return await asyncio.wait_for(
                probe.check(),
                timeout=self._probe_timeout_seconds,
            )
        except TimeoutError:
            return ProbeResult(HealthStatus.UNAVAILABLE, "probe_timeout")
        except (ConnectionError, OSError):
            return ProbeResult(HealthStatus.UNAVAILABLE, "dependency_unavailable")
        except Exception:
            return ProbeResult(HealthStatus.UNAVAILABLE, "probe_failed")


__all__ = [
    "ComponentProbe",
    "DependencyCriticality",
    "HealthRegistry",
    "HealthReport",
    "HealthStatus",
    "ProbeResult",
]
