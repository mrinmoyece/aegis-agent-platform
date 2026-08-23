"""Bounded specialist metrics and OpenTelemetry spans without content."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace
from opentelemetry.trace import SpanKind

from aegis_agent_platform.agents.artifacts import AgentRole


class AgentMetrics:
    """Fixed metric names and role labels; identifiers and content are forbidden."""

    _ALLOWED = frozenset(
        {
            "investigations_requested",
            "tasks_dispatched",
            "tasks_succeeded",
            "tasks_failed",
            "tasks_timed_out",
            "task_retries",
            "artifacts_recorded",
            "critic_rejections",
            "budget_exhaustions",
            "abstentions",
            "investigations_finalized",
        }
    )

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def add(
        self,
        name: str,
        *,
        role: AgentRole | None = None,
        value: float = 1,
    ) -> None:
        if name not in self._ALLOWED:
            raise ValueError("unrecognized bounded agent metric")
        if value < 0:
            raise ValueError("metric increments cannot be negative")
        label = role.value if role is not None else "none"
        with self._lock:
            key = (name, label)
            self._values[key] = self._values.get(key, 0) + value

    def snapshot(self) -> Mapping[tuple[str, str], float]:
        with self._lock:
            return dict(self._values)


class AgentTracer:
    """Only fixed operation and role attributes enter spans."""

    def __init__(self, instrumentation_name: str = "aegis.specialist-runtime") -> None:
        self._tracer = trace.get_tracer(instrumentation_name)

    @contextmanager
    def task(self, role: AgentRole) -> Iterator[None]:
        with self._tracer.start_as_current_span(
            "specialist.execute",
            kind=SpanKind.INTERNAL,
            attributes={"aegis.agent.role": role.value},
        ):
            yield


__all__ = ["AgentMetrics", "AgentTracer"]
