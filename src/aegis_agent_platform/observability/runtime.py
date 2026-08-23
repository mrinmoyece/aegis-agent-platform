"""OpenTelemetry runtime spans and bounded in-process metric instruments.

TODO: queue-wide gauges such as ``stream_pending_depth``, ``oldest_pending_age``,
and ``dlq_depth`` still need bounded transport snapshots from the runtime loop.
The shared in-process registry below keeps those metric names reserved so future
queue inspections can publish them without changing the public telemetry surface.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace
from opentelemetry.trace import SpanKind


class RuntimeMetrics:
    """Thread-safe bounded metrics with no tenant/run/message label support."""

    _ALLOWED = frozenset(
        {
            "outbox_lag",
            "publish_failures",
            "stream_pending_depth",
            "oldest_pending_age",
            "claim_conflicts",
            "active_leases",
            "heartbeat_failures",
            "retries",
            "dead_letters",
            "dlq_depth",
            "work_latency",
            "cancellations",
            "reconciliation_success",
            "reconciliation_failure",
        }
    )

    def __init__(self) -> None:
        self._values: dict[str, float] = {}
        self._lock = Lock()

    def add(self, name: str, value: float = 1) -> None:
        if name not in self._ALLOWED:
            raise ValueError("unrecognized bounded metric")
        if value < 0:
            raise ValueError("metric increments cannot be negative")
        with self._lock:
            self._values[name] = self._values.get(name, 0.0) + value

    def set_gauge(self, name: str, value: float) -> None:
        if name not in self._ALLOWED:
            raise ValueError("unrecognized bounded metric")
        if value < 0:
            raise ValueError("metric gauges cannot be negative")
        with self._lock:
            self._values[name] = value

    def snapshot(self) -> Mapping[str, float]:
        with self._lock:
            return dict(self._values)


_SHARED_RUNTIME_METRICS = RuntimeMetrics()


def shared_runtime_metrics() -> RuntimeMetrics:
    """Return the process-wide bounded runtime metric registry."""
    return _SHARED_RUNTIME_METRICS


class RuntimeTracer:
    """Small OTel adapter that records operation classes, never identifiers."""

    def __init__(self, instrumentation_name: str = "aegis.worker-runtime") -> None:
        self._tracer = trace.get_tracer(instrumentation_name)

    @contextmanager
    def span(self, operation: str) -> Iterator[None]:
        if operation not in {
            "outbox.publish",
            "queue.consume",
            "work.claim",
            "work.execute",
            "work.reconcile",
        }:
            raise ValueError("unrecognized runtime operation")
        with self._tracer.start_as_current_span(
            operation,
            kind=SpanKind.INTERNAL,
        ):
            yield


__all__ = ["RuntimeMetrics", "RuntimeTracer", "shared_runtime_metrics"]
