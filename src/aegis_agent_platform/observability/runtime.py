"""OpenTelemetry runtime spans and bounded in-process metric instruments."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace
from opentelemetry.trace import (
    Link,
    NonRecordingSpan,
    SpanContext,
    SpanKind,
    TraceFlags,
    TraceState,
    set_span_in_context,
)

from aegis_agent_platform.observability.context import PropagationContext, TraceLink
from aegis_agent_platform.observability.semantic import (
    SEMANTIC_SCHEMA_VERSION,
    require_operation,
)


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


class RuntimeTracer:
    """Small OTel adapter that records operation classes, never identifiers."""

    def __init__(self, instrumentation_name: str = "aegis.worker-runtime") -> None:
        self._tracer = trace.get_tracer(instrumentation_name)

    @contextmanager
    def span(
        self,
        operation: str,
        *,
        parent: PropagationContext | None = None,
        links: Sequence[TraceLink] = (),
    ) -> Iterator[None]:
        """Start a fixed-name span with validated provider-neutral causal metadata."""
        require_operation(operation)
        parent_context = (
            set_span_in_context(NonRecordingSpan(_span_context(parent)))
            if parent is not None
            else None
        )
        with self._tracer.start_as_current_span(
            operation,
            kind=SpanKind.INTERNAL,
            context=parent_context,
            links=[
                Link(
                    _link_context(link),
                    {"aegis.link.kind": link.kind.value},
                )
                for link in links
            ],
            attributes={"aegis.schema.version": SEMANTIC_SCHEMA_VERSION},
        ):
            yield


def _span_context(context: PropagationContext) -> SpanContext:
    return SpanContext(
        trace_id=int(context.trace_id, 16),
        span_id=int(context.parent_span_id, 16),
        is_remote=True,
        trace_flags=TraceFlags(
            TraceFlags.SAMPLED if context.sampled else TraceFlags.DEFAULT
        ),
        trace_state=(
            TraceState.from_header([context.tracestate])
            if context.tracestate is not None
            else TraceState()
        ),
    )


def _link_context(link: TraceLink) -> SpanContext:
    return SpanContext(
        trace_id=int(link.trace_id, 16),
        span_id=int(link.span_id, 16),
        is_remote=True,
        trace_flags=TraceFlags(
            TraceFlags.SAMPLED if link.sampled else TraceFlags.DEFAULT
        ),
    )


__all__ = ["RuntimeMetrics", "RuntimeTracer"]
