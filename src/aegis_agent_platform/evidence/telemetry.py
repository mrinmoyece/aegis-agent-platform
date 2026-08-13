"""Bounded connector metrics and redacted tracing."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace

from aegis_agent_platform.domain import EvidenceSourceKind


class EvidenceMetrics:
    _NAMES = frozenset(
        {
            "queries",
            "latency_ms",
            "errors",
            "rate_limits",
            "partial_results",
            "evidence_records",
            "evidence_bytes",
            "quarantined",
            "deduplicated",
            "cursor_advanced",
            "webhook_verification_failures",
            "correlation_completed",
            "correlation_conflicts",
        }
    )

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def add(
        self,
        name: str,
        source: EvidenceSourceKind,
        value: float = 1,
    ) -> None:
        if name not in self._NAMES or value < 0:
            raise ValueError("evidence metric must use a bounded name and value")
        key = (name, source.value)
        with self._lock:
            self._values[key] = self._values.get(key, 0) + value

    def snapshot(self) -> Mapping[tuple[str, str], float]:
        with self._lock:
            return dict(self._values)


class EvidenceTracer:
    def __init__(self) -> None:
        self._tracer = trace.get_tracer("aegis.evidence")

    @contextmanager
    def query(self, source: EvidenceSourceKind) -> Iterator[None]:
        with self._tracer.start_as_current_span("evidence.connector.query") as span:
            span.set_attribute("aegis.evidence.source", source.value)
            yield

    @contextmanager
    def correlation(self) -> Iterator[None]:
        with self._tracer.start_as_current_span("evidence.correlation"):
            yield


__all__ = ["EvidenceMetrics", "EvidenceTracer"]
