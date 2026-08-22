"""Bounded in-process metric aggregation and non-blocking export buffering."""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Lock
from types import MappingProxyType

from aegis_agent_platform.observability.semantic import (
    METRICS,
    MetricDefinition,
    MetricKind,
    validate_metric_labels,
)

MAX_LABEL_VALUES_PER_METRIC = 32
MAX_SERIES_PER_METRIC = 256
MAX_DEDUPLICATION_KEYS = 10_000
MAX_EXPORT_BUFFER = 4_096


@dataclass(frozen=True, slots=True)
class MetricPoint:
    """One validated aggregate point."""

    name: str
    labels: tuple[tuple[str, str], ...]
    value: float
    count: int = 1
    buckets: tuple[tuple[float, int], ...] = ()


@dataclass(frozen=True, slots=True)
class MetricSnapshot:
    """Immutable aggregate view suitable for an exporter adapter."""

    points: tuple[MetricPoint, ...]
    dropped: int
    duplicate_business_outcomes: int


class BoundedMetrics:
    """Enforce registered names, label budgets, and durable-outcome de-duplication."""

    def __init__(
        self,
        definitions: Mapping[str, MetricDefinition] = METRICS,
        *,
        max_label_values: int = MAX_LABEL_VALUES_PER_METRIC,
        max_series: int = MAX_SERIES_PER_METRIC,
    ) -> None:
        if not 1 <= max_label_values <= MAX_LABEL_VALUES_PER_METRIC:
            raise ValueError("max_label_values exceeds the reviewed budget")
        if not 1 <= max_series <= MAX_SERIES_PER_METRIC:
            raise ValueError("max_series exceeds the reviewed budget")
        self._definitions = definitions
        self._max_label_values = max_label_values
        self._max_series = max_series
        self._values: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._counts: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}
        self._histogram_buckets: dict[
            tuple[str, tuple[tuple[str, str], ...]], dict[float, int]
        ] = {}
        self._label_values: dict[tuple[str, str], set[str]] = {}
        self._outcomes: set[str] = set()
        self._outcome_order: deque[str] = deque()
        self._dropped = 0
        self._duplicates = 0
        self._lock = Lock()

    def add(
        self,
        name: str,
        value: float = 1,
        *,
        labels: Mapping[str, str] | None = None,
        outcome_key: str | None = None,
    ) -> bool:
        """Record a counter or histogram point; return false when safely dropped."""
        definition = self._definition(name)
        if definition.kind is MetricKind.GAUGE:
            raise ValueError("gauges must use set_gauge")
        if not math.isfinite(value):
            raise ValueError("metric values must be finite")
        if value < 0:
            raise ValueError("metric values cannot be negative")
        label_key = self._labels(definition, labels or {})
        with self._lock:
            if not self._admit(name, label_key):
                self._dropped += 1
                return False
            if definition.business_outcome:
                if outcome_key is None:
                    raise ValueError("business outcome metrics require an outcome key")
                if not self._new_outcome(f"{name}:{outcome_key}"):
                    self._duplicates += 1
                    return False
            key = (name, label_key)
            self._values[key] = self._values.get(key, 0.0) + value
            self._counts[key] = self._counts.get(key, 0) + 1
            if definition.kind is MetricKind.HISTOGRAM:
                buckets = self._histogram_buckets.setdefault(
                    key,
                    dict.fromkeys(definition.buckets, 0),
                )
                for bucket in definition.buckets:
                    if value <= bucket:
                        buckets[bucket] += 1
            return True

    def set_gauge(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, str] | None = None,
    ) -> bool:
        """Set a non-negative derived gauge within its cardinality budget."""
        definition = self._definition(name)
        if definition.kind is not MetricKind.GAUGE:
            raise ValueError("only gauges may be set")
        if not math.isfinite(value):
            raise ValueError("gauge values must be finite")
        if value < 0:
            raise ValueError("gauge values cannot be negative")
        label_key = self._labels(definition, labels or {})
        with self._lock:
            if not self._admit(name, label_key):
                self._dropped += 1
                return False
            key = (name, label_key)
            self._values[key] = value
            self._counts[key] = 1
            self._histogram_buckets.pop(key, None)
            return True

    def snapshot(self) -> MetricSnapshot:
        """Return sorted points without exposing mutable aggregation state."""
        with self._lock:
            points = tuple(
                MetricPoint(
                    name,
                    labels,
                    value,
                    self._counts[(name, labels)],
                    tuple(
                        sorted(self._histogram_buckets.get((name, labels), {}).items())
                    ),
                )
                for (name, labels), value in sorted(self._values.items())
            )
            return MetricSnapshot(points, self._dropped, self._duplicates)

    def distinct_label_values(self, name: str, label: str) -> int:
        """Return current cardinality for deterministic budget tests."""
        with self._lock:
            return len(self._label_values.get((name, label), set()))

    def _definition(self, name: str) -> MetricDefinition:
        try:
            return self._definitions[name]
        except KeyError as error:
            raise ValueError("unregistered metric") from error

    def _labels(
        self,
        definition: MetricDefinition,
        labels: Mapping[str, str],
    ) -> tuple[tuple[str, str], ...]:
        supplied = tuple(sorted(labels))
        validate_metric_labels(supplied)
        if supplied != tuple(sorted(definition.labels)):
            raise ValueError("metric labels do not match the registered definition")
        normalized: list[tuple[str, str]] = []
        for name in supplied:
            value = labels[name]
            if (
                not value
                or len(value) > 64
                or not value.replace("_", "")
                .replace("-", "")
                .replace(".", "")
                .isalnum()
            ):
                raise ValueError("metric label value must be a bounded identifier")
            normalized.append((name, value))
        return tuple(normalized)

    def _admit(self, name: str, labels: tuple[tuple[str, str], ...]) -> bool:
        series = sum(1 for metric_name, _ in self._values if metric_name == name)
        if (name, labels) not in self._values and series >= self._max_series:
            return False
        for label, value in labels:
            values = self._label_values.setdefault((name, label), set())
            if value not in values and len(values) >= self._max_label_values:
                return False
        for label, value in labels:
            self._label_values[(name, label)].add(value)
        return True

    def _new_outcome(self, key: str) -> bool:
        if not key or len(key) > 256:
            raise ValueError("outcome key is required and bounded")
        if key in self._outcomes:
            return False
        # Best-effort bounded in-memory deduplication: eviction and process restarts can
        # admit a later replay of the same durable outcome, so this does not prove
        # exactly-once business counters beyond the reviewed retention window.
        if len(self._outcome_order) >= MAX_DEDUPLICATION_KEYS:
            expired = self._outcome_order.popleft()
            self._outcomes.remove(expired)
        self._outcome_order.append(key)
        self._outcomes.add(key)
        return True


class BoundedExportBuffer:
    """Non-blocking telemetry buffer; exporter failure cannot affect runtime work."""

    def __init__(self, *, capacity: int = MAX_EXPORT_BUFFER) -> None:
        if not 1 <= capacity <= MAX_EXPORT_BUFFER:
            raise ValueError("export buffer capacity is outside the reviewed bound")
        self._items: deque[Mapping[str, object]] = deque(maxlen=capacity)
        self._capacity = capacity
        self._dropped = 0
        self._failures = 0
        self._circuit_open = False
        self._lock = Lock()
        self._drain_lock = Lock()

    def offer(self, item: Mapping[str, object]) -> bool:
        """Copy one bounded item without waiting for an exporter."""
        frozen = MappingProxyType(dict(item))
        with self._lock:
            if len(self._items) >= self._capacity:
                self._dropped += 1
                return False
            self._items.append(frozen)
            return True

    def drain(
        self,
        exporter: Callable[[tuple[Mapping[str, object], ...]], None],
        *,
        limit: int = 128,
    ) -> int:
        """Attempt one bounded batch; retain it when the adapter fails."""
        if not 1 <= limit <= 1_000:
            raise ValueError("export drain limit must be between 1 and 1000")
        if not self._drain_lock.acquire(blocking=False):
            return 0
        try:
            with self._lock:
                if self._circuit_open or not self._items:
                    return 0
                batch = tuple(list(self._items)[:limit])
            try:
                exporter(batch)
            except (OSError, TimeoutError):
                with self._lock:
                    self._failures += 1
                    self._circuit_open = self._failures >= 3
                return 0
            with self._lock:
                for _ in batch:
                    self._items.popleft()
                self._failures = 0
            return len(batch)
        finally:
            self._drain_lock.release()

    def reset_circuit(self) -> None:
        """Allow an operator-controlled or timed adapter probe to retry export."""
        with self._lock:
            self._circuit_open = False
            self._failures = 0

    @property
    def status(self) -> Mapping[str, int | bool]:
        """Return payload-free exporter self-observation."""
        with self._lock:
            return MappingProxyType(
                {
                    "buffered": len(self._items),
                    "dropped": self._dropped,
                    "failures": self._failures,
                    "circuit_open": self._circuit_open,
                }
            )


__all__ = [
    "MAX_DEDUPLICATION_KEYS",
    "MAX_EXPORT_BUFFER",
    "MAX_LABEL_VALUES_PER_METRIC",
    "MAX_SERIES_PER_METRIC",
    "BoundedExportBuffer",
    "BoundedMetrics",
    "MetricPoint",
    "MetricSnapshot",
]
