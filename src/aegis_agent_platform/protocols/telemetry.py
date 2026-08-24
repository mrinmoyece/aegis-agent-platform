"""Bounded protocol metrics and redacted OpenTelemetry spans."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock

from opentelemetry import trace

from aegis_agent_platform.domain import (
    ProtocolFamily,
    ProtocolTransport,
    validate_identifier,
)

_OUTCOMES = frozenset(
    {
        "requested",
        "completed",
        "failed",
        "ambiguous",
        "cancelled",
        "denied",
        "quarantined",
        "auth_failed",
        "drift",
    }
)
_BYTE_BUCKETS = (1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576)
# The only legal bucket labels are the byte-bucket sizes, the overflow sentinel,
# and "none" (the default for non-byte metrics).  Accepting arbitrary caller-
# supplied strings would create unbounded metric series.
_BUCKETS = frozenset({"none", "overflow"} | {str(limit) for limit in _BYTE_BUCKETS})


@dataclass(frozen=True, slots=True)
class ProtocolBoundary:
    family: ProtocolFamily
    version: str
    transport: ProtocolTransport

    def __post_init__(self) -> None:
        validate_identifier(self.version, "protocol telemetry version")


class ProtocolMetrics:
    """In-process metric evidence with a finite boundary and outcome catalog."""

    _NAMES = frozenset(
        {
            "operations",
            "latency_ms",
            "request_bytes",
            "response_bytes",
            "retries",
            "reconciliations",
            "drift",
            "quarantine",
            "auth_failures",
        }
    )

    def __init__(self, allowed_boundaries: tuple[ProtocolBoundary, ...]) -> None:
        if not allowed_boundaries:
            raise ValueError("protocol metrics require a bounded boundary catalog")
        self._allowed = frozenset(allowed_boundaries)
        self._values: dict[
            tuple[str, str, str, str, str, str],
            float,
        ] = {}
        self._lock = Lock()

    def add(
        self,
        name: str,
        boundary: ProtocolBoundary,
        outcome: str,
        value: float = 1,
        *,
        bucket: str = "none",
    ) -> None:
        if (
            name not in self._NAMES
            or boundary not in self._allowed
            or outcome not in _OUTCOMES
            or bucket not in _BUCKETS
        ):
            raise ValueError("protocol metric labels must use bounded catalog values")
        if value < 0:
            raise ValueError("protocol metric increments cannot be negative")
        key = (
            name,
            boundary.family.value,
            boundary.version,
            boundary.transport.value,
            outcome,
            bucket,
        )
        with self._lock:
            self._values[key] = self._values.get(key, 0) + value

    def observe_bytes(
        self,
        direction: str,
        boundary: ProtocolBoundary,
        outcome: str,
        byte_count: int,
    ) -> None:
        if direction not in {"request", "response"} or byte_count < 0:
            raise ValueError("protocol byte observation is invalid")
        bucket = next(
            (str(limit) for limit in _BYTE_BUCKETS if byte_count <= limit),
            "overflow",
        )
        self.add(
            f"{direction}_bytes",
            boundary,
            outcome,
            1,
            bucket=bucket,
        )

    def snapshot(
        self,
    ) -> Mapping[tuple[str, str, str, str, str, str], float]:
        with self._lock:
            return dict(self._values)


class ProtocolTracer:
    """Emit protocol spans without tenant, peer, URL, capability, or content labels."""

    def __init__(self, allowed_boundaries: tuple[ProtocolBoundary, ...]) -> None:
        if not allowed_boundaries:
            raise ValueError("protocol tracer requires a bounded boundary catalog")
        self._allowed = frozenset(allowed_boundaries)
        self._tracer = trace.get_tracer("aegis.protocol-boundary")

    @contextmanager
    def operation(self, boundary: ProtocolBoundary) -> Iterator[None]:
        if boundary not in self._allowed:
            raise ValueError("protocol trace boundary is outside the bounded catalog")
        with self._tracer.start_as_current_span("protocol.operation") as span:
            span.set_attribute("aegis.protocol.family", boundary.family.value)
            span.set_attribute("aegis.protocol.version", boundary.version)
            span.set_attribute("aegis.protocol.transport", boundary.transport.value)
            yield


__all__ = ["ProtocolBoundary", "ProtocolMetrics", "ProtocolTracer"]
