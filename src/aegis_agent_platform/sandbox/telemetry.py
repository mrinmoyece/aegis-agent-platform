"""Bounded sandbox telemetry without command, path, output, or tenant labels."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace

from aegis_agent_platform.domain import SandboxPurpose


class SandboxMetrics:
    _NAMES = frozenset(
        {
            "requests",
            "policy_denials",
            "queue_claims",
            "provision_attempts",
            "run_attempts",
            "limit_terminations",
            "cleanup_attempts",
            "cleanup_failures",
            "quarantines",
            "reconciliations",
        }
    )

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def add(
        self,
        name: str,
        *,
        purpose: SandboxPurpose | None = None,
        value: float = 1,
    ) -> None:
        if name not in self._NAMES or value < 0:
            raise ValueError("sandbox metric must use bounded names and values")
        label = purpose.value if purpose is not None else "none"
        with self._lock:
            key = (name, label)
            self._values[key] = self._values.get(key, 0) + value

    def snapshot(self) -> Mapping[tuple[str, str], float]:
        with self._lock:
            return dict(self._values)


class SandboxTracer:
    def __init__(self) -> None:
        self._tracer = trace.get_tracer("aegis.sandbox")

    @contextmanager
    def operation(self, name: str, purpose: SandboxPurpose) -> Iterator[None]:
        if name not in {
            "policy",
            "provision",
            "start",
            "collect",
            "reconcile",
            "cleanup",
            "scan",
        }:
            raise ValueError("unrecognized sandbox span")
        with self._tracer.start_as_current_span(f"sandbox.{name}") as span:
            span.set_attribute("aegis.sandbox.purpose", purpose.value)
            yield


__all__ = ["SandboxMetrics", "SandboxTracer"]
