"""Bounded remediation metrics and traces without target or rationale content."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace

from aegis_agent_platform.domain import ActionKind


class RemediationMetrics:
    _NAMES = frozenset(
        {
            "proposals",
            "policy_denials",
            "approvals_requested",
            "approvals_granted",
            "approvals_denied",
            "approvals_expired",
            "approvals_revoked",
            "actions_dispatched",
            "dry_runs",
            "attempts",
            "retries",
            "ambiguous_outcomes",
            "reconciliations",
            "verification_successes",
            "verification_failures",
            "rollbacks",
            "compensations",
        }
    )

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def add(
        self,
        name: str,
        *,
        action_kind: ActionKind | None = None,
        value: float = 1,
    ) -> None:
        if name not in self._NAMES or value < 0:
            raise ValueError("remediation metric must use bounded names and values")
        label = action_kind.value if action_kind is not None else "none"
        with self._lock:
            key = (name, label)
            self._values[key] = self._values.get(key, 0) + value

    def snapshot(self) -> Mapping[tuple[str, str], float]:
        with self._lock:
            return dict(self._values)


class RemediationTracer:
    def __init__(self) -> None:
        self._tracer = trace.get_tracer("aegis.remediation")

    @contextmanager
    def operation(self, name: str, action_kind: ActionKind) -> Iterator[None]:
        if name not in {"preflight", "dry_run", "execute", "reconcile", "verify"}:
            raise ValueError("unrecognized remediation span")
        with self._tracer.start_as_current_span(f"remediation.{name}") as span:
            span.set_attribute("aegis.action.kind", action_kind.value)
            yield


__all__ = ["RemediationMetrics", "RemediationTracer"]
