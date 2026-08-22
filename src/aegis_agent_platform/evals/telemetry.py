"""Bounded low-cardinality evaluation observability without case content."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace
from opentelemetry.trace import SpanKind

_OPERATIONS = frozenset(
    {
        "eval.catalog",
        "eval.run",
        "eval.case",
        "eval.score",
        "eval.compare",
        "eval.report",
        "eval.fixture_check",
    }
)
_METRICS = frozenset(
    {
        "eval_runs",
        "eval_cases",
        "eval_passes",
        "eval_failures",
        "eval_evaluator_errors",
        "eval_safety_failures",
        "eval_regressions",
        "eval_fixture_failures",
        "eval_steps",
        "eval_tokens",
        "eval_cost_microusd",
    }
)
_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")


class EvaluationMetrics:
    """In-process counters with no label or arbitrary metric registration surface."""

    def __init__(self) -> None:
        self._values: dict[str, int] = {}
        self._lock = Lock()

    def add(self, name: str, value: int = 1) -> None:
        if name not in _METRICS:
            raise ValueError("unrecognized bounded evaluation metric")
        if value < 0:
            raise ValueError("evaluation metric increments cannot be negative")
        with self._lock:
            self._values[name] = self._values.get(name, 0) + value

    def snapshot(self) -> Mapping[str, int]:
        with self._lock:
            return dict(sorted(self._values.items()))


class EvaluationTracer:
    """OTel adapter limited to operation class and reviewed run fingerprints."""

    def __init__(self) -> None:
        self._tracer = trace.get_tracer("aegis.evaluations")

    @contextmanager
    def span(
        self,
        operation: str,
        *,
        run_fingerprint: str,
        mode: str,
    ) -> Iterator[None]:
        if operation not in _OPERATIONS:
            raise ValueError("unrecognized evaluation trace operation")
        if _FINGERPRINT_PATTERN.fullmatch(run_fingerprint) is None or mode not in {
            "deterministic",
            "integration",
            "live",
        }:
            raise ValueError("invalid evaluation trace attributes")
        with self._tracer.start_as_current_span(
            operation,
            kind=SpanKind.INTERNAL,
            attributes={
                "eval.run_fingerprint": run_fingerprint,
                "eval.mode": mode,
            },
        ):
            yield


def evaluation_log(
    *,
    operation: str,
    outcome: str,
    run_fingerprint: str,
    reason_code: str | None = None,
) -> Mapping[str, str]:
    """Return a fixed-schema log record with no free-form content."""
    if operation not in _OPERATIONS:
        raise ValueError("unrecognized evaluation log operation")
    if outcome not in {"started", "passed", "failed", "cancelled"}:
        raise ValueError("unrecognized evaluation log outcome")
    if _FINGERPRINT_PATTERN.fullmatch(run_fingerprint) is None:
        raise ValueError("invalid evaluation log fingerprint")
    record = {
        "operation": operation,
        "outcome": outcome,
        "run_fingerprint": run_fingerprint,
    }
    if reason_code is not None:
        if not reason_code.replace("_", "").isalnum() or len(reason_code) > 64:
            raise ValueError("reason_code must be a bounded identifier")
        record["reason_code"] = reason_code
    return record


__all__ = ["EvaluationMetrics", "EvaluationTracer", "evaluation_log"]
