"""Redacted OTel spans and bounded model-gateway metrics."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import Lock

from opentelemetry import trace

from aegis_agent_platform.domain import ModelIdentity, TokenUsage


class GatewayMetrics:
    _NAMES = frozenset(
        {
            "attempts",
            "latency_ms",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "reasoning_tokens",
            "cost_usd",
            "route_decisions",
            "retries",
            "fallbacks",
            "rate_limits",
            "circuit_open",
            "malformed_responses",
            "budget_denials",
            "reservation_drift_tokens",
            "reservation_drift_cost_usd",
        }
    )

    def __init__(self, allowed_models: tuple[ModelIdentity, ...]) -> None:
        self._allowed = frozenset(allowed_models)
        self._values: dict[tuple[str, str, str], float] = {}
        self._lock = Lock()

    def add(self, name: str, model: ModelIdentity, value: float = 1) -> None:
        if name not in self._NAMES or model not in self._allowed:
            raise ValueError("metric name and model must be bounded catalog values")
        if value < 0:
            raise ValueError("metric increments cannot be negative")
        key = (name, model.provider, model.model)
        with self._lock:
            self._values[key] = self._values.get(key, 0) + value

    def usage(self, model: ModelIdentity, usage: TokenUsage) -> None:
        self.add("input_tokens", model, usage.input_tokens)
        self.add("output_tokens", model, usage.output_tokens)
        self.add("cache_read_tokens", model, usage.cache_read_tokens)
        self.add("cache_write_tokens", model, usage.cache_write_tokens)
        self.add("reasoning_tokens", model, usage.reasoning_tokens)

    def snapshot(self) -> Mapping[tuple[str, str, str], float]:
        with self._lock:
            return dict(self._values)


class GatewayTracer:
    def __init__(self, allowed_models: tuple[ModelIdentity, ...]) -> None:
        self._allowed = frozenset(allowed_models)
        self._tracer = trace.get_tracer("aegis.model-gateway")

    @contextmanager
    def attempt(self, model: ModelIdentity) -> Iterator[None]:
        if model not in self._allowed:
            raise ValueError("trace model must be a bounded catalog value")
        with self._tracer.start_as_current_span("model.attempt") as span:
            span.set_attribute("gen_ai.provider.name", model.provider)
            span.set_attribute("gen_ai.request.model", model.model)
            yield


__all__ = ["GatewayMetrics", "GatewayTracer"]
