"""Deterministic circuit, rate, concurrency, and retry controls."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

from aegis_agent_platform.domain import ModelGatewayError, ModelIdentity
from aegis_agent_platform.runtime.backoff import ExponentialBackoff


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    pass


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 3
    recovery_seconds: float = 30.0
    clock: Callable[[], float] = monotonic
    _failures: int = 0
    _opened_at: float | None = None
    _half_open_inflight: bool = False

    def __post_init__(self) -> None:
        if self.failure_threshold < 1 or self.recovery_seconds <= 0:
            raise ValueError("circuit bounds must be positive")

    @property
    def state(self) -> CircuitState:
        if self._opened_at is None:
            return CircuitState.CLOSED
        if self.clock() - self._opened_at >= self.recovery_seconds:
            return CircuitState.HALF_OPEN
        return CircuitState.OPEN

    def acquire(self) -> None:
        state = self.state
        if state is CircuitState.OPEN:
            raise CircuitOpenError("provider circuit is open")
        if state is CircuitState.HALF_OPEN:
            if self._half_open_inflight:
                raise CircuitOpenError("provider circuit half-open probe is busy")
            self._half_open_inflight = True

    def succeed(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._half_open_inflight = False

    def fail(self) -> None:
        self._half_open_inflight = False
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = self.clock()


@dataclass(slots=True)
class TokenBucket:
    capacity: float
    refill_per_second: float
    clock: Callable[[], float] = monotonic
    _tokens: float = -1
    _updated_at: float = -1

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.refill_per_second <= 0:
            raise ValueError("rate limit values must be positive")
        self._tokens = self.capacity
        self._updated_at = self.clock()

    def consume(self, amount: float = 1) -> bool:
        if amount <= 0 or amount > self.capacity:
            raise ValueError("rate limit amount is invalid")
        now = self.clock()
        elapsed = max(0.0, now - self._updated_at)
        self._tokens = min(
            self.capacity,
            self._tokens + elapsed * self.refill_per_second,
        )
        self._updated_at = now
        if self._tokens < amount:
            return False
        self._tokens -= amount
        return True


class ProviderControls:
    """Per-catalog provider/model controls with bounded known identities."""

    def __init__(
        self,
        models: tuple[ModelIdentity, ...],
        *,
        concurrency: int,
        requests_per_minute: int,
        tokens_per_minute: int,
        circuit_failure_threshold: int = 3,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be positive")
        self._semaphores = {model: asyncio.Semaphore(concurrency) for model in models}
        self._request_buckets = {
            model: TokenBucket(requests_per_minute, requests_per_minute / 60, clock)
            for model in models
        }
        self._token_buckets = {
            model: TokenBucket(tokens_per_minute, tokens_per_minute / 60, clock)
            for model in models
        }
        self._circuits = {
            model: CircuitBreaker(circuit_failure_threshold, clock=clock)
            for model in models
        }

    def circuit(self, model: ModelIdentity) -> CircuitBreaker:
        return self._known(self._circuits, model)

    def semaphore(self, model: ModelIdentity) -> asyncio.Semaphore:
        return self._known(self._semaphores, model)

    def admit(self, model: ModelIdentity, tokens: int) -> bool:
        token_bucket = self._known(self._token_buckets, model)
        if tokens > token_bucket.capacity:
            return False
        return self._known(self._request_buckets, model).consume() and (
            token_bucket.consume(float(tokens))
        )

    @staticmethod
    def _known[T](values: dict[ModelIdentity, T], model: ModelIdentity) -> T:
        try:
            return values[model]
        except KeyError as error:
            raise ValueError("model is not configured for runtime controls") from error


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int
    max_failovers: int
    backoff: ExponentialBackoff

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("attempt limit must be between 1 and 10")
        if not 0 <= self.max_failovers <= 5:
            raise ValueError("failover limit must be between 0 and 5")

    def may_retry(self, error: ModelGatewayError, attempt: int) -> bool:
        return error.retryable and attempt < self.max_attempts


__all__ = [
    "CircuitBreaker",
    "CircuitOpenError",
    "CircuitState",
    "ProviderControls",
    "RetryPolicy",
    "TokenBucket",
]
