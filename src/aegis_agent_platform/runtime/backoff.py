"""Deterministic retry-delay strategies."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True, slots=True)
class ExponentialBackoff:
    """Bounded exponential delay with injectable deterministic jitter."""

    base: timedelta = timedelta(seconds=1)
    maximum: timedelta = timedelta(minutes=5)
    jitter: Callable[[int, float], float] = lambda _attempt, seconds: seconds

    def __post_init__(self) -> None:
        if self.base <= timedelta(0) or self.maximum < self.base:
            raise ValueError("backoff bounds are invalid")

    def delay(self, attempt: int) -> timedelta:
        if attempt < 1:
            raise ValueError("attempt must be positive")
        unjittered = min(
            self.maximum.total_seconds(),
            self.base.total_seconds() * (2 ** min(attempt - 1, 30)),
        )
        seconds = self.jitter(attempt, unjittered)
        if not 0 <= seconds <= self.maximum.total_seconds():
            raise ValueError("jitter returned an out-of-bounds delay")
        return timedelta(seconds=seconds)


__all__ = ["ExponentialBackoff"]
