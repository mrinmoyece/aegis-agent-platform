"""Opt-in non-CI statistical evaluation boundary for registered live adapters."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from math import sqrt
from time import monotonic
from typing import Protocol


@dataclass(frozen=True, slots=True)
class LiveEvaluationConfig:
    """Fail-closed limits for non-reproducible live evaluation."""

    enabled_acknowledgement: str
    credential_references: Mapping[str, str]
    tenant_allowlist: frozenset[str]
    sample_cap: int
    spend_cap_usd: Decimal
    time_cap_seconds: int
    requests_per_minute: int
    pii_allowed: bool = False
    production_effects_allowed: bool = False
    retain_raw_results: bool = False

    def __post_init__(self) -> None:
        if self.enabled_acknowledgement != "I_UNDERSTAND_NON_REPRODUCIBLE_LIVE_EVAL":
            raise ValueError("live evaluation requires an explicit acknowledgement")
        if not self.credential_references or any(
            not key or not value.startswith("secret-ref://")
            for key, value in self.credential_references.items()
        ):
            raise ValueError("live evaluation requires secret references, never values")
        if not self.tenant_allowlist:
            raise ValueError("live evaluation requires an explicit tenant allowlist")
        if not 1 <= self.sample_cap <= 20:
            raise ValueError("live sample_cap must be between 1 and 20")
        if not Decimal("0") < self.spend_cap_usd <= Decimal("25"):
            raise ValueError(
                "live spend cap must be greater than zero and at most 25 USD"
            )
        if not 1 <= self.time_cap_seconds <= 1_800:
            raise ValueError("live time cap must be between 1 and 1800 seconds")
        if not 1 <= self.requests_per_minute <= 60:
            raise ValueError("live rate limit must be between 1 and 60")
        if self.pii_allowed or self.production_effects_allowed:
            raise ValueError("live evaluation cannot enable PII or production effects")


@dataclass(frozen=True, slots=True)
class LiveTrialResult:
    """Minimal controlled output from a provider/connector adapter trial."""

    score: Decimal
    cost_usd: Decimal
    duration_ms: int
    contains_pii: bool
    production_effect_attempted: bool
    raw_result_reference: str | None = None

    def __post_init__(self) -> None:
        if not Decimal(0) <= self.score <= Decimal(1):
            raise ValueError("live trial score must be between zero and one")
        if self.cost_usd < 0 or self.duration_ms < 0:
            raise ValueError("live trial accounting cannot be negative")
        if (
            self.raw_result_reference is not None
            and not self.raw_result_reference.startswith("aegis-restricted-object://")
        ):
            raise ValueError("raw live results require a restricted object reference")


@dataclass(frozen=True, slots=True)
class LiveTrialBudget:
    """Pre-dispatch capability ceiling that a registered adapter must enforce."""

    max_cost_usd: Decimal
    timeout_seconds: int
    requests_per_minute: int
    read_only: bool = True
    pii_allowed: bool = False
    production_effects_allowed: bool = False

    def __post_init__(self) -> None:
        if self.max_cost_usd <= 0:
            raise ValueError("live trial requires a positive remaining spend cap")
        if self.timeout_seconds <= 0 or self.requests_per_minute <= 0:
            raise ValueError("live trial time and rate ceilings must be positive")
        if not self.read_only or self.pii_allowed or self.production_effects_allowed:
            raise ValueError("live trial capability must remain read-only and PII-free")


class LiveEvaluationAdapter(Protocol):
    """Opt-in adapter over an existing provider-neutral read/model port."""

    adapter_id: str

    async def run_trial(
        self,
        *,
        case_id: str,
        tenant_id: str,
        trial: int,
        budget: LiveTrialBudget,
    ) -> LiveTrialResult: ...


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    """Normal-approximation summary labeled as non-reproducible."""

    samples: int
    mean: Decimal
    lower_95: Decimal
    upper_95: Decimal
    total_cost_usd: Decimal
    non_reproducible: bool = True


@dataclass(frozen=True, slots=True)
class ModelJudgeConfig:
    """Optional isolated judge; deterministic security gates remain mandatory."""

    enabled: bool = False
    judge_version: str | None = None
    rubric_digest: str | None = None
    injection_delimited: bool = True
    sole_safety_gate: bool = False

    def __post_init__(self) -> None:
        if self.sole_safety_gate:
            raise ValueError("model judge cannot be the sole safety gate")
        if self.enabled and (
            not self.judge_version
            or self.rubric_digest is None
            or len(self.rubric_digest) != 64
            or not self.injection_delimited
        ):
            raise ValueError("enabled model judge requires versioned isolated rubric")


class LiveEvaluationExecutor:
    """Enforce caps around explicitly registered adapters; none register by default."""

    def __init__(
        self,
        adapters: Mapping[str, LiveEvaluationAdapter],
        *,
        clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._adapters = dict(adapters)
        self._clock = clock
        self._sleep = sleep

    async def run(
        self,
        *,
        adapter_id: str,
        case_id: str,
        tenant_id: str,
        config: LiveEvaluationConfig,
    ) -> ConfidenceInterval:
        if os.getenv("CI"):
            raise RuntimeError("live evaluation is prohibited in CI")
        if tenant_id not in config.tenant_allowlist:
            raise PermissionError("live evaluation tenant is not allowlisted")
        try:
            adapter = self._adapters[adapter_id]
        except KeyError as error:
            raise ValueError("live evaluation adapter is not registered") from error
        total_cost = Decimal(0)
        total_duration_ms = 0
        results: list[Decimal] = []
        started_at = self._clock()
        previous_trial_at: float | None = None
        minimum_interval = 60 / config.requests_per_minute
        for trial in range(config.sample_cap):
            elapsed = self._clock() - started_at
            remaining = config.time_cap_seconds - elapsed
            if remaining <= 0:
                raise TimeoutError("live evaluation time cap exceeded")
            if previous_trial_at is not None:
                delay = minimum_interval - (self._clock() - previous_trial_at)
                if delay > 0:
                    if delay >= remaining:
                        raise TimeoutError(
                            "live evaluation rate limit exceeds time cap"
                        )
                    await asyncio.wait_for(self._sleep(delay), timeout=remaining)
            elapsed = self._clock() - started_at
            remaining = config.time_cap_seconds - elapsed
            if remaining <= 0:
                raise TimeoutError("live evaluation time cap exceeded")
            previous_trial_at = self._clock()
            budget = LiveTrialBudget(
                config.spend_cap_usd - total_cost,
                max(1, int(remaining)),
                config.requests_per_minute,
            )
            result = await asyncio.wait_for(
                adapter.run_trial(
                    case_id=case_id,
                    tenant_id=tenant_id,
                    trial=trial,
                    budget=budget,
                ),
                timeout=remaining,
            )
            if result.contains_pii or result.production_effect_attempted:
                raise RuntimeError("live adapter violated PII/effect containment")
            total_cost += result.cost_usd
            if total_cost > config.spend_cap_usd:
                raise RuntimeError("live evaluation spend cap exceeded")
            total_duration_ms += result.duration_ms
            if total_duration_ms > config.time_cap_seconds * 1_000:
                raise TimeoutError("live evaluation reported duration exceeds time cap")
            if (
                result.raw_result_reference is not None
                and not config.retain_raw_results
            ):
                raise RuntimeError("raw live result retention was not authorized")
            results.append(result.score)
        return confidence_interval(tuple(results), total_cost)


def confidence_interval(
    scores: tuple[Decimal, ...],
    total_cost_usd: Decimal,
) -> ConfidenceInterval:
    """Compute a bounded repeated-trial 95% interval with explicit edge cases."""
    if not scores or len(scores) > 20:
        raise ValueError("confidence interval requires between 1 and 20 scores")
    if any(score < 0 or score > 1 for score in scores):
        raise ValueError("confidence interval scores must be between zero and one")
    mean = sum(scores, Decimal(0)) / Decimal(len(scores))
    if len(scores) == 1:
        return ConfidenceInterval(1, mean, mean, mean, total_cost_usd)
    variance = sum((score - mean) ** 2 for score in scores) / Decimal(len(scores) - 1)
    standard_error = Decimal(str(sqrt(float(variance) / len(scores))))
    margin = Decimal("1.96") * standard_error
    return ConfidenceInterval(
        len(scores),
        mean,
        max(Decimal(0), mean - margin),
        min(Decimal(1), mean + margin),
        total_cost_usd,
    )


__all__ = [
    "ConfidenceInterval",
    "LiveEvaluationAdapter",
    "LiveEvaluationConfig",
    "LiveEvaluationExecutor",
    "LiveTrialBudget",
    "LiveTrialResult",
    "ModelJudgeConfig",
    "confidence_interval",
]
