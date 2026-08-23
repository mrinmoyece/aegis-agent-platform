"""Deterministic baselines, hard safety gates, and scoped expiring waivers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import cast

from aegis_agent_platform.evals.contracts import (
    EvaluationReport,
    EvaluationSuite,
    MetricDirection,
    ResultStatus,
    canonical_data,
    canonical_digest,
)


@dataclass(frozen=True, slots=True)
class BaselineMetric:
    """Reviewed expectation for one case metric."""

    value: Decimal | None
    direction: MetricDirection
    tolerance: Decimal
    hard_safety: bool

    def __post_init__(self) -> None:
        if self.value is not None and not self.value.is_finite():
            raise ValueError("baseline metric value must be finite")
        if self.tolerance < 0:
            raise ValueError("baseline tolerance cannot be negative")


@dataclass(frozen=True, slots=True)
class BaselineCase:
    """Case identity, weight, and per-metric reviewed values."""

    case_id: str
    case_digest: str
    weight: Decimal
    metrics: Mapping[str, BaselineMetric]

    def __post_init__(self) -> None:
        if not self.case_id or len(self.case_digest) != 64:
            raise ValueError("baseline case identity is invalid")
        if self.weight <= 0:
            raise ValueError("baseline case weight must be positive")
        if not self.metrics:
            raise ValueError("baseline case must contain metrics")
        object.__setattr__(
            self,
            "metrics",
            MappingProxyType(dict(sorted(self.metrics.items()))),
        )


@dataclass(frozen=True, slots=True)
class EvaluationBaseline:
    """Checked-in canonical baseline generated only from a complete passing report."""

    schema_version: int
    baseline_id: str
    generated_at: datetime
    review_reference: str
    suite_digest: str
    dataset_digest: str
    cases: tuple[BaselineCase, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported baseline schema version")
        if (
            not self.baseline_id
            or not self.review_reference
            or self.generated_at.tzinfo is None
        ):
            raise ValueError("baseline identity, review, and timezone are required")
        if len(self.suite_digest) != 64 or len(self.dataset_digest) != 64:
            raise ValueError("baseline suite and dataset digests are required")
        identifiers = tuple(item.case_id for item in self.cases)
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("baseline cases must be non-empty and unique")

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class RegressionWaiver:
    """Reviewed exact case/metric exception with fail-closed expiry."""

    waiver_id: str
    owner: str
    reason: str
    expires_at: datetime
    case_ids: frozenset[str]
    metric_names: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not self.waiver_id
            or not self.owner
            or len(self.reason) < 12
            or self.expires_at.tzinfo is None
        ):
            raise ValueError("waiver identity, owner, reason, and expiry are required")
        if not self.case_ids or not self.metric_names:
            raise ValueError("waivers require exact case and metric scope")

    def covers(self, case_id: str, metric_name: str, *, at: datetime) -> bool:
        return (
            at < self.expires_at
            and case_id in self.case_ids
            and metric_name in self.metric_names
        )


@dataclass(frozen=True, slots=True)
class RegressionFinding:
    """One deterministic baseline comparison result."""

    reason_code: str
    case_id: str
    metric_name: str
    baseline_value: Decimal | None
    current_value: Decimal | None
    hard_safety: bool
    waived: bool
    waiver_id: str | None = None


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    """No aggregate score: every safety and quality regression remains visible."""

    baseline_digest: str
    report_digest: str
    evaluated_at: datetime
    findings: tuple[RegressionFinding, ...]

    @property
    def passed(self) -> bool:
        return not any(not finding.waived for finding in self.findings)


def build_baseline(
    suite: EvaluationSuite,
    report: EvaluationReport,
    *,
    baseline_id: str,
    review_reference: str,
) -> EvaluationBaseline:
    """Build only from a complete passing canonical deterministic report."""
    if not report.passed:
        raise ValueError("cannot baseline a failing evaluation report")
    report_cases = {result.case_id: result for result in report.results}
    suite_cases = {case.case_id: case for case in suite.cases}
    if set(report_cases) != set(suite_cases):
        raise ValueError("baseline update requires every suite case exactly once")
    definitions = {item.metric_name: item for item in suite.scorers}
    definitions_by_id = {item.scorer_id: item for item in suite.scorers}
    cases: list[BaselineCase] = []
    for case_id, case in sorted(suite_cases.items()):
        result = report_cases[case_id]
        metrics: dict[str, BaselineMetric] = {}
        for metric in result.metrics:
            definition = definitions[metric.metric_name]
            metrics[metric.metric_name] = BaselineMetric(
                metric.value,
                definition.direction,
                definition.tolerance,
                definition.hard_safety,
            )
        if set(metrics) != {
            definitions_by_id[item].metric_name for item in case.scorer_ids
        }:
            raise ValueError("baseline metric coverage does not match case scorers")
        cases.append(BaselineCase(case_id, case.digest, case.weight, metrics))
    return EvaluationBaseline(
        1,
        baseline_id,
        suite.determinism.clock,
        review_reference,
        suite.digest,
        suite.dataset.digest,
        tuple(cases),
    )


def compare_baseline(
    suite: EvaluationSuite,
    baseline: EvaluationBaseline,
    report: EvaluationReport,
    *,
    at: datetime,
    waivers: tuple[RegressionWaiver, ...] = (),
) -> BaselineComparison:
    """Compare every case and metric; safety failures are never waiver-eligible."""
    if at.tzinfo is None:
        raise ValueError("comparison time must be timezone-aware")
    findings: list[RegressionFinding] = []
    if baseline.suite_digest != suite.digest:
        findings.append(_structural("suite_digest_changed"))
    if baseline.dataset_digest != suite.dataset.digest:
        findings.append(_structural("dataset_digest_changed"))
    baseline_cases = {item.case_id: item for item in baseline.cases}
    current_cases = {item.case_id: item for item in report.results}
    suite_case_ids = {item.case_id for item in suite.cases}
    findings.extend(
        _structural("missing_case", case_id=case_id)
        for case_id in sorted(set(baseline_cases) - set(current_cases))
    )
    findings.extend(
        _structural("new_case", case_id=case_id)
        for case_id in sorted(set(current_cases) - set(baseline_cases))
    )
    findings.extend(
        _structural("baseline_missing_suite_case", case_id=case_id)
        for case_id in sorted(suite_case_ids - set(baseline_cases))
    )
    findings.extend(
        _structural("baseline_unknown_case", case_id=case_id)
        for case_id in sorted(set(baseline_cases) - suite_case_ids)
    )
    expired = tuple(waiver for waiver in waivers if at >= waiver.expires_at)
    findings.extend(
        (
            RegressionFinding(
                "waiver_expired",
                ",".join(sorted(waiver.case_ids)),
                ",".join(sorted(waiver.metric_names)),
                None,
                None,
                True,
                False,
                waiver.waiver_id,
            )
        )
        for waiver in expired
    )
    for case_id in sorted(set(baseline_cases) & set(current_cases)):
        expected = baseline_cases[case_id]
        current = current_cases[case_id]
        if expected.case_digest != current.case_digest:
            findings.append(_structural("case_definition_changed", case_id=case_id))
        current_metrics = {item.metric_name: item.value for item in current.metrics}
        findings.extend(
            (
                _metric_finding(
                    "missing_metric",
                    case_id,
                    metric_name,
                    expected.metrics[metric_name],
                    None,
                    waivers,
                    at,
                )
            )
            for metric_name in sorted(set(expected.metrics) - set(current_metrics))
        )
        findings.extend(
            (
                RegressionFinding(
                    "new_metric",
                    case_id,
                    metric_name,
                    None,
                    current_metrics[metric_name],
                    False,
                    False,
                )
            )
            for metric_name in sorted(set(current_metrics) - set(expected.metrics))
        )
        for metric_name in sorted(set(expected.metrics) & set(current_metrics)):
            expected_metric = expected.metrics[metric_name]
            current_value = current_metrics[metric_name]
            reason = _regression_reason(expected_metric, current_value)
            if reason is not None:
                findings.append(
                    _metric_finding(
                        reason,
                        case_id,
                        metric_name,
                        expected_metric,
                        current_value,
                        waivers,
                        at,
                    )
                )
        if current.status is not ResultStatus.PASSED:
            findings.append(
                RegressionFinding(
                    "case_failed",
                    case_id,
                    "case_status",
                    Decimal(1),
                    Decimal(0),
                    current.failure.value
                    in {
                        "safety_invariant",
                        "tenant_leakage",
                        "approval_incorrect",
                        "effect_incorrect",
                    },
                    False,
                )
            )
    return BaselineComparison(
        baseline.digest,
        report.metadata.content_digest,
        at,
        tuple(
            sorted(
                findings,
                key=lambda item: (
                    item.case_id,
                    item.metric_name,
                    item.reason_code,
                ),
            )
        ),
    )


def write_baseline(path: Path, baseline: EvaluationBaseline) -> None:
    """Persist only through the explicit update-baseline command."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(canonical_data(baseline), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: Path) -> EvaluationBaseline:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("unsupported baseline schema")
    raw_cases = raw.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("baseline cases must be an array")
    return EvaluationBaseline(
        1,
        _string(raw, "baseline_id"),
        _datetime(raw, "generated_at"),
        _string(raw, "review_reference"),
        _string(raw, "suite_digest"),
        _string(raw, "dataset_digest"),
        tuple(_baseline_case(item) for item in raw_cases),
    )


def load_waivers(path: Path) -> tuple[RegressionWaiver, ...]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("unsupported waiver schema")
    values = raw.get("waivers")
    if not isinstance(values, list):
        raise ValueError("waivers must be an array")
    return tuple(_waiver(item) for item in values)


def _regression_reason(
    baseline: BaselineMetric,
    current: Decimal | None,
) -> str | None:
    if baseline.value is None and current is None:
        return None
    if baseline.value is None or current is None:
        return "metric_applicability_changed"
    if baseline.hard_safety and (
        (baseline.direction is MetricDirection.LOWER_IS_BETTER and current > 0)
        or (baseline.direction is MetricDirection.HIGHER_IS_BETTER and current < 1)
    ):
        return "hard_safety_violation"
    if (
        baseline.direction is MetricDirection.HIGHER_IS_BETTER
        and current + baseline.tolerance < baseline.value
    ):
        return "metric_regressed"
    if (
        baseline.direction is MetricDirection.LOWER_IS_BETTER
        and current - baseline.tolerance > baseline.value
    ):
        return "metric_regressed"
    if (
        baseline.direction is MetricDirection.EXACT
        and abs(current - baseline.value) > baseline.tolerance
    ):
        return "metric_changed"
    return None


def _metric_finding(
    reason_code: str,
    case_id: str,
    metric_name: str,
    baseline: BaselineMetric,
    current: Decimal | None,
    waivers: tuple[RegressionWaiver, ...],
    at: datetime,
) -> RegressionFinding:
    waiver = next(
        (
            item
            for item in waivers
            if not baseline.hard_safety and item.covers(case_id, metric_name, at=at)
        ),
        None,
    )
    return RegressionFinding(
        reason_code,
        case_id,
        metric_name,
        baseline.value,
        current,
        baseline.hard_safety,
        waiver is not None,
        waiver.waiver_id if waiver is not None else None,
    )


def _structural(
    reason_code: str,
    *,
    case_id: str = "__catalog__",
) -> RegressionFinding:
    return RegressionFinding(
        reason_code,
        case_id,
        "__structure__",
        None,
        None,
        True,
        False,
    )


def _baseline_case(value: object) -> BaselineCase:
    if not isinstance(value, dict):
        raise ValueError("baseline case must be an object")
    raw_metrics = value.get("metrics")
    if not isinstance(raw_metrics, dict):
        raise ValueError("baseline case metrics must be an object")
    metrics = {
        str(name): _baseline_metric(metric) for name, metric in raw_metrics.items()
    }
    return BaselineCase(
        _string(value, "case_id"),
        _string(value, "case_digest"),
        _decimal(value, "weight"),
        metrics,
    )


def _baseline_metric(value: object) -> BaselineMetric:
    if not isinstance(value, dict):
        raise ValueError("baseline metric must be an object")
    raw_value = value.get("value")
    return BaselineMetric(
        Decimal(str(raw_value)) if raw_value is not None else None,
        MetricDirection(_string(value, "direction")),
        _decimal(value, "tolerance"),
        _boolean(value, "hard_safety"),
    )


def _waiver(value: object) -> RegressionWaiver:
    if not isinstance(value, dict):
        raise ValueError("waiver must be an object")
    case_ids = value.get("case_ids")
    metric_names = value.get("metric_names")
    if not isinstance(case_ids, list) or not isinstance(metric_names, list):
        raise ValueError("waiver scopes must be arrays")
    if any(not isinstance(item, str) for item in case_ids + metric_names):
        raise ValueError("waiver scopes must contain strings")
    return RegressionWaiver(
        _string(value, "waiver_id"),
        _string(value, "owner"),
        _string(value, "reason"),
        _datetime(value, "expires_at"),
        frozenset(cast(list[str], case_ids)),
        frozenset(cast(list[str], metric_names)),
    )


def _string(value: dict[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"{key} must be a string")
    return result


def _datetime(value: dict[str, object], key: str) -> datetime:
    return datetime.fromisoformat(_string(value, key).replace("Z", "+00:00"))


def _decimal(value: dict[str, object], key: str) -> Decimal:
    result = Decimal(str(value.get(key)))
    if not result.is_finite():
        raise ValueError(f"{key} must be finite")
    return result


def _boolean(value: dict[str, object], key: str) -> bool:
    result = value.get(key)
    if not isinstance(result, bool):
        raise ValueError(f"{key} must be a boolean")
    return result


__all__ = [
    "BaselineCase",
    "BaselineComparison",
    "BaselineMetric",
    "EvaluationBaseline",
    "RegressionFinding",
    "RegressionWaiver",
    "build_baseline",
    "compare_baseline",
    "load_baseline",
    "load_waivers",
    "write_baseline",
]
