"""Deterministic hermetic scenario runner with bounded parallel execution."""

from __future__ import annotations

import asyncio
import hmac
import platform
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from uuid import uuid5

from aegis_agent_platform.evals.contracts import (
    AppliedWaiver,
    CaseResult,
    EvaluationCase,
    EvaluationMode,
    EvaluationReport,
    EvaluationSuite,
    ExpectedOutcome,
    FailureTaxonomy,
    InvariantSeverity,
    MetricDirection,
    ReportMetadata,
    ResultStatus,
    SystemFingerprint,
    canonical_digest,
)
from aegis_agent_platform.evals.governance import load_fixture_documents
from aegis_agent_platform.evals.hermetic import HermeticExecutionGuard
from aegis_agent_platform.evals.probes import ProbeResult, execute_probe
from aegis_agent_platform.evals.scoring import score_observation
from aegis_agent_platform.evals.telemetry import (
    EvaluationMetrics,
    EvaluationTracer,
    evaluation_log,
)


@dataclass(frozen=True, slots=True)
class RunSelection:
    """Stable case filters and shard selection."""

    case_ids: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()
    shard_index: int = 0
    shard_count: int = 1

    def __post_init__(self) -> None:
        if not 1 <= self.shard_count <= 128:
            raise ValueError("shard_count must be between 1 and 128")
        if not 0 <= self.shard_index < self.shard_count:
            raise ValueError("shard_index must be within shard_count")


@dataclass(frozen=True, slots=True)
class RunOptions:
    """Execution bounds that cannot enable network or production effects."""

    source_revision: str
    selection: RunSelection = RunSelection()
    concurrency: int | None = None
    timeout_seconds: int | None = None
    signing_key: bytes | None = None
    signer: str | None = None
    repository_root: Path = Path()

    def __post_init__(self) -> None:
        if not self.source_revision or len(self.source_revision) > 128:
            raise ValueError("source_revision is required and bounded")
        if self.concurrency is not None and not 1 <= self.concurrency <= 32:
            raise ValueError("concurrency must be between 1 and 32")
        if self.timeout_seconds is not None and not 1 <= self.timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be between 1 and 600")
        if (self.signing_key is None) != (self.signer is None):
            raise ValueError("signing_key and signer must be supplied together")
        if self.signing_key is not None and len(self.signing_key) < 32:
            raise ValueError("report signing key must contain at least 32 bytes")
        if not self.repository_root.is_dir():
            raise ValueError("evaluation repository_root must be a directory")


class EvaluationRunner:
    """Run registered probes only; fixture data cannot select arbitrary callables."""

    def __init__(
        self,
        suite: EvaluationSuite,
        *,
        metrics: EvaluationMetrics | None = None,
        tracer: EvaluationTracer | None = None,
        log_sink: Callable[[Mapping[str, str]], None] | None = None,
    ) -> None:
        self._suite = suite
        self._scorers = {item.scorer_id: item for item in suite.scorers}
        self._metrics = metrics or EvaluationMetrics()
        self._tracer = tracer or EvaluationTracer()
        self._log_sink = log_sink or _discard_log

    @property
    def suite(self) -> EvaluationSuite:
        return self._suite

    @property
    def metrics(self) -> Mapping[str, int]:
        """Return bounded aggregate counters without case or tenant labels."""
        return self._metrics.snapshot()

    async def run(
        self,
        options: RunOptions,
        *,
        cancellation: asyncio.Event | None = None,
        waivers: tuple[AppliedWaiver, ...] = (),
    ) -> EvaluationReport:
        """Execute selected cases and return sorted reproducible evidence."""
        selected = self.select(options.selection)
        if not selected:
            raise ValueError("evaluation selection matched no cases")
        concurrency = options.concurrency or self._suite.determinism.concurrency
        timeout = options.timeout_seconds or self._suite.determinism.timeout_seconds
        semaphore = asyncio.Semaphore(concurrency)
        fixture_documents = load_fixture_documents(
            options.repository_root,
            self._suite.dataset,
        )
        fingerprint = self.fingerprint(options.source_revision)
        run_fingerprint = canonical_digest(fingerprint)
        self._metrics.add("eval_runs")
        self._log_sink(
            evaluation_log(
                operation="eval.run",
                outcome="started",
                run_fingerprint=run_fingerprint,
            )
        )

        async def execute(case: EvaluationCase) -> CaseResult:
            with self._tracer.span(
                "eval.case",
                run_fingerprint=run_fingerprint,
                mode=EvaluationMode.DETERMINISTIC.value,
            ):
                async with semaphore:
                    if cancellation is not None and cancellation.is_set():
                        return self._cancelled(case)
                    return await self._run_case(
                        case,
                        timeout,
                        {
                            fixture_id: fixture_documents[fixture_id]
                            for fixture_id in case.fixture_ids
                        },
                    )

        with (
            self._tracer.span(
                "eval.run",
                run_fingerprint=run_fingerprint,
                mode=EvaluationMode.DETERMINISTIC.value,
            ),
            HermeticExecutionGuard(),
        ):
            results = await asyncio.gather(*(execute(case) for case in selected))
        ordered = tuple(sorted(results, key=lambda item: item.case_id))
        self._record_metrics(ordered)
        passed = all(result.status is ResultStatus.PASSED for result in ordered)
        self._log_sink(
            evaluation_log(
                operation="eval.run",
                outcome="passed" if passed else "failed",
                run_fingerprint=run_fingerprint,
            )
        )
        unsigned_content = {
            "schema_version": 1,
            "mode": EvaluationMode.DETERMINISTIC.value,
            "reproducible": True,
            "production_truth": False,
            "fingerprint": fingerprint,
            "results": ordered,
            "waivers": waivers,
        }
        content_digest = canonical_digest(unsigned_content)
        signature = (
            hmac.new(options.signing_key, content_digest.encode(), sha256).hexdigest()
            if options.signing_key is not None
            else None
        )
        metadata = ReportMetadata(
            uuid5(self._suite.determinism.id_namespace, content_digest),
            self._suite.determinism.clock,
            self._suite.digest,
            self._suite.dataset.digest,
            None,
            None,
            content_digest,
            "hmac-sha256" if signature is not None else None,
            options.signer,
            signature,
        )
        return EvaluationReport(
            1,
            EvaluationMode.DETERMINISTIC,
            True,
            False,
            fingerprint,
            ordered,
            waivers,
            metadata,
        )

    def _record_metrics(self, results: tuple[CaseResult, ...]) -> None:
        self._metrics.add("eval_cases", len(results))
        self._metrics.add(
            "eval_passes",
            sum(result.status is ResultStatus.PASSED for result in results),
        )
        self._metrics.add(
            "eval_failures",
            sum(result.status is ResultStatus.FAILED for result in results),
        )
        self._metrics.add(
            "eval_evaluator_errors",
            sum(result.status is ResultStatus.EVALUATOR_ERROR for result in results),
        )
        self._metrics.add(
            "eval_safety_failures",
            sum(
                result.failure is FailureTaxonomy.SAFETY_INVARIANT for result in results
            ),
        )
        self._metrics.add("eval_steps", sum(result.steps for result in results))
        self._metrics.add("eval_tokens", sum(result.token_count for result in results))
        self._metrics.add(
            "eval_cost_microusd",
            int(sum((result.cost_usd for result in results), Decimal(0)) * 1_000_000),
        )

    def select(self, selection: RunSelection) -> tuple[EvaluationCase, ...]:
        """Select in case-id order so test order and catalog order cannot leak in."""
        available = {case.case_id for case in self._suite.cases}
        unknown = selection.case_ids - available
        if unknown:
            raise ValueError(f"unknown evaluation case identifiers: {sorted(unknown)}")
        selected = tuple(
            case
            for case in sorted(self._suite.cases, key=lambda item: item.case_id)
            if (not selection.case_ids or case.case_id in selection.case_ids)
            and (not selection.tags or selection.tags.issubset(set(case.tags)))
        )
        return tuple(
            case
            for index, case in enumerate(selected)
            if index % selection.shard_count == selection.shard_index
        )

    def fingerprint(self, source_revision: str) -> SystemFingerprint:
        """Bind results to all stable evaluator-affecting configuration classes."""
        return SystemFingerprint(
            source_revision,
            canonical_digest(
                {
                    "suite": self._suite.suite_id,
                    "version": self._suite.version,
                    "cases": tuple(case.digest for case in self._suite.cases),
                }
            ),
            canonical_digest(self._suite.determinism),
            canonical_digest(
                {
                    "runtime_policy": "code-enforced",
                    "evaluation_is_not_runtime_truth": True,
                }
            ),
            canonical_digest({"model": "deterministic-fakes-only", "version": "v1"}),
            canonical_digest(
                {"providers": ("scripted", "deterministic-embedding"), "version": "v1"}
            ),
            canonical_digest(
                {"prompt_handling": "untrusted-delimited", "version": "v1"}
            ),
            canonical_digest(
                {
                    "event_compatibility": "additive",
                    "dataset_schema": self._suite.dataset.schema_version,
                    "report_schema": 1,
                }
            ),
            self._suite.version,
            platform.python_version(),
        )

    async def _run_case(
        self,
        case: EvaluationCase,
        timeout_seconds: int,
        fixture_documents: Mapping[str, Mapping[str, object]],
    ) -> CaseResult:
        try:
            probe = await asyncio.wait_for(
                execute_probe(case, fixture_documents=fixture_documents),
                timeout=min(timeout_seconds, case.timeout_seconds),
            )
        except TimeoutError:
            return self._evaluator_failure(
                case,
                FailureTaxonomy.TIMEOUT,
                ("case_timeout",),
            )
        except Exception as error:
            return self._evaluator_failure(
                case,
                FailureTaxonomy.EVALUATOR_FAILURE,
                ("evaluator_exception", type(error).__name__),
            )
        return self._result(case, probe)

    def _result(
        self,
        case: EvaluationCase,
        probe: ProbeResult,
    ) -> CaseResult:
        outcome_correct = probe.outcome is case.expected_outcome
        observation = replace(
            probe.observation,
            outcome_correct=outcome_correct and probe.observation.outcome_correct,
        )
        definitions = tuple(self._scorers[identifier] for identifier in case.scorer_ids)
        metrics = score_observation(observation, definitions)
        invariant_results = {
            invariant.invariant_id: probe.checks.get(invariant.invariant_id, False)
            for invariant in case.invariants
        }
        hard_invariant_failed = any(
            invariant.severity is InvariantSeverity.HARD_SAFETY
            and not invariant_results[invariant.invariant_id]
            for invariant in case.invariants
        )
        hard_metric_failed = any(
            definition.hard_safety
            and _hard_metric_failed(definition.direction, metric.value)
            for definition, metric in zip(definitions, metrics, strict=True)
        )
        required_failed = not all(invariant_results.values())
        failed = (
            not outcome_correct
            or not probe.observation.outcome_correct
            or required_failed
            or hard_metric_failed
        )
        failure = (
            FailureTaxonomy.SAFETY_INVARIANT
            if hard_invariant_failed or hard_metric_failed
            else FailureTaxonomy.OUTCOME_MISMATCH
            if not outcome_correct
            else FailureTaxonomy.POLICY_VIOLATION
            if required_failed
            else FailureTaxonomy.NONE
        )
        reasons = list(probe.reason_codes)
        if not outcome_correct:
            reasons.append("unexpected_outcome")
        reasons.extend(
            f"invariant_failed:{identifier}"
            for identifier, passed in invariant_results.items()
            if not passed
        )
        if hard_metric_failed:
            reasons.append("hard_safety_metric_failed")
        return CaseResult(
            case.case_id,
            case.digest,
            ResultStatus.FAILED if failed else ResultStatus.PASSED,
            probe.outcome,
            failure,
            tuple(sorted(set(reasons))),
            invariant_results,
            metrics,
            (),
            probe.trace,
            observation.steps,
            observation.tokens,
            observation.cost_usd,
            0,
        )

    def _evaluator_failure(
        self,
        case: EvaluationCase,
        failure: FailureTaxonomy,
        reasons: tuple[str, ...],
    ) -> CaseResult:
        return CaseResult(
            case.case_id,
            case.digest,
            ResultStatus.EVALUATOR_ERROR,
            ExpectedOutcome.SAFE_FAILURE,
            failure,
            reasons,
            {invariant.invariant_id: False for invariant in case.invariants},
            (),
            (),
            (),
            0,
            0,
            Decimal(0),
            0,
        )

    def _cancelled(self, case: EvaluationCase) -> CaseResult:
        return CaseResult(
            case.case_id,
            case.digest,
            ResultStatus.CANCELLED,
            ExpectedOutcome.CANCELLED,
            FailureTaxonomy.NONE,
            ("evaluation_cancelled",),
            {invariant.invariant_id: False for invariant in case.invariants},
            (),
            (),
            (),
            0,
            0,
            Decimal(0),
            0,
        )


def _hard_metric_failed(
    direction: MetricDirection,
    value: object,
) -> bool:
    if value is None:
        return False
    numeric = cast_decimal(value)
    if direction is MetricDirection.LOWER_IS_BETTER:
        return numeric > 0
    if direction is MetricDirection.HIGHER_IS_BETTER:
        return numeric < 1
    return numeric != 0


def cast_decimal(value: object) -> Decimal:
    """Narrow helper kept separate for strict type checking."""
    if not isinstance(value, Decimal):
        raise TypeError("metric value must be Decimal")
    return value


def _discard_log(_record: Mapping[str, str]) -> None:
    return None


__all__ = ["EvaluationRunner", "RunOptions", "RunSelection"]
