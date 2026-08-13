"""Layered deterministic evaluation and optional live-evaluation boundary."""

from aegis_agent_platform.evals.baseline import (
    BaselineComparison,
    EvaluationBaseline,
    RegressionWaiver,
    build_baseline,
    compare_baseline,
)
from aegis_agent_platform.evals.catalog import build_suite
from aegis_agent_platform.evals.contracts import (
    CaseResult,
    DatasetManifest,
    DeterminismContract,
    EvaluationCase,
    EvaluationMode,
    EvaluationReport,
    EvaluationScenario,
    EvaluationSuite,
    ExpectedOutcome,
    FailureTaxonomy,
    FixtureProvenance,
    MetricResult,
    ScorerDefinition,
    SystemFingerprint,
    canonical_digest,
    canonical_json,
)
from aegis_agent_platform.evals.runner import (
    EvaluationRunner,
    RunOptions,
    RunSelection,
)

__all__ = [
    "BaselineComparison",
    "CaseResult",
    "DatasetManifest",
    "DeterminismContract",
    "EvaluationBaseline",
    "EvaluationCase",
    "EvaluationMode",
    "EvaluationReport",
    "EvaluationRunner",
    "EvaluationScenario",
    "EvaluationSuite",
    "ExpectedOutcome",
    "FailureTaxonomy",
    "FixtureProvenance",
    "MetricResult",
    "RegressionWaiver",
    "RunOptions",
    "RunSelection",
    "ScorerDefinition",
    "SystemFingerprint",
    "build_baseline",
    "build_suite",
    "canonical_digest",
    "canonical_json",
    "compare_baseline",
]
