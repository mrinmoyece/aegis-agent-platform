"""Meta-tests for deterministic evaluation, safety gates, and governance."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_agent_platform.evals import runner as runner_module
from aegis_agent_platform.evals.baseline import (
    RegressionWaiver,
    compare_baseline,
    load_baseline,
)
from aegis_agent_platform.evals.catalog import build_suite
from aegis_agent_platform.evals.cli import catalog_json, main
from aegis_agent_platform.evals.contracts import (
    EvaluationMode,
    EvaluationReport,
    ExecutionTraceReference,
    ExpectedOutcome,
    FailureTaxonomy,
    FixtureClassification,
    FixtureDisposition,
    FixtureProvenance,
    MetricResult,
    ResultStatus,
    canonical_data,
    canonical_digest,
    canonical_json,
)
from aegis_agent_platform.evals.faults import (
    DeterministicFaultInjector,
    FaultAction,
    FaultCutPoint,
    FaultPlan,
)
from aegis_agent_platform.evals.governance import (
    load_dataset_manifest,
    load_fixture_documents,
    migrate_dataset_manifest,
    verify_dataset,
)
from aegis_agent_platform.evals.live import (
    LiveEvaluationConfig,
    LiveEvaluationExecutor,
    LiveTrialBudget,
    LiveTrialResult,
    ModelJudgeConfig,
    confidence_interval,
)
from aegis_agent_platform.evals.probes import ProbeResult, execute_probe
from aegis_agent_platform.evals.reporting import (
    read_report_case_ids,
    validate_report_content,
    write_report_bundle,
)
from aegis_agent_platform.evals.runner import (
    EvaluationRunner,
    RunOptions,
    RunSelection,
)
from aegis_agent_platform.evals.scoring import (
    ScoringObservation,
    default_scorers,
    score_observation,
)
from aegis_agent_platform.evals.telemetry import (
    EvaluationMetrics,
    EvaluationTracer,
    evaluation_log,
)

BASELINE = Path("evals/baselines/canonical-v1.json")
MANIFEST = Path("evals/datasets/checkout-layer11-v1.json")


@pytest.fixture(scope="module")
def full_report() -> EvaluationReport:
    return asyncio.run(
        EvaluationRunner(build_suite()).run(
            RunOptions("c" * 40),
        )
    )


def test_catalog_covers_every_layer_outcome_and_gate_pack() -> None:
    suite = build_suite()

    assert len(suite.cases) == 119
    assert {case.layer for case in suite.cases} == {
        "layer-2",
        "layer-3",
        "layer-4",
        "layer-5",
        "layer-6",
        "layer-7",
        "layer-8",
        "layer-9",
        "layer-10",
        "layer-12",
        "layer-13",
        "layer-14",
        "layer-15",
        "cross-layer",
    }
    assert set(ExpectedOutcome).issubset(
        {case.expected_outcome for case in suite.cases}
    )
    assert sum("adversarial" in case.tags for case in suite.cases) == 12
    assert sum(
        "recovery" in case.tags and "chaos" in case.tags for case in suite.cases
    ) == len(FaultCutPoint)
    assert {
        "gateway.retry-fallback",
        "gateway.permanent-failure",
        "gateway.structured-output-failure",
        "gateway.budget-denial",
        "gateway.stale-worker",
    }.issubset({case.case_id for case in suite.cases})
    assert sum("deployment" in case.tags for case in suite.cases) == 8
    schema_case = next(
        case for case in suite.cases if case.case_id == "adversarial.schema-smuggling"
    )
    assert schema_case.fixture_ids == ("quarantined-malformed-v1",)
    common_operator_invariants = {
        "no_live_network",
        "no_production_effect",
        "bounded_execution",
        "redacted_output",
        "fail_closed",
    }
    operator_invariants = {
        case.case_id: {invariant.invariant_id for invariant in case.invariants}
        - common_operator_invariants
        for case in suite.cases
        if case.layer == "layer-13"
    }
    assert operator_invariants == {
        "operator.server-denial": {"server_denial_authoritative"},
        "operator.exact-approval-scope": {
            "approval_scope_visible",
            "approval_exact",
        },
        "operator.ambiguous-not-success": {"ambiguous_never_success"},
        "operator.tenant-switch-clears": {
            "tenant_switch_clears",
            "tenant_isolation",
        },
        "operator.injected-evidence-data": {"injected_evidence_is_data"},
        "operator.ui-outage-contained": {"ui_outage_contained"},
    }
    protocol_invariants = {
        case.case_id: {invariant.invariant_id for invariant in case.invariants}
        - common_operator_invariants
        for case in suite.cases
        if case.layer == "layer-14"
    }
    assert protocol_invariants == {
        "protocol.a2a-ambiguous-reconciled": {
            "ambiguous_reconciles",
            "replay_convergence",
        },
        "protocol.a2a-self-approval": {
            "approval_exact",
            "peer_cannot_self_approve",
        },
        "protocol.capability-drift": {"capability_drift_quarantines"},
        "protocol.external-policy-injection": {"external_content_is_data"},
        "protocol.mcp-destructive-proposal": {
            "approval_exact",
            "destructive_is_proposal",
        },
        "protocol.outage-contained": {
            "protocol_outage_contained",
            "replay_convergence",
        },
        "protocol.revocation": {"revocation_blocks_calls"},
        "protocol.tenant-isolation": {"tenant_isolation"},
    }
    assert json.loads(catalog_json())[0]["case_id"] == suite.cases[0].case_id


def test_contracts_are_canonical_immutable_and_strict() -> None:
    suite = build_suite()
    first = canonical_json(suite)
    second = canonical_json(suite)

    assert first == second
    assert canonical_digest(suite) == sha256(first.encode()).hexdigest()
    with pytest.raises(TypeError):
        suite.cases[0].parameters["unsafe"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="concurrency"):
        replace(suite.determinism, concurrency=0)


def test_contract_bounds_and_canonical_failures_are_explicit(
    full_report: EvaluationReport,
) -> None:
    suite = build_suite()
    fixture = suite.dataset.fixtures[0]
    case = suite.cases[0]

    for determinism_change in (
        {"clock": suite.determinism.clock.replace(tzinfo=None)},
        {"seed": -1},
        {"timeout_seconds": 0},
    ):
        with pytest.raises(ValueError, match=r".+"):
            replace(suite.determinism, **determinism_change)
    for fixture_change in (
        {"path": "/absolute.json"},
        {"retention_days": 0},
        {
            "disposition": FixtureDisposition.DELETED,
            "deletion_reference": None,
        },
        {
            "synthetic": False,
            "classification": FixtureClassification.RESTRICTED,
        },
    ):
        with pytest.raises(ValueError, match=r".+"):
            replace(fixture, **fixture_change)
    with pytest.raises(ValueError, match="schema"):
        replace(suite.dataset, schema_version=2)
    with pytest.raises(ValueError, match="timezone"):
        replace(suite.dataset, created_at=suite.dataset.created_at.replace(tzinfo=None))
    with pytest.raises(ValueError, match="duplicates"):
        replace(suite.dataset, fixtures=(fixture, fixture))
    with pytest.raises(ValueError, match="unique"):
        replace(
            suite.dataset,
            fixtures=(fixture, replace(fixture, path="other.json")),
        )
    for case_change in (
        {"invariants": ()},
        {"weight": Decimal(0)},
        {"timeout_seconds": 0},
    ):
        with pytest.raises(ValueError, match=r".+"):
            replace(case, **case_change)
    with pytest.raises(ValueError, match="cases"):
        replace(suite, cases=())
    with pytest.raises(ValueError, match="case identifiers"):
        replace(suite, cases=(suite.cases[0], suite.cases[0]))
    with pytest.raises(ValueError, match="dataset and suite"):
        replace(suite, cases=suite.cases[1:])
    with pytest.raises(ValueError, match="unknown scorer"):
        replace(
            suite,
            cases=(replace(case, scorer_ids=("unknown",)), *suite.cases[1:]),
        )
    with pytest.raises(ValueError, match="unknown fixture"):
        replace(
            suite,
            cases=(replace(case, fixture_ids=("unknown",)), *suite.cases[1:]),
        )
    extra_fixture = replace(
        fixture,
        fixture_id="unreferenced",
        path="evals/fixtures/unreferenced.json",
    )
    with pytest.raises(ValueError, match="every governed fixture"):
        replace(
            suite,
            dataset=replace(
                suite.dataset,
                fixtures=(*suite.dataset.fixtures, extra_fixture),
            ),
        )
    with pytest.raises(ValueError, match="cover every case"):
        replace(
            suite,
            scenarios=(
                replace(suite.scenarios[0], case_ids=()),
                *suite.scenarios[1:],
            ),
        )
    with pytest.raises(ValueError, match="ordinal"):
        ExecutionTraceReference("phase", -1)
    with pytest.raises(ValueError, match="negative"):
        MetricResult(
            "metric",
            "scorer",
            "v1",
            Decimal(0),
            Decimal(-1),
            Decimal(1),
            (),
        )
    with pytest.raises(ValueError, match="accounting"):
        replace(full_report.results[0], steps=-1)
    with pytest.raises(ValueError, match="signature"):
        replace(full_report.metadata, signer="incomplete")
    with pytest.raises(ValueError, match="production truth"):
        replace(full_report, production_truth=True)
    with pytest.raises(ValueError, match="non-reproducible"):
        replace(
            full_report,
            mode=EvaluationMode.LIVE,
            reproducible=True,
        )
    with pytest.raises(ValueError, match="finite"):
        canonical_data(float("inf"))
    with pytest.raises(ValueError, match="finite"):
        canonical_data(Decimal("NaN"))
    with pytest.raises(ValueError, match="timezone"):
        canonical_data(datetime(2026, 1, 1))
    with pytest.raises(TypeError, match="keys"):
        canonical_data({1: "not-a-string-key"})
    with pytest.raises(TypeError, match="unsupported"):
        canonical_data(object())


def test_runner_is_repeatable_and_order_independent() -> None:
    suite = build_suite()
    reversed_suite = replace(suite, cases=tuple(reversed(suite.cases)))

    first = asyncio.run(EvaluationRunner(suite).run(RunOptions("d" * 40)))
    second = asyncio.run(EvaluationRunner(reversed_suite).run(RunOptions("d" * 40)))

    assert canonical_data(first) == canonical_data(second)
    assert first.metadata.content_digest == second.metadata.content_digest


def test_shards_are_equivalent_to_unsharded_run(
    full_report: EvaluationReport,
) -> None:
    suite = build_suite()
    shards = tuple(
        asyncio.run(
            EvaluationRunner(suite).run(
                RunOptions(
                    "c" * 40,
                    RunSelection(shard_index=index, shard_count=4),
                )
            )
        )
        for index in range(4)
    )
    combined = tuple(
        sorted(
            (result for shard in shards for result in shard.results),
            key=lambda result: result.case_id,
        )
    )

    assert combined == full_report.results


def test_scorers_define_denominators_boundaries_and_reason_codes() -> None:
    definitions = default_scorers()
    observation = ScoringObservation(
        outcome_correct=True,
        expected_evidence_ids=frozenset({"a", "b"}),
        observed_evidence_ids=frozenset({"a", "c"}),
        valid_citations=1,
        total_citations=2,
        supported_claims=3,
        total_claims=4,
        handled_contradictions=1,
        total_contradictions=2,
        confidence_samples=((Decimal("0.75"), True),),
        abstention_expected=True,
        abstained=True,
        safety_violations=0,
        policy_checks=4,
        approval_checks=2,
        correct_approvals=2,
        effect_checks=1,
        correct_effects=1,
        verified_effects=1,
        recovery_expected=True,
        recovery_converged=True,
        privacy_checks=2,
        privacy_exposures=0,
        steps=7,
        tokens=50,
        budget_tokens=100,
        ranked_ids=("irrelevant", "a"),
        relevant_ranked_ids=frozenset({"a"}),
    )
    results = {
        item.metric_name: item for item in score_observation(observation, definitions)
    }

    assert results["evidence_precision"].value == Decimal("0.5")
    assert results["evidence_recall"].value == Decimal("0.5")
    assert results["unsupported_claim_rate"].value == Decimal("0.25")
    assert results["confidence_calibration_error"].value == Decimal("0.25")
    assert results["memory_retrieval_mrr"].value == Decimal("0.5")
    assert results["token_budget_utilization"].value == Decimal("0.5")

    not_applicable = score_observation(ScoringObservation(True), definitions)
    assert all(
        item.value is None and item.reason_codes == ("not_applicable",)
        for item in not_applicable
        if item.denominator == 0
    )


def test_full_report_has_no_safety_or_evaluator_failures(
    full_report: EvaluationReport,
) -> None:
    assert full_report.passed
    assert all(result.status is ResultStatus.PASSED for result in full_report.results)
    assert all(result.failure is FailureTaxonomy.NONE for result in full_report.results)
    assert all(not result.citations for result in full_report.results)


def test_report_signing_is_optional_explicit_and_stable() -> None:
    selection = RunSelection(frozenset({"identity.cross-tenant"}))
    report = asyncio.run(
        EvaluationRunner(build_suite()).run(
            RunOptions(
                "e" * 40,
                selection,
                signing_key=b"x" * 32,
                signer="local-review-key",
            )
        )
    )

    assert report.metadata.signature_algorithm == "hmac-sha256"
    assert report.metadata.signer == "local-review-key"
    assert report.metadata.signature is not None
    assert len(report.metadata.signature) == 64


def test_checked_baseline_and_manifest_match_executable_catalog(
    full_report: EvaluationReport,
) -> None:
    suite = build_suite()
    baseline = load_baseline(BASELINE)
    manifest = load_dataset_manifest(MANIFEST)

    assert manifest.digest == suite.dataset.digest
    assert verify_dataset(Path.cwd(), manifest).passed
    assert compare_baseline(
        suite,
        baseline,
        full_report,
        at=suite.determinism.clock,
    ).passed


def test_baseline_detects_tamper_missing_and_new_cases(
    full_report: EvaluationReport,
) -> None:
    suite = build_suite()
    baseline = load_baseline(BASELINE)
    tampered = replace(baseline, suite_digest="0" * 64)
    missing = replace(full_report, results=full_report.results[1:])
    extra_result = replace(
        full_report.results[0],
        case_id="unknown.synthetic-case",
    )
    extra = replace(full_report, results=(*full_report.results, extra_result))

    assert {
        item.reason_code
        for item in compare_baseline(
            suite,
            tampered,
            full_report,
            at=suite.determinism.clock,
        ).findings
    } == {"suite_digest_changed"}
    assert "missing_case" in {
        item.reason_code
        for item in compare_baseline(
            suite,
            baseline,
            missing,
            at=suite.determinism.clock,
        ).findings
    }
    assert "new_case" in {
        item.reason_code
        for item in compare_baseline(
            suite,
            baseline,
            extra,
            at=suite.determinism.clock,
        ).findings
    }


def test_waiver_scope_expiry_and_hard_safety_are_fail_closed(
    full_report: EvaluationReport,
) -> None:
    suite = build_suite()
    baseline = load_baseline(BASELINE)
    case = full_report.results[0]
    metrics = tuple(
        replace(metric, value=Decimal(99))
        if metric.metric_name == "latency_step_count"
        else metric
        for metric in case.metrics
    )
    regressed = replace(
        full_report,
        results=(replace(case, metrics=metrics), *full_report.results[1:]),
    )
    waiver = RegressionWaiver(
        "waiver-quality",
        "eval-owner",
        "Temporary bounded quality regression.",
        suite.determinism.clock.replace(year=2027),
        frozenset({case.case_id}),
        frozenset({"latency_step_count"}),
    )
    comparison = compare_baseline(
        suite,
        baseline,
        regressed,
        at=suite.determinism.clock,
        waivers=(waiver,),
    )

    assert any(
        finding.metric_name == "latency_step_count" and finding.waived
        for finding in comparison.findings
    )
    expired = replace(waiver, expires_at=suite.determinism.clock)
    assert "waiver_expired" in {
        finding.reason_code
        for finding in compare_baseline(
            suite,
            baseline,
            regressed,
            at=suite.determinism.clock,
            waivers=(expired,),
        ).findings
    }

    safety_metrics = tuple(
        replace(metric, value=Decimal(1), numerator=Decimal(1))
        if metric.metric_name == "policy_safety_violation_rate"
        else metric
        for metric in case.metrics
    )
    unsafe = replace(
        full_report,
        results=(replace(case, metrics=safety_metrics), *full_report.results[1:]),
    )
    unsafe_waiver = replace(
        waiver,
        metric_names=frozenset({"policy_safety_violation_rate"}),
    )
    unsafe_comparison = compare_baseline(
        suite,
        baseline,
        unsafe,
        at=suite.determinism.clock,
        waivers=(unsafe_waiver,),
    )
    assert any(
        finding.reason_code == "hard_safety_violation" and not finding.waived
        for finding in unsafe_comparison.findings
    )


def test_fault_hooks_must_be_covered_exactly() -> None:
    suite = build_suite()
    cases = {case.case_id: case for case in suite.cases}
    fixtures = load_fixture_documents(Path.cwd(), suite.dataset)
    for cut_point in FaultCutPoint:
        injector = DeterministicFaultInjector((FaultPlan(cut_point, FaultAction.DROP),))
        with pytest.raises(AssertionError, match="not reached"):
            injector.assert_complete()
        assert injector.visit(cut_point) is FaultAction.DROP
        injector.assert_complete()

        runtime_injector = DeterministicFaultInjector(
            (FaultPlan(cut_point, FaultAction.DROP),)
        )
        case = cases[f"fault.{cut_point.value}"]
        result = asyncio.run(
            execute_probe(
                case,
                fault_injector=runtime_injector,
                fixture_documents={
                    fixture_id: fixtures[fixture_id] for fixture_id in case.fixture_ids
                },
            )
        )
        runtime_injector.assert_complete()
        assert result.outcome is ExpectedOutcome.RECOVERED
        assert result.checks["replay_convergence"]


def test_fixture_tamper_secret_and_manifest_migration_fail_closed(
    tmp_path: Path,
) -> None:
    suite = build_suite()
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text('{"api_key":"syntheticcredentialvalue"}', encoding="utf-8")
    fixture = FixtureProvenance(
        "synthetic-secret",
        "fixture.json",
        sha256(fixture_path.read_bytes()).hexdigest(),
        "synthetic",
        "CC0-1.0",
        "synthetic-no-human-subject",
        FixtureClassification.INTERNAL,
        30,
        True,
        True,
    )
    manifest = replace(suite.dataset, fixtures=(fixture,))
    report = verify_dataset(tmp_path, manifest)

    assert {item.reason_code for item in report.findings} == {"fixture_secret_detected"}
    fixture_path.write_text('{"safe":true}', encoding="utf-8")
    assert "fixture_digest_mismatch" in {
        item.reason_code for item in verify_dataset(tmp_path, manifest).findings
    }
    loaded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert migrate_dataset_manifest(loaded).digest == suite.dataset.digest
    loaded["schema_version"] = 999
    with pytest.raises(ValueError, match="no migration"):
        migrate_dataset_manifest(loaded)


def test_fixture_governance_rejects_unsafe_shapes_and_lifecycle_states(
    tmp_path: Path,
) -> None:
    suite = build_suite()
    template = suite.dataset.fixtures[0]

    def fixture_for(
        name: str,
        content: bytes | None,
        *,
        redacted: bool = True,
        classification: FixtureClassification = FixtureClassification.INTERNAL,
        disposition: FixtureDisposition = FixtureDisposition.ACTIVE,
        deletion_reference: str | None = None,
    ) -> FixtureProvenance:
        if content is not None:
            (tmp_path / name).write_bytes(content)
        return replace(
            template,
            fixture_id=name,
            path=name,
            content_digest=sha256(content or b"").hexdigest(),
            redacted=redacted,
            classification=classification,
            disposition=disposition,
            deletion_reference=deletion_reference,
        )

    target = tmp_path / "target.json"
    target.write_text('{"safe":true}', encoding="utf-8")
    (tmp_path / "linked.json").symlink_to(target)
    fixtures = (
        fixture_for("missing.json", None),
        fixture_for("oversized.json", b"x" * 1_000_001),
        fixture_for("invalid.json", b"\xff"),
        fixture_for("array.json", b"[]"),
        fixture_for("pii.json", b'{"email":"person@corp.test"}'),
        fixture_for(
            "not-ci.json",
            b'{"safe":true}',
            redacted=False,
            classification=FixtureClassification.CONFIDENTIAL,
        ),
        fixture_for(
            "deleted.json",
            b'{"safe":true}',
            disposition=FixtureDisposition.DELETED,
            deletion_reference="deletion-ticket-1",
        ),
        replace(
            template,
            fixture_id="linked.json",
            path="linked.json",
            content_digest=sha256(target.read_bytes()).hexdigest(),
        ),
    )
    report = verify_dataset(tmp_path, replace(suite.dataset, fixtures=fixtures))
    assert {
        "fixture_missing",
        "fixture_oversized",
        "fixture_invalid_json",
        "fixture_invalid_root",
        "fixture_pii_detected",
        "fixture_not_ci_eligible",
        "deleted_fixture_present",
        "fixture_symlink",
    }.issubset({finding.reason_code for finding in report.findings})

    manifest_path = tmp_path / "bad-manifest.json"
    manifest_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="root"):
        load_dataset_manifest(manifest_path)
    manifest_path.write_text('{"schema_version":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        load_dataset_manifest(manifest_path)
    manifest_path.write_text(
        '{"schema_version":1,"fixtures":{},"case_ids":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="arrays"):
        load_dataset_manifest(manifest_path)
    with pytest.raises(ValueError, match="arrays"):
        migrate_dataset_manifest({"schema_version": 1, "fixtures": [], "case_ids": {}})
    with pytest.raises(ValueError, match="entry"):
        migrate_dataset_manifest(
            {
                "schema_version": 1,
                "dataset_id": "x",
                "version": "1",
                "description": "x",
                "created_at": "2026-01-01T00:00:00Z",
                "fixtures": [1],
                "case_ids": [],
            }
        )
    raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
    raw["case_ids"] = [1]
    with pytest.raises(ValueError, match="contain strings"):
        migrate_dataset_manifest(raw)


def test_report_outputs_are_bounded_redacted_and_replayable(
    tmp_path: Path,
    full_report: EvaluationReport,
) -> None:
    first = write_report_bundle(tmp_path / "first", full_report)
    second = write_report_bundle(tmp_path / "second", full_report)

    assert first.json.read_bytes() == second.json.read_bytes()
    assert first.markdown.read_bytes() == second.markdown.read_bytes()
    assert first.junit.read_bytes() == second.junit.read_bytes()
    assert read_report_case_ids(first.json) == tuple(
        result.case_id for result in full_report.results
    )
    assert "release evidence only" in first.markdown.read_text(encoding="utf-8")
    failed_result = replace(
        full_report.results[0],
        status=ResultStatus.FAILED,
        failure=FailureTaxonomy.SAFETY_INVARIANT,
        reason_codes=("intent_before_effect",),
    )
    failed_report = replace(
        full_report,
        results=(failed_result, *full_report.results[1:]),
    )
    failed_paths = write_report_bundle(tmp_path / "failed", failed_report)
    assert "## Failures" in failed_paths.markdown.read_text(encoding="utf-8")
    assert 'failures="1"' in failed_paths.junit.read_text(encoding="utf-8")

    baseline = load_baseline(BASELINE)
    case = full_report.results[0]
    metrics = tuple(
        replace(metric, value=Decimal(99))
        if metric.metric_name == "latency_step_count"
        else metric
        for metric in case.metrics
    )
    regressed = replace(
        full_report,
        results=(replace(case, metrics=metrics), *full_report.results[1:]),
    )
    comparison = compare_baseline(
        build_suite(),
        baseline,
        regressed,
        at=build_suite().determinism.clock,
    )
    compared_paths = write_report_bundle(
        tmp_path / "comparison",
        regressed,
        comparison=comparison,
    )
    assert "Baseline comparison" in compared_paths.markdown.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content("authorization: Bearer syntheticcredential")
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content("customer_email=person@corp.test")
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content("tenant=customer-a")
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"tenant_id":"customer-a"}')
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"api_key":"syntheticcredentialvalue"}')
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content("phone=+15551234567")
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content("ssn=123-45-6789")
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"contact":"15551234567"}')
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"note":"reach eval-user@example.invalid now"}')
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"note":"tenant_id=customer-a must remain private"}')
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"note":"call +15551234567 before release"}')
    with pytest.raises(ValueError, match="sensitive"):
        validate_report_content('{"note":"synthetic SSN 123-45-6789 must be removed"}')
    validate_report_content('{"trace_id":"12345678-1234-4234-8234-123456789012"}')


def test_cancellation_and_evaluator_failure_are_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = build_suite()
    selection = RunSelection(frozenset({"identity.cross-tenant"}))
    cancellation = asyncio.Event()
    cancellation.set()
    cancelled = asyncio.run(
        EvaluationRunner(suite).run(
            RunOptions("f" * 40, selection),
            cancellation=cancellation,
        )
    )
    assert cancelled.results[0].status is ResultStatus.CANCELLED

    async def broken_probe(
        case: object,
        *,
        fault_injector: object = None,
        fixture_documents: object = None,
    ) -> ProbeResult:
        del case, fault_injector, fixture_documents
        raise RuntimeError("synthetic evaluator bug")

    monkeypatch.setattr(runner_module, "execute_probe", broken_probe)
    failed = asyncio.run(EvaluationRunner(suite).run(RunOptions("f" * 40, selection)))
    assert failed.results[0].status is ResultStatus.EVALUATOR_ERROR
    assert failed.results[0].failure is FailureTaxonomy.EVALUATOR_FAILURE


def test_timeout_is_bounded_and_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = build_suite()
    selection = RunSelection(frozenset({"identity.cross-tenant"}))

    async def slow_probe(
        case: object,
        *,
        fault_injector: object = None,
        fixture_documents: object = None,
    ) -> ProbeResult:
        del case, fault_injector, fixture_documents
        await asyncio.sleep(2)
        raise AssertionError("wait_for should cancel this probe")

    monkeypatch.setattr(runner_module, "execute_probe", slow_probe)
    report = asyncio.run(
        EvaluationRunner(suite).run(RunOptions("1" * 40, selection, timeout_seconds=1))
    )
    assert report.results[0].failure is FailureTaxonomy.TIMEOUT
    assert report.results[0].status is ResultStatus.EVALUATOR_ERROR


def test_hermetic_runner_blocks_network_and_process_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = build_suite()
    selection = RunSelection(frozenset({"identity.cross-tenant"}))

    async def network_probe(
        case: object,
        *,
        fault_injector: object = None,
        fixture_documents: object = None,
    ) -> ProbeResult:
        import socket

        del case, fault_injector, fixture_documents
        socket.socket()
        raise AssertionError("network guard did not fail closed")

    monkeypatch.setattr(runner_module, "execute_probe", network_probe)
    network = asyncio.run(EvaluationRunner(suite).run(RunOptions("2" * 40, selection)))
    assert network.results[0].status is ResultStatus.EVALUATOR_ERROR
    assert network.results[0].failure is FailureTaxonomy.EVALUATOR_FAILURE

    async def process_probe(
        case: object,
        *,
        fault_injector: object = None,
        fixture_documents: object = None,
    ) -> ProbeResult:
        import subprocess

        del case, fault_injector, fixture_documents
        subprocess.Popen(("echo", "unsafe"))  # noqa: S607
        raise AssertionError("process guard did not fail closed")

    monkeypatch.setattr(runner_module, "execute_probe", process_probe)
    process = asyncio.run(EvaluationRunner(suite).run(RunOptions("3" * 40, selection)))
    assert process.results[0].status is ResultStatus.EVALUATOR_ERROR
    assert process.results[0].failure is FailureTaxonomy.EVALUATOR_FAILURE

    async def spawn_probe(
        case: object,
        *,
        fault_injector: object = None,
        fixture_documents: object = None,
    ) -> ProbeResult:
        import os

        del case, fault_injector, fixture_documents
        os.spawnv(os.P_WAIT, "/bin/echo", ("echo", "unsafe"))  # noqa: S606
        raise AssertionError("spawn guard did not fail closed")

    monkeypatch.setattr(runner_module, "execute_probe", spawn_probe)
    spawned = asyncio.run(EvaluationRunner(suite).run(RunOptions("4" * 40, selection)))
    assert spawned.results[0].status is ResultStatus.EVALUATOR_ERROR
    assert spawned.results[0].failure is FailureTaxonomy.EVALUATOR_FAILURE


def test_live_and_model_judge_boundaries_are_disabled_and_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(ValueError, match="acknowledgement"):
        LiveEvaluationConfig(
            "no",
            {"provider": "secret-ref://live/provider"},
            frozenset({"live-eval-tenant"}),
            2,
            Decimal("1"),
            10,
            5,
        )
    config = LiveEvaluationConfig(
        "I_UNDERSTAND_NON_REPRODUCIBLE_LIVE_EVAL",
        {"provider": "secret-ref://live/provider"},
        frozenset({"live-eval-tenant"}),
        2,
        Decimal("1"),
        10,
        5,
    )
    assert not config.production_effects_allowed
    interval = confidence_interval(
        (Decimal("0.5"), Decimal("1.0")),
        Decimal("0.01"),
    )
    assert interval.non_reproducible
    assert interval.lower_95 <= interval.mean <= interval.upper_95
    clock = [0.0]

    async def advance(seconds: float) -> None:
        clock[0] += seconds

    class FakeLiveAdapter:
        adapter_id = "fake-live"

        async def run_trial(
            self,
            *,
            case_id: str,
            tenant_id: str,
            trial: int,
            budget: LiveTrialBudget,
        ) -> LiveTrialResult:
            del case_id, tenant_id, trial
            assert budget.read_only
            assert not budget.production_effects_allowed
            return LiveTrialResult(
                Decimal("1"),
                Decimal("0.01"),
                5,
                False,
                False,
            )

    executor = LiveEvaluationExecutor(
        {"fake-live": FakeLiveAdapter()},
        clock=lambda: clock[0],
        sleep=advance,
    )
    result = asyncio.run(
        executor.run(
            adapter_id="fake-live",
            case_id="gateway.success",
            tenant_id="live-eval-tenant",
            config=replace(config, time_cap_seconds=30, requests_per_minute=60),
        )
    )
    assert result.samples == 2
    assert clock[0] == 1
    with pytest.raises(TimeoutError, match="rate limit"):
        asyncio.run(
            executor.run(
                adapter_id="fake-live",
                case_id="gateway.success",
                tenant_id="live-eval-tenant",
                config=replace(
                    config,
                    time_cap_seconds=1,
                    requests_per_minute=1,
                ),
            )
        )
    with pytest.raises(ValueError, match="sole safety"):
        ModelJudgeConfig(sole_safety_gate=True)


def test_live_executor_fails_closed_on_every_runtime_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = LiveEvaluationConfig(
        "I_UNDERSTAND_NON_REPRODUCIBLE_LIVE_EVAL",
        {"provider": "secret-ref://live/provider"},
        frozenset({"live-eval-tenant"}),
        1,
        Decimal("1"),
        10,
        60,
    )
    with pytest.raises(ValueError, match="secret references"):
        replace(config, credential_references={})
    with pytest.raises(ValueError, match="allowlist"):
        replace(config, tenant_allowlist=frozenset())
    with pytest.raises(ValueError, match="sample_cap"):
        replace(config, sample_cap=0)
    with pytest.raises(ValueError, match="spend cap"):
        replace(config, spend_cap_usd=Decimal(0))
    with pytest.raises(ValueError, match="time cap"):
        replace(config, time_cap_seconds=0)
    with pytest.raises(ValueError, match="rate limit"):
        replace(config, requests_per_minute=0)
    with pytest.raises(ValueError, match="PII"):
        replace(config, pii_allowed=True)
    with pytest.raises(ValueError, match="production effects"):
        replace(config, production_effects_allowed=True)
    with pytest.raises(ValueError, match="score"):
        LiveTrialResult(Decimal("2"), Decimal(0), 0, False, False)
    with pytest.raises(ValueError, match="negative"):
        LiveTrialResult(Decimal(1), Decimal("-1"), 0, False, False)
    with pytest.raises(ValueError, match="restricted"):
        LiveTrialResult(
            Decimal(1),
            Decimal(0),
            0,
            False,
            False,
            "file:///unsafe",
        )
    with pytest.raises(ValueError, match="versioned"):
        ModelJudgeConfig(enabled=True)
    with pytest.raises(ValueError, match="scores"):
        confidence_interval((), Decimal(0))
    with pytest.raises(ValueError, match="between zero"):
        confidence_interval((Decimal("2"),), Decimal(0))

    class UnsafeAdapter:
        adapter_id = "unsafe"

        def __init__(self, result: LiveTrialResult) -> None:
            self.result = result

        async def run_trial(
            self,
            *,
            case_id: str,
            tenant_id: str,
            trial: int,
            budget: LiveTrialBudget,
        ) -> LiveTrialResult:
            del case_id, tenant_id, trial
            assert budget.max_cost_usd <= config.spend_cap_usd
            return self.result

    safe = LiveTrialResult(Decimal(1), Decimal(0), 1, False, False)
    executor = LiveEvaluationExecutor({"unsafe": UnsafeAdapter(safe)})
    monkeypatch.setenv("CI", "true")
    with pytest.raises(RuntimeError, match="prohibited"):
        asyncio.run(
            executor.run(
                adapter_id="unsafe",
                case_id="gateway.success",
                tenant_id="live-eval-tenant",
                config=config,
            )
        )
    monkeypatch.delenv("CI")
    with pytest.raises(PermissionError, match="allowlisted"):
        asyncio.run(
            executor.run(
                adapter_id="unsafe",
                case_id="gateway.success",
                tenant_id="not-allowlisted",
                config=config,
            )
        )
    with pytest.raises(ValueError, match="registered"):
        asyncio.run(
            executor.run(
                adapter_id="missing",
                case_id="gateway.success",
                tenant_id="live-eval-tenant",
                config=config,
            )
        )

    violations = (
        (
            LiveTrialResult(Decimal(1), Decimal(0), 1, True, False),
            "containment",
            config,
        ),
        (
            LiveTrialResult(Decimal(1), Decimal("2"), 1, False, False),
            "spend cap",
            config,
        ),
        (
            LiveTrialResult(Decimal(1), Decimal(0), 11_000, False, False),
            "duration",
            config,
        ),
        (
            LiveTrialResult(
                Decimal(1),
                Decimal(0),
                1,
                False,
                False,
                "aegis-restricted-object://result",
            ),
            "retention",
            config,
        ),
    )
    for result, message, bounded_config in violations:
        failing = LiveEvaluationExecutor({"unsafe": UnsafeAdapter(result)})
        with pytest.raises((RuntimeError, TimeoutError), match=message):
            asyncio.run(
                failing.run(
                    adapter_id="unsafe",
                    case_id="gateway.success",
                    tenant_id="live-eval-tenant",
                    config=bounded_config,
                )
            )


def test_cli_covers_list_run_replay_compare_and_reviewed_updates(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_directory = tmp_path / "run"
    replay_directory = tmp_path / "replay"
    compare_directory = tmp_path / "compare"
    baseline_path = tmp_path / "baseline.json"
    manifest_path = tmp_path / "manifest.json"

    assert main(["list"]) == 0
    assert "gateway.retry-fallback" in capsys.readouterr().out
    assert main(["check-fixtures"]) == 0
    assert (
        main(
            [
                "run",
                "--case",
                "gateway.retry-fallback",
                "--concurrency",
                "1",
                "--timeout",
                "10",
                "--output",
                str(run_directory),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "replay",
                str(run_directory / "report.json"),
                "--output",
                str(replay_directory),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "compare",
                "--output",
                str(compare_directory),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "update-baseline",
                "--baseline",
                str(baseline_path),
                "--review-reference",
                "meta-test-review",
                "--yes",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "write-manifest",
                "--manifest",
                str(manifest_path),
                "--yes",
            ]
        )
        == 0
    )
    assert baseline_path.is_file()
    assert manifest_path.is_file()
    assert (run_directory / "report.json").read_bytes() == (
        replay_directory / "report.json"
    ).read_bytes()

    with pytest.raises(SystemExit):
        main(["write-manifest", "--manifest", str(manifest_path)])
    with pytest.raises(SystemExit):
        main(
            [
                "update-baseline",
                "--baseline",
                str(baseline_path),
                "--review-reference",
                "missing-confirmation",
            ]
        )


def test_observability_is_bounded_and_content_free() -> None:
    fingerprint = "a" * 64
    metrics = EvaluationMetrics()
    metrics.add("eval_runs")
    metrics.add("eval_cases", 2)
    assert metrics.snapshot() == {"eval_cases": 2, "eval_runs": 1}
    with pytest.raises(ValueError, match="unrecognized"):
        metrics.add("tenant-eval-a")
    with pytest.raises(ValueError, match="negative"):
        metrics.add("eval_runs", -1)

    record = evaluation_log(
        operation="eval.run",
        outcome="failed",
        run_fingerprint=fingerprint,
        reason_code="hard_safety_violation",
    )
    assert record == {
        "operation": "eval.run",
        "outcome": "failed",
        "reason_code": "hard_safety_violation",
        "run_fingerprint": fingerprint,
    }
    with pytest.raises(ValueError, match="operation"):
        evaluation_log(
            operation="tenant-eval-a",
            outcome="failed",
            run_fingerprint=fingerprint,
        )
    with pytest.raises(ValueError, match="outcome"):
        evaluation_log(
            operation="eval.run",
            outcome="unsafe-content",
            run_fingerprint=fingerprint,
        )
    with pytest.raises(ValueError, match="fingerprint"):
        evaluation_log(
            operation="eval.run",
            outcome="passed",
            run_fingerprint="short",
        )
    with pytest.raises(ValueError, match="reason_code"):
        evaluation_log(
            operation="eval.run",
            outcome="failed",
            run_fingerprint=fingerprint,
            reason_code="raw content is prohibited",
        )

    tracer = EvaluationTracer()
    with tracer.span(
        "eval.run",
        run_fingerprint=fingerprint,
        mode="deterministic",
    ):
        pass
    with (
        pytest.raises(ValueError, match="operation"),
        tracer.span(
            "tenant-eval-a",
            run_fingerprint=fingerprint,
            mode="deterministic",
        ),
    ):
        pass
    with (
        pytest.raises(ValueError, match="attributes"),
        tracer.span(
            "eval.run",
            run_fingerprint="short",
            mode="deterministic",
        ),
    ):
        pass

    logs: list[dict[str, str]] = []
    runner = EvaluationRunner(
        build_suite(),
        log_sink=lambda record: logs.append(dict(record)),
    )
    report = asyncio.run(
        runner.run(
            RunOptions(
                "a" * 40,
                RunSelection(frozenset({"gateway.retry-fallback"})),
            )
        )
    )
    assert report.passed
    assert runner.metrics["eval_runs"] == 1
    assert runner.metrics["eval_cases"] == 1
    assert [record["outcome"] for record in logs] == ["started", "passed"]
    assert all(
        set(record) <= {"operation", "outcome", "run_fingerprint"} for record in logs
    )
