"""Validate Layer 16 release evidence, risks, matrices, and claim boundaries."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualification"
STATUSES = {
    "Implemented",
    "Locally Verified",
    "Environment-Gated",
    "Live Evidence Required",
    "Deferred/Not Claimed",
}
EXPECTED_CATEGORIES = {
    "architecture",
    "security",
    "identity",
    "tenancy",
    "reliability",
    "data",
    "model-safety",
    "connectors",
    "agents",
    "approvals-actions",
    "sandbox",
    "memory",
    "evals",
    "observability-slo",
    "operator-ui",
    "mcp-a2a",
    "supply-chain",
    "deployment",
    "ha-dr",
    "multi-region",
    "performance",
    "compliance",
    "operations",
    "governance",
}
EXPECTED_PERFORMANCE_PROFILES = {
    "api_event_append_read_replay",
    "outbox_worker_throughput_queue_lag",
    "provider_gateway_concurrency_budgets",
    "connector_pagination_correlation",
    "dag_fanout_fanin",
    "approval_effect_flow",
    "sandbox_scheduling_model",
    "pgvector_retrieval_model",
    "eval_runner",
    "protocol_boundary_exchange",
    "ui_bundle_large_timeline",
    "restore_rebuild",
}
REQUIRED_DOCUMENTS = {
    "docs/final-qualification.md",
    "docs/security-assessment.md",
    "docs/performance-chaos-qualification.md",
    "docs/production-readiness-scorecard.md",
    "docs/operational-acceptance.md",
    "docs/compliance-control-map.md",
    "docs/learning-path.md",
    "docs/framework-comparison-handoff.md",
    "docs/repository-governance.md",
    "docs/adr/0027-final-enterprise-qualification.md",
    "CHANGELOG.md",
}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")


def _document(name: str) -> Mapping[str, Any]:
    path = QUALIFICATION / name
    value: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or value.get("schema_version") != 1:
        raise ValueError(f"{path.relative_to(ROOT)} requires schema_version 1")
    return value


def _objects(
    document: Mapping[str, Any],
    key: str,
    *,
    minimum: int,
) -> tuple[Mapping[str, Any], ...]:
    values = document.get(key)
    if not isinstance(values, list) or len(values) < minimum:
        raise ValueError(f"{key} requires at least {minimum} records")
    if any(not isinstance(value, Mapping) for value in values):
        raise ValueError(f"{key} must contain objects")
    return tuple(value for value in values if isinstance(value, Mapping))


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _identifiers(
    values: Sequence[Mapping[str, Any]],
    *,
    field: str = "id",
) -> set[str]:
    identifiers = {_required_text(value.get(field), field) for value in values}
    if len(identifiers) != len(values):
        raise ValueError(f"{field} values must be unique")
    if any(_IDENTIFIER.fullmatch(identifier) is None for identifier in identifiers):
        raise ValueError(f"{field} contains an invalid identifier")
    return identifiers


def _validate_readiness() -> None:
    document = _document("release-readiness.json")
    if document.get("production_ready") is not False:
        raise ValueError("release readiness must remain false")
    if document.get("certification_claimed") is not False:
        raise ValueError("release manifest must not claim certification")
    categories = _objects(document, "categories", minimum=len(EXPECTED_CATEGORIES))
    if _identifiers(categories) != EXPECTED_CATEGORIES:
        raise ValueError("release-readiness categories are incomplete or unexpected")
    for category in categories:
        if category.get("status") not in STATUSES:
            raise ValueError(f"invalid readiness status for {category['id']}")
        _required_text(category.get("owner"), "owner")
        _required_text(category.get("rollback_criteria"), "rollback_criteria")
        commands = category.get("evidence_commands")
        blockers = category.get("blockers")
        if not isinstance(commands, list) or not commands:
            raise ValueError(f"{category['id']} requires evidence commands")
        if not isinstance(blockers, list):
            raise ValueError(f"{category['id']} blockers must be a list")
    gates = _objects(document, "hard_go_live_gates", minimum=6)
    _identifiers(gates)
    for gate in gates:
        for field in ("owner", "evidence_command", "rollback_criteria"):
            _required_text(gate.get(field), field)
        if gate.get("required_status") != "Live Evidence Required":
            raise ValueError("hard go-live gates require live evidence")


def _validate_risks() -> None:
    risks = _objects(_document("residual-risks.json"), "risks", minimum=10)
    _identifiers(risks)
    for risk in risks:
        if risk.get("severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"invalid residual-risk severity: {risk['id']}")
        for field in ("title", "owner", "mitigation", "trigger"):
            _required_text(risk.get(field), field)
        evidence = risk.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"{risk['id']} requires executable evidence")
        target = date.fromisoformat(
            _required_text(risk.get("target_date"), "target_date")
        )
        if risk.get("status") == "open" and target < date.today():
            raise ValueError(f"open residual risk target date passed: {risk['id']}")


def _validate_chaos() -> None:
    scenarios = _objects(_document("chaos-matrix.json"), "scenarios", minimum=16)
    _identifiers(scenarios)
    for scenario in scenarios:
        for field in ("failure", "runbook", "alert"):
            _required_text(scenario.get(field), field)
        invariants = scenario.get("expected_invariants")
        tests = scenario.get("tests")
        if not isinstance(invariants, list) or not invariants:
            raise ValueError(f"{scenario['id']} requires expected invariants")
        if not isinstance(tests, list) or not tests:
            raise ValueError(f"{scenario['id']} requires tests")
        runbook = str(scenario["runbook"]).split("#", maxsplit=1)[0]
        if runbook.startswith("docs/") and not (ROOT / runbook).is_file():
            raise ValueError(f"missing chaos runbook: {runbook}")


def _validate_performance() -> None:
    profiles = _objects(
        _document("performance-budgets.json"),
        "profiles",
        minimum=len(EXPECTED_PERFORMANCE_PROFILES),
    )
    if _identifiers(profiles) != EXPECTED_PERFORMANCE_PROFILES:
        raise ValueError("performance profile coverage is incomplete")
    for profile in profiles:
        if profile.get("gate") not in {"ci-smoke", "environment-gated"}:
            raise ValueError(f"invalid performance gate: {profile['id']}")
        p95 = profile.get("p95_budget_ms")
        errors = profile.get("maximum_error_rate")
        if not isinstance(p95, int | float) or not 1 <= p95 <= 60_000:
            raise ValueError(f"invalid p95 budget: {profile['id']}")
        if not isinstance(errors, int | float) or not 0 <= errors <= 1:
            raise ValueError(f"invalid error budget: {profile['id']}")
        _required_text(profile.get("fixture"), "fixture")
    source = (
        ROOT / "src" / "aegis_agent_platform" / "qualification" / "smoke.py"
    ).read_text(encoding="utf-8")
    missing = sorted(
        profile for profile in EXPECTED_PERFORMANCE_PROFILES if profile not in source
    )
    if missing:
        raise ValueError("load runner misses profiles: " + ", ".join(missing))


def _validate_framework_and_compliance() -> None:
    framework = _document("framework-parity.json")
    for key, minimum in (
        ("candidate_options", 3),
        ("required_parity", 10),
        ("measurable_axes", 8),
        ("framework_removable_custom_code", 5),
        ("controls_that_remain_custom", 5),
        ("escape_hatch_criteria", 5),
    ):
        values = framework.get(key)
        if not isinstance(values, list) or len(values) < minimum:
            raise ValueError(f"framework parity {key} is incomplete")
    controls = _objects(_document("compliance-map.json"), "controls", minimum=12)
    _identifiers(controls)
    for control in controls:
        for key in (
            "concept",
            "code",
            "tests",
            "evidence",
            "missing_live_or_process_evidence",
        ):
            value = control.get(key)
            if key == "concept":
                _required_text(value, key)
            elif not isinstance(value, list) or not value:
                raise ValueError(f"{control['id']} requires {key}")


def _validate_repository_claims() -> None:
    missing = sorted(path for path in REQUIRED_DOCUMENTS if not (ROOT / path).is_file())
    if missing:
        raise ValueError("missing Layer 16 documents: " + ", ".join(missing))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    status = (ROOT / "docs" / "status.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    if "Current status: Layer 16" not in readme:
        raise ValueError("README must identify Layer 16")
    if "Layer 16" not in status:
        raise ValueError("status document must identify Layer 16")
    if "Layer 1 provides architecture" in security:
        raise ValueError("SECURITY.md contains the stale Layer 1 scope warning")
    waiver = _document("../security/vulnerability-waivers.yaml")
    waiver_values = waiver.get("waivers")
    if not isinstance(waiver_values, list):
        raise ValueError("vulnerability waivers must be a list")
    false_positives = {
        value.get("report")
        for value in waiver_values
        if isinstance(value, Mapping)
        and value.get("vulnerability_id") == "CVE-2026-15308"
        and value.get("package_version") == "3.14.7"
        and value.get("disposition") == "false_positive"
        and value.get("scanner") == "grype"
        and value.get("scanner_version") == "0.117.0"
        and str(value.get("advisory_reference", "")).startswith("https://")
        and bool(value.get("verification_evidence"))
    }
    if false_positives != {
        "aegis-agent-platform/linux-amd64",
        "aegis-agent-platform/linux-arm64",
    }:
        raise ValueError("fixed Python scanner disposition is incomplete")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if dockerfile.count("python:3.14.7-slim-bookworm@sha256:") != 2:
        raise ValueError("fixed supported Python 3.14.7 base must be pinned twice")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    for target in (
        "qualification-check:",
        "qualification-demo:",
        "qualification-chaos:",
        "qualification-load:",
        "qualification:",
    ):
        if target not in makefile:
            raise ValueError(f"Makefile misses Layer 16 target: {target}")
    if (
        "final-qualification:" not in workflow
        or "run: make qualification" not in workflow
    ):
        raise ValueError("CI misses the final qualification job")
    if (
        "package-ecosystem: npm" not in dependabot
        or "directory: /frontend" not in dependabot
    ):
        raise ValueError("Dependabot must cover the frontend package graph")
    for ownership in (
        "/src/aegis_agent_platform/qualification/",
        "/qualification/",
        "/security/",
    ):
        if ownership not in codeowners:
            raise ValueError(f"CODEOWNERS misses {ownership}")


def main() -> None:
    _validate_readiness()
    _validate_risks()
    _validate_chaos()
    _validate_performance()
    _validate_framework_and_compliance()
    _validate_repository_claims()


if __name__ == "__main__":
    main()
