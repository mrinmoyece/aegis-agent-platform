"""Deterministic redacted JSON, Markdown, and JUnit evaluation reports."""

from __future__ import annotations

import json
import re
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from aegis_agent_platform.evals.baseline import BaselineComparison
from aegis_agent_platform.evals.contracts import (
    EvaluationReport,
    ResultStatus,
    canonical_data,
)

MAX_REPORT_BYTES = 5_000_000
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+"),
    re.compile(
        r"""(?i)\b(?:password|client_secret|api[_-]?key|token)["']?\s*"""
        r"""[=:]\s*["']?\S+"""
    ),
)
_PII_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(
        r"(?<![\w-])(?:\+\d{1,3}[- .]?)?(?:\(\d{2,4}\)|\d{2,4})"
        r"[- .]\d{3,4}[- .]\d{3,4}(?![\w-])"
    ),
    re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
)
_RAW_TENANT = re.compile(
    r"""(?i)\btenant(?:[_ -]?id)?["']?\s*[=:]\s*["']?[A-Za-z0-9_-]+"""
)
_FORBIDDEN_JSON_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "client_secret",
        "email",
        "password",
        "phone",
        "prompt",
        "raw_evidence",
        "raw_memory",
        "ssn",
        "tenant",
        "tenant_id",
        "token",
    }
)
_COMPACT_PHONE = re.compile(r"\+?[1-9]\d{7,14}")
_RAW_COMPACT_PHONE = re.compile(r"(?<![\w-])\+?[1-9]\d{7,14}(?![\w-])")


@dataclass(frozen=True, slots=True)
class ReportPaths:
    """Paths emitted by one bounded reporting operation."""

    json: Path
    markdown: Path
    junit: Path


def write_report_bundle(
    directory: Path,
    report: EvaluationReport,
    *,
    comparison: BaselineComparison | None = None,
) -> ReportPaths:
    """Write bounded artifacts atomically after a content-safety check."""
    directory.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(canonical_data(report), indent=2, sort_keys=True) + "\n"
    markdown_text = render_markdown(report, comparison=comparison)
    junit_text = render_junit(report)
    for content in (json_text, markdown_text, junit_text):
        validate_report_content(content)
        if len(content.encode()) > MAX_REPORT_BYTES:
            raise ValueError("evaluation report exceeds the five megabyte cap")
    paths = ReportPaths(
        directory / "report.json",
        directory / "report.md",
        directory / "junit.xml",
    )
    _write_atomic(paths.json, json_text)
    _write_atomic(paths.markdown, markdown_text)
    _write_atomic(paths.junit, junit_text)
    return paths


def render_markdown(
    report: EvaluationReport,
    *,
    comparison: BaselineComparison | None = None,
) -> str:
    """Render concise failure evidence without raw prompts, evidence, or tenants."""
    passed = sum(result.status is ResultStatus.PASSED for result in report.results)
    lines = [
        "# Aegis evaluation report",
        "",
        f"- Report: `{report.metadata.report_id}`",
        f"- Mode: `{report.mode.value}`",
        f"- Reproducible: `{str(report.reproducible).lower()}`",
        f"- Cases: `{passed}/{len(report.results)}` passed",
        f"- Content digest: `{report.metadata.content_digest}`",
        "- Authority: release evidence only; the event ledger remains runtime truth.",
        "",
        "| Case | Status | Outcome | Failure |",
        "| --- | --- | --- | --- |",
    ]
    lines.extend(
        (
            f"| `{result.case_id}` | {result.status.value} | "
            f"{result.observed_outcome.value} | {result.failure.value} |"
        )
        for result in report.results
    )
    failures = tuple(
        result for result in report.results if result.status is not ResultStatus.PASSED
    )
    if failures:
        lines.extend(["", "## Failures", ""])
        for result in failures:
            trace = result.trace[-1] if result.trace else None
            phase = trace.phase if trace is not None else "evaluator"
            reasons = ", ".join(result.reason_codes) or result.failure.value
            reference = (
                trace.event_type
                if trace is not None and trace.event_type is not None
                else trace.artifact_reference
                if trace is not None
                else None
            )
            lines.extend(
                [
                    f"### `{result.case_id}`",
                    "",
                    f"- Invariant/reason: `{reasons}`",
                    f"- Phase: `{phase}`",
                    f"- Event/artifact reference: `{reference or 'none'}`",
                    f"- Guidance: {_guidance(result.failure.value)}",
                    "",
                ]
            )
    if comparison is not None:
        lines.extend(
            [
                "## Baseline comparison",
                "",
                f"- Evaluated at: `{comparison.evaluated_at.isoformat()}`",
                f"- Passed: `{str(comparison.passed).lower()}`",
                f"- Findings: `{len(comparison.findings)}`",
                "",
            ]
        )
        lines.extend(
            (
                f"- `{finding.case_id}` / `{finding.metric_name}`: "
                f"`{finding.reason_code}`"
                + (f" (waiver `{finding.waiver_id}`)" if finding.waived else "")
            )
            for finding in comparison.findings
        )
    return "\n".join(lines).rstrip() + "\n"


def render_junit(report: EvaluationReport) -> str:
    """Render stable JUnit XML for CI annotations."""
    failures = sum(
        result.status in {ResultStatus.FAILED, ResultStatus.EVALUATOR_ERROR}
        for result in report.results
    )
    skipped = sum(result.status is ResultStatus.CANCELLED for result in report.results)
    suite = ET.Element(
        "testsuite",
        {
            "name": "aegis-layer12-evaluations",
            "tests": str(len(report.results)),
            "failures": str(failures),
            "errors": "0",
            "skipped": str(skipped),
            "time": "0",
        },
    )
    for result in report.results:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": "aegis.evals",
                "name": result.case_id,
                "time": "0",
            },
        )
        if result.status in {ResultStatus.FAILED, ResultStatus.EVALUATOR_ERROR}:
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "type": result.failure.value,
                    "message": ",".join(result.reason_codes) or result.failure.value,
                },
            )
            failure.text = (
                "See the bounded JSON trace references; raw content is omitted."
            )
        elif result.status is ResultStatus.CANCELLED:
            ET.SubElement(case, "skipped", {"message": "evaluation_cancelled"})
    ET.indent(suite, space="  ")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def read_report_case_ids(path: Path) -> tuple[str, ...]:
    """Read only bounded case identifiers needed for deterministic replay."""
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the supported replay cap")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("report root must be an object")
    results = raw.get("results")
    if not isinstance(results, list) or not 1 <= len(results) <= 512:
        raise ValueError("report results are missing or outside bounds")
    identifiers: list[str] = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("case_id"), str):
            raise ValueError("report result case_id is invalid")
        identifiers.append(result["case_id"])
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("report contains duplicate case identifiers")
    return tuple(identifiers)


def validate_report_content(content: str) -> None:
    """Reject credentials, raw tenant labels, and other forbidden report content."""
    if any(pattern.search(content) for pattern in _SECRET_PATTERNS):
        raise ValueError("report contains disallowed sensitive content")
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        if (
            _RAW_TENANT.search(content)
            or _RAW_COMPACT_PHONE.search(content)
            or any(pattern.search(content) for pattern in _PII_PATTERNS)
        ):
            raise ValueError("report contains disallowed sensitive content") from None
        return
    if _contains_sensitive_json(value):
        raise ValueError("report contains disallowed sensitive content")


def _contains_sensitive_json(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower().replace("-", "_") in _FORBIDDEN_JSON_KEYS
            or _contains_sensitive_json(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_json(item) for item in value)
    return isinstance(value, str) and (
        _RAW_TENANT.search(value) is not None
        or _COMPACT_PHONE.fullmatch(value) is not None
        or _RAW_COMPACT_PHONE.search(value) is not None
        or any(pattern.search(value) for pattern in _SECRET_PATTERNS)
        or any(pattern.search(value) for pattern in _PII_PATTERNS)
    )


def _guidance(failure: str) -> str:
    return {
        "safety_invariant": "Restore the code-enforced boundary; do not waive it.",
        "outcome_mismatch": (
            "Inspect the cited phase and update code or reviewed expectations."
        ),
        "policy_violation": (
            "Inspect policy and fold behavior; keep deny-by-default handling."
        ),
        "timeout": "Reduce bounded work or repair the deterministic timeout path.",
        "evaluator_failure": (
            "Repair evaluator infrastructure before judging system behavior."
        ),
    }.get(failure, "Inspect the bounded trace and preserve ledger evidence.")


def _write_atomic(path: Path, content: str) -> None:
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


__all__ = [
    "MAX_REPORT_BYTES",
    "ReportPaths",
    "read_report_case_ids",
    "render_junit",
    "render_markdown",
    "validate_report_content",
    "write_report_bundle",
]
