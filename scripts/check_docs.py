"""Validate repository documentation without external services."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCUMENTS = {
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "docs" / "architecture.md",
    ROOT / "docs" / "threat-model.md",
    ROOT / "docs" / "enterprise-checklist.md",
    ROOT / "docs" / "roadmap.md",
    ROOT / "docs" / "getting-started.md",
    ROOT / "docs" / "curriculum.md",
    ROOT / "docs" / "demo-script.md",
    ROOT / "docs" / "interview-question-bank.md",
    ROOT / "docs" / "labs.md",
    ROOT / "docs" / "glossary.md",
    ROOT / "docs" / "limitations.md",
    ROOT / "docs" / "protocols.md",
    ROOT / "docs" / "enterprise-implementation-plan.md",
    ROOT / "docs" / "identity-tenancy.md",
    ROOT / "docs" / "durable-execution.md",
    ROOT / "docs" / "failure-modes.md",
    ROOT / "docs" / "runbook.md",
    ROOT / "docs" / "worker-runtime.md",
    ROOT / "docs" / "adr" / "0011-shared-redis-stream.md",
    ROOT / "docs" / "adr" / "0009-tenant-governance-audit-and-secrets.md",
}
LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def markdown_files() -> list[Path]:
    """Return tracked documentation candidates in deterministic order."""
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if ".venv" not in path.parts and ".git" not in path.parts
    )


def broken_relative_links(path: Path) -> list[str]:
    """Find local Markdown links whose target does not exist."""
    failures: list[str] = []
    for raw_target in LINK_PATTERN.findall(path.read_text(encoding="utf-8")):
        target = raw_target.split("#", maxsplit=1)[0].strip()
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            failures.append(f"{path.relative_to(ROOT)} -> {raw_target}")
    return failures


def main() -> None:
    """Validate required documents, ADR count, and relative links."""
    missing = sorted(
        str(path.relative_to(ROOT)) for path in REQUIRED_DOCUMENTS if not path.is_file()
    )
    if missing:
        raise SystemExit("missing required documentation: " + ", ".join(missing))

    adrs = sorted((ROOT / "docs" / "adr").glob("*.md"))
    if len(adrs) < 7:
        raise SystemExit("expected at least seven architecture decision records")

    failures = [
        failure for path in markdown_files() for failure in broken_relative_links(path)
    ]
    if failures:
        raise SystemExit("broken documentation links:\n" + "\n".join(failures))

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "Current status: Layer 4" not in readme:
        raise SystemExit("README must state the current implementation layer")


if __name__ == "__main__":
    main()
