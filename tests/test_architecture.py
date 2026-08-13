"""Static package dependency rules."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = ROOT / "src" / "aegis_agent_platform" / "domain"


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add("." * node.level + node.module)
    return imports


def test_domain_has_no_outward_platform_dependencies() -> None:
    violations = [
        f"{path.relative_to(ROOT)} imports {module}"
        for path in sorted(DOMAIN.rglob("*.py"))
        for module in imported_modules(path)
        if (
            module.startswith("aegis_agent_platform.")
            and not module.startswith("aegis_agent_platform.domain")
        )
        or module.startswith("..")
    ]

    assert not violations, "\n".join(violations)


def test_no_agent_framework_dependencies() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()

    assert "langchain" not in pyproject
    assert "crewai" not in pyproject
    assert "autogen" not in pyproject
