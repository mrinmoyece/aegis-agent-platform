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
        elif isinstance(node, ast.ImportFrom):
            imports.add("." * node.level + (node.module or ""))
    return imports


def is_outward_domain_import(module: str) -> bool:
    """Return whether an import crosses the pure-domain package boundary."""
    if module.startswith(".."):
        return True
    if module == "aegis_agent_platform":
        return True
    if not module.startswith("aegis_agent_platform."):
        return False
    return module != "aegis_agent_platform.domain" and not module.startswith(
        "aegis_agent_platform.domain."
    )


def test_domain_has_no_outward_platform_dependencies() -> None:
    violations = [
        f"{path.relative_to(ROOT)} imports {module}"
        for path in sorted(DOMAIN.rglob("*.py"))
        for module in imported_modules(path)
        if is_outward_domain_import(module)
    ]

    assert not violations, "\n".join(violations)


def test_parent_relative_import_without_module_is_detected(tmp_path: Path) -> None:
    source = tmp_path / "module.py"
    source.write_text("from .. import config\n", encoding="utf-8")

    assert imported_modules(source) == {".."}
    assert is_outward_domain_import("..")


def test_package_root_and_domain_prefix_are_distinguished() -> None:
    assert is_outward_domain_import("aegis_agent_platform")
    assert is_outward_domain_import("aegis_agent_platform.domain_adapter")
    assert not is_outward_domain_import("aegis_agent_platform.domain")
    assert not is_outward_domain_import("aegis_agent_platform.domain.events")


def test_no_agent_framework_dependencies() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()

    assert "langchain" not in pyproject
    assert "crewai" not in pyproject
    assert "autogen" not in pyproject
