"""Static package dependency rules."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = ROOT / "src" / "aegis_agent_platform" / "domain"
ALLOWED_DOMAIN_IMPORT_ROOTS = {
    "__future__",
    "collections",
    "dataclasses",
    "decimal",
    "datetime",
    "enum",
    # Pure-computation stdlib modules used in domain validation logic.
    # These perform no I/O, clock reads, or random generation.
    "hashlib",
    "ipaddress",
    "json",
    "math",
    "pathlib",
    "posixpath",
    "re",
    "types",
    "typing",
    "unicodedata",
    "urllib",
    "uuid",
}
PROHIBITED_DOMAIN_CALLS = {
    "datetime.date.today",
    "datetime.datetime.now",
    "datetime.datetime.today",
    "datetime.datetime.utcnow",
    "input",
    "open",
    "print",
    "random.random",
    "secrets.token_bytes",
    "secrets.token_hex",
    "secrets.token_urlsafe",
    "time.monotonic",
    "time.perf_counter",
    "time.time",
    "uuid.uuid1",
    "uuid.uuid4",
}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package_parts = _package_parts(path)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.update(_import_from_modules(node, package_parts))
    return imports


def _package_parts(path: Path) -> tuple[str, ...]:
    relative = path.relative_to(ROOT / "src")
    return relative.parts[:-1]


def _import_from_modules(
    node: ast.ImportFrom,
    package_parts: tuple[str, ...],
) -> set[str]:
    if node.level:
        base_parts = package_parts[: len(package_parts) - (node.level - 1)]
    else:
        base_parts = ()
    module_parts = tuple(node.module.split(".")) if node.module else ()
    prefix = ".".join((*base_parts, *module_parts))
    imports = {prefix} if prefix and node.module else set()
    imports.update(
        ".".join((*base_parts, *module_parts, alias.name))
        for alias in node.names
        if alias.name != "*"
    )
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


def prohibited_domain_uses(path: Path) -> set[str]:
    """Find framework, I/O, wall-clock, and random-generation dependencies."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".", maxsplit=1)[0]] = (
                    alias.name
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    violations = {
        module
        for module in imported_modules(path)
        if not module.startswith(".")
        and not module.startswith("aegis_agent_platform.domain")
        and module.split(".", maxsplit=1)[0] not in ALLOWED_DOMAIN_IMPORT_ROOTS
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call = resolved_name(node.func, bindings)
        if call in PROHIBITED_DOMAIN_CALLS:
            violations.add(call)
    return violations


def resolved_name(node: ast.expr, bindings: dict[str, str]) -> str:
    """Resolve a called name through direct and aliased imports."""
    if isinstance(node, ast.Name):
        return bindings.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        owner = resolved_name(node.value, bindings)
        return f"{owner}.{node.attr}" if owner else node.attr
    return ""


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


def test_domain_has_no_framework_io_clock_or_random_dependencies() -> None:
    violations = [
        f"{path.relative_to(ROOT)} uses {use}"
        for path in sorted(DOMAIN.rglob("*.py"))
        for use in sorted(prohibited_domain_uses(path))
    ]

    assert not violations, "\n".join(violations)


def test_prohibited_domain_dependencies_are_detected(tmp_path: Path) -> None:
    source = tmp_path / "module.py"
    source.write_text(
        "import os\n"
        "from datetime import datetime as clock\n"
        "from uuid import uuid4\n"
        "first = clock.now()\n"
        "second = clock.today()\n"
        "third = uuid4()\n"
        "fourth = open('state')\n"
        "fifth = input()\n"
        "print(fifth)\n",
        encoding="utf-8",
    )

    assert prohibited_domain_uses(source) == {
        "os",
        "datetime.datetime.now",
        "datetime.datetime.today",
        "uuid.uuid4",
        "open",
        "input",
        "print",
    }


def test_domain_import_allowlist_blocks_io_bypasses(tmp_path: Path) -> None:
    source = tmp_path / "module.py"
    source.write_text(
        "import http.client\n"
        "import builtins\n"
        "first = http.client.HTTPConnection('example.test')\n"
        "second = builtins.open('state')\n",
        encoding="utf-8",
    )

    assert prohibited_domain_uses(source) == {"http.client", "builtins"}


def test_no_agent_framework_dependencies() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()

    assert "langchain" not in pyproject
    assert "crewai" not in pyproject
    assert "autogen" not in pyproject


def test_vendor_sdks_are_isolated_to_provider_adapters() -> None:
    allowed = {
        ROOT / "src" / "aegis_agent_platform" / "providers" / "openai.py",
        ROOT / "src" / "aegis_agent_platform" / "providers" / "anthropic.py",
    }
    violations = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "src").rglob("*.py")
        if path not in allowed
        and imported_modules(path).intersection({"openai", "anthropic"})
    ]

    assert not violations


def test_kubernetes_sdk_is_isolated_to_official_adapter() -> None:
    allowed = (
        ROOT
        / "src"
        / "aegis_agent_platform"
        / "integrations"
        / "kubernetes"
        / "official.py"
    )
    violations = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "src").rglob("*.py")
        if path != allowed and "kubernetes" in imported_modules(path)
    ]

    assert not violations


def test_evaluation_never_becomes_a_runtime_dependency() -> None:
    evals = ROOT / "src" / "aegis_agent_platform" / "evals"
    violations = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "src" / "aegis_agent_platform").rglob("*.py")
        if evals not in path.parents
        and any(
            module.startswith("aegis_agent_platform.evals")
            for module in imported_modules(path)
        )
    ]

    assert not violations


def test_import_helper_tracks_from_import_targets_and_relative_imports() -> None:
    absolute_node = ast.parse("from aegis_agent_platform import evals").body[0]
    relative_node = ast.parse("from . import evals").body[0]

    assert isinstance(absolute_node, ast.ImportFrom)
    assert isinstance(relative_node, ast.ImportFrom)
    assert _import_from_modules(absolute_node, ("aegis_agent_platform",)) == {
        "aegis_agent_platform",
        "aegis_agent_platform.evals",
    }
    assert _import_from_modules(relative_node, ("aegis_agent_platform",)) == {
        "aegis_agent_platform.evals"
    }
