"""Validate static repository and deployment manifests."""

from __future__ import annotations

import json
import re
import tomllib
from itertools import chain
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION_PATTERN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
REQUIRED_SERVICES = {
    "api",
    "postgres",
    "redis",
    "keycloak",
    "otel-collector",
    "prometheus",
    "grafana",
}


def load_yaml(path: Path) -> Any:
    """Load YAML and fail with a path-specific message."""
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def dockerfile_final_user(dockerfile: str) -> tuple[int, str | None]:
    """Return the stage count and effective user declared in the final stage."""
    stage_count = 0
    final_user: str | None = None
    for raw_line in dockerfile.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        instruction = parts[0]
        value = parts[1] if len(parts) == 2 else ""
        if instruction.upper() == "FROM":
            stage_count += 1
            final_user = None
        elif instruction.upper() == "USER":
            final_user = value.strip()
    return stage_count, final_user


def workflow_paths() -> list[Path]:
    """Return every workflow extension recognized by GitHub Actions."""
    workflows = ROOT / ".github" / "workflows"
    return sorted(chain(workflows.glob("*.yml"), workflows.glob("*.yaml")))


def unpinned_workflow_actions(workflow: dict[str, Any]) -> list[str]:
    """Return step actions and reusable workflows not pinned to a commit SHA."""
    actions: list[str] = []
    for job in workflow["jobs"].values():
        reusable_workflow = job.get("uses")
        if reusable_workflow and not action_is_pinned(reusable_workflow):
            actions.append(reusable_workflow)
        for step in job.get("steps", []):
            action = step.get("uses")
            if action and not action_is_pinned(action):
                actions.append(action)
    return actions


def action_is_pinned(action: str) -> bool:
    """Accept local actions or remote actions pinned to a full commit SHA."""
    return action.startswith("./") or ACTION_PATTERN.fullmatch(action) is not None


def main() -> None:
    """Check parseability and repository security conventions."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    if project["requires-python"] != ">=3.12":
        raise SystemExit("pyproject.toml must require Python 3.12 or newer")

    compose = load_yaml(ROOT / "compose.yaml")
    services = compose["services"]
    missing_services = REQUIRED_SERVICES - services.keys()
    if missing_services:
        raise SystemExit(
            "compose.yaml missing services: " + ", ".join(sorted(missing_services))
        )

    for service_name, service in services.items():
        for port in service.get("ports", []):
            rendered = port if isinstance(port, str) else str(port)
            if not rendered.startswith("127.0.0.1:"):
                raise SystemExit(
                    f"{service_name} publishes a port outside loopback: {rendered}"
                )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    stage_count, final_user = dockerfile_final_user(dockerfile)
    if stage_count < 2 or final_user != "10001:10001":
        raise SystemExit("Dockerfile must be multi-stage and run as non-root")

    for workflow_path in workflow_paths():
        workflow = load_yaml(workflow_path)
        unpinned = unpinned_workflow_actions(workflow)
        if unpinned:
            raise SystemExit(
                f"{workflow_path.name} action is not SHA-pinned: {unpinned[0]}"
            )

    for yaml_path in [
        ROOT / ".github" / "dependabot.yml",
        ROOT / "deploy" / "otel-collector.yaml",
        ROOT / "deploy" / "prometheus.yml",
        ROOT / "deploy" / "grafana" / "provisioning" / "datasources" / "prometheus.yml",
    ]:
        load_yaml(yaml_path)

    with (ROOT / "deploy" / "keycloak" / "realm-aegis.json").open(
        encoding="utf-8"
    ) as handle:
        realm = json.load(handle)
    if realm["realm"] != "aegis" or realm.get("registrationAllowed") is not False:
        raise SystemExit("local Keycloak realm must disable self-registration")


if __name__ == "__main__":
    main()
