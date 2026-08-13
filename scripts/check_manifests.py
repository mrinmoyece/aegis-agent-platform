"""Validate static repository and deployment manifests."""

from __future__ import annotations

import json
import re
import tomllib
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

    database_url = services["api"]["environment"]["AEGIS_DATABASE_URL"]
    if "aegis_runtime:" not in database_url:
        raise SystemExit("API database URL must use the non-superuser runtime login")
    init_mounts = services["postgres"]["volumes"]
    if not any("40-create-app-user.sh" in volume for volume in init_mounts):
        raise SystemExit("PostgreSQL must create the restricted runtime login")
    runtime_init = (ROOT / "docker" / "postgres" / "40-create-app-user.sh").read_text(
        encoding="utf-8"
    )
    if "LOGIN INHERIT NOBYPASSRLS" not in runtime_init:
        raise SystemExit("runtime database login must inherit only the app role")

    for service_name, service in services.items():
        for port in service.get("ports", []):
            rendered = port if isinstance(port, str) else str(port)
            if not rendered.startswith("127.0.0.1:"):
                raise SystemExit(
                    f"{service_name} publishes a port outside loopback: {rendered}"
                )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "USER 10001:10001" not in dockerfile or " AS builder" not in dockerfile:
        raise SystemExit("Dockerfile must be multi-stage and run as non-root")

    for workflow_path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = load_yaml(workflow_path)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                action = step.get("uses")
                if action and not ACTION_PATTERN.fullmatch(action):
                    raise SystemExit(
                        f"{workflow_path.name} action is not SHA-pinned: {action}"
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
    client = next(
        (
            item
            for item in realm["clients"]
            if item.get("clientId") == "aegis-control-plane"
        ),
        None,
    )
    if client is None or client.get("directAccessGrantsEnabled") is not False:
        raise SystemExit("Keycloak control-plane client must disable password grants")
    mapper_names = {mapper.get("name") for mapper in client.get("protocolMappers", [])}
    if not {"aegis-audience", "tenant-id"} <= mapper_names:
        raise SystemExit("Keycloak client requires audience and tenant claim mappers")


if __name__ == "__main__":
    main()
