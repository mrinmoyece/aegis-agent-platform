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
    "migration",
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


def keycloak_mapper_matches(
    mapper: dict[str, Any],
    *,
    mapper_type: str,
    required_config: dict[str, str],
) -> bool:
    """Validate the mapper type and every security-relevant setting."""
    config = mapper.get("config")
    return (
        mapper.get("protocol") == "openid-connect"
        and mapper.get("protocolMapper") == mapper_type
        and isinstance(config, dict)
        and all(config.get(key) == value for key, value in required_config.items())
    )


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
    legacy_init_migrations = sorted((ROOT / "migrations").glob("000[1-9]_*.sql"))
    legacy_init_migrations.extend((ROOT / "migrations").glob("0010_*.sql"))
    for migration in legacy_init_migrations:
        mount = f"./migrations/{migration.name}:"
        if not any(mount in volume for volume in init_mounts):
            raise SystemExit(f"PostgreSQL init mounts must include {migration.name}")
    migration_command = " ".join(services["migration"]["command"])
    if (
        "scripts/migrate.py" not in migration_command
        or "--adopt-existing" not in migration_command
    ):
        raise SystemExit(
            "Compose migration service must adopt and manage schema history"
        )
    if (
        services["api"]["depends_on"].get("migration", {}).get("condition")
        != "service_completed_successfully"
    ):
        raise SystemExit("API must wait for successful managed migrations")
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
    mappers = {
        mapper.get("name"): mapper for mapper in client.get("protocolMappers", [])
    }
    audience_mapper = mappers.get("aegis-audience")
    tenant_mapper = mappers.get("tenant-id")
    if not isinstance(audience_mapper, dict) or not keycloak_mapper_matches(
        audience_mapper,
        mapper_type="oidc-audience-mapper",
        required_config={
            "included.client.audience": "aegis-control-plane",
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    ):
        raise SystemExit("Keycloak client audience mapper is unsafe")
    if not isinstance(tenant_mapper, dict) or not keycloak_mapper_matches(
        tenant_mapper,
        mapper_type="oidc-usermodel-attribute-mapper",
        required_config={
            "user.attribute": "tenant_id",
            "claim.name": "tenant_id",
            "jsonType.label": "String",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "multivalued": "false",
        },
    ):
        raise SystemExit("Keycloak client requires audience and tenant claim mappers")


if __name__ == "__main__":
    main()
