"""Validate Layer 12 observability conventions and provisioned assets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from aegis_agent_platform.observability.semantic import (
    FORBIDDEN_METRIC_LABEL_FRAGMENTS,
    METRICS,
    OPERATIONS,
    validate_metric_labels,
)

ROOT = Path(__file__).resolve().parents[1]


def _yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _collector() -> None:
    config = _yaml(ROOT / "deploy" / "otel-collector.yaml")
    exporters = config.get("exporters", {})
    if "debug" in exporters or "logging" in exporters:
        raise SystemExit("collector must not enable sensitive debug/logging exporters")
    extensions = config.get("extensions", {})
    if "health_check" not in extensions:
        raise SystemExit("collector must expose the health_check extension")
    pipelines = config["service"]["pipelines"]
    for signal in ("traces", "metrics", "logs"):
        processors = pipelines[signal]["processors"]
        if not processors or not str(processors[0]).startswith("memory_limiter"):
            raise SystemExit(f"{signal} pipeline must apply memory_limiter first")
        if not any(str(item).startswith("batch") for item in processors):
            raise SystemExit(f"{signal} pipeline must include bounded batching")
    configured_extensions = config["service"].get("extensions", [])
    if "health_check" not in configured_extensions:
        raise SystemExit("collector health_check extension is not enabled")


def _rules() -> None:
    rule_paths = sorted((ROOT / "deploy" / "prometheus" / "rules").glob("*.yml"))
    if not rule_paths:
        raise SystemExit("no Prometheus rules are provisioned")
    alert_count = 0
    for path in rule_paths:
        document = _yaml(path)
        for group in document.get("groups", []):
            if not group.get("name") or not group.get("rules"):
                raise SystemExit(f"{path} contains an empty rule group")
            for rule in group["rules"]:
                if "alert" not in rule:
                    continue
                alert_count += 1
                annotations = rule.get("annotations", {})
                labels = rule.get("labels", {})
                if not {"owner", "severity"} <= labels.keys():
                    raise SystemExit(f"{path}: {rule['alert']} lacks owner/severity")
                if not {"summary", "runbook_url"} <= annotations.keys():
                    raise SystemExit(
                        f"{path}: {rule['alert']} lacks runbook annotations"
                    )
                expression = str(rule.get("expr", "")).lower()
                if any(
                    fragment + "=" in expression
                    for fragment in FORBIDDEN_METRIC_LABEL_FRAGMENTS
                ):
                    raise SystemExit(f"{path}: {rule['alert']} uses a forbidden label")
    if alert_count < 15:
        raise SystemExit("Layer 12 requires at least fifteen actionable alerts")


def _dashboards() -> None:
    dashboard_paths = sorted(
        (ROOT / "deploy" / "grafana" / "dashboards").glob("*.json")
    )
    if len(dashboard_paths) < 10:
        raise SystemExit("Layer 12 requires ten provisioned operational dashboards")
    uids: set[str] = set()
    for path in dashboard_paths:
        with path.open(encoding="utf-8") as handle:
            dashboard = json.load(handle)
        uid = dashboard.get("uid")
        if not isinstance(uid, str) or not uid or uid in uids:
            raise SystemExit(f"{path} has a missing or duplicate dashboard uid")
        uids.add(uid)
        if not dashboard.get("title") or not dashboard.get("panels"):
            raise SystemExit(f"{path} must define a title and panels")
        variables = dashboard.get("templating", {}).get("list", [])
        for variable in variables:
            name = str(variable.get("name", "")).lower()
            if any(fragment in name for fragment in ("tenant", "user", "incident")):
                raise SystemExit(f"{path} exposes a forbidden enumeration variable")
    provisioning = _yaml(
        ROOT / "deploy" / "grafana" / "provisioning" / "dashboards" / "dashboards.yml"
    )
    if not provisioning.get("providers"):
        raise SystemExit("Grafana dashboard provisioning is empty")


def _semantic_conventions() -> None:
    if len(OPERATIONS) < 30 or len(METRICS) < 35:
        raise SystemExit("semantic convention catalog is incomplete")
    for definition in METRICS.values():
        validate_metric_labels(definition.labels)
        if not definition.unit or not definition.owner:
            raise SystemExit(f"{definition.name} lacks unit or ownership")


def main() -> None:
    """Run deterministic local checks without contacting telemetry backends."""
    _semantic_conventions()
    _collector()
    _rules()
    _dashboards()


if __name__ == "__main__":
    main()
