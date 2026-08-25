"""Fail closed unless production cluster controllers and APIs are ready."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "deploy" / "kubernetes" / "bootstrap" / "controller-lock.json"
_ECR_IMAGE = re.compile(
    r"^(?P<registry>[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com)/"
    r"(?P<repository>[a-z0-9][a-z0-9._/-]+)@(?P<digest>sha256:[0-9a-f]{64})$"
)


def _document(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _kubectl_json(arguments: Sequence[str]) -> Mapping[str, Any]:
    result = subprocess.run(  # noqa: S603
        ["kubectl", *arguments, "-o", "json"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("kubectl returned a non-object document")
    return value


def _live_snapshot(lock: Mapping[str, Any]) -> Mapping[str, Any]:
    resources = subprocess.run(
        ["kubectl", "api-resources", "-o", "name"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    names = [line.strip() for line in resources.stdout.splitlines() if line.strip()]
    versions = subprocess.run(
        ["kubectl", "api-versions"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    workloads: dict[str, Mapping[str, Any]] = {}
    for expected in lock["workloads"]:
        kind = str(expected["kind"]).lower()
        namespace = str(expected["namespace"])
        name = str(expected["name"])
        key = f"{expected['kind']}/{namespace}/{name}"
        workloads[key] = _kubectl_json(["get", kind, name, "--namespace", namespace])
    return {
        "api_resources": names,
        "api_versions": [
            line.strip() for line in versions.stdout.splitlines() if line.strip()
        ],
        "workloads": workloads,
    }


def verify(
    lock: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return bounded validation errors for a cluster snapshot."""
    errors: list[str] = []
    actual_resources = {str(value) for value in snapshot.get("api_resources", [])}
    errors.extend(
        f"missing API resource: {resource}"
        for resource in lock.get("api_resources", [])
        if resource not in actual_resources
    )
    actual_versions = {str(value) for value in snapshot.get("api_versions", [])}
    errors.extend(
        f"missing served API version: {version}"
        for version in lock.get("api_versions", [])
        if version not in actual_versions
    )
    expected_registry = str(lock.get("registry", ""))
    if _ECR_IMAGE.fullmatch(
        f"{expected_registry}/controller@sha256:{'0' * 64}"
    ) is None or expected_registry.startswith("000000000000."):
        errors.append("controller registry is not materialized")

    actual_workloads = snapshot.get("workloads", {})
    if not isinstance(actual_workloads, dict):
        return (*errors, "snapshot workloads must be an object")
    for expected in lock.get("workloads", []):
        key = f"{expected['kind']}/{expected['namespace']}/{expected['name']}"
        workload = actual_workloads.get(key)
        if not isinstance(workload, dict):
            errors.append(f"missing controller workload: {key}")
            continue
        metadata = workload.get("metadata", {})
        status = workload.get("status", {})
        spec = workload.get("spec", {})
        if not all(isinstance(value, dict) for value in (metadata, status, spec)):
            errors.append(f"invalid controller workload: {key}")
            continue
        if status.get("observedGeneration") != metadata.get("generation"):
            errors.append(f"controller generation not observed: {key}")
        if int(status.get("availableReplicas", 0)) < 1:
            errors.append(f"controller has no available replica: {key}")
        template = spec.get("template", {})
        pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
        containers = (
            pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
        )
        init_containers = (
            pod_spec.get("initContainers", []) if isinstance(pod_spec, dict) else []
        )
        images = [
            container.get("image")
            for container in [*containers, *init_containers]
            if isinstance(container, dict)
        ]
        expected_repository = str(expected["repository"])
        expected_digests = {str(value) for value in expected["digests"]}
        observed_digests: set[str] = set()
        for image in images:
            match = _ECR_IMAGE.fullmatch(image) if isinstance(image, str) else None
            if (
                match is None
                or match.group("registry") != expected_registry
                or match.group("repository") != expected_repository
            ):
                errors.append(f"controller image repository is not locked: {key}")
                continue
            observed_digests.add(match.group("digest"))
        if observed_digests != expected_digests:
            errors.append(f"controller image digests do not match lock: {key}")
    return tuple(errors)


def main() -> None:
    """Validate a live cluster or deterministic snapshot against the lock."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    lock = _document(arguments.lock)
    snapshot = (
        _document(arguments.snapshot)
        if arguments.snapshot is not None
        else _live_snapshot(lock)
    )
    errors = verify(lock, snapshot)
    evidence = {
        "schema_version": 1,
        "controller_versions": lock.get("components", {}),
        "result": "pass" if not errors else "fail",
        "errors": list(errors),
    }
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if errors:
        raise SystemExit("; ".join(errors))
    print("cluster prerequisite contract: pass")


if __name__ == "__main__":
    main()
