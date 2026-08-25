"""Deterministic controller and promotion bundle evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from scripts.materialize_kustomize_bundle import materialize
from scripts.verify_cluster_prerequisites import verify


def _controller_snapshot(lock: dict[str, object]) -> dict[str, object]:
    workloads = {}
    expected_workloads = cast(list[dict[str, str]], lock["workloads"])
    for expected in expected_workloads:
        key = f"{expected['kind']}/{expected['namespace']}/{expected['name']}"
        workloads[key] = {
            "metadata": {"generation": 2},
            "status": {"observedGeneration": 2, "availableReplicas": 1},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "image": (
                                    f"{lock['registry']}/"
                                    f"{expected['repository']}@{digest}"
                                )
                            }
                            for digest in expected["digests"]
                        ]
                    }
                }
            },
        }
    return {
        "api_resources": lock["api_resources"],
        "api_versions": lock["api_versions"],
        "workloads": workloads,
    }


def test_controller_prerequisite_snapshot_passes() -> None:
    lock = json.loads(
        Path("deploy/kubernetes/bootstrap/controller-lock.json").read_text(
            encoding="utf-8"
        )
    )
    lock["registry"] = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"

    assert verify(lock, _controller_snapshot(lock)) == ()


def test_controller_prerequisite_rejects_mutable_image() -> None:
    lock = json.loads(
        Path("deploy/kubernetes/bootstrap/controller-lock.json").read_text(
            encoding="utf-8"
        )
    )
    lock["registry"] = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"
    snapshot = _controller_snapshot(lock)
    workloads = cast(dict[str, dict[str, Any]], snapshot["workloads"])
    workload = next(iter(workloads.values()))
    workload["spec"]["template"]["spec"]["containers"][0]["image"] = "controller:latest"

    assert any("not locked" in error for error in verify(lock, snapshot))


@pytest.mark.parametrize("environment", ["development", "staging", "production"])
def test_materialized_bundle_pins_both_private_images(
    tmp_path: Path,
    environment: str,
) -> None:
    output = tmp_path / "bundle"
    materialize(
        environment=environment,
        control_plane_image=(
            "123456789012.dkr.ecr.eu-west-1.amazonaws.com/aegis-agent-platform"
        ),
        control_plane_digest=f"sha256:{'1' * 64}",
        operator_ui_image=(
            "123456789012.dkr.ecr.eu-west-1.amazonaws.com/aegis-operator-ui"
        ),
        operator_ui_digest=f"sha256:{'2' * 64}",
        otel_image=(
            "123456789012.dkr.ecr.eu-west-1.amazonaws.com/aegis-otel-collector"
        ),
        otel_digest=f"sha256:{'3' * 64}",
        public_domain=f"aegis.{environment}.example.com",
        oidc_issuer=f"https://identity.{environment}.example.com/realms/aegis",
        oidc_jwks_url=(
            f"https://identity.{environment}.example.com/realms/aegis/certs"
        ),
        aws_region="eu-west-1",
        data_cidr="10.42.128.0/17",
        egress_proxy_url=(
            "https://aegis-egress-gateway.aegis-egress.svc.cluster.local:8443"
        ),
        otel_server_name=f"telemetry.{environment}.example.com",
        platform_alert_route="platform-primary",
        database_alert_route="database-primary",
        change_reference="change-ref://CAB-123",
        output=output,
    )

    overlay = yaml.safe_load(
        (
            output / f"deploy/kubernetes/overlays/{environment}/kustomization.yaml"
        ).read_text(encoding="utf-8")
    )
    assert [image["digest"] for image in overlay["images"]] == [
        f"sha256:{'1' * 64}",
        f"sha256:{'2' * 64}",
        f"sha256:{'3' * 64}",
    ]
    assert (
        json.loads((output / "promotion.json").read_text(encoding="utf-8"))[
            "environment"
        ]
        == environment
    )
    assert (output / "SHA256SUMS").read_text(encoding="utf-8")
    rendered_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (output / "deploy/kubernetes").rglob("*")
        if path.is_file()
    )
    assert ".example.invalid" not in rendered_text
    assert f"api.aegis.{environment}.example.com" in rendered_text
    assert f"identity.{environment}.example.com" in rendered_text
    assert f"telemetry.{environment}.example.com" in rendered_text
    assert "platform-primary" in rendered_text
    assert "database-primary" in rendered_text
    assert "aegis-egress-gateway.aegis-egress.svc.cluster.local:8443" in rendered_text
    assert "000000000000.dkr.ecr" not in rendered_text
    assert "aegis-schema-migration-" in rendered_text
    assert (
        "123456789012.dkr.ecr.eu-west-1.amazonaws.com/aegis-agent-platform*"
    ) in rendered_text
    assert (
        rendered_text.count(
            "123456789012.dkr.ecr.eu-west-1.amazonaws.com/aegis-agent-platform*"
        )
        == 2
    )
    assert "type: Cosign" in rendered_text
    assert "cosignOCI11: true" in rendered_text
    assert "type: SigstoreBundle" in rendered_text
