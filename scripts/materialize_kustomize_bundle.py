"""Create a digest-pinned Kustomize promotion bundle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parents[1]
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(
    r"^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9][a-z0-9._/-]+$"
)
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)
_AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_ALERT_ROUTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PLACEHOLDER_DIGESTS = {f"sha256:{character * 64}" for character in "abcdef"}


def materialize(
    *,
    environment: str,
    control_plane_image: str,
    control_plane_digest: str,
    operator_ui_image: str,
    operator_ui_digest: str,
    otel_image: str,
    otel_digest: str,
    public_domain: str,
    oidc_issuer: str,
    oidc_jwks_url: str,
    aws_region: str,
    data_cidr: str,
    egress_proxy_url: str,
    otel_server_name: str,
    platform_alert_route: str,
    database_alert_route: str,
    change_reference: str,
    output: Path,
) -> Path:
    """Copy only deployment inputs and replace both application images."""
    if environment not in {"development", "staging", "production"}:
        raise ValueError("environment must be development, staging, or production")
    for digest in (control_plane_digest, operator_ui_digest, otel_digest):
        if not _DIGEST.fullmatch(digest):
            raise ValueError("promotion digests must be immutable sha256 values")
    for image in (control_plane_image, operator_ui_image, otel_image):
        if not _IMAGE.fullmatch(image):
            raise ValueError("promotion images must be private AWS ECR repositories")
    registries = {
        image.partition("/")[0]
        for image in (control_plane_image, operator_ui_image, otel_image)
    }
    if len(registries) != 1:
        raise ValueError("all promotion images must use one environment ECR registry")
    if not change_reference.startswith("change-ref://"):
        raise ValueError("change reference must use change-ref://")
    if not _DNS_NAME.fullmatch(public_domain) or public_domain.endswith(".invalid"):
        raise ValueError("public domain must be a deployable DNS name")
    _https_endpoint(oidc_issuer, "OIDC issuer")
    _https_endpoint(oidc_jwks_url, "OIDC JWKS URL")
    if not _AWS_REGION.fullmatch(aws_region):
        raise ValueError("AWS region is invalid")
    if not _DNS_NAME.fullmatch(otel_server_name) or otel_server_name.endswith(
        ".invalid"
    ):
        raise ValueError("OTLP server name must be a deployable DNS name")
    network = ipaddress.ip_network(data_cidr)
    if (
        network.version != 4
        or not network.is_private
        or not 16 <= network.prefixlen <= 28
    ):
        raise ValueError("data CIDR must be a bounded private IPv4 network")
    proxy = urlparse(egress_proxy_url)
    if (
        proxy.scheme != "https"
        or proxy.hostname is None
        or not proxy.hostname.endswith((".svc", ".svc.cluster.local"))
        or proxy.port != 8443
        or proxy.username is not None
        or proxy.password is not None
        or proxy.path not in {"", "/"}
    ):
        raise ValueError(
            "egress proxy must be a credential-free HTTPS cluster service on 8443"
        )
    for route in (platform_alert_route, database_alert_route):
        if not _ALERT_ROUTE.fullmatch(route) or "placeholder" in route.lower():
            raise ValueError("alert routes must be bounded non-placeholder identifiers")
    if output.exists():
        raise ValueError("output directory must not already exist")

    source = ROOT / "deploy" / "kubernetes"
    bundle_root = output / "deploy" / "kubernetes"
    shutil.copytree(source / "base", bundle_root / "base")
    shutil.copytree(
        source / "overlays" / environment,
        bundle_root / "overlays" / environment,
    )
    shutil.copytree(source / "policies", bundle_root / "policies")
    shutil.copytree(source / "bootstrap", bundle_root / "bootstrap")

    kustomization_path = bundle_root / "overlays" / environment / "kustomization.yaml"
    document: dict[str, Any] = yaml.safe_load(
        kustomization_path.read_text(encoding="utf-8")
    )
    replacements = {
        "aegis-control-plane": (control_plane_image, control_plane_digest),
        "aegis-operator-ui": (operator_ui_image, operator_ui_digest),
        "otel/opentelemetry-collector-contrib": (otel_image, otel_digest),
    }
    images = document.get("images", [])
    for image in images:
        name = image.get("name")
        if name in replacements:
            image["newName"], image["digest"] = replacements[name]
    declared = {image.get("name") for image in images}
    if not replacements.keys() <= declared:
        raise ValueError("overlay does not declare both required application images")
    _materialize_overlay_runtime(
        document,
        oidc_issuer=oidc_issuer,
        oidc_jwks_url=oidc_jwks_url,
        aws_region=aws_region,
    )
    kustomization_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    _materialize_runtime(
        bundle_root / "base" / "external-secrets.yaml",
        oidc_issuer=oidc_issuer,
        oidc_jwks_url=oidc_jwks_url,
        aws_region=aws_region,
        egress_proxy_url=egress_proxy_url,
    )
    _materialize_ingress(
        bundle_root / "base" / "ingress.yaml",
        public_domain=public_domain,
    )
    _materialize_data_cidr(
        bundle_root / "base" / "network-policies.yaml",
        data_cidr=str(network),
    )
    _materialize_admission(
        bundle_root / "policies" / "kyverno.yaml",
        application_images=(control_plane_image, operator_ui_image),
    )
    _materialize_observability(
        bundle_root / "base" / "observability.yaml",
        otel_endpoint=f"{proxy.hostname}:{proxy.port}",
        otel_server_name=otel_server_name,
        platform_alert_route=platform_alert_route,
        database_alert_route=database_alert_route,
    )
    git_commit = _git_commit()
    release_id = hashlib.sha256(
        "|".join(
            (
                environment,
                control_plane_digest,
                operator_ui_digest,
                otel_digest,
                change_reference,
                git_commit,
            )
        ).encode()
    ).hexdigest()[:12]
    _materialize_release_jobs(bundle_root, release_id=release_id)
    _materialize_controller_lock(
        bundle_root / "bootstrap" / "controller-lock.json",
        registry=next(iter(registries)),
    )
    for path in bundle_root.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if ".example.invalid" in text:
            raise ValueError(f"bundle retains an environment placeholder: {path}")
        if "placeholder" in text.lower():
            raise ValueError(f"bundle retains an unresolved placeholder: {path}")
        if "000000000000.dkr.ecr" in text:
            raise ValueError(f"bundle retains a registry placeholder: {path}")
        if any(digest in text for digest in _PLACEHOLDER_DIGESTS):
            raise ValueError(
                f"bundle retains an application digest placeholder: {path}"
            )

    metadata = {
        "schema_version": 1,
        "environment": environment,
        "change_reference": change_reference,
        "images": {
            "control_plane": f"{control_plane_image}@{control_plane_digest}",
            "operator_ui": f"{operator_ui_image}@{operator_ui_digest}",
            "otel_collector": f"{otel_image}@{otel_digest}",
        },
        "git_commit": git_commit,
        "release_id": release_id,
        "deployment": {
            "public_domain": public_domain,
            "oidc_issuer": oidc_issuer,
            "oidc_jwks_url": oidc_jwks_url,
            "aws_region": aws_region,
            "data_cidr": str(network),
            "egress_proxy_url": egress_proxy_url,
            "otel_server_name": otel_server_name,
            "platform_alert_route": platform_alert_route,
            "database_alert_route": database_alert_route,
        },
    }
    metadata_path = output / "promotion.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksum_path = output / "SHA256SUMS"
    files = sorted(path for path in output.rglob("*") if path.is_file())
    checksum_path.write_text(
        "".join(f"{_sha256(path)}  {path.relative_to(output)}\n" for path in files),
        encoding="utf-8",
    )
    return checksum_path


def _https_endpoint(value: str, label: str) -> None:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname.endswith(".invalid")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS endpoint")


def _yaml_documents(path: Path) -> list[dict[str, Any]]:
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    if not documents or any(not isinstance(document, dict) for document in documents):
        raise ValueError(f"{path} must contain only YAML objects")
    return documents


def _write_yaml_documents(path: Path, documents: list[dict[str, Any]]) -> None:
    path.write_text(
        yaml.safe_dump_all(documents, sort_keys=False),
        encoding="utf-8",
    )


def _materialize_runtime(
    path: Path,
    *,
    oidc_issuer: str,
    oidc_jwks_url: str,
    aws_region: str,
    egress_proxy_url: str,
) -> None:
    documents = _yaml_documents(path)
    runtime = next(
        document
        for document in documents
        if document.get("kind") == "ConfigMap"
        and document["metadata"]["name"] == "aegis-runtime"
    )
    data = runtime["data"]
    data["AEGIS_OIDC_ISSUER"] = oidc_issuer
    data["AEGIS_OIDC_JWKS_URL"] = oidc_jwks_url
    data["HTTPS_PROXY"] = egress_proxy_url
    data["https_proxy"] = egress_proxy_url
    data["NO_PROXY"] = ".svc,.svc.cluster.local,localhost,127.0.0.1"
    data["no_proxy"] = data["NO_PROXY"]
    attributes = str(data["OTEL_RESOURCE_ATTRIBUTES"])
    data["OTEL_RESOURCE_ATTRIBUTES"] = re.sub(
        r"cloud\.region=[^,]+",
        f"cloud.region={aws_region}",
        attributes,
    )
    store = next(
        document
        for document in documents
        if document.get("kind") == "ClusterSecretStore"
    )
    store["spec"]["provider"]["aws"]["region"] = aws_region
    _write_yaml_documents(path, documents)


def _materialize_overlay_runtime(
    document: dict[str, Any],
    *,
    oidc_issuer: str,
    oidc_jwks_url: str,
    aws_region: str,
) -> None:
    replacements = {
        "/data/AEGIS_OIDC_ISSUER": oidc_issuer,
        "/data/AEGIS_OIDC_JWKS_URL": oidc_jwks_url,
    }
    for patch in document.get("patches", []):
        target = patch.get("target", {})
        if target.get("kind") != "ConfigMap" or target.get("name") != "aegis-runtime":
            continue
        operations = yaml.safe_load(patch["patch"])
        for operation in operations:
            path = operation.get("path")
            if path in replacements:
                operation["value"] = replacements[path]
            elif path == "/data/OTEL_RESOURCE_ATTRIBUTES":
                operation["value"] = re.sub(
                    r"cloud\.region=[^,]+",
                    f"cloud.region={aws_region}",
                    str(operation["value"]),
                )
        patch["patch"] = yaml.safe_dump(operations, sort_keys=False).rstrip()


def _materialize_ingress(path: Path, *, public_domain: str) -> None:
    documents = _yaml_documents(path)
    for document in documents:
        if document.get("kind") == "Gateway":
            for listener in document["spec"]["listeners"]:
                listener["hostname"] = (
                    f"*.{public_domain}"
                    if listener["name"] == "http"
                    else f"api.{public_domain}"
                    if listener["name"] == "api-https"
                    else f"operator.{public_domain}"
                )
        elif document.get("kind") == "HTTPRoute":
            name = document["metadata"]["name"]
            document["spec"]["hostnames"] = (
                [f"api.{public_domain}", f"operator.{public_domain}"]
                if name == "aegis-http-redirect"
                else [f"api.{public_domain}"]
                if name == "aegis-api"
                else [f"operator.{public_domain}"]
            )
    _write_yaml_documents(path, documents)


def _materialize_data_cidr(path: Path, *, data_cidr: str) -> None:
    documents = _yaml_documents(path)
    replacements = 0
    for document in documents:
        spec = document.get("spec", {})
        for rule in spec.get("egress", []):
            for destination in rule.get("to", []):
                block = destination.get("ipBlock")
                if isinstance(block, dict) and block.get("cidr") == "10.42.128.0/17":
                    block["cidr"] = data_cidr
                    replacements += 1
    if replacements != 3:
        raise ValueError("managed data CIDR policy count has drifted")
    _write_yaml_documents(path, documents)


def _materialize_admission(
    path: Path,
    *,
    application_images: tuple[str, str],
) -> None:
    documents = _yaml_documents(path)
    policy = next(
        document
        for document in documents
        if document.get("kind") == "ClusterPolicy"
        and document["metadata"]["name"] == "aegis-image-verification"
    )
    for verification in policy["spec"]["rules"][0]["verifyImages"]:
        verification["imageReferences"] = [f"{image}*" for image in application_images]
    _write_yaml_documents(path, documents)


def _materialize_observability(
    path: Path,
    *,
    otel_endpoint: str,
    otel_server_name: str,
    platform_alert_route: str,
    database_alert_route: str,
) -> None:
    documents = _yaml_documents(path)
    config_map = next(
        document
        for document in documents
        if document.get("kind") == "ConfigMap"
        and document["metadata"]["name"] == "aegis-otel-collector"
    )
    collector_config = yaml.safe_load(config_map["data"]["config.yaml"])
    collector_config["exporters"]["otlp"]["endpoint"] = otel_endpoint
    collector_config["exporters"]["otlp"]["tls"]["server_name"] = otel_server_name
    config_map["data"]["config.yaml"] = yaml.safe_dump(
        collector_config,
        sort_keys=False,
    )
    rules = next(
        document
        for document in documents
        if document.get("kind") == "PrometheusRule"
        and document["metadata"]["name"] == "aegis-deployment"
    )
    alert_routes = {
        "AegisDeploymentUnavailable": platform_alert_route,
        "AegisMigrationJobFailed": database_alert_route,
    }
    for rule in rules["spec"]["groups"][0]["rules"]:
        rule["labels"]["route"] = alert_routes[rule["alert"]]
    _write_yaml_documents(path, documents)


def _materialize_release_jobs(bundle_root: Path, *, release_id: str) -> None:
    for relative_path in ("base/migration-job.yaml", "base/sandbox-boundary.yaml"):
        path = bundle_root / relative_path
        documents = _yaml_documents(path)
        for document in documents:
            if document.get("kind") != "Job":
                continue
            original_name = str(document["metadata"]["name"])
            document["metadata"]["name"] = f"{original_name}-{release_id}"
            document["metadata"].setdefault("labels", {})["aegis.dev/release-id"] = (
                release_id
            )
        _write_yaml_documents(path, documents)


def _materialize_controller_lock(path: Path, *, registry: str) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    document["registry"] = registry
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_commit() -> str:
    import subprocess

    return subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> None:
    """Parse CLI inputs and write the immutable promotion bundle."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    parser.add_argument("--control-plane-image", required=True)
    parser.add_argument("--control-plane-digest", required=True)
    parser.add_argument("--operator-ui-image", required=True)
    parser.add_argument("--operator-ui-digest", required=True)
    parser.add_argument("--otel-image", required=True)
    parser.add_argument("--otel-digest", required=True)
    parser.add_argument("--public-domain", required=True)
    parser.add_argument("--oidc-issuer", required=True)
    parser.add_argument("--oidc-jwks-url", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--data-cidr", required=True)
    parser.add_argument("--egress-proxy-url", required=True)
    parser.add_argument("--otel-server-name", required=True)
    parser.add_argument("--platform-alert-route", required=True)
    parser.add_argument("--database-alert-route", required=True)
    parser.add_argument("--change-reference", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    checksum = materialize(
        environment=arguments.environment,
        control_plane_image=arguments.control_plane_image,
        control_plane_digest=arguments.control_plane_digest,
        operator_ui_image=arguments.operator_ui_image,
        operator_ui_digest=arguments.operator_ui_digest,
        otel_image=arguments.otel_image,
        otel_digest=arguments.otel_digest,
        public_domain=arguments.public_domain,
        oidc_issuer=arguments.oidc_issuer,
        oidc_jwks_url=arguments.oidc_jwks_url,
        aws_region=arguments.aws_region,
        data_cidr=arguments.data_cidr,
        egress_proxy_url=arguments.egress_proxy_url,
        otel_server_name=arguments.otel_server_name,
        platform_alert_route=arguments.platform_alert_route,
        database_alert_route=arguments.database_alert_route,
        change_reference=arguments.change_reference,
        output=arguments.output,
    )
    print(checksum)


if __name__ == "__main__":
    main()
