"""Validate deterministic Layer 15 deployment and operations invariants."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
KUBERNETES = ROOT / "deploy" / "kubernetes"
TERRAFORM = ROOT / "infra" / "terraform" / "aws"
DIGEST = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
ALLOWED_IMAGE_ALIASES = {
    "aegis-control-plane",
    "aegis-operator-ui",
    "otel-collector",
}


def _documents(paths: Iterable[Path]) -> tuple[Mapping[str, Any], ...]:
    documents: list[Mapping[str, Any]] = []
    for path in paths:
        for raw in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if raw is None:
                continue
            if not isinstance(raw, Mapping):
                raise SystemExit(f"{path} contains a non-object YAML document")
            documents.append(raw)
    return tuple(documents)


def _metadata(document: Mapping[str, Any]) -> Mapping[str, Any]:
    value = document.get("metadata", {})
    if not isinstance(value, Mapping):
        raise SystemExit("resource metadata must be an object")
    return value


def _name(document: Mapping[str, Any]) -> str:
    value = _metadata(document).get("name")
    if not isinstance(value, str) or not value:
        raise SystemExit("every Kubernetes resource requires metadata.name")
    return value


def _pod_spec(document: Mapping[str, Any]) -> Mapping[str, Any] | None:
    kind = document.get("kind")
    spec = document.get("spec")
    if not isinstance(spec, Mapping):
        return None
    if kind == "Deployment" or kind == "Job":
        template = spec.get("template")
    else:
        return None
    if not isinstance(template, Mapping):
        raise SystemExit(f"{_name(document)} lacks a pod template")
    value = template.get("spec")
    if not isinstance(value, Mapping):
        raise SystemExit(f"{_name(document)} lacks a pod spec")
    return value


def _validate_workload(document: Mapping[str, Any], pod: Mapping[str, Any]) -> None:
    name = _name(document)
    security = pod.get("securityContext")
    if not isinstance(security, Mapping):
        raise SystemExit(f"{name} lacks pod securityContext")
    if security.get("runAsNonRoot") is not True:
        raise SystemExit(f"{name} must run as non-root")
    seccomp = security.get("seccompProfile")
    if not isinstance(seccomp, Mapping) or seccomp.get("type") != "RuntimeDefault":
        raise SystemExit(f"{name} must use RuntimeDefault seccomp")
    if pod.get("automountServiceAccountToken") is not False:
        raise SystemExit(f"{name} must disable service-account token automount")
    for boundary in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(boundary) is True:
            raise SystemExit(f"{name} enables forbidden {boundary}")
    for volume in pod.get("volumes", []):
        if isinstance(volume, Mapping) and "hostPath" in volume:
            raise SystemExit(f"{name} uses forbidden hostPath")
    containers = pod.get("containers")
    if not isinstance(containers, list) or not containers:
        raise SystemExit(f"{name} requires containers")
    for container in containers:
        if not isinstance(container, Mapping):
            raise SystemExit(f"{name} contains an invalid container")
        image = container.get("image")
        if not isinstance(image, str) or (
            image not in ALLOWED_IMAGE_ALIASES and DIGEST.fullmatch(image) is None
        ):
            raise SystemExit(f"{name} image is not digest-pinned or a known alias")
        container_security = container.get("securityContext")
        if not isinstance(container_security, Mapping):
            raise SystemExit(f"{name} lacks container securityContext")
        if container_security.get("allowPrivilegeEscalation") is not False:
            raise SystemExit(f"{name} allows privilege escalation")
        if container_security.get("readOnlyRootFilesystem") is not True:
            raise SystemExit(f"{name} root filesystem is writable")
        capabilities = container_security.get("capabilities")
        if not isinstance(capabilities, Mapping) or capabilities.get("drop") != ["ALL"]:
            raise SystemExit(f"{name} must drop all Linux capabilities")
        resources = container.get("resources")
        if not isinstance(resources, Mapping):
            raise SystemExit(f"{name} lacks resources")
        if not resources.get("requests") or not resources.get("limits"):
            raise SystemExit(f"{name} requires resource requests and limits")
    if document.get("kind") == "Deployment":
        deployment_spec = document.get("spec")
        if not isinstance(deployment_spec, Mapping):
            raise SystemExit(f"{name} lacks a deployment spec")
        strategy = deployment_spec.get("strategy")
        if not isinstance(strategy, Mapping) or strategy.get("type") != "RollingUpdate":
            raise SystemExit(f"{name} lacks an explicit rolling strategy")
        if not pod.get("terminationGracePeriodSeconds"):
            raise SystemExit(f"{name} lacks a termination budget")
        if not pod.get("topologySpreadConstraints"):
            raise SystemExit(f"{name} lacks topology spread")
        for container in containers:
            if not isinstance(container, Mapping):
                continue
            if not all(
                probe in container
                for probe in ("startupProbe", "readinessProbe", "livenessProbe")
            ):
                raise SystemExit(f"{name} lacks health probes")
            if not isinstance(container.get("lifecycle"), Mapping):
                raise SystemExit(f"{name} lacks graceful preStop handling")


def _validate_kubernetes() -> None:
    base_paths = sorted((KUBERNETES / "base").glob("*.yaml"))
    documents = _documents(base_paths)
    kinds = {str(document.get("kind")) for document in documents}
    required_kinds = {
        "Deployment",
        "BackendTrafficPolicy",
        "ExternalSecret",
        "Gateway",
        "HorizontalPodAutoscaler",
        "HTTPRoute",
        "Job",
        "LimitRange",
        "Namespace",
        "NetworkPolicy",
        "PodDisruptionBudget",
        "PodMonitor",
        "PriorityClass",
        "PrometheusRule",
        "ResourceQuota",
        "Role",
        "RoleBinding",
        "RuntimeClass",
        "Service",
        "ServiceAccount",
        "ServiceMonitor",
    }
    missing_kinds = required_kinds - kinds
    if missing_kinds:
        raise SystemExit(
            "Kubernetes foundation missing: " + ", ".join(sorted(missing_kinds))
        )
    if any(document.get("kind") == "Secret" for document in documents):
        raise SystemExit("plaintext Kubernetes Secret resources are prohibited")
    external_resources = [
        document
        for document in documents
        if document.get("kind") in {"ExternalSecret", "ClusterSecretStore"}
    ]
    if not external_resources or any(
        document.get("apiVersion") != "external-secrets.io/v1"
        for document in external_resources
    ):
        raise SystemExit("External Secrets resources must use the served v1 API")
    base_kustomization = (KUBERNETES / "base" / "kustomization.yaml").read_text(
        encoding="utf-8"
    )
    for control in (
        "securityContext/fsGroup",
        "value: 10001",
        "fsGroupChangePolicy",
        "defaultMode: 288",
    ):
        if control not in base_kustomization:
            raise SystemExit(
                f"writer-fence secret ownership control missing: {control}"
            )
    service_accounts = {
        (
            str(_metadata(document).get("namespace")),
            _name(document),
        )
        for document in documents
        if document.get("kind") == "ServiceAccount"
    }
    expected_service_accounts = {
        ("aegis-sandbox", "aegis-sandbox-cleanup"),
        ("aegis-sandbox", "aegis-sandbox-runner"),
        ("aegis-system", "aegis-api"),
        ("aegis-system", "aegis-migrator"),
        ("aegis-system", "aegis-operator-ui"),
        ("aegis-system", "aegis-otel"),
        ("aegis-system", "aegis-worker"),
    }
    if service_accounts != expected_service_accounts:
        raise SystemExit("Kubernetes service-account matrix has drifted")
    roles = [document for document in documents if document.get("kind") == "Role"]
    if len(roles) != 1 or _name(roles[0]) != "sandbox-cleanup":
        raise SystemExit("only the sandbox cleanup controller may hold Kubernetes RBAC")
    rules = roles[0].get("rules")
    if not isinstance(rules, list) or {
        (
            tuple(str(item) for item in rule.get("apiGroups", [])),
            tuple(str(item) for item in rule.get("resources", [])),
            tuple(str(item) for item in rule.get("verbs", [])),
        )
        for rule in rules
        if isinstance(rule, Mapping)
    } != {
        (("batch",), ("jobs",), ("get", "list", "watch", "delete")),
        (("",), ("pods",), ("get", "list", "watch", "delete")),
    }:
        raise SystemExit("sandbox cleanup can-i matrix exceeds reviewed permissions")
    workload_names: set[str] = set()
    for document in documents:
        pod = _pod_spec(document)
        if pod is not None:
            _validate_workload(document, pod)
            workload_names.add(_name(document))
    required_workloads = {
        "aegis-api",
        "aegis-operator-bff",
        "aegis-operator-ui",
        "aegis-worker-general",
        "aegis-worker-evidence",
        "aegis-outbox-publisher",
        "aegis-reconciler",
        "aegis-protocol-gateway",
        "aegis-otel-collector",
        "aegis-schema-migration",
        "aegis-sandbox-conformance-template",
    }
    if missing := required_workloads - workload_names:
        raise SystemExit("Kubernetes workloads missing: " + ", ".join(sorted(missing)))
    deployments = {
        _name(document): document
        for document in documents
        if document.get("kind") == "Deployment"
    }
    for gated in (
        "aegis-operator-bff",
        "aegis-protocol-gateway",
        "aegis-worker-evidence",
        "aegis-worker-general",
    ):
        spec = deployments[gated].get("spec")
        if not isinstance(spec, Mapping) or spec.get("replicas") != 0:
            raise SystemExit(f"{gated} must fail closed at zero replicas")
    disruption_budgets = {
        _name(document)
        for document in documents
        if document.get("kind") == "PodDisruptionBudget"
    }
    required_budgets = {
        "aegis-api",
        "aegis-operator-ui",
        "aegis-otel-collector",
        "aegis-outbox-publisher",
        "aegis-reconciler",
    }
    if disruption_budgets != required_budgets:
        raise SystemExit("PodDisruptionBudget coverage has drifted")
    default_denies = {
        str(_metadata(document).get("namespace"))
        for document in documents
        if document.get("kind") == "NetworkPolicy" and _name(document) == "default-deny"
    }
    if default_denies != {
        "aegis-data",
        "aegis-egress",
        "aegis-sandbox",
        "aegis-system",
    }:
        raise SystemExit("every Aegis workload namespace requires default deny")
    network_text = (KUBERNETES / "base" / "network-policies.yaml").read_text(
        encoding="utf-8"
    )
    for intent in (
        "allow-dns",
        "allow-data-services",
        "allow-migration-postgresql",
        "allow-postgresql-from-system",
        "allow-redis-from-system",
        "allow-otel",
        "allow-otel-ingress",
        "allow-approved-external-egress",
        "allow-telemetry-via-egress-gateway",
        "allow-system-to-egress-gateway",
        "allow-egress-gateway-public-tls",
        "allow-envoy-gateway",
        "oidc-provider-connectors-and-protocol-peers-via-egress-gateway",
        "deny-metadata-link-local-private-and-special-use-addresses",
        "network-policy-data-cidr-plus-aws-security-group",
        "10.42.128.0/17",
    ):
        if intent not in network_text:
            raise SystemExit(f"network intent missing: {intent}")
    ingress_text = (KUBERNETES / "base" / "ingress.yaml").read_text(encoding="utf-8")
    for control in (
        "envoy-gateway-v1.8.3",
        "scheme: https",
        "requestBuffer:",
        "rateLimit:",
        "timeouts:",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    ):
        if control not in ingress_text:
            raise SystemExit(f"ingress control missing: {control}")
    migration_job = (KUBERNETES / "base" / "migration-job.yaml").read_text(
        encoding="utf-8"
    )
    if "--adopt-existing" in migration_job:
        raise SystemExit("migration Job must not adopt unverified legacy schemas")
    policy = (KUBERNETES / "policies" / "kyverno.yaml").read_text(encoding="utf-8")
    for control in (
        "validationFailureAction: Enforce",
        "verifyImages:",
        "failurePolicy: Fail",
        "type: Cosign",
        "cosignOCI11: true",
        "type: SigstoreBundle",
        "immutable-images",
        "no-host-boundaries",
        "no-host-paths",
        "initContainers",
        "ephemeralContainers",
    ):
        if control not in policy:
            raise SystemExit(f"admission policy control missing: {control}")
    for overlay in ("development", "staging", "production"):
        path = KUBERNETES / "overlays" / overlay / "kustomization.yaml"
        overlay_text = path.read_text(encoding="utf-8")
        configuration = yaml.safe_load(overlay_text)
        if not isinstance(configuration, Mapping):
            raise SystemExit(f"{overlay} kustomization is invalid")
        images = configuration.get("images")
        if not isinstance(images, list) or len(images) < 2:
            raise SystemExit(f"{overlay} must promote application images by digest")
        for image in images:
            if not isinstance(image, Mapping):
                raise SystemExit(f"{overlay} image transform is invalid")
            digest = image.get("digest")
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            ):
                raise SystemExit(f"{overlay} image digest is invalid")
        if overlay != "production":
            for marker in (
                f"value: {overlay}",
                f"/aegis/{overlay}/database",
                f"/aegis/{overlay}/ingress-tls",
                f"/aegis/{overlay}/writer-fences",
                f"identity.{overlay}.example.invalid",
                f"deployment.environment={overlay}",
            ):
                if marker not in overlay_text:
                    raise SystemExit(
                        f"{overlay} environment isolation missing: {marker}"
                    )


def _validate_terraform() -> None:
    terraform_files = sorted(TERRAFORM.rglob("*.tf"))
    if not terraform_files:
        raise SystemExit("AWS Terraform reference is missing")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in terraform_files)
    required = (
        'required_version = "= 1.11.4"',
        'version = "= 5.100.0"',
        'backend "s3"',
        "enable_reference_environment",
        "aws_eks_cluster",
        "endpoint_public_access  = false",
        "aws_db_instance",
        "manage_master_user_password",
        "multi_az",
        "aws_elasticache_replication_group",
        "transit_encryption_enabled = true",
        "aws_backup_vault_lock_configuration",
        "AWSBackupServiceRolePolicyForS3Backup",
        'aws_kms_key" "logs',
        '"eks-auth"',
        "aws_eks_access_entry",
        "aws_eks_pod_identity_association",
        "aws_eks_addon",
        'enableNetworkPolicy = "true"',
        'aws_iam_role" "external_secrets',
        'image_tag_mutability = "IMMUTABLE"',
        '"aegis-otel-collector"',
        "aws_vpc_endpoint",
    )
    for control in required:
        if control not in combined:
            raise SystemExit(f"Terraform control missing: {control}")
    iam = (TERRAFORM / "modules" / "reference" / "security.tf").read_text(
        encoding="utf-8"
    )
    if "master_user_secret" in iam:
        raise SystemExit(
            "runtime workload identities must not read the RDS master secret"
        )
    forbidden = re.compile(
        r"(?im)^\s*(?:password|auth_token|secret_string)\s*=\s*\"[^\"]+\""
    )
    if forbidden.search(combined):
        raise SystemExit("Terraform contains a plaintext credential")
    backend = (TERRAFORM / "backend.hcl.example").read_text(encoding="utf-8")
    for control in ("encrypt      = true", "use_lockfile = true", "kms_key_id"):
        if control not in backend:
            raise SystemExit(f"remote-state control missing: {control}")
    if not (TERRAFORM / "tests" / "reference.tftest.hcl").exists():
        raise SystemExit("mocked Terraform plan tests are required")


def _validate_supply_chain() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if dockerfile.count("FROM python:3.14.7-slim-bookworm@sha256:") != 2:
        raise SystemExit("Python base images must be digest-pinned")
    for lockfile in ("requirements.lock", "requirements-dev.lock"):
        lock = ROOT / lockfile
        if not lock.is_file() or "--hash=sha256:" not in lock.read_text(
            encoding="utf-8"
        ):
            raise SystemExit(f"hashed Python dependency lock missing: {lockfile}")
    if "--require-hashes" not in dockerfile:
        raise SystemExit("application image must enforce dependency hashes")
    if "--no-build-isolation" not in dockerfile:
        raise SystemExit("application build backend must come from the hashed lock")
    if "hatchling==" not in (ROOT / "requirements.lock").read_text(encoding="utf-8"):
        raise SystemExit("application build backend is missing from the hashed lock")
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose.get("services", {}) if isinstance(compose, Mapping) else {}
    if not isinstance(services, Mapping):
        raise SystemExit("Compose services are invalid")
    for name, service in services.items():
        if not isinstance(service, Mapping):
            continue
        image = service.get("image")
        if image is not None and (
            not isinstance(image, str) or DIGEST.fullmatch(image) is None
        ):
            raise SystemExit(f"Compose image is mutable: {name}")
    for workflow in (
        "infrastructure.yml",
        "promotion.yml",
        "restore-drill.yml",
        "supply-chain.yml",
    ):
        if not (ROOT / ".github" / "workflows" / workflow).exists():
            raise SystemExit(f"Layer 15 workflow missing: {workflow}")
    supply_chain = (ROOT / ".github" / "workflows" / "supply-chain.yml").read_text(
        encoding="utf-8"
    )
    for control in (
        "github.event_name == 'push'",
        "linux/amd64,linux/arm64",
        "format: spdx-json",
        "severity-cutoff: high",
        "only-fixed: false",
        "Resolve exact platform digests",
        "application_arm64",
        "check_vulnerability_policy.py",
        "scan-type: fs",
        "scanners: secret",
        "cosign sign --yes --registry-referrers-mode oci-1-1",
        "actions/attest-build-provenance@",
        "actions/attest@",
        "https://spdx.dev/Document/v2.3",
        "build_spdx_index.py",
        "qemu-v9.2.2@sha256:1b804311fe87047a4c96d38b4b3ef6f62fca8cd125265917a9e3dc3c996c39e6",
        "id-token: write",
        "packages: write",
        "retention-days: 30",
    ):
        if control not in supply_chain:
            raise SystemExit(f"supply-chain control missing: {control}")
    if "pull_request_target:" in supply_chain:
        raise SystemExit("supply-chain workflow must not expose secrets to forks")
    promotion = (ROOT / ".github" / "workflows" / "promotion.yml").read_text(
        encoding="utf-8"
    )
    mirror = (ROOT / "scripts" / "mirror_promotion_images.sh").read_text(
        encoding="utf-8"
    )
    for control in (
        "cosign verify",
        "gh attestation verify",
        "--certificate-identity-regexp",
        "--certificate-oidc-issuer",
        "https://slsa.dev/provenance/v1",
        "https://spdx.dev/Document/v2.3",
        "--signer-workflow",
        "--source-ref refs/heads/master",
        "operator-ui-linux-arm64.grype.json",
        '"${image}@${digest}"',
        "packages: read",
        "docker/login-action@",
        "aws-actions/configure-aws-credentials@",
        "aws-actions/amazon-ecr-login@",
        "materialize_kustomize_bundle.py",
        "aegis-production-bundle",
        "--public-domain",
        "--egress-proxy-url",
        "--otel-server-name",
        "--platform-alert-route",
        "--database-alert-route",
        "sha256sum --check SHA256SUMS",
        "check_vulnerability_policy.py",
        "environment: development",
        "environment: staging",
        "environment: production",
        'test "${GITHUB_REF}" = "refs/heads/master"',
        "oras-project/setup-oras@22ce207df3b08e061f537244349aac6ae1d214f6",
        "version: 1.2.2",
        "GH_TOKEN: ${{ github.token }}",
    ):
        if control not in promotion:
            raise SystemExit(f"promotion control missing: {control}")
    for control in (
        "oras copy --recursive",
        "--bundle-from-oci",
        "--registry-referrers-mode oci-1-1",
        "gh attestation verify",
        "aegis-otel-collector",
        'test "${mirrored}"',
    ):
        if control not in mirror:
            raise SystemExit(f"private registry mirror control missing: {control}")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for control in (
        "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
        "sha256:e5bb2084ccf45087bda1c9bffdea0eb15ee67f0b91646106e466714f9de3c7e3",
        "/opt/aegis/trust/rds-global-bundle.pem",
    ):
        if control not in dockerfile:
            raise SystemExit(f"RDS trust-bundle control missing: {control}")
    controller_lock = KUBERNETES / "bootstrap" / "controller-lock.json"
    if (
        not controller_lock.is_file()
        or not (ROOT / "scripts" / "verify_cluster_prerequisites.py").is_file()
    ):
        raise SystemExit("versioned controller prerequisite gate is missing")
    locked_controllers = json.loads(controller_lock.read_text(encoding="utf-8"))
    if locked_controllers.get("api_versions") != [
        "external-secrets.io/v1",
        "monitoring.coreos.com/v1",
    ]:
        raise SystemExit("served controller API versions are not locked")
    if "prometheus-operator" not in locked_controllers.get("components", {}):
        raise SystemExit("Prometheus Operator prerequisite is not locked")
    waiver_path = ROOT / "security" / "vulnerability-waivers.yaml"
    waivers = yaml.safe_load(waiver_path.read_text(encoding="utf-8"))
    if not isinstance(waivers, Mapping) or not isinstance(waivers.get("waivers"), list):
        raise SystemExit("vulnerability waivers must use the reviewed schema")
    expected_false_positive_reports = {
        "aegis-agent-platform/linux-amd64",
        "aegis-agent-platform/linux-arm64",
    }
    false_positive_reports = {
        str(waiver.get("report"))
        for waiver in waivers["waivers"]
        if isinstance(waiver, Mapping)
        and waiver.get("vulnerability_id") == "CVE-2026-15308"
        and waiver.get("package") == "python"
        and waiver.get("package_version") == "3.14.7"
        and waiver.get("disposition") == "false_positive"
        and waiver.get("scanner") == "grype"
        and waiver.get("scanner_version") == "0.117.0"
        and str(waiver.get("advisory_reference", "")).startswith("https://")
        and bool(waiver.get("verification_evidence"))
    }
    if false_positive_reports != expected_false_positive_reports:
        raise SystemExit("Python scanner false-positive scope is incomplete")


def main() -> None:
    """Run all dependency-free production-foundation assertions."""
    _validate_kubernetes()
    _validate_terraform()
    _validate_supply_chain()


if __name__ == "__main__":
    main()
