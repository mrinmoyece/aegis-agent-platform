"""Read-only Kubernetes evidence adapter over the official Python client."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Protocol

from aegis_agent_platform.domain import (
    DeploymentReference,
    EvidenceKind,
    EvidenceReference,
    EvidenceSeverity,
    EvidenceSourceKind,
    JsonValue,
    PartialResult,
    ResourceIdentity,
    ServiceIdentity,
    TrustStatus,
)
from aegis_agent_platform.evidence import (
    CancellationSignal,
    ConnectorCapability,
    ConnectorError,
    ConnectorErrorClass,
    ConnectorPage,
    EvidenceQuery,
    RawEvidence,
)
from aegis_agent_platform.integrations._pagination import decode_cursor, encode_cursor
from aegis_agent_platform.integrations.config import KubernetesConnectorConfig
from aegis_agent_platform.integrations.kubernetes.official import (
    OfficialKubernetesClient,
)
from aegis_agent_platform.tenancy import TenantContext

_DNS = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
_SUPPORTED = (
    EvidenceKind.WORKLOAD,
    EvidenceKind.POD,
    EvidenceKind.REPLICA_SET,
    EvidenceKind.EVENT,
    EvidenceKind.LOG,
)


class KubernetesClient(Protocol):
    """Neutral subset implemented with the official client inside the adapter."""

    async def list_resources(
        self,
        kind: EvidenceKind,
        namespace: str,
        *,
        label_selector: str | None,
        name: str | None,
        limit: int,
        continue_token: str | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Sequence[Mapping[str, object]], str | None]: ...

    async def pod_logs(
        self,
        namespace: str,
        pod: str,
        *,
        since_seconds: int,
        tail_lines: int,
        limit_bytes: int,
        timeout_seconds: float,
    ) -> str: ...


class KubernetesAdapter:
    source = EvidenceSourceKind.KUBERNETES

    def __init__(
        self,
        context: TenantContext,
        config: KubernetesConnectorConfig,
        client: KubernetesClient,
    ) -> None:
        if context.tenant_id != config.tenant_id:
            raise PermissionError("cross_tenant_connector_config")
        if not config.enabled:
            raise ValueError("Kubernetes connector is disabled")
        self._context = context
        self._config = config
        self._client = client

    async def capability(self) -> ConnectorCapability:
        kinds = tuple(
            kind
            for kind in _SUPPORTED
            if kind is not EvidenceKind.LOG or self._config.allow_logs
        )
        return ConnectorCapability(
            self.source,
            kinds,
            "kubernetes-readonly-v1",
            True,
            "workload_identity",
        )

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> ConnectorPage:
        namespace = query.selectors.get("namespace")
        if query.tenant_id != str(self._context.tenant_id):
            raise PermissionError("cross_tenant_query")
        if len(query.kinds) != 1:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "kubernetes_single_kind_required",
                retryable=False,
            )
        if namespace not in self._config.namespaces:
            raise PermissionError("namespace_not_allowed")
        label = query.selectors.get("label")
        name = query.selectors.get("name")
        if any(value is not None and not _selector(value) for value in (label, name)):
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "unsafe_kubernetes_selector",
                retryable=False,
            )
        records: list[RawEvidence] = []
        reasons: list[str] = []
        cursor_state = decode_cursor(
            query.cursor,
            allowed_keys=tuple(kind.value for kind in query.kinds),
        )
        next_cursors: dict[str, str] = {}
        record_cap = min(query.limit, self._config.limits.max_records)
        active_kinds = (
            query.kinds
            if cursor_state is None
            else tuple(kind for kind in query.kinds if kind.value in cursor_state)
        )
        for kind in active_kinds:
            if len(records) >= record_cap:
                reasons.append("record_cap")
                break
            if cancellation is not None and cancellation.cancelled:
                raise ConnectorError(
                    ConnectorErrorClass.CANCELLED,
                    "query_cancelled",
                    retryable=False,
                    partial=bool(records),
                )
            if kind is EvidenceKind.LOG:
                if not self._config.allow_logs:
                    raise PermissionError("kubernetes_logs_not_allowed")
                pod = query.selectors.get("pod")
                if pod is None or not _selector(pod):
                    raise ConnectorError(
                        ConnectorErrorClass.INVALID_QUERY,
                        "pod_selector_required",
                        retryable=False,
                    )
                text = await self._client.pod_logs(
                    namespace,
                    pod,
                    since_seconds=min(
                        int((query.window.end - query.window.start).total_seconds()),
                        self._config.limits.max_window_seconds,
                    ),
                    tail_lines=self._config.max_log_lines,
                    limit_bytes=self._config.max_log_bytes,
                    timeout_seconds=self._config.limits.timeout_seconds,
                )
                encoded = text.encode()
                truncated = len(encoded) > self._config.max_log_bytes
                if truncated:
                    text = encoded[: self._config.max_log_bytes].decode(
                        "utf-8", errors="replace"
                    )
                    reasons.append("log_byte_cap")
                records.append(
                    RawEvidence(
                        f"{namespace}/{pod}/{query.window.end.isoformat()}",
                        EvidenceKind.LOG,
                        query.window.end.astimezone(UTC),
                        f"bounded logs for pod {pod}",
                        {"content": text, "truncated": truncated},
                        f"https://kubernetes.invalid/{self._config.cluster}/{namespace}/pods/{pod}",
                        service=ServiceIdentity(query.selectors.get("service", pod)),
                        resource=ResourceIdentity(
                            "pod", pod, namespace, self._config.cluster
                        ),
                        trust=TrustStatus.VERIFIED,
                    )
                )
                continue
            if kind not in _SUPPORTED:
                raise ConnectorError(
                    ConnectorErrorClass.CAPABILITY,
                    "unsupported_evidence_kind",
                    retryable=False,
                )
            items, cursor = await self._client.list_resources(
                kind,
                namespace,
                label_selector=label,
                name=name,
                limit=record_cap - len(records),
                continue_token=(cursor_state.get(kind.value) if cursor_state else None),
                timeout_seconds=self._config.limits.timeout_seconds,
                max_response_bytes=self._config.limits.max_response_bytes,
            )
            records.extend(
                _normalize(item, kind, self._config.cluster, namespace)
                for item in items
            )
            if cursor:
                next_cursors[kind.value] = cursor
                reasons.append("upstream_pagination")
        if len(records) > record_cap:
            records = records[:record_cap]
            reasons.append("record_cap")
        return ConnectorPage(
            records,
            encode_cursor(next_cursors),
            PartialResult(
                bool(reasons),
                "record_cap" in reasons or "log_byte_cap" in reasons,
                tuple(sorted(set(reasons))),
            ),
        )


def _normalize(
    item: Mapping[str, object],
    kind: EvidenceKind,
    cluster: str,
    namespace: str,
) -> RawEvidence:
    metadata = item.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "kubernetes_metadata_missing",
            retryable=False,
        )
    name = metadata.get("name")
    uid = metadata.get("uid")
    timestamp = metadata.get("creationTimestamp")
    if not isinstance(name, str) or not isinstance(uid, str):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "kubernetes_identity_missing",
            retryable=False,
        )
    observed = _time(
        _first_timestamp(
            item.get("lastTimestamp"),
            item.get("eventTime"),
            timestamp,
        )
    )
    status = item.get("status")
    status_mapping = status if isinstance(status, Mapping) else {}
    spec = item.get("spec")
    spec_mapping = spec if isinstance(spec, Mapping) else {}
    termination_reasons = _termination_reasons(status_mapping)
    images, image_digests = _container_images(spec_mapping, status_mapping)
    fields: dict[str, JsonValue] = {
        "uid": uid,
        "generation": metadata.get("generation"),
        "resourceVersion": metadata.get("resourceVersion"),
        "replicas": spec_mapping.get("replicas"),
        "readyReplicas": status_mapping.get("readyReplicas"),
        "availableReplicas": status_mapping.get("availableReplicas"),
        "phase": status_mapping.get("phase"),
        "reason": str(item["reason"]) if item.get("reason") is not None else None,
        "terminationReasons": termination_reasons,
        "images": images,
    }
    revision = metadata.get("annotations")
    annotations = revision if isinstance(revision, Mapping) else {}
    reference_items: list[EvidenceReference] = []
    rollout = annotations.get("deployment.kubernetes.io/revision")
    if isinstance(rollout, str):
        reference_items.extend(
            DeploymentReference(rollout, digest) for digest in image_digests
        )
        if not image_digests:
            reference_items.append(DeploymentReference(rollout))
    elif image_digests:
        reference_items.extend(
            DeploymentReference(digest, digest) for digest in image_digests
        )
    reason = str(item.get("reason", status_mapping.get("phase", kind.value)))
    return RawEvidence(
        uid,
        kind,
        observed,
        f"{kind.value} {namespace}/{name}: {reason}"[:4096],
        fields,
        f"https://kubernetes.invalid/{cluster}/{namespace}/{kind.value}/{name}",
        service=ServiceIdentity(str(metadata.get("labels", {}).get("app", name)))
        if isinstance(metadata.get("labels"), Mapping)
        else ServiceIdentity(name),
        resource=ResourceIdentity(kind.value, name, namespace, cluster),
        severity=(
            EvidenceSeverity.WARNING
            if str(item.get("type", "")).lower() == "warning"
            else EvidenceSeverity.INFO
        ),
        references=tuple(reference_items),
        trust=TrustStatus.VERIFIED,
    )


def _time(value: object) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            pass
    raise ConnectorError(
        ConnectorErrorClass.MALFORMED_RESPONSE,
        "kubernetes_timestamp_invalid",
        retryable=False,
    )


def _first_timestamp(*values: object) -> object:
    for value in values:
        if isinstance(value, str) and value:
            return value
    return None


def _selector(value: str) -> bool:
    return len(value) <= 253 and bool(_DNS.fullmatch(value))


def _termination_reasons(status: Mapping[str, object]) -> tuple[str, ...]:
    reasons: set[str] = set()
    raw_statuses = status.get("containerStatuses", [])
    if not isinstance(raw_statuses, list):
        return ()
    for raw_status in raw_statuses[:50]:
        if not isinstance(raw_status, Mapping):
            continue
        for state_name in ("state", "lastState"):
            state = raw_status.get(state_name)
            state_mapping = state if isinstance(state, Mapping) else {}
            terminated = state_mapping.get("terminated")
            terminated_mapping = terminated if isinstance(terminated, Mapping) else {}
            reason = terminated_mapping.get("reason")
            if isinstance(reason, str) and 0 < len(reason) <= 128:
                reasons.add(reason)
    return tuple(sorted(reasons))


def _container_images(
    spec: Mapping[str, object],
    status: Mapping[str, object],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    template = spec.get("template")
    template_mapping = template if isinstance(template, Mapping) else {}
    pod_spec = template_mapping.get("spec", spec)
    pod_spec_mapping = pod_spec if isinstance(pod_spec, Mapping) else {}
    images: set[str] = set()
    containers = pod_spec_mapping.get("containers", [])
    if isinstance(containers, list):
        for container in containers[:50]:
            if not isinstance(container, Mapping):
                continue
            image = container.get("image")
            if isinstance(image, str) and 0 < len(image) <= 2048:
                images.add(image)
    statuses = status.get("containerStatuses", [])
    if isinstance(statuses, list):
        for container in statuses[:50]:
            if not isinstance(container, Mapping):
                continue
            image = container.get("image")
            if isinstance(image, str) and 0 < len(image) <= 2048:
                images.add(image)
            image_id = container.get("imageID")
            if isinstance(image_id, str) and 0 < len(image_id) <= 2048:
                images.add(image_id)
    digests = {
        match.group(0)
        for image in images
        if (match := re.search(r"sha256:[0-9a-fA-F]{64}", image)) is not None
    }
    return tuple(sorted(images)), tuple(sorted(digests))


__all__ = ["KubernetesAdapter", "KubernetesClient", "OfficialKubernetesClient"]
