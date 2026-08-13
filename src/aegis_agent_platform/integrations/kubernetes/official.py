"""Official Kubernetes client bootstrap and vendor-type containment."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from typing import cast
from urllib.parse import quote

from urllib3.exceptions import HTTPError

from aegis_agent_platform.domain import EvidenceKind
from aegis_agent_platform.evidence import ConnectorError, ConnectorErrorClass


class OfficialKubernetesClient:
    """Vendor-containing boundary configured from workload identity or kubeconfig."""

    def __init__(self, *, in_cluster: bool = True) -> None:
        try:
            from kubernetes import client, config
        except ImportError as error:
            raise RuntimeError("kubernetes dependency is not installed") from error
        if in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
        self._api = client.ApiClient()
        self._host = self._api.configuration.host.rstrip("/")
        if not self._host.startswith("https://"):
            raise ValueError("Kubernetes API origin must use HTTPS")

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
    ) -> tuple[Sequence[Mapping[str, object]], str | None]:
        resource_path = {
            EvidenceKind.POD: "api/v1",
            EvidenceKind.EVENT: "api/v1",
            EvidenceKind.WORKLOAD: "apis/apps/v1",
            EvidenceKind.REPLICA_SET: "apis/apps/v1",
        }.get(kind)
        collection = {
            EvidenceKind.POD: "pods",
            EvidenceKind.EVENT: "events",
            EvidenceKind.WORKLOAD: "deployments",
            EvidenceKind.REPLICA_SET: "replicasets",
        }.get(kind)
        if resource_path is None or collection is None:
            raise ValueError("unsupported Kubernetes list kind")
        path = f"/{resource_path}/namespaces/{quote(namespace, safe='')}/{collection}"
        content = await self._get(
            path,
            (
                ("labelSelector", label_selector),
                ("fieldSelector", f"metadata.name={name}" if name else None),
                ("limit", str(limit)),
                ("continue", continue_token),
            ),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        try:
            serialized = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_response_invalid_json",
                retryable=False,
            ) from error
        if not isinstance(serialized, dict):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_collection_invalid",
                retryable=False,
            )
        items = serialized.get("items", [])
        metadata = serialized.get("metadata", {})
        if not isinstance(items, list) or not isinstance(metadata, dict):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_collection_invalid",
                retryable=False,
            )
        return (
            tuple(
                cast(Mapping[str, object], item)
                for item in items
                if isinstance(item, dict)
            ),
            cast(str | None, metadata.get("_continue") or metadata.get("continue")),
        )

    async def pod_logs(
        self,
        namespace: str,
        pod: str,
        *,
        since_seconds: int,
        tail_lines: int,
        limit_bytes: int,
        timeout_seconds: float,
    ) -> str:
        value = await self._get(
            (
                f"/api/v1/namespaces/{quote(namespace, safe='')}/pods/"
                f"{quote(pod, safe='')}/log"
            ),
            (
                ("sinceSeconds", str(since_seconds)),
                ("tailLines", str(tail_lines)),
                ("limitBytes", str(limit_bytes)),
                ("timestamps", "true"),
            ),
            timeout_seconds=timeout_seconds,
            max_response_bytes=limit_bytes,
            accept="text/plain",
        )
        return value.decode("utf-8", errors="replace")

    async def _get(
        self,
        path: str,
        query: Sequence[tuple[str, str | None]],
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        accept: str = "application/json",
    ) -> bytes:
        return await asyncio.to_thread(
            self._get_sync,
            path,
            query,
            timeout_seconds,
            max_response_bytes,
            accept,
        )

    def _get_sync(
        self,
        path: str,
        query: Sequence[tuple[str, str | None]],
        timeout_seconds: float,
        max_response_bytes: int,
        accept: str,
    ) -> bytes:
        headers = {"accept": accept}
        parameters = [(key, value) for key, value in query if value is not None]
        self._api.update_params_for_auth(headers, parameters, ["BearerToken"])
        try:
            response = self._api.rest_client.pool_manager.request(
                "GET",
                self._host + path,
                fields=parameters,
                preload_content=False,
                timeout=timeout_seconds,
                headers=headers,
                redirect=False,
            )
            content = _bounded_response(response, max_response_bytes)
        except ConnectorError:
            raise
        except (HTTPError, TimeoutError, OSError) as error:
            raise ConnectorError(
                ConnectorErrorClass.UNAVAILABLE,
                "kubernetes_transport_failed",
                retryable=True,
            ) from error
        if not 200 <= response.status < 300:
            raise _api_error(response.status)
        return content


def _bounded_response(response: object, maximum: int) -> bytes:
    read = getattr(response, "read", None)
    release = getattr(response, "release_conn", None)
    close = getattr(response, "close", None)
    if not callable(read) or not callable(release) or not callable(close):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "kubernetes_response_invalid",
            retryable=False,
        )
    try:
        content = read(maximum + 1)
    except (HTTPError, TimeoutError, OSError):
        close()
        raise
    if not isinstance(content, bytes):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "kubernetes_response_invalid",
            retryable=False,
        )
    if len(content) > maximum:
        close()
        raise ConnectorError(
            ConnectorErrorClass.RESPONSE_TOO_LARGE,
            "kubernetes_response_too_large",
            retryable=False,
        )
    release()
    return content


def _api_error(status: object) -> ConnectorError:
    code = status if isinstance(status, int) else 0
    if code == 401:
        error_class = ConnectorErrorClass.AUTHENTICATION
        retryable = False
    elif code == 403:
        error_class = ConnectorErrorClass.AUTHORIZATION
        retryable = False
    elif code == 429:
        error_class = ConnectorErrorClass.RATE_LIMIT
        retryable = True
    elif code in {408, 504}:
        error_class = ConnectorErrorClass.TIMEOUT
        retryable = True
    else:
        error_class = ConnectorErrorClass.UNAVAILABLE
        retryable = code == 0 or code >= 500
    return ConnectorError(
        error_class,
        "kubernetes_api_request_failed",
        retryable=retryable,
    )


__all__ = ["OfficialKubernetesClient"]
