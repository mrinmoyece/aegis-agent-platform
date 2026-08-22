"""Official Kubernetes client bootstrap and vendor-type containment."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast
from urllib.parse import quote, urlencode

from urllib3.exceptions import HTTPError

from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    EvidenceKind,
    JsonScalar,
    ReconciliationOutcome,
)
from aegis_agent_platform.evidence import ConnectorError, ConnectorErrorClass
from aegis_agent_platform.remediation.execution import (
    ActionAdapterResult,
    ActionErrorClass,
    ActionObservation,
    ControlledActionError,
    ControlledActionPort,
)
from aegis_agent_platform.tenancy import TenantContext


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
        if any(not isinstance(item, dict) for item in items):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_collection_invalid",
                retryable=False,
            )
        return (
            tuple(cast(Mapping[str, object], item) for item in items),
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

    async def deployment(
        self,
        namespace: str,
        name: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int = 65_536,
    ) -> Mapping[str, object]:
        """Read one deployment through the same bounded official-client transport."""
        content = await self._get(
            (
                f"/apis/apps/v1/namespaces/{quote(namespace, safe='')}/"
                f"deployments/{quote(name, safe='')}"
            ),
            (),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return _json_object(content, "kubernetes_deployment_invalid")

    async def restart_deployment(
        self,
        namespace: str,
        name: str,
        *,
        idempotency_key: str,
        dry_run: bool,
        timeout_seconds: float,
        max_response_bytes: int = 65_536,
    ) -> Mapping[str, object]:
        """Apply one idempotent rollout annotation; no arbitrary patch is accepted."""
        if not idempotency_key or len(idempotency_key.encode()) > 128:
            raise ValueError("restart idempotency key must be bounded")
        path = (
            f"/apis/apps/v1/namespaces/{quote(namespace, safe='')}/"
            f"deployments/{quote(name, safe='')}"
        )
        body = json.dumps(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "aegis.github.com/restart-id": idempotency_key
                            }
                        }
                    }
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        content = await asyncio.to_thread(
            self._request_sync,
            "PATCH",
            path,
            (("dryRun", "All" if dry_run else None),),
            timeout_seconds,
            max_response_bytes,
            "application/json",
            body,
            "application/merge-patch+json",
        )
        return _json_object(content, "kubernetes_restart_response_invalid")

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
        return self._request_sync(
            "GET",
            path,
            query,
            timeout_seconds,
            max_response_bytes,
            accept,
            None,
            None,
        )

    def _request_sync(
        self,
        method: str,
        path: str,
        query: Sequence[tuple[str, str | None]],
        timeout_seconds: float,
        max_response_bytes: int,
        accept: str,
        body: bytes | None,
        content_type: str | None,
    ) -> bytes:
        headers = {"accept": accept}
        if content_type is not None:
            headers["content-type"] = content_type
        parameters = [(key, value) for key, value in query if value is not None]
        self._api.update_params_for_auth(headers, parameters, ["BearerToken"])
        url = self._host + path
        fields: Sequence[tuple[str, str]] | None = parameters
        if body is not None and parameters:
            url = f"{url}?{urlencode(parameters)}"
            fields = None
        try:
            response = self._api.rest_client.pool_manager.request(
                method,
                url,
                fields=fields,
                body=body,
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


class OfficialKubernetesActionAdapter(ControlledActionPort):
    """Bounded rollout-restart adapter; unsupported reversal fails closed."""

    def __init__(
        self,
        client: OfficialKubernetesClient,
        *,
        tenant_id: str,
        environment: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not tenant_id or not environment:
            raise ValueError("Kubernetes action tenant and environment are required")
        self._client = client
        self._tenant_id = tenant_id
        self._environment = environment
        self._clock = clock

    def supports(self, action: ActionSpecification) -> bool:
        return (
            action.kind is ActionKind.KUBERNETES_ROLLOUT_RESTART
            and action.target.provider == "kubernetes"
            and action.target.environment == self._environment
            and action.target.resource_type == "deployment"
        )

    async def observe(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionObservation:
        self._validate_binding(context, action)
        deployment = await self._deployment(action)
        metadata = _object_field(deployment, "metadata")
        target_fingerprint = self._observed_target_fingerprint(action, metadata)
        spec = _object_field(deployment, "spec")
        status = _object_field(deployment, "status")
        template = _object_field(spec, "template")
        template_metadata = _object_field(template, "metadata")
        annotations = _object_field(template_metadata, "annotations")
        restart_id = annotations.get("aegis.github.com/restart-id")
        observed_generation = status.get("observedGeneration")
        generation = metadata.get("generation")
        available = status.get("availableReplicas")
        desired = spec.get("replicas")
        values: dict[str, JsonScalar] = {
            "deployment.available": (
                isinstance(available, int)
                and isinstance(desired, int)
                and available >= desired
            ),
            "deployment.restart_observed": restart_id == action.idempotency_key,
            "deployment.generation_observed": (
                isinstance(observed_generation, int)
                and isinstance(generation, int)
                and observed_generation >= generation
            ),
        }
        state_fingerprint = sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        resource_version = metadata.get("resourceVersion")
        evidence_id = (
            f"kubernetes:{resource_version}"
            if isinstance(resource_version, str) and resource_version
            else "kubernetes:deployment"
        )
        return ActionObservation(
            target_fingerprint=target_fingerprint,
            state_fingerprint=state_fingerprint,
            values=values,
            evidence_ids=(evidence_id[:256],),
            observed_at=self._clock(),
        )

    async def dry_run(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        self._validate_binding(context, action)
        response = await self._restart(action, dry_run=True)
        return self._result(action, response, "kubernetes-dry-run")

    async def execute(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        self._validate_binding(context, action)
        response = await self._restart(action, dry_run=False)
        return self._result(action, response, "kubernetes-restart")

    async def reconcile(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> tuple[ReconciliationOutcome, ActionObservation]:
        observation = await self.observe(context, action)
        applied = observation.values.get("deployment.restart_observed") is True
        return (
            ReconciliationOutcome.APPLIED
            if applied
            else ReconciliationOutcome.NOT_APPLIED,
            observation,
        )

    async def rollback(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        del context, action
        raise ControlledActionError(
            ActionErrorClass.PERMANENT,
            "rollout_restart_has_no_safe_rollback",
            retryable=False,
        )

    async def compensate(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> ActionAdapterResult:
        del context, action
        raise ControlledActionError(
            ActionErrorClass.PERMANENT,
            "rollout_restart_has_no_safe_compensation",
            retryable=False,
        )

    async def _deployment(
        self,
        action: ActionSpecification,
    ) -> Mapping[str, object]:
        try:
            return await self._client.deployment(
                action.target.scope,
                action.target.resource_id,
                timeout_seconds=action.timeout_seconds,
            )
        except ConnectorError as error:
            raise _action_error(error) from error

    async def _restart(
        self,
        action: ActionSpecification,
        *,
        dry_run: bool,
    ) -> Mapping[str, object]:
        try:
            return await self._client.restart_deployment(
                action.target.scope,
                action.target.resource_id,
                idempotency_key=action.idempotency_key,
                dry_run=dry_run,
                timeout_seconds=action.timeout_seconds,
            )
        except ConnectorError as error:
            raise _action_error(error) from error

    def _result(
        self,
        action: ActionSpecification,
        response: Mapping[str, object],
        fallback: str,
    ) -> ActionAdapterResult:
        metadata = _object_field(response, "metadata")
        target_fingerprint = self._observed_target_fingerprint(action, metadata)
        uid = metadata.get("uid")
        resource_version = metadata.get("resourceVersion")
        reference = (
            f"{uid}:{resource_version}"
            if isinstance(uid, str)
            and uid
            and isinstance(resource_version, str)
            and resource_version
            else fallback
        )
        return ActionAdapterResult(
            provider_reference=reference[:512],
            target_fingerprint=target_fingerprint,
            completed_at=self._clock(),
        )

    def _validate_binding(
        self,
        context: TenantContext,
        action: ActionSpecification,
    ) -> None:
        _validate_action_context(context, action)
        if str(context.tenant_id) != self._tenant_id:
            raise PermissionError("Kubernetes action adapter tenant mismatch")
        if not self.supports(action):
            raise PermissionError("Kubernetes action target binding mismatch")

    def _observed_target_fingerprint(
        self,
        action: ActionSpecification,
        metadata: Mapping[str, object],
    ) -> str:
        name = metadata.get("name")
        namespace = metadata.get("namespace")
        if not isinstance(name, str) or not isinstance(namespace, str):
            raise ControlledActionError(
                ActionErrorClass.PROVIDER_BUG,
                "kubernetes_target_identity_missing",
                retryable=False,
            )
        if name != action.target.resource_id or namespace != action.target.scope:
            raise ControlledActionError(
                ActionErrorClass.CONFLICT,
                "kubernetes_target_identity_changed",
                retryable=False,
            )
        return action.target.fingerprint


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


def _json_object(content: bytes, code: str) -> Mapping[str, object]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            code,
            retryable=False,
        ) from error
    if not isinstance(value, dict):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            code,
            retryable=False,
        )
    return cast(Mapping[str, object], value)


def _object_field(value: Mapping[str, object], name: str) -> Mapping[str, object]:
    field = value.get(name)
    if field is None:
        return {}
    if not isinstance(field, dict):
        raise ControlledActionError(
            ActionErrorClass.PERMANENT,
            "kubernetes_provider_object_malformed",
            retryable=False,
        )
    return cast(Mapping[str, object], field)


def _validate_action_context(
    context: TenantContext,
    action: ActionSpecification,
) -> None:
    if not str(context.tenant_id):
        raise PermissionError("tenant context is required")
    if not action.idempotency_key.startswith(f"{context.tenant_id}:"):
        raise PermissionError("action idempotency key is not tenant scoped")
    if action.kind is not ActionKind.KUBERNETES_ROLLOUT_RESTART:
        raise ValueError("unsupported Kubernetes controlled action")
    if (
        action.target.provider != "kubernetes"
        or action.target.resource_type != "deployment"
    ):
        raise ValueError("unsupported Kubernetes controlled target")


def _action_error(error: ConnectorError) -> ControlledActionError:
    error_class = {
        ConnectorErrorClass.AUTHENTICATION: ActionErrorClass.AUTHENTICATION,
        ConnectorErrorClass.AUTHORIZATION: ActionErrorClass.AUTHORIZATION,
        ConnectorErrorClass.RATE_LIMIT: ActionErrorClass.RATE_LIMIT,
        ConnectorErrorClass.TIMEOUT: ActionErrorClass.TIMEOUT,
        ConnectorErrorClass.UNAVAILABLE: ActionErrorClass.TRANSIENT,
    }.get(error.error_class, ActionErrorClass.PERMANENT)
    return ControlledActionError(
        error_class,
        error.code,
        retryable=error.retryable,
        ambiguous=error.error_class is ConnectorErrorClass.TIMEOUT,
    )


__all__ = ["OfficialKubernetesActionAdapter", "OfficialKubernetesClient"]
