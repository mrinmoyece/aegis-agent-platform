"""Official Kubernetes client bootstrap and vendor-type containment."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Protocol, cast
from urllib.parse import quote, urlencode

from urllib3.exceptions import HTTPError

from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    CapturedArtifact,
    CapturedOutput,
    EvidenceKind,
    JsonScalar,
    MountAccess,
    NetworkMode,
    ReconciliationOutcome,
    SandboxExecutionOutcome,
    SandboxReconciliationOutcome,
    SandboxRequest,
    SandboxResult,
    WorkLease,
)
from aegis_agent_platform.evidence import ConnectorError, ConnectorErrorClass
from aegis_agent_platform.remediation.execution import (
    ActionAdapterResult,
    ActionErrorClass,
    ActionObservation,
    ControlledActionError,
    ControlledActionPort,
)
from aegis_agent_platform.sandbox.execution import (
    BackendReadiness,
    ProvisionedSandbox,
    SandboxBackend,
    SandboxBackendError,
    SandboxErrorClass,
    SandboxObservation,
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
        if not all(isinstance(item, dict) for item in items):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_collection_item_invalid",
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

    async def sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int = 262_144,
    ) -> Mapping[str, object] | None:
        """Observe a stable Job name without turning a 404 into ambiguity."""
        content = await self._get(
            f"/apis/batch/v1/namespaces/{quote(namespace, safe='')}/jobs",
            (
                ("fieldSelector", f"metadata.name={name}"),
                ("limit", "2"),
            ),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        collection = _json_object(content, "kubernetes_job_collection_invalid")
        items = collection.get("items")
        if not isinstance(items, list):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_job_collection_invalid",
                retryable=False,
            )
        objects = tuple(item for item in items if isinstance(item, Mapping))
        if len(objects) > 1:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "kubernetes_job_identity_conflict",
                retryable=False,
            )
        return cast(Mapping[str, object], objects[0]) if objects else None

    async def create_sandbox_job(
        self,
        namespace: str,
        manifest: Mapping[str, object],
        *,
        timeout_seconds: float,
        max_response_bytes: int = 262_144,
    ) -> Mapping[str, object]:
        """Create one prevalidated suspended Job using the official transport."""
        body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        content = await asyncio.to_thread(
            self._request_sync,
            "POST",
            f"/apis/batch/v1/namespaces/{quote(namespace, safe='')}/jobs",
            (),
            timeout_seconds,
            max_response_bytes,
            "application/json",
            body,
            "application/json",
        )
        return _json_object(content, "kubernetes_job_create_response_invalid")

    async def start_sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        fence_annotations: Mapping[str, str],
        resource_version: str,
        timeout_seconds: float,
        max_response_bytes: int = 262_144,
    ) -> Mapping[str, object]:
        """Unsuspend the exact previously provisioned Job."""
        body = json.dumps(
            {
                "metadata": {
                    "annotations": dict(fence_annotations),
                    "resourceVersion": resource_version,
                },
                "spec": {"suspend": False},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        content = await asyncio.to_thread(
            self._request_sync,
            "PATCH",
            (
                f"/apis/batch/v1/namespaces/{quote(namespace, safe='')}/jobs/"
                f"{quote(name, safe='')}"
            ),
            (),
            timeout_seconds,
            max_response_bytes,
            "application/json",
            body,
            "application/merge-patch+json",
        )
        return _json_object(content, "kubernetes_job_start_response_invalid")

    async def fence_sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        fence_annotations: Mapping[str, str],
        resource_version: str,
        timeout_seconds: float,
        max_response_bytes: int = 262_144,
    ) -> Mapping[str, object]:
        """Claim the external fence through the required admission boundary."""
        body = json.dumps(
            {
                "metadata": {
                    "annotations": dict(fence_annotations),
                    "resourceVersion": resource_version,
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        content = await asyncio.to_thread(
            self._request_sync,
            "PATCH",
            (
                f"/apis/batch/v1/namespaces/{quote(namespace, safe='')}/jobs/"
                f"{quote(name, safe='')}"
            ),
            (),
            timeout_seconds,
            max_response_bytes,
            "application/json",
            body,
            "application/merge-patch+json",
        )
        return _json_object(content, "kubernetes_job_fence_response_invalid")

    async def delete_sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        uid: str,
        resource_version: str,
        timeout_seconds: float,
        max_response_bytes: int = 65_536,
    ) -> None:
        """Delete one stable Job with foreground propagation."""
        body = json.dumps(
            {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {
                    "resourceVersion": resource_version,
                    "uid": uid,
                },
                "propagationPolicy": "Foreground",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        await asyncio.to_thread(
            self._request_sync,
            "DELETE",
            (
                f"/apis/batch/v1/namespaces/{quote(namespace, safe='')}/jobs/"
                f"{quote(name, safe='')}"
            ),
            (),
            timeout_seconds,
            max_response_bytes,
            "application/json",
            body,
            "application/json",
        )

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


@dataclass(frozen=True, slots=True)
class KubernetesSandboxControls:
    """Deployment evidence supplied by the platform readiness integration."""

    namespace: str
    runtime_class_name: str
    admission_policy_verified: bool
    default_deny_network_verified: bool
    runtime_isolation_verified: bool
    pid_limit_verified: bool
    artifact_collector_verified: bool
    brokered_egress_verified: bool
    fencing_admission_verified: bool

    def __post_init__(self) -> None:
        for value, name in (
            (self.namespace, "sandbox namespace"),
            (self.runtime_class_name, "sandbox runtime class"),
        ):
            if (
                not value
                or value != value.strip()
                or len(value) > 128
                or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-."
                    for character in value
                )
            ):
                raise ValueError(f"{name} is invalid")

    @property
    def ready(self) -> bool:
        return (
            self.admission_policy_verified
            and self.default_deny_network_verified
            and self.runtime_isolation_verified
            and self.pid_limit_verified
            and self.artifact_collector_verified
            and self.fencing_admission_verified
        )


class KubernetesArtifactCollector(Protocol):
    """Trusted artifact sidecar/object-store boundary, never pod exec."""

    async def collect(
        self,
        context: TenantContext,
        request: SandboxRequest,
        job_name: str,
    ) -> tuple[CapturedArtifact, ...]: ...


class OfficialKubernetesSandboxBackend(SandboxBackend):
    """Hardened suspended-Job adapter with honest environment readiness gates."""

    def __init__(
        self,
        client: OfficialKubernetesClient,
        controls: KubernetesSandboxControls,
        artifact_collector: KubernetesArtifactCollector,
        *,
        tenant_id: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not tenant_id:
            raise ValueError("Kubernetes sandbox tenant is required")
        self._client = client
        self._controls = controls
        self._artifacts = artifact_collector
        self._tenant_id = tenant_id
        self._clock = clock
        self._sleep = sleep

    async def readiness(self, context: TenantContext) -> BackendReadiness:
        tenant_matches = str(context.tenant_id) == self._tenant_id
        ready = tenant_matches and self._controls.ready
        return BackendReadiness(
            ready=ready,
            reason=(
                "kubernetes_sandbox_controls_verified"
                if ready
                else "kubernetes_sandbox_controls_unverified"
            ),
            backend_identity="official-kubernetes-job-v1",
            isolation_verified=(
                tenant_matches
                and self._controls.runtime_isolation_verified
                and self._controls.pid_limit_verified
            ),
            egress_verified=(
                tenant_matches and self._controls.default_deny_network_verified
            ),
            admission_verified=(
                tenant_matches and self._controls.admission_policy_verified
            ),
        )

    async def observe(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> SandboxObservation:
        self._validate_scope(context, request)
        try:
            job = await self._client.sandbox_job(
                self._controls.namespace,
                _sandbox_job_name(request.sandbox_id),
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=True) from error
        if job is None:
            return SandboxObservation(
                SandboxReconciliationOutcome.ABSENT,
                None,
                None,
                self._clock(),
            )
        reference, _name, _uid, _resource_version, observed_digest = (
            _sandbox_job_details(job, request)
        )
        status = _object_field(job, "status")
        active = status.get("active")
        succeeded = status.get("succeeded")
        failed = status.get("failed")
        outcome = (
            SandboxReconciliationOutcome.TERMINAL
            if (isinstance(succeeded, int) and succeeded > 0)
            or (isinstance(failed, int) and failed > 0)
            else SandboxReconciliationOutcome.RUNNING
            if isinstance(active, int) and active > 0
            else SandboxReconciliationOutcome.PRESENT
        )
        return SandboxObservation(
            outcome,
            reference,
            observed_digest,
            self._clock(),
        )

    async def provision(
        self,
        context: TenantContext,
        request: SandboxRequest,
        lease: WorkLease,
    ) -> ProvisionedSandbox:
        self._validate(context, request)
        self._validate_lease(request, lease)
        manifest = kubernetes_sandbox_workload(
            request,
            lease,
            namespace=self._controls.namespace,
            runtime_class_name=self._controls.runtime_class_name,
        )
        try:
            created = await self._client.create_sandbox_job(
                self._controls.namespace,
                manifest,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=True) from error
        reference, _name, _uid, _resource_version, observed_digest = (
            _sandbox_job_details(created, request)
        )
        if observed_digest != request.spec.digest:
            raise SandboxBackendError(
                SandboxErrorClass.CONFLICT,
                "kubernetes_sandbox_spec_annotation_changed",
                retryable=False,
            )
        return ProvisionedSandbox(reference, request.spec.digest, self._clock())

    async def start(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None:
        self._validate_reference(context, request, backend_reference)
        self._validate(context, request)
        self._validate_lease(request, lease)
        name, _uid = _sandbox_reference_parts(request, backend_reference)
        try:
            current = await self._client.sandbox_job(
                self._controls.namespace,
                name,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
            if current is None:
                raise SandboxBackendError(
                    SandboxErrorClass.CONFLICT,
                    "kubernetes_sandbox_job_missing_before_start",
                    retryable=False,
                )
            (
                observed_reference,
                _observed_name,
                _observed_uid,
                resource_version,
                observed_digest,
            ) = _sandbox_job_details(current, request)
            if (
                observed_reference != backend_reference
                or observed_digest != request.spec.digest
            ):
                raise SandboxBackendError(
                    SandboxErrorClass.CONFLICT,
                    "kubernetes_sandbox_start_identity_changed",
                    retryable=False,
                )
            started = await self._client.start_sandbox_job(
                self._controls.namespace,
                name,
                fence_annotations=_fence_annotations(request, lease),
                resource_version=resource_version,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=True) from error
        started_reference, _name, _uid, _version, started_digest = _sandbox_job_details(
            started, request
        )
        if (
            started_reference != backend_reference
            or started_digest != request.spec.digest
        ):
            raise SandboxBackendError(
                SandboxErrorClass.CONFLICT,
                "kubernetes_sandbox_start_response_changed",
                retryable=False,
            )

    async def collect(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
    ) -> SandboxResult:
        self._validate_reference(context, request, backend_reference)
        self._validate(context, request)
        name, uid = _sandbox_reference_parts(request, backend_reference)
        async with asyncio.timeout(request.spec.resources.timeout_seconds):
            while True:
                observation = await self.observe(context, request)
                if (
                    observation.backend_reference != backend_reference
                    or observation.observed_spec_digest != request.spec.digest
                ):
                    raise SandboxBackendError(
                        SandboxErrorClass.CONFLICT,
                        "kubernetes_sandbox_collect_identity_changed",
                        retryable=False,
                    )
                if observation.outcome is SandboxReconciliationOutcome.TERMINAL:
                    break
                await self._sleep(0.25)
        try:
            pods, _cursor = await self._client.list_resources(
                EvidenceKind.POD,
                self._controls.namespace,
                label_selector=f"batch.kubernetes.io/controller-uid={uid}",
                name=None,
                limit=2,
                continue_token=None,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
                max_response_bytes=262_144,
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=False) from error
        if len(pods) != 1:
            raise SandboxBackendError(
                SandboxErrorClass.PROVIDER_BUG,
                "kubernetes_sandbox_pod_identity_invalid",
                retryable=False,
            )
        pod = pods[0]
        metadata = _object_field(pod, "metadata")
        pod_name = metadata.get("name")
        if not isinstance(pod_name, str):
            raise SandboxBackendError(
                SandboxErrorClass.PROVIDER_BUG,
                "kubernetes_sandbox_pod_name_missing",
                retryable=False,
            )
        _validate_pod_owner(metadata, name, uid)
        try:
            logs = await self._client.pod_logs(
                self._controls.namespace,
                pod_name,
                since_seconds=request.spec.resources.timeout_seconds + 60,
                tail_lines=10_000,
                limit_bytes=request.spec.resources.max_output_bytes,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=False) from error
        encoded = logs.encode()
        artifacts = await self._artifacts.collect(
            context,
            request,
            backend_reference,
        )
        try:
            final_job = await self._client.sandbox_job(
                self._controls.namespace,
                name,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=False) from error
        if final_job is None:
            raise SandboxBackendError(
                SandboxErrorClass.CONFLICT,
                "kubernetes_sandbox_job_missing_after_collection",
                retryable=False,
            )
        final_reference, _name, _uid, _version, final_digest = _sandbox_job_details(
            final_job, request
        )
        if final_reference != backend_reference or final_digest != request.spec.digest:
            raise SandboxBackendError(
                SandboxErrorClass.CONFLICT,
                "kubernetes_sandbox_collection_identity_changed",
                retryable=False,
            )
        outcome, exit_code, error_code = _pod_outcome(pod)
        empty_digest = sha256(b"").hexdigest()
        return SandboxResult(
            outcome=outcome,
            exit_code=exit_code,
            started_at=self._clock(),
            completed_at=self._clock(),
            stdout=CapturedOutput(
                "stdout",
                sha256(encoded).hexdigest(),
                len(encoded),
                len(encoded) >= request.spec.resources.max_output_bytes,
                True,
            ),
            stderr=CapturedOutput("stderr", empty_digest, 0, False, True),
            artifacts=artifacts,
            error_code=error_code,
        )

    async def terminate(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None:
        await self.cleanup(context, request, backend_reference, lease)

    async def cleanup(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
        lease: WorkLease,
    ) -> None:
        self._validate_reference(context, request, backend_reference)
        self._validate_lease(request, lease)
        name, uid = _sandbox_reference_parts(request, backend_reference)
        observation = await self.observe(context, request)
        if observation.outcome in {
            SandboxReconciliationOutcome.ABSENT,
            SandboxReconciliationOutcome.DELETED,
        }:
            return
        if (
            observation.backend_reference != backend_reference
            or observation.observed_spec_digest != request.spec.digest
        ):
            raise SandboxBackendError(
                SandboxErrorClass.CONFLICT,
                "kubernetes_sandbox_cleanup_identity_changed",
                retryable=False,
            )
        try:
            current = await self._client.sandbox_job(
                self._controls.namespace,
                name,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
            if current is None:
                return
            (
                current_reference,
                _current_name,
                _current_uid,
                current_resource_version,
                current_digest,
            ) = _sandbox_job_details(current, request)
            if (
                current_reference != backend_reference
                or current_digest != request.spec.digest
            ):
                raise SandboxBackendError(
                    SandboxErrorClass.CONFLICT,
                    "kubernetes_sandbox_cleanup_identity_changed",
                    retryable=False,
                )
            fenced = await self._client.fence_sandbox_job(
                self._controls.namespace,
                name,
                fence_annotations=_fence_annotations(request, lease),
                resource_version=current_resource_version,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
            (
                fenced_reference,
                _fenced_name,
                _fenced_uid,
                resource_version,
                fenced_digest,
            ) = _sandbox_job_details(fenced, request)
            if (
                fenced_reference != backend_reference
                or fenced_digest != request.spec.digest
            ):
                raise SandboxBackendError(
                    SandboxErrorClass.CONFLICT,
                    "kubernetes_sandbox_fence_response_changed",
                    retryable=False,
                )
            await self._client.delete_sandbox_job(
                self._controls.namespace,
                name,
                uid=uid,
                resource_version=resource_version,
                timeout_seconds=min(30, request.spec.resources.timeout_seconds),
            )
        except ConnectorError as error:
            raise _sandbox_error(error, ambiguous=True) from error
        try:
            async with asyncio.timeout(min(30, request.spec.resources.timeout_seconds)):
                while True:
                    observation = await self.observe(context, request)
                    if observation.outcome in {
                        SandboxReconciliationOutcome.ABSENT,
                        SandboxReconciliationOutcome.DELETED,
                    }:
                        return
                    if observation.backend_reference != backend_reference:
                        raise SandboxBackendError(
                            SandboxErrorClass.CONFLICT,
                            "kubernetes_sandbox_replaced_during_cleanup",
                            retryable=False,
                        )
                    await self._sleep(0.25)
        except TimeoutError as error:
            raise SandboxBackendError(
                SandboxErrorClass.AMBIGUOUS,
                "kubernetes_sandbox_delete_not_observed",
                retryable=True,
                ambiguous=True,
            ) from error

    def _validate(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> None:
        self._validate_scope(context, request)
        if not self._controls.ready:
            raise PermissionError("Kubernetes sandbox controls are not verified")
        if request.spec.network_mode is NetworkMode.BROKERED and not (
            self._controls.brokered_egress_verified
        ):
            raise PermissionError("Kubernetes brokered egress is not verified")
        if request.spec.secret_environment:
            raise PermissionError("Kubernetes sandbox secret broker is not implemented")
        if any(mount.access is MountAccess.READ_WRITE for mount in request.spec.mounts):
            raise PermissionError(
                "Kubernetes copy-on-write input staging is not implemented"
            )

    def _validate_scope(
        self,
        context: TenantContext,
        request: SandboxRequest,
    ) -> None:
        if (
            str(context.tenant_id) != self._tenant_id
            or request.linkage.tenant_id != self._tenant_id
        ):
            raise PermissionError("Kubernetes sandbox tenant mismatch")

    def _validate_reference(
        self,
        context: TenantContext,
        request: SandboxRequest,
        backend_reference: str,
    ) -> None:
        self._validate_scope(context, request)
        try:
            _sandbox_reference_parts(request, backend_reference)
        except SandboxBackendError as error:
            raise PermissionError("Kubernetes sandbox reference mismatch") from error

    def _validate_lease(self, request: SandboxRequest, lease: WorkLease) -> None:
        if (
            lease.work_id != request.sandbox_id
            or lease.tenant_id != request.linkage.tenant_id
            or lease.expires_at <= self._clock()
        ):
            raise PermissionError("Kubernetes sandbox fence is stale")


def kubernetes_sandbox_workload(
    request: SandboxRequest,
    lease: WorkLease,
    *,
    namespace: str,
    runtime_class_name: str,
) -> Mapping[str, object]:
    """Generate a locked-down suspended Job; cluster controls remain external."""
    spec = request.spec
    name = _sandbox_job_name(request.sandbox_id)
    tenant_hash = sha256(request.linkage.tenant_id.encode()).hexdigest()[:16]
    labels = {
        "app.kubernetes.io/name": "aegis-sandbox",
        "aegis.github.com/sandbox-id": str(request.sandbox_id),
        "aegis.github.com/tenant-hash": tenant_hash,
    }
    mounts: list[Mapping[str, object]] = [
        {"mountPath": "/workspace", "name": "workspace"},
        {"mountPath": "/outputs", "name": "outputs"},
    ]
    snapshot_csi: dict[str, object] = {
        "driver": "content.aegis.github.com",
        "readOnly": True,
        "volumeAttributes": {
            "contentDigest": spec.input_snapshot.digest,
            "contentReference": spec.input_snapshot.uri,
        },
    }
    volumes: list[Mapping[str, object]] = [
        {
            "emptyDir": {"sizeLimit": str(spec.resources.ephemeral_storage_bytes)},
            "name": "workspace",
        },
        {
            "emptyDir": {"sizeLimit": str(spec.resources.max_artifact_bytes)},
            "name": "outputs",
        },
        {
            "csi": snapshot_csi,
            "name": "input-snapshot",
        },
    ]
    mounts.append(
        {
            "mountPath": "/inputs/snapshot",
            "name": "input-snapshot",
            "readOnly": True,
        }
    )
    for index, mount in enumerate(spec.mounts):
        volume_name = f"input-{index}"
        mount_csi: dict[str, object] = {
            "driver": "content.aegis.github.com",
            "readOnly": mount.access.value == "read_only",
            "volumeAttributes": {
                "contentDigest": mount.source.digest,
                "contentReference": mount.source.uri,
            },
        }
        volumes.append(
            {
                "csi": mount_csi,
                "name": volume_name,
            }
        )
        mounts.append(
            {
                "mountPath": f"/{mount.target}",
                "name": volume_name,
                "readOnly": mount.access.value == "read_only",
            }
        )
    security_context = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"add": [], "drop": ["ALL"]},
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "runAsGroup": spec.isolation.run_as_group,
        "runAsNonRoot": True,
        "runAsUser": spec.isolation.run_as_user,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "annotations": {
                "aegis.github.com/apparmor-profile": (spec.isolation.apparmor_profile),
                **_fence_annotations(request, lease),
                "aegis.github.com/input-digest": spec.input_snapshot.digest,
                "aegis.github.com/sandbox-id": str(request.sandbox_id),
                "aegis.github.com/spec-digest": spec.digest,
            },
            "labels": labels,
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "activeDeadlineSeconds": spec.resources.timeout_seconds,
            "backoffLimit": 0,
            "completions": 1,
            "parallelism": 1,
            "suspend": True,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [
                        {
                            "args": list(spec.argv[1:]),
                            "command": [spec.argv[0]],
                            "env": [
                                {"name": key, "value": value}
                                for key, value in spec.environment.items()
                            ],
                            "image": spec.image,
                            "imagePullPolicy": "IfNotPresent",
                            "name": "analysis",
                            "resources": {
                                "limits": {
                                    "cpu": f"{spec.resources.cpu_millis}m",
                                    "ephemeral-storage": (
                                        str(spec.resources.ephemeral_storage_bytes)
                                    ),
                                    "memory": str(spec.resources.memory_bytes),
                                },
                                "requests": {
                                    "cpu": f"{spec.resources.cpu_millis}m",
                                    "ephemeral-storage": (
                                        str(spec.resources.ephemeral_storage_bytes)
                                    ),
                                    "memory": str(spec.resources.memory_bytes),
                                },
                            },
                            "securityContext": security_context,
                            "volumeMounts": mounts,
                            "workingDir": f"/{spec.working_directory}",
                        }
                    ],
                    "dnsPolicy": "None",
                    "dnsConfig": {"nameservers": ["127.0.0.1"]},
                    "enableServiceLinks": False,
                    "hostIPC": False,
                    "hostNetwork": False,
                    "hostPID": False,
                    "restartPolicy": "Never",
                    "runtimeClassName": runtime_class_name,
                    "securityContext": {
                        "fsGroup": spec.isolation.run_as_group,
                        "runAsGroup": spec.isolation.run_as_group,
                        "runAsNonRoot": True,
                        "runAsUser": spec.isolation.run_as_user,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "shareProcessNamespace": False,
                    "terminationGracePeriodSeconds": 5,
                    "volumes": volumes,
                },
            },
            "ttlSecondsAfterFinished": min(
                3_600,
                spec.cleanup_policy.maximum_retention_seconds,
            ),
        },
    }


def _fence_annotations(
    request: SandboxRequest,
    lease: WorkLease,
) -> Mapping[str, str]:
    return {
        "aegis.github.com/fence-generation": str(lease.generation),
        "aegis.github.com/fence-token-digest": sha256(
            str(lease.token).encode()
        ).hexdigest(),
        "aegis.github.com/sandbox-id": str(request.sandbox_id),
        "aegis.github.com/tenant-digest": sha256(
            request.linkage.tenant_id.encode()
        ).hexdigest(),
    }


def _sandbox_job_name(sandbox_id: object) -> str:
    identifier = str(sandbox_id).replace("-", "")
    return f"aegis-sbx-{identifier}"


def _sandbox_reference_parts(
    request: SandboxRequest,
    backend_reference: str,
) -> tuple[str, str]:
    name, separator, uid = backend_reference.partition("@")
    if (
        separator != "@"
        or name != _sandbox_job_name(request.sandbox_id)
        or not uid
        or len(uid) > 128
        or any(
            not (character.isascii() and (character.isalnum() or character in ".-"))
            for character in uid
        )
    ):
        raise SandboxBackendError(
            SandboxErrorClass.CONFLICT,
            "kubernetes_sandbox_reference_invalid",
            retryable=False,
        )
    return name, uid


def _sandbox_job_details(
    job: Mapping[str, object],
    request: SandboxRequest,
) -> tuple[str, str, str, str, str]:
    metadata = _object_field(job, "metadata")
    annotations = _object_field(metadata, "annotations")
    name = metadata.get("name")
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    sandbox_id = annotations.get("aegis.github.com/sandbox-id")
    spec_digest = annotations.get("aegis.github.com/spec-digest")
    if (
        name != _sandbox_job_name(request.sandbox_id)
        or not isinstance(uid, str)
        or not uid
        or not isinstance(resource_version, str)
        or not resource_version
        or sandbox_id != str(request.sandbox_id)
        or not isinstance(spec_digest, str)
    ):
        raise SandboxBackendError(
            SandboxErrorClass.CONFLICT,
            "kubernetes_sandbox_job_identity_invalid",
            retryable=False,
        )
    reference = f"{name}@{uid}"
    _sandbox_reference_parts(request, reference)
    return reference, name, uid, resource_version, spec_digest


def _validate_pod_owner(
    metadata: Mapping[str, object],
    job_name: str,
    job_uid: str,
) -> None:
    owner_references = metadata.get("ownerReferences")
    if not isinstance(owner_references, list):
        raise SandboxBackendError(
            SandboxErrorClass.CONFLICT,
            "kubernetes_sandbox_pod_owner_missing",
            retryable=False,
        )
    controllers = [
        owner
        for owner in owner_references
        if isinstance(owner, Mapping) and owner.get("controller") is True
    ]
    if len(controllers) != 1 or not (
        controllers[0].get("apiVersion") == "batch/v1"
        and controllers[0].get("kind") == "Job"
        and controllers[0].get("name") == job_name
        and controllers[0].get("uid") == job_uid
    ):
        raise SandboxBackendError(
            SandboxErrorClass.CONFLICT,
            "kubernetes_sandbox_pod_owner_invalid",
            retryable=False,
        )


def _pod_outcome(
    pod: Mapping[str, object],
) -> tuple[SandboxExecutionOutcome, int | None, str | None]:
    status = _object_field(pod, "status")
    container_statuses = status.get("containerStatuses")
    if not isinstance(container_statuses, list) or len(container_statuses) != 1:
        return SandboxExecutionOutcome.FAILED, None, "kubernetes_status_missing"
    container_status = container_statuses[0]
    if not isinstance(container_status, Mapping):
        return SandboxExecutionOutcome.FAILED, None, "kubernetes_status_invalid"
    state = _object_field(container_status, "state")
    terminated = _object_field(state, "terminated")
    reason = terminated.get("reason")
    exit_code = terminated.get("exitCode")
    parsed_exit = (
        exit_code
        if isinstance(exit_code, int) and not isinstance(exit_code, bool)
        else None
    )
    if reason == "OOMKilled":
        return SandboxExecutionOutcome.OOM_KILLED, parsed_exit, "sandbox_oom_killed"
    if reason == "DeadlineExceeded":
        return SandboxExecutionOutcome.TIMED_OUT, parsed_exit, "sandbox_timed_out"
    if parsed_exit == 0:
        return SandboxExecutionOutcome.SUCCEEDED, 0, None
    return SandboxExecutionOutcome.FAILED, parsed_exit, "sandbox_nonzero_exit"


def _sandbox_error(
    error: ConnectorError,
    *,
    ambiguous: bool,
) -> SandboxBackendError:
    error_class = {
        ConnectorErrorClass.AUTHENTICATION: SandboxErrorClass.AUTHENTICATION,
        ConnectorErrorClass.AUTHORIZATION: SandboxErrorClass.AUTHORIZATION,
        ConnectorErrorClass.RATE_LIMIT: SandboxErrorClass.RATE_LIMIT,
        ConnectorErrorClass.TIMEOUT: SandboxErrorClass.TIMEOUT,
        ConnectorErrorClass.INVALID_QUERY: SandboxErrorClass.INVALID_REQUEST,
        ConnectorErrorClass.MALFORMED_RESPONSE: SandboxErrorClass.PROVIDER_BUG,
        ConnectorErrorClass.RESPONSE_TOO_LARGE: SandboxErrorClass.PERMANENT,
        ConnectorErrorClass.CANCELLED: SandboxErrorClass.PERMANENT,
        ConnectorErrorClass.CAPABILITY: SandboxErrorClass.PERMANENT,
        ConnectorErrorClass.UNAVAILABLE: SandboxErrorClass.TRANSIENT,
    }[error.error_class]
    return SandboxBackendError(
        error_class,
        f"kubernetes_sandbox_{error.code}",
        retryable=error.retryable,
        ambiguous=ambiguous
        and error.error_class
        in {
            ConnectorErrorClass.TIMEOUT,
            ConnectorErrorClass.UNAVAILABLE,
        },
    )


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
