"""Official Kubernetes sandbox adapter boundary tests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import cast
from uuid import UUID

import pytest

from aegis_agent_platform.domain import (
    CapturedArtifact,
    EvidenceKind,
    MountAccess,
    MountDeclaration,
    NetworkMode,
    SandboxExecutionOutcome,
    SandboxReconciliationOutcome,
    SandboxRequest,
)
from aegis_agent_platform.integrations.kubernetes import (
    KubernetesArtifactCollector,
    KubernetesSandboxControls,
    OfficialKubernetesSandboxBackend,
    kubernetes_sandbox_workload,
)
from aegis_agent_platform.sandbox.execution import SandboxBackendError
from sandbox_helpers import CONTEXT, TENANT_ID, Clock, UUIDs, lease, request, spec


def _controls(**changes: object) -> KubernetesSandboxControls:
    values: dict[str, object] = {
        "namespace": "aegis-sandboxes",
        "runtime_class_name": "gvisor",
        "admission_policy_verified": True,
        "default_deny_network_verified": True,
        "runtime_isolation_verified": True,
        "pid_limit_verified": True,
        "artifact_collector_verified": True,
        "brokered_egress_verified": False,
        "fencing_admission_verified": True,
    }
    values.update(changes)
    return KubernetesSandboxControls(**values)  # type: ignore[arg-type]


class _Artifacts(KubernetesArtifactCollector):
    def __init__(self, artifact: CapturedArtifact) -> None:
        self.artifact = artifact
        self.calls: list[str] = []

    async def collect(
        self,
        context: object,
        request: SandboxRequest,
        job_name: str,
    ) -> tuple[CapturedArtifact, ...]:
        del context, request
        self.calls.append(job_name)
        return (self.artifact,)


class _KubernetesClient:
    def __init__(self) -> None:
        self.job: Mapping[str, object] | None = None
        self.manifest: Mapping[str, object] | None = None
        self.deleted = False
        self.calls: list[str] = []
        self.uid = "11111111-2222-3333-4444-555555555555"
        self.start_resource_version: str | None = None
        self.fence_resource_version: str | None = None
        self.delete_uid: str | None = None
        self.delete_resource_version: str | None = None
        self.pod_selector: str | None = None
        self.pod_owner_uid: str | None = None

    async def sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        timeout_seconds: float,
    ) -> Mapping[str, object] | None:
        del namespace, name, timeout_seconds
        self.calls.append("observe")
        return None if self.deleted else self.job

    async def create_sandbox_job(
        self,
        namespace: str,
        manifest: Mapping[str, object],
        *,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del namespace, timeout_seconds
        self.calls.append("create")
        self.manifest = manifest
        self.job = {
            "metadata": {
                **cast(Mapping[str, object], manifest["metadata"]),
                "resourceVersion": "1",
                "uid": self.uid,
            },
            "status": {},
        }
        return self.job

    async def start_sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        fence_annotations: Mapping[str, str],
        resource_version: str,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del namespace, name, timeout_seconds
        self.calls.append("start")
        self.start_resource_version = resource_version
        if self.job is None:
            raise AssertionError("job was not created")
        self.job = {
            **self.job,
            "metadata": {
                **cast(Mapping[str, object], self.job["metadata"]),
                "annotations": {
                    **cast(
                        Mapping[str, object],
                        cast(Mapping[str, object], self.job["metadata"])["annotations"],
                    ),
                    **fence_annotations,
                },
                "resourceVersion": "2",
            },
            "status": {"active": 1},
        }
        return self.job

    async def fence_sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        fence_annotations: Mapping[str, str],
        resource_version: str,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del namespace, name, timeout_seconds
        self.calls.append("fence")
        self.fence_resource_version = resource_version
        if self.job is None:
            raise AssertionError("job was not created")
        self.job = {
            **self.job,
            "metadata": {
                **cast(Mapping[str, object], self.job["metadata"]),
                "annotations": {
                    **cast(
                        Mapping[str, object],
                        cast(Mapping[str, object], self.job["metadata"])["annotations"],
                    ),
                    **fence_annotations,
                },
                "resourceVersion": "3",
            },
        }
        return self.job

    async def delete_sandbox_job(
        self,
        namespace: str,
        name: str,
        *,
        uid: str,
        resource_version: str,
        timeout_seconds: float,
    ) -> None:
        del namespace, name, timeout_seconds
        self.calls.append("delete")
        self.delete_uid = uid
        self.delete_resource_version = resource_version
        self.deleted = True

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
        del (
            kind,
            namespace,
            name,
            limit,
            continue_token,
            timeout_seconds,
            max_response_bytes,
        )
        self.pod_selector = label_selector
        self.calls.append("pods")
        return (
            (
                {
                    "metadata": {
                        "name": "sandbox-pod",
                        "ownerReferences": [
                            {
                                "apiVersion": "batch/v1",
                                "controller": True,
                                "kind": "Job",
                                "name": cast(
                                    Mapping[str, object],
                                    cast(Mapping[str, object], self.job)["metadata"],
                                )["name"],
                                "uid": self.pod_owner_uid or self.uid,
                            }
                        ],
                    },
                    "status": {
                        "containerStatuses": [
                            {
                                "state": {
                                    "terminated": {
                                        "exitCode": 0,
                                        "reason": "Completed",
                                    }
                                }
                            }
                        ]
                    },
                },
            ),
            None,
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
        del (
            namespace,
            pod,
            since_seconds,
            tail_lines,
            limit_bytes,
            timeout_seconds,
        )
        self.calls.append("logs")
        return '{"safe":true}\n'


def test_workload_is_suspended_pinned_and_locked_down() -> None:
    uuids = UUIDs()
    sandbox_request = request(uuids)
    work_lease = lease(sandbox_request, uuids)
    manifest = kubernetes_sandbox_workload(
        sandbox_request,
        work_lease,
        namespace="aegis-sandboxes",
        runtime_class_name="gvisor",
    )
    metadata = cast(Mapping[str, object], manifest["metadata"])
    job_spec = cast(Mapping[str, object], manifest["spec"])
    template = cast(Mapping[str, object], job_spec["template"])
    pod = cast(Mapping[str, object], template["spec"])
    container = cast(
        Mapping[str, object],
        cast(list[object], pod["containers"])[0],
    )
    security = cast(Mapping[str, object], container["securityContext"])
    image = cast(str, container["image"])
    assert job_spec["suspend"] is True
    assert job_spec["backoffLimit"] == 0
    assert job_spec["activeDeadlineSeconds"] == 30
    assert image.endswith("@sha256:" + "a" * 64)
    assert container["command"] == ["python"]
    assert container["args"] == ["-m", "pytest", "-q"]
    assert security == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"add": [], "drop": ["ALL"]},
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "runAsGroup": 65_532,
        "runAsNonRoot": True,
        "runAsUser": 65_532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert pod["automountServiceAccountToken"] is False
    assert pod["hostNetwork"] is False
    assert pod["hostPID"] is False
    assert pod["hostIPC"] is False
    assert pod["shareProcessNamespace"] is False
    assert pod["runtimeClassName"] == "gvisor"
    assert metadata["namespace"] == "aegis-sandboxes"
    labels = cast(Mapping[str, object], metadata["labels"])
    assert str(TENANT_ID) not in labels.values()
    annotations = cast(Mapping[str, object], metadata["annotations"])
    assert annotations["aegis.github.com/fence-generation"] == "1"
    assert annotations["aegis.github.com/sandbox-id"] == str(sandbox_request.sandbox_id)
    assert str(work_lease.token) not in annotations.values()


def test_workload_name_uses_full_sandbox_uuid() -> None:
    uuids = UUIDs("colliding-sandbox-names")
    first = replace(
        request(uuids),
        sandbox_id=UUID("01234567-89ab-cdef-0123-000000000001"),
    )
    second = replace(
        first,
        sandbox_id=UUID("01234567-89ab-cdef-0123-000000000002"),
    )
    first_name = cast(
        Mapping[str, object],
        kubernetes_sandbox_workload(
            first,
            lease(first, uuids),
            namespace="aegis-sandboxes",
            runtime_class_name="gvisor",
        )["metadata"],
    )["name"]
    second_name = cast(
        Mapping[str, object],
        kubernetes_sandbox_workload(
            second,
            lease(second, uuids),
            namespace="aegis-sandboxes",
            runtime_class_name="gvisor",
        )["metadata"],
    )["name"]
    assert first_name != second_name
    assert first_name == "aegis-sbx-0123456789abcdef0123000000000001"


@pytest.mark.asyncio
async def test_backend_fails_readiness_closed_for_unverified_controls() -> None:
    uuids = UUIDs()
    client = _KubernetesClient()
    artifact = CapturedArtifact(
        uuids(),
        "outputs/analysis.json",
        "c" * 64,
        10,
        "application/json",
        False,
    )
    backend = OfficialKubernetesSandboxBackend(
        client,  # type: ignore[arg-type]
        _controls(runtime_isolation_verified=False),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )
    readiness = await backend.readiness(CONTEXT)
    assert not readiness.ready
    assert not readiness.isolation_verified


@pytest.mark.asyncio
async def test_backend_observe_create_start_collect_and_delete_lifecycle() -> None:
    uuids = UUIDs()
    sandbox_request = request(uuids)
    artifact = CapturedArtifact(
        uuids(),
        "outputs/analysis.json",
        "c" * 64,
        10,
        "application/json",
        False,
    )
    client = _KubernetesClient()
    collector = _Artifacts(artifact)

    async def complete_after_poll(_delay: float) -> None:
        if client.job is None:
            raise AssertionError("job was not created")
        client.job = {
            **client.job,
            "status": {"succeeded": 1},
        }

    backend = OfficialKubernetesSandboxBackend(
        client,  # type: ignore[arg-type]
        _controls(),
        collector,
        tenant_id=str(TENANT_ID),
        clock=Clock(),
        sleep=complete_after_poll,
    )
    work_lease = lease(sandbox_request, uuids)
    absent = await backend.observe(CONTEXT, sandbox_request)
    assert absent.outcome is SandboxReconciliationOutcome.ABSENT
    provisioned = await backend.provision(CONTEXT, sandbox_request, work_lease)
    assert provisioned.spec_digest == sandbox_request.spec.digest
    assert provisioned.backend_reference.endswith(f"@{client.uid}")
    present = await backend.observe(CONTEXT, sandbox_request)
    assert present.outcome is SandboxReconciliationOutcome.PRESENT
    await backend.start(
        CONTEXT,
        sandbox_request,
        provisioned.backend_reference,
        work_lease,
    )
    running = await backend.observe(CONTEXT, sandbox_request)
    assert running.outcome is SandboxReconciliationOutcome.RUNNING

    result = await backend.collect(
        CONTEXT,
        sandbox_request,
        provisioned.backend_reference,
    )
    assert result.outcome is SandboxExecutionOutcome.SUCCEEDED
    assert result.stdout.redacted
    assert result.artifacts == (artifact,)
    assert collector.calls == [provisioned.backend_reference]
    assert client.pod_selector == f"batch.kubernetes.io/controller-uid={client.uid}"
    await backend.cleanup(
        CONTEXT,
        sandbox_request,
        provisioned.backend_reference,
        work_lease,
    )
    assert client.deleted
    assert client.start_resource_version == "1"
    assert client.fence_resource_version == "2"
    assert client.delete_resource_version == "3"
    assert client.delete_uid == client.uid
    assert client.calls == [
        "observe",
        "create",
        "observe",
        "observe",
        "start",
        "observe",
        "observe",
        "observe",
        "pods",
        "logs",
        "observe",
        "observe",
        "observe",
        "fence",
        "delete",
        "observe",
    ]


@pytest.mark.asyncio
async def test_backend_rejects_wrong_sandbox_annotation() -> None:
    uuids = UUIDs("wrong-sandbox-annotation")
    sandbox_request = request(uuids)
    artifact = CapturedArtifact(
        uuids(), "outputs/analysis.json", "c" * 64, 10, "application/json", False
    )
    client = _KubernetesClient()
    backend = OfficialKubernetesSandboxBackend(
        client,  # type: ignore[arg-type]
        _controls(),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )
    await backend.provision(CONTEXT, sandbox_request, lease(sandbox_request, uuids))
    assert client.job is not None
    metadata = dict(cast(Mapping[str, object], client.job["metadata"]))
    annotations = dict(cast(Mapping[str, object], metadata["annotations"]))
    annotations["aegis.github.com/sandbox-id"] = str(uuids())
    metadata["annotations"] = annotations
    client.job = {**client.job, "metadata": metadata}

    with pytest.raises(SandboxBackendError, match="job_identity_invalid"):
        await backend.observe(CONTEXT, sandbox_request)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["start", "collect", "cleanup"])
async def test_backend_rejects_same_name_replacement(operation: str) -> None:
    uuids = UUIDs("same-name-replacement")
    sandbox_request = request(uuids)
    artifact = CapturedArtifact(
        uuids(), "outputs/analysis.json", "c" * 64, 10, "application/json", False
    )
    client = _KubernetesClient()
    backend = OfficialKubernetesSandboxBackend(
        client,  # type: ignore[arg-type]
        _controls(),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )
    work_lease = lease(sandbox_request, uuids)
    provisioned = await backend.provision(CONTEXT, sandbox_request, work_lease)
    assert client.job is not None
    metadata = {
        **cast(Mapping[str, object], client.job["metadata"]),
        "uid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    }
    client.job = {**client.job, "metadata": metadata}

    async def perform() -> None:
        if operation == "start":
            await backend.start(
                CONTEXT,
                sandbox_request,
                provisioned.backend_reference,
                work_lease,
            )
        elif operation == "collect":
            await backend.collect(
                CONTEXT,
                sandbox_request,
                provisioned.backend_reference,
            )
        else:
            await backend.cleanup(
                CONTEXT,
                sandbox_request,
                provisioned.backend_reference,
                work_lease,
            )

    with pytest.raises(SandboxBackendError, match="identity_changed"):
        await perform()


@pytest.mark.asyncio
async def test_backend_rejects_pod_without_matching_job_owner() -> None:
    uuids = UUIDs("wrong-pod-owner")
    sandbox_request = request(uuids)
    artifact = CapturedArtifact(
        uuids(), "outputs/analysis.json", "c" * 64, 10, "application/json", False
    )
    client = _KubernetesClient()
    backend = OfficialKubernetesSandboxBackend(
        client,  # type: ignore[arg-type]
        _controls(),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )
    provisioned = await backend.provision(
        CONTEXT,
        sandbox_request,
        lease(sandbox_request, uuids),
    )
    assert client.job is not None
    client.job = {**client.job, "status": {"succeeded": 1}}
    client.pod_owner_uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    with pytest.raises(SandboxBackendError, match="pod_owner_invalid"):
        await backend.collect(
            CONTEXT,
            sandbox_request,
            provisioned.backend_reference,
        )


@pytest.mark.asyncio
async def test_backend_readiness_requires_external_fencing_admission() -> None:
    uuids = UUIDs("unverified-fencing")
    artifact = CapturedArtifact(
        uuids(),
        "outputs/analysis.json",
        "c" * 64,
        10,
        "application/json",
        False,
    )
    backend = OfficialKubernetesSandboxBackend(
        _KubernetesClient(),  # type: ignore[arg-type]
        _controls(fencing_admission_verified=False),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )

    readiness = await backend.readiness(CONTEXT)

    assert not readiness.ready
    sandbox_request = request(uuids)
    with pytest.raises(PermissionError, match="controls are not verified"):
        await backend.provision(
            CONTEXT,
            sandbox_request,
            lease(sandbox_request, uuids),
        )


@pytest.mark.asyncio
async def test_backend_denies_cross_tenant_secret_and_copy_on_write_gaps() -> None:
    uuids = UUIDs()
    source = spec().input_snapshot
    read_write = MountDeclaration(source, "workspace/cache", MountAccess.READ_WRITE)
    sandbox_request = request(uuids, sandbox_spec=spec(mounts=(read_write,)))
    artifact = CapturedArtifact(
        uuids(),
        "outputs/analysis.json",
        "c" * 64,
        10,
        "application/json",
        False,
    )
    backend = OfficialKubernetesSandboxBackend(
        _KubernetesClient(),  # type: ignore[arg-type]
        _controls(),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )
    with pytest.raises(PermissionError, match="copy-on-write"):
        await backend.provision(
            CONTEXT,
            sandbox_request,
            lease(sandbox_request, uuids),
        )
    with pytest.raises(PermissionError, match="tenant mismatch"):
        await backend.observe(
            replace(CONTEXT, tenant_id=type(TENANT_ID)("tenant-other")),
            request(UUIDs()),
        )


@pytest.mark.asyncio
async def test_brokered_network_requires_verified_egress_boundary() -> None:
    from aegis_agent_platform.domain import EgressRule

    networked = spec(
        network_mode=NetworkMode.BROKERED,
        egress_rules=(EgressRule("https", "api.example.invalid", 443),),
    )
    sandbox_request = request(UUIDs(), sandbox_spec=networked)
    client = _KubernetesClient()
    artifact = CapturedArtifact(
        UUIDs()(),
        "outputs/analysis.json",
        "c" * 64,
        10,
        "application/json",
        False,
    )
    backend = OfficialKubernetesSandboxBackend(
        client,  # type: ignore[arg-type]
        _controls(brokered_egress_verified=False),
        _Artifacts(artifact),
        tenant_id=str(TENANT_ID),
        clock=Clock(),
    )
    with pytest.raises(PermissionError, match="egress is not verified"):
        await backend.provision(
            CONTEXT,
            sandbox_request,
            lease(sandbox_request, UUIDs()),
        )
