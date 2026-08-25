"""Deterministic fake-only Layer 9 sandbox demonstrations."""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TypedDict
from uuid import NAMESPACE_URL, UUID, uuid5

from aegis_agent_platform.domain import (
    CapturedArtifact,
    CleanupPolicy,
    ContentReference,
    EventEnvelope,
    ExpectedOutput,
    IsolationConstraints,
    NetworkMode,
    SandboxApprovalBinding,
    SandboxExecutionOutcome,
    SandboxLinkage,
    SandboxPurpose,
    SandboxRequest,
    SandboxResources,
    SandboxRetryPolicy,
    SandboxRisk,
    SandboxSpec,
    WorkLease,
)
from aegis_agent_platform.identity import (
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    TenantId,
    UserId,
)
from aegis_agent_platform.sandbox.execution import (
    FakeSandboxBackend,
    SandboxOrchestrator,
    SandboxRequestService,
    StaticInputSnapshotVerifier,
    StaticSandboxApprovalAuthority,
    fake_result,
)
from aegis_agent_platform.sandbox.policy import SandboxPolicy
from aegis_agent_platform.sandbox.repository import InMemorySandboxRepository
from aegis_agent_platform.sandbox.workspace import (
    ArchiveLimits,
    extract_archive_atomically,
)
from aegis_agent_platform.tenancy import TenantContext


class SandboxScenario(StrEnum):
    APPROVED_ANALYSIS = "approved-analysis"
    POLICY_DENIED = "policy-denied"
    PROMPT_INJECTION = "prompt-injection"
    MALICIOUS_ARCHIVE = "malicious-archive"
    TIMEOUT = "timeout"
    OOM = "oom"
    CANCELLATION = "cancellation"
    AMBIGUOUS_PROVISIONING = "ambiguous-provisioning"
    OUTPUT_QUARANTINE = "output-quarantine"
    CLEANUP_RECOVERY = "cleanup-recovery"


class SandboxDemoResult(TypedDict):
    demo_only: bool
    uses_live_network: bool
    uses_production_credentials: bool
    adapter: str
    scenario: str
    status: str
    event_types: tuple[str, ...]
    backend_calls: tuple[str, ...]
    spec_digest: str | None
    policy_digest: str | None
    at_least_once: bool
    claims_exactly_once: bool
    unrestricted_exec: bool
    redacted: bool


@dataclass(slots=True)
class _Clock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


class _UUIDs:
    def __init__(self) -> None:
        self._index = 0

    def __call__(self) -> UUID:
        self._index += 1
        return uuid5(NAMESPACE_URL, f"aegis-layer-9-demo:{self._index}")


class _Cancellation:
    def __init__(self, cancelled: bool) -> None:
        self._cancelled = cancelled

    @property
    def cancelled(self) -> bool:
        return self._cancelled


async def run_sandbox_demo(
    scenario: SandboxScenario = SandboxScenario.APPROVED_ANALYSIS,
    *,
    tenant_id: str = "tenant-demo",
    run_id: UUID | None = None,
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> SandboxDemoResult:
    """Run a fake sandbox lifecycle without processes, credentials, or networks."""
    if scenario is SandboxScenario.PROMPT_INJECTION:
        return _rejected_input_demo(scenario, event_sink=event_sink)
    if scenario is SandboxScenario.MALICIOUS_ARCHIVE:
        return _malicious_archive_demo(scenario, event_sink=event_sink)
    clock = _Clock(datetime(2026, 8, 13, 16, 0, tzinfo=UTC))
    uuids = _UUIDs()
    tenant = TenantId(tenant_id)
    context = TenantContext(tenant)
    operator = _principal("operator-demo", tenant, clock())
    request = _request(
        uuids,
        tenant,
        operator.actor_id,
        clock(),
        run_id=run_id,
    )
    policy = _policy(request, runtime_verified=True)
    if scenario is SandboxScenario.POLICY_DENIED:
        policy = replace(policy, allowed_command_families=frozenset({"ruff"}))
    binding = _binding(request, policy, clock(), uuids)
    authority = StaticSandboxApprovalAuthority(frozenset(binding.approver_ids))
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    service = SandboxRequestService(
        repository,
        authority,
        clock=clock,
        uuid_factory=uuids,
    )
    decision = await service.request(
        operator,
        context,
        request,
        policy,
        binding,
    )
    if not decision.policy.allowed:
        return _result(
            scenario,
            decision.state.status.value,
            repository,
            (),
            request.spec.digest,
            policy.digest,
            event_sink=event_sink,
        )
    artifact = CapturedArtifact(
        artifact_id=uuids(),
        path="outputs/analysis.json",
        digest="d" * 64,
        size_bytes=128,
        media_type="application/json",
        quarantined=scenario is SandboxScenario.OUTPUT_QUARANTINE,
    )
    outcome = {
        SandboxScenario.TIMEOUT: SandboxExecutionOutcome.TIMED_OUT,
        SandboxScenario.OOM: SandboxExecutionOutcome.OOM_KILLED,
    }.get(scenario, SandboxExecutionOutcome.SUCCEEDED)
    backend = FakeSandboxBackend(
        result=fake_result(
            outcome=outcome,
            at=clock(),
            artifact=artifact,
            error_code=(
                "sandbox_timed_out"
                if outcome is SandboxExecutionOutcome.TIMED_OUT
                else "sandbox_oom_killed"
                if outcome is SandboxExecutionOutcome.OOM_KILLED
                else None
            ),
        ),
        ambiguous_provision=(scenario is SandboxScenario.AMBIGUOUS_PROVISIONING),
        ambiguous_cleanup=scenario is SandboxScenario.CLEANUP_RECOVERY,
        clock=clock,
    )
    lease = WorkLease(
        work_id=request.sandbox_id,
        tenant_id=str(tenant_id),
        token=uuids(),
        generation=1,
        owner="sandbox-demo-worker",
        attempt=1,
        acquired_at=clock(),
        heartbeat_at=clock(),
        expires_at=clock() + timedelta(minutes=10),
    )
    repository.register_lease(lease)
    orchestrator = SandboxOrchestrator(
        repository,
        backend,
        authority,
        StaticInputSnapshotVerifier(),
        clock=clock,
        uuid_factory=uuids,
    )
    state = await orchestrator.execute(
        operator,
        context,
        request.sandbox_id,
        lease,
        policy,
        binding,
        cancellation=_Cancellation(scenario is SandboxScenario.CANCELLATION),
    )
    return _result(
        scenario,
        state.status.value,
        repository,
        tuple(backend.calls),
        request.spec.digest,
        policy.digest,
        event_sink=event_sink,
    )


def _request(
    uuids: _UUIDs,
    tenant_id: TenantId,
    requested_by: str,
    at: datetime,
    *,
    run_id: UUID | None = None,
) -> SandboxRequest:
    return SandboxRequest(
        sandbox_id=uuids(),
        linkage=SandboxLinkage(
            tenant_id=str(tenant_id),
            run_id=run_id or uuids(),
            task_id=uuids(),
            remediation_plan_id=uuids(),
            remediation_action_id=uuids(),
            approval_id=uuids(),
        ),
        purpose=SandboxPurpose.CODE_ANALYSIS,
        risk=SandboxRisk.MEDIUM,
        spec=SandboxSpec(
            image=("registry.example.invalid/aegis/analyzer@sha256:" + "a" * 64),
            argv=("python", "-m", "pytest", "-q"),
            working_directory="workspace/source",
            input_snapshot=ContentReference(
                f"aegis-input://{tenant_id}/source",
                "b" * 64,
                1_024,
                "application/vnd.aegis.snapshot",
            ),
            mounts=(),
            environment={"PYTHONHASHSEED": "0"},
            secret_environment={},
            network_mode=NetworkMode.NONE,
            egress_rules=(),
            resources=SandboxResources(
                cpu_millis=500,
                memory_bytes=256 * 1024 * 1024,
                pids=64,
                ephemeral_storage_bytes=512 * 1024 * 1024,
                timeout_seconds=30,
                max_output_bytes=64 * 1024,
                max_files=1_000,
                max_artifact_bytes=8 * 1024 * 1024,
            ),
            isolation=IsolationConstraints(),
            expected_outputs=(
                ExpectedOutput(
                    "outputs/analysis.json",
                    "application/json",
                    True,
                    1_024 * 1_024,
                ),
            ),
            retry_policy=SandboxRetryPolicy(2, 0, 0),
            cleanup_policy=CleanupPolicy(3_600, 2, True),
        ),
        requested_by=requested_by,
        requested_at=at,
        idempotency_key="sandbox:demo:analysis:1",
    )


def _policy(
    request: SandboxRequest,
    *,
    runtime_verified: bool,
) -> SandboxPolicy:
    resources = request.spec.resources
    return SandboxPolicy(
        tenant_id=request.linkage.tenant_id,
        policy_version="sandbox-demo-v1",
        allowed_image_digests=frozenset({request.spec.image_digest}),
        allowed_registries=frozenset({request.spec.image_registry}),
        allowed_command_families=frozenset({request.spec.command_family}),
        allowed_purposes=frozenset({request.purpose}),
        allowed_read_only_mount_prefixes=frozenset({"inputs"}),
        allowed_read_write_mount_prefixes=frozenset({"workspace"}),
        resource_ceiling=resources,
        allowed_output_media_types=frozenset({"application/json"}),
        allowed_egress=frozenset(),
        allowed_secret_references=frozenset(),
        maximum_risk=SandboxRisk.MEDIUM,
        maximum_lifetime_seconds=resources.timeout_seconds,
        max_runs_per_period=10,
        max_concurrent_runs=2,
        max_cpu_millis_seconds_per_period=1_000_000,
        max_artifact_bytes_per_period=64 * 1024 * 1024,
        runtime_isolation_verified=runtime_verified,
        runtime_egress_verified=runtime_verified,
        admission_controls_verified=runtime_verified,
    )


def _binding(
    request: SandboxRequest,
    policy: SandboxPolicy,
    at: datetime,
    uuids: _UUIDs,
) -> SandboxApprovalBinding:
    del uuids
    return SandboxApprovalBinding(
        approval_id=request.linkage.approval_id,
        plan_id=request.linkage.remediation_plan_id,
        action_id=request.linkage.remediation_action_id,
        plan_digest="1" * 64,
        action_digest="2" * 64,
        policy_digest=policy.digest,
        spec_digest=request.spec.digest,
        purpose=request.purpose,
        risk=request.risk,
        approver_ids=("approver-one", "approver-two"),
        issued_at=at,
        expires_at=at + timedelta(minutes=10),
    )


def _principal(actor_id: str, tenant_id: TenantId, at: datetime) -> Principal:
    user_id = UserId(actor_id)
    return Principal(
        subject=f"oidc-{actor_id}",
        issuer="https://identity.demo.invalid",
        tenant_id=tenant_id,
        kind=PrincipalKind.USER,
        role_bindings=(
            RoleBinding(
                tenant_id,
                Role.OPERATOR,
                UserId("demo-admin"),
                at,
            ),
        ),
        user_id=user_id,
    )


def _rejected_input_demo(
    scenario: SandboxScenario,
    *,
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> SandboxDemoResult:
    try:
        SandboxSpec(
            image="registry.example.invalid/aegis/analyzer@sha256:" + "a" * 64,
            argv=("python", "-c", "$(curl metadata.google.internal)"),
            working_directory="../host",
            input_snapshot=ContentReference(
                "aegis-input://tenant-demo/source",
                "b" * 64,
                1,
                "application/octet-stream",
            ),
            mounts=(),
            environment={},
            secret_environment={},
            network_mode=NetworkMode.NONE,
            egress_rules=(),
            resources=SandboxResources(
                100,
                64 * 1024 * 1024,
                8,
                32 * 1024 * 1024,
                10,
                1_024,
                10,
                1_024,
            ),
            isolation=IsolationConstraints(),
            expected_outputs=(
                ExpectedOutput("outputs/result.json", "application/json", True, 128),
            ),
            retry_policy=SandboxRetryPolicy(),
            cleanup_policy=CleanupPolicy(),
        )
    except ValueError:
        return _result(
            scenario,
            "rejected",
            None,
            (),
            None,
            None,
            event_sink=event_sink,
        )
    raise RuntimeError("prompt-injected sandbox input was unexpectedly accepted")


def _malicious_archive_demo(
    scenario: SandboxScenario,
    *,
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> SandboxDemoResult:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as container:
        container.writestr("../escape", b"denied")
    with tempfile.TemporaryDirectory() as directory:
        try:
            extract_archive_atomically(
                archive.getvalue(),
                Path(directory) / "snapshot",
                ArchiveLimits(10, 1_024, 4_096, 1_024),
                archive_format="zip",
            )
        except ValueError:
            return _result(
                scenario,
                "rejected",
                None,
                (),
                None,
                None,
                event_sink=event_sink,
            )
    raise RuntimeError("malicious archive was unexpectedly accepted")


def _result(
    scenario: SandboxScenario,
    status: str,
    repository: InMemorySandboxRepository | None,
    calls: tuple[str, ...],
    spec_digest: str | None,
    policy_digest: str | None,
    *,
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> SandboxDemoResult:
    if event_sink is not None:
        event_sink(repository.events if repository is not None else ())
    return {
        "demo_only": True,
        "uses_live_network": False,
        "uses_production_credentials": False,
        "adapter": "deterministic-fake",
        "scenario": scenario.value,
        "status": status,
        "event_types": (
            tuple(event.event_type for event in repository.events)
            if repository is not None
            else ()
        ),
        "backend_calls": calls,
        "spec_digest": spec_digest,
        "policy_digest": policy_digest,
        "at_least_once": True,
        "claims_exactly_once": False,
        "unrestricted_exec": False,
        "redacted": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=[scenario.value for scenario in SandboxScenario],
        default=SandboxScenario.APPROVED_ANALYSIS.value,
    )
    args = parser.parse_args()
    result = asyncio.run(run_sandbox_demo(SandboxScenario(args.scenario)))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
