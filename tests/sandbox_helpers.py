"""Deterministic Layer 9 fixtures shared by sandbox tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

from aegis_agent_platform.domain import (
    CapturedArtifact,
    CapturedOutput,
    CleanupPolicy,
    ContentReference,
    ExpectedOutput,
    IsolationConstraints,
    NetworkMode,
    SandboxApprovalBinding,
    SandboxExecutionOutcome,
    SandboxLinkage,
    SandboxPurpose,
    SandboxRequest,
    SandboxResources,
    SandboxResult,
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
from aegis_agent_platform.sandbox.policy import SandboxPolicy
from aegis_agent_platform.tenancy import TenantContext

NOW = datetime(2026, 8, 13, 16, 0, tzinfo=UTC)
TENANT_ID = TenantId("tenant-test")
CONTEXT = TenantContext(TENANT_ID)


@dataclass(slots=True)
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class UUIDs:
    def __init__(self, namespace: str = "tests") -> None:
        self._namespace = namespace
        self._index = 0

    def __call__(self) -> UUID:
        self._index += 1
        return uuid5(NAMESPACE_URL, f"aegis-sandbox:{self._namespace}:{self._index}")


def spec(**changes: object) -> SandboxSpec:
    values: dict[str, object] = {
        "image": "registry.example.invalid/aegis/analyzer@sha256:" + "a" * 64,
        "argv": ("python", "-m", "pytest", "-q"),
        "working_directory": "workspace/source",
        "input_snapshot": ContentReference(
            f"aegis-input://{TENANT_ID}/snapshot",
            "b" * 64,
            1_024,
            "application/vnd.aegis.snapshot",
        ),
        "mounts": (),
        "environment": {"PYTHONHASHSEED": "0"},
        "secret_environment": {},
        "network_mode": NetworkMode.NONE,
        "egress_rules": (),
        "resources": SandboxResources(
            500,
            256 * 1024 * 1024,
            64,
            512 * 1024 * 1024,
            30,
            64 * 1024,
            1_000,
            8 * 1024 * 1024,
        ),
        "isolation": IsolationConstraints(),
        "expected_outputs": (
            ExpectedOutput(
                "outputs/analysis.json",
                "application/json",
                True,
                1_024 * 1_024,
            ),
        ),
        "retry_policy": SandboxRetryPolicy(2, 0, 0),
        "cleanup_policy": CleanupPolicy(3_600, 2, True),
    }
    values.update(changes)
    return SandboxSpec(**values)  # type: ignore[arg-type]


def request(
    uuids: UUIDs,
    *,
    sandbox_spec: SandboxSpec | None = None,
    requested_at: datetime = NOW,
) -> SandboxRequest:
    return SandboxRequest(
        sandbox_id=uuids(),
        linkage=SandboxLinkage(
            tenant_id=str(TENANT_ID),
            run_id=uuids(),
            task_id=uuids(),
            remediation_plan_id=uuids(),
            remediation_action_id=uuids(),
            approval_id=uuids(),
        ),
        purpose=SandboxPurpose.CODE_ANALYSIS,
        risk=SandboxRisk.MEDIUM,
        spec=sandbox_spec or spec(),
        requested_by="operator-test",
        requested_at=requested_at,
        idempotency_key="sandbox:test:analysis:1",
    )


def policy(
    sandbox_request: SandboxRequest,
    *,
    runtime_verified: bool = True,
) -> SandboxPolicy:
    resources = sandbox_request.spec.resources
    return SandboxPolicy(
        tenant_id=sandbox_request.linkage.tenant_id,
        policy_version="sandbox-test-v1",
        allowed_image_digests=frozenset({sandbox_request.spec.image_digest}),
        allowed_registries=frozenset({sandbox_request.spec.image_registry}),
        allowed_command_families=frozenset({sandbox_request.spec.command_family}),
        allowed_purposes=frozenset({sandbox_request.purpose}),
        allowed_read_only_mount_prefixes=frozenset({"inputs"}),
        allowed_read_write_mount_prefixes=frozenset({"workspace"}),
        resource_ceiling=resources,
        allowed_output_media_types=frozenset({"application/json"}),
        allowed_egress=frozenset(sandbox_request.spec.egress_rules),
        allowed_secret_references=frozenset(
            item.uri for item in sandbox_request.spec.secret_environment.values()
        ),
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


def binding(
    sandbox_request: SandboxRequest,
    sandbox_policy: SandboxPolicy,
) -> SandboxApprovalBinding:
    return SandboxApprovalBinding(
        approval_id=sandbox_request.linkage.approval_id,
        plan_id=sandbox_request.linkage.remediation_plan_id,
        action_id=sandbox_request.linkage.remediation_action_id,
        plan_digest="1" * 64,
        action_digest="2" * 64,
        policy_digest=sandbox_policy.digest,
        spec_digest=sandbox_request.spec.digest,
        purpose=sandbox_request.purpose,
        risk=sandbox_request.risk,
        approver_ids=("approver-one", "approver-two"),
        issued_at=sandbox_request.requested_at,
        expires_at=sandbox_request.requested_at + timedelta(minutes=10),
    )


def principal(
    *,
    role: Role = Role.OPERATOR,
    tenant_id: TenantId = TENANT_ID,
    issued_at: datetime | None = None,
) -> Principal:
    user_id = UserId("operator-test")
    return Principal(
        subject="oidc-operator-test",
        issuer="https://identity.test.invalid",
        tenant_id=tenant_id,
        kind=PrincipalKind.USER,
        role_bindings=(
            RoleBinding(
                tenant_id,
                role,
                UserId("tenant-admin"),
                issued_at or NOW - timedelta(minutes=1),
            ),
        ),
        user_id=user_id,
    )


def lease(
    sandbox_request: SandboxRequest,
    uuids: UUIDs,
    *,
    generation: int = 1,
    expires_at: datetime | None = None,
) -> WorkLease:
    return WorkLease(
        sandbox_request.sandbox_id,
        sandbox_request.linkage.tenant_id,
        uuids(),
        generation,
        "sandbox-test-worker",
        1,
        NOW,
        NOW,
        expires_at or NOW + timedelta(minutes=10),
    )


def result(
    uuids: UUIDs,
    *,
    outcome: SandboxExecutionOutcome,
    output_bytes: int = 0,
    quarantined: bool = False,
) -> SandboxResult:
    artifact = CapturedArtifact(
        uuids(),
        "outputs/analysis.json",
        "c" * 64,
        512,
        "application/json",
        quarantined,
    )
    return SandboxResult(
        outcome,
        0 if outcome is SandboxExecutionOutcome.SUCCEEDED else None,
        NOW,
        NOW + timedelta(seconds=1),
        CapturedOutput("stdout", "d" * 64, output_bytes, False, True),
        CapturedOutput("stderr", "e" * 64, 0, False, True),
        (artifact,),
        (
            None
            if outcome is SandboxExecutionOutcome.SUCCEEDED
            else f"sandbox_{outcome.value}"
        ),
    )
