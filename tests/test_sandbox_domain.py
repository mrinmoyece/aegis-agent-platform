"""Layer 9 sandbox contracts, validation, policy, and replay tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from aegis_agent_platform.domain import (
    CleanupPolicy,
    ContentReference,
    DomainEventType,
    EgressRule,
    EventEnvelope,
    ExpectedOutput,
    IsolationConstraints,
    JsonValue,
    MountAccess,
    MountDeclaration,
    NetworkMode,
    SandboxExecutionOutcome,
    SandboxPurpose,
    SandboxReplayError,
    SandboxRetryPolicy,
    SandboxRisk,
    SandboxStatus,
    SecretReference,
    replay_sandbox,
    sandbox_request_from_payload,
    sandbox_request_to_payload,
)
from aegis_agent_platform.sandbox.policy import (
    SandboxPolicyEvaluator,
    SandboxQuotaUsage,
)
from sandbox_helpers import (
    CONTEXT,
    NOW,
    TENANT_ID,
    UUIDs,
    binding,
    policy,
    request,
    result,
    spec,
)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"image": "registry.example.invalid/aegis/analyzer:latest"}, "immutable OCI"),
        ({"argv": ("sh", "-c", "echo ok")}, "shell command families"),
        ({"argv": ("python", "${TOKEN}")}, "shell interpolation"),
        ({"argv": ("python", "a;b")}, "shell metacharacters"),
        ({"argv": ("python", "line\nbreak")}, "canonical"),
        ({"argv": ("\uff50ython",)}, "canonical"),
        ({"working_directory": "/workspace"}, "relative"),
        ({"working_directory": "workspace/../host"}, "unsafe"),
        ({"working_directory": "workspace/NUL"}, "unsafe"),
        (
            {
                "environment": {
                    "PASSWORD": "literal-secret",
                }
            },
            "secret-like",
        ),
        (
            {
                "environment": {"TOKEN": "public"},
                "secret_environment": {
                    "TOKEN": SecretReference(
                        "TOKEN",
                        f"aegis-secret://{TENANT_ID}/token",
                    )
                },
            },
            "conflict",
        ),
        (
            {
                "network_mode": NetworkMode.NONE,
                "egress_rules": (EgressRule("https", "api.example.invalid", 443),),
            },
            "network-none",
        ),
        (
            {
                "network_mode": NetworkMode.BROKERED,
                "egress_rules": (),
            },
            "requires exact egress",
        ),
        (
            {
                "expected_outputs": (
                    ExpectedOutput(
                        "outputs/report",
                        "application/json",
                        True,
                        1024,
                    ),
                    ExpectedOutput(
                        "outputs/report/child",
                        "application/json",
                        False,
                        1024,
                    ),
                )
            },
            "conflict",
        ),
    ],
)
def test_spec_rejects_untrusted_inputs(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        spec(**changes)


def test_isolation_contract_cannot_be_constructed_with_privilege() -> None:
    with pytest.raises(ValueError, match="cannot weaken"):
        IsolationConstraints(privileged=True)
    with pytest.raises(ValueError, match="drop all"):
        IsolationConstraints(capability_add=("NET_ADMIN",))
    with pytest.raises(ValueError, match="RuntimeDefault"):
        IsolationConstraints(seccomp_profile="Unconfined")
    with pytest.raises(ValueError, match="AppArmor"):
        IsolationConstraints(apparmor_profile="unconfined")
    with pytest.raises(ValueError, match="non-system"):
        IsolationConstraints(run_as_user=0)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "127.0.0.1",
        "169.254.169.254",
        "10.1.2.3",
        "service.local",
    ],
)
def test_egress_rejects_metadata_loopback_and_private_targets(host: str) -> None:
    with pytest.raises(
        ValueError,
        match=r"denied|invalid|loopback|private|metadata",
    ):
        EgressRule("https", host, 443)


def test_spec_is_canonical_and_request_round_trips() -> None:
    output_a = ExpectedOutput("outputs/a.json", "application/json", True, 100)
    output_b = ExpectedOutput("outputs/b.json", "application/json", False, 100)
    first = spec(
        environment={"Z_VALUE": "2", "A_VALUE": "1"},
        expected_outputs=(output_b, output_a),
    )
    second = spec(
        environment={"A_VALUE": "1", "Z_VALUE": "2"},
        expected_outputs=(output_a, output_b),
    )
    assert first.digest == second.digest
    assert first.command_family == "python"
    assert first.image_registry == "registry.example.invalid"
    assert first.image_digest == "a" * 64

    sandbox_request = request(UUIDs(), sandbox_spec=first)
    decoded = sandbox_request_from_payload(sandbox_request_to_payload(sandbox_request))
    assert decoded == sandbox_request
    assert decoded.digest == sandbox_request.digest
    assert decoded.spec.digest == first.digest


def test_tenant_bound_content_mounts_and_secrets() -> None:
    uuids = UUIDs()
    cross_tenant = spec(
        input_snapshot=ContentReference(
            "aegis-input://tenant-other/snapshot",
            "b" * 64,
            1,
            "application/vnd.aegis.snapshot",
        )
    )
    with pytest.raises(ValueError, match="not tenant-bound"):
        request(uuids, sandbox_spec=cross_tenant)

    source = ContentReference(
        f"aegis-input://{TENANT_ID}/mount",
        "c" * 64,
        1,
        "application/octet-stream",
    )
    with pytest.raises(ValueError, match="reserved"):
        MountDeclaration(source, "workspace", MountAccess.READ_ONLY)
    with pytest.raises(ValueError, match="denied host"):
        MountDeclaration(source, "run/docker.sock", MountAccess.READ_WRITE)


def test_contract_bounds_reject_invalid_values() -> None:
    uuids = UUIDs("contract-bounds")
    base_request = request(uuids)
    base_spec = base_request.spec
    successful = result(uuids, outcome=SandboxExecutionOutcome.SUCCEEDED)
    nil = UUID(int=0)

    with pytest.raises(ValueError, match="object scheme"):
        ContentReference("https://example.com/input", "a" * 64, 1, "text/plain")
    with pytest.raises(ValueError, match="size"):
        ContentReference(
            f"aegis-input://{TENANT_ID}/large",
            "a" * 64,
            2 * 1024**3,
            "text/plain",
        )
    with pytest.raises(ValueError, match="cannot be nil"):
        replace(base_request.linkage, run_id=nil)
    with pytest.raises(ValueError, match="name"):
        SecretReference("not-valid", f"aegis-secret://{TENANT_ID}/value")
    with pytest.raises(ValueError, match="aegis-secret"):
        SecretReference("VALUE", "vault://value")
    with pytest.raises(ValueError, match="encrypted"):
        EgressRule("http", "api.example.com", 80)
    with pytest.raises(ValueError, match="canonical"):
        EgressRule("https", "API.example.com", 443)
    with pytest.raises(ValueError, match="port"):
        EgressRule("https", "api.example.com", 0)
    with pytest.raises(ValueError, match="cpu"):
        replace(base_spec.resources, cpu_millis=1)
    with pytest.raises(ValueError, match="outputs/"):
        ExpectedOutput("report.json", "application/json", True, 1)
    with pytest.raises(ValueError, match="output size"):
        ExpectedOutput("outputs/report.json", "application/json", True, 0)
    with pytest.raises(ValueError, match="attempts"):
        SandboxRetryPolicy(max_attempts=0)
    with pytest.raises(ValueError, match="initial backoff"):
        SandboxRetryPolicy(initial_backoff_seconds=-1)
    with pytest.raises(ValueError, match="maximum backoff"):
        SandboxRetryPolicy(initial_backoff_seconds=2, maximum_backoff_seconds=1)
    with pytest.raises(ValueError, match="reconcile"):
        SandboxRetryPolicy(reconcile_before_retry=False)
    with pytest.raises(ValueError, match="retention"):
        CleanupPolicy(maximum_retention_seconds=1)
    with pytest.raises(ValueError, match="attempts"):
        CleanupPolicy(max_attempts=0)
    with pytest.raises(ValueError, match="quarantine"):
        CleanupPolicy(quarantine_on_failure=False)
    with pytest.raises(ValueError, match="sandbox_id"):
        replace(base_request, sandbox_id=nil)
    with pytest.raises(ValueError, match="additive"):
        replace(base_request, schema_version=2)

    approval = binding(base_request, policy(base_request))
    with pytest.raises(ValueError, match="identifiers"):
        replace(approval, approval_id=nil)
    with pytest.raises(ValueError, match="bounded approvers"):
        replace(approval, approver_ids=())
    with pytest.raises(ValueError, match="distinct"):
        replace(approval, approver_ids=("same", "same"))
    with pytest.raises(ValueError, match="follow issuance"):
        replace(approval, expires_at=approval.issued_at)

    with pytest.raises(ValueError, match="stream"):
        replace(successful.stdout, stream="combined")
    with pytest.raises(ValueError, match="size"):
        replace(successful.stdout, captured_bytes=-1)
    with pytest.raises(ValueError, match="redacted"):
        replace(successful.stdout, redacted=False)
    with pytest.raises(ValueError, match="artifact_id"):
        replace(successful.artifacts[0], artifact_id=nil)
    with pytest.raises(ValueError, match="artifact size"):
        replace(successful.artifacts[0], size_bytes=2 * 1024**3)
    with pytest.raises(ValueError, match="precede"):
        replace(successful, completed_at=successful.started_at - timedelta(seconds=1))
    with pytest.raises(ValueError, match="exit code"):
        replace(successful, exit_code=999)
    with pytest.raises(ValueError, match="artifact count"):
        replace(successful, artifacts=successful.artifacts * 33)


def test_spec_count_and_tenant_bounds_fail_closed() -> None:
    uuids = UUIDs("spec-bounds")
    source = ContentReference(
        f"aegis-input://{TENANT_ID}/mount",
        "c" * 64,
        1,
        "application/octet-stream",
    )
    rule = EgressRule("https", "api.example.com", 443)
    output = ExpectedOutput("outputs/report.json", "application/json", True, 1)

    with pytest.raises(ValueError, match="token count"):
        spec(argv=())
    with pytest.raises(ValueError, match="below workspace"):
        spec(working_directory="source")
    mounts = tuple(
        MountDeclaration(source, f"inputs/source-{index}", MountAccess.READ_ONLY)
        for index in range(33)
    )
    with pytest.raises(ValueError, match="mount count"):
        spec(mounts=mounts)
    with pytest.raises(ValueError, match="environment exceeds"):
        spec(environment={f"VALUE_{index}": "x" for index in range(129)})
    secrets = {
        f"SECRET_{index}": SecretReference(
            f"SECRET_{index}",
            f"aegis-secret://{TENANT_ID}/secret-{index}",
        )
        for index in range(129)
    }
    with pytest.raises(ValueError, match="secret environment exceeds"):
        spec(secret_environment=secrets)
    egress = tuple(
        EgressRule("https", f"api-{index}.example.com", 443) for index in range(33)
    )
    with pytest.raises(ValueError, match="egress rules exceed"):
        spec(network_mode=NetworkMode.BROKERED, egress_rules=egress)
    with pytest.raises(ValueError, match="unique"):
        spec(network_mode=NetworkMode.BROKERED, egress_rules=(rule, rule))
    with pytest.raises(ValueError, match="output count"):
        spec(expected_outputs=())
    with pytest.raises(ValueError, match="paths must be unique"):
        spec(expected_outputs=(output, output))

    cross_mount = MountDeclaration(
        replace(source, uri="aegis-input://tenant-other/mount"),
        "inputs/cross",
        MountAccess.READ_ONLY,
    )
    with pytest.raises(ValueError, match="mount source"):
        request(uuids, sandbox_spec=spec(mounts=(cross_mount,)))
    cross_secret = SecretReference("SECRET", "aegis-secret://tenant-other/value")
    with pytest.raises(ValueError, match="secret reference"):
        request(
            uuids,
            sandbox_spec=spec(secret_environment={"SECRET": cross_secret}),
        )


def test_low_level_canonical_contract_guards_reject_corruption() -> None:
    uuids = UUIDs("canonical-guards")
    base_request = request(uuids)
    with pytest.raises(ValueError, match="lowercase sha256"):
        replace(base_request.spec.input_snapshot, digest="A" * 64)
    with pytest.raises(ValueError, match="safe identifier"):
        replace(base_request, requested_by="unsafe requester")
    with pytest.raises(ValueError, match="timezone"):
        replace(base_request, requested_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="environment name"):
        spec(environment={"invalid-name": "value"})
    with pytest.raises(ValueError, match="name changed"):
        spec(
            secret_environment={
                "OTHER": SecretReference(
                    "SECRET",
                    f"aegis-secret://{TENANT_ID}/secret",
                )
            }
        )
    with pytest.raises(ValueError, match="byte bound"):
        spec(environment={f"VALUE_{index}": "x" * 4_096 for index in range(4)})
    approval = binding(base_request, policy(base_request))
    with pytest.raises(ValueError, match="lowercase sha256"):
        replace(approval, plan_digest="invalid")
    with pytest.raises(ValueError, match="safe identifier"):
        replace(
            result(uuids, outcome=SandboxExecutionOutcome.FAILED),
            error_code="unsafe error",
        )

    requested = _event(
        uuids,
        base_request.sandbox_id,
        DomainEventType.SANDBOX_REQUESTED,
        1,
        {"request": sandbox_request_to_payload(base_request)},
    )
    with pytest.raises(SandboxReplayError, match="request digest"):
        replay_sandbox(
            (
                replace(
                    requested,
                    payload={
                        **requested.payload,
                        "request_digest": "f" * 64,
                    },
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="duplicate sandbox event"):
        replay_sandbox((requested, replace(requested, aggregate_sequence=2)))
    duplicate_key = _event(
        uuids,
        base_request.sandbox_id,
        "sandbox.future",
        2,
        {},
    )
    duplicate_key = replace(
        duplicate_key,
        idempotency_key=requested.idempotency_key,
    )
    with pytest.raises(SandboxReplayError, match="duplicate sandbox idempotency"):
        replay_sandbox((requested, duplicate_key))
    with pytest.raises(SandboxReplayError, match="no request"):
        replay_sandbox((replace(duplicate_key, aggregate_sequence=1),))
    with pytest.raises(SandboxReplayError, match="requested twice"):
        replay_sandbox(
            (
                requested,
                replace(
                    requested,
                    event_id=uuids(),
                    idempotency_key="sandbox:requested:twice",
                    aggregate_sequence=2,
                ),
            )
        )


def test_approval_scope_invalidates_policy_spec_risk_and_expiry_changes() -> None:
    sandbox_request = request(UUIDs())
    sandbox_policy = policy(sandbox_request)
    approval = binding(sandbox_request, sandbox_policy)
    assert approval.valid_for(
        sandbox_request,
        policy_digest=sandbox_policy.digest,
        at=NOW,
    )
    assert not approval.valid_for(
        sandbox_request,
        policy_digest="f" * 64,
        at=NOW,
    )
    changed_request = replace(
        sandbox_request,
        spec=spec(argv=("python", "-m", "pytest", "-x")),
    )
    assert not approval.valid_for(
        changed_request,
        policy_digest=sandbox_policy.digest,
        at=NOW,
    )
    assert not approval.valid_for(
        replace(sandbox_request, risk=SandboxRisk.HIGH),
        policy_digest=sandbox_policy.digest,
        at=NOW,
    )
    assert not approval.valid_for(
        sandbox_request,
        policy_digest=sandbox_policy.digest,
        at=approval.expires_at,
    )


def test_policy_allows_only_exact_verified_scope() -> None:
    sandbox_request = request(UUIDs())
    sandbox_policy = policy(sandbox_request)
    decision = SandboxPolicyEvaluator().evaluate(
        CONTEXT,
        sandbox_request,
        sandbox_policy,
        SandboxQuotaUsage(0, 0, 0, 0),
        at=NOW,
    )
    assert decision.allowed
    assert decision.reasons == ("exact_scope_allowed",)

    denied = SandboxPolicyEvaluator().evaluate(
        CONTEXT,
        replace(
            sandbox_request,
            purpose=SandboxPurpose.PATCH_PREPARATION,
            risk=SandboxRisk.HIGH,
        ),
        replace(
            sandbox_policy,
            runtime_isolation_verified=False,
            admission_controls_verified=False,
        ),
        SandboxQuotaUsage(10, 2, 1_000_000, 64 * 1024 * 1024),
        at=NOW,
    )
    assert not denied.allowed
    assert {
        "purpose_not_allowed",
        "risk_threshold_exceeded",
        "period_run_limit_exceeded",
        "sandbox_concurrency_limit_exceeded",
        "sandbox_cpu_budget_exceeded",
        "sandbox_artifact_budget_exceeded",
        "runtime_isolation_unverified",
        "admission_controls_unverified",
    }.issubset(denied.reasons)


def test_policy_contract_and_exact_allowlists_fail_closed() -> None:
    base_request = request(UUIDs("policy-contract"))
    base_policy = policy(base_request)
    with pytest.raises(ValueError, match="negative"):
        SandboxQuotaUsage(-1, 0, 0, 0)
    with pytest.raises(ValueError, match="tenant and version"):
        replace(base_policy, tenant_id="")
    with pytest.raises(ValueError, match="image allowlists"):
        replace(base_policy, allowed_image_digests=frozenset())
    with pytest.raises(ValueError, match="command and purpose"):
        replace(base_policy, allowed_command_families=frozenset())
    with pytest.raises(ValueError, match="image digest"):
        replace(base_policy, allowed_image_digests=frozenset({"invalid"}))
    with pytest.raises(ValueError, match="lifetime"):
        replace(base_policy, maximum_lifetime_seconds=0)
    with pytest.raises(ValueError, match="quotas"):
        replace(base_policy, max_runs_per_period=0)
    with pytest.raises(ValueError, match="additive"):
        replace(base_policy, schema_version=2)

    allowed = SandboxPolicyEvaluator().evaluate(
        CONTEXT,
        base_request,
        base_policy,
        SandboxQuotaUsage(0, 0, 0, 0),
        at=NOW,
    )
    with pytest.raises(ValueError, match="bounded reasons"):
        replace(allowed, reasons=())
    with pytest.raises(ValueError, match="timezone"):
        replace(allowed, evaluated_at=NOW.replace(tzinfo=None))

    source = ContentReference(
        f"aegis-input://{TENANT_ID}/dependency",
        "c" * 64,
        1,
        "application/octet-stream",
    )
    exact_rule = EgressRule("https", "packages.example.com", 443)
    exact_secret = SecretReference(
        "LICENSE_FILE",
        f"aegis-secret://{TENANT_ID}/license",
    )
    denied_request = request(
        UUIDs("policy-denials"),
        sandbox_spec=spec(
            image="registry.other.example/analyzer@sha256:" + "b" * 64,
            argv=("python3", "-m", "pytest"),
            mounts=(
                MountDeclaration(source, "inputs/dependency", MountAccess.READ_ONLY),
            ),
            secret_environment={"LICENSE_FILE": exact_secret},
            network_mode=NetworkMode.BROKERED,
            egress_rules=(exact_rule,),
            expected_outputs=(
                ExpectedOutput("outputs/report.txt", "text/plain", True, 1),
            ),
        ),
    )
    denied_policy = replace(
        policy(denied_request),
        tenant_id="tenant-other",
        allowed_image_digests=frozenset({"f" * 64}),
        allowed_registries=frozenset({"registry.denied.example"}),
        allowed_command_families=frozenset({"analyzer"}),
        allowed_read_only_mount_prefixes=frozenset(),
        resource_ceiling=replace(denied_request.spec.resources, cpu_millis=50),
        allowed_output_media_types=frozenset({"application/json"}),
        allowed_egress=frozenset(),
        allowed_secret_references=frozenset(),
        maximum_lifetime_seconds=1,
        runtime_egress_verified=False,
    )
    denied = SandboxPolicyEvaluator().evaluate(
        CONTEXT,
        denied_request,
        denied_policy,
        SandboxQuotaUsage(0, 0, 0, 0),
        at=NOW,
    )
    assert {
        "cross_tenant_policy",
        "image_digest_not_allowed",
        "image_registry_not_allowed",
        "command_family_not_allowed",
        "maximum_lifetime_exceeded",
        "cpu_limit_exceeded",
        "mount_not_allowed",
        "output_type_not_allowed",
        "egress_destination_not_allowed",
        "egress_enforcement_unverified",
        "secret_reference_not_allowed",
    }.issubset(denied.reasons)
    with pytest.raises(ValueError, match="timezone"):
        SandboxPolicyEvaluator().evaluate(
            CONTEXT,
            base_request,
            base_policy,
            SandboxQuotaUsage(0, 0, 0, 0),
            at=NOW.replace(tzinfo=None),
        )


def _event(
    uuids: UUIDs,
    sandbox_id: UUID,
    event_type: str,
    sequence: int,
    payload: dict[str, JsonValue],
    *,
    tenant_id: str = str(TENANT_ID),
) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuids(),
        tenant_id=tenant_id,
        aggregate_id=str(sandbox_id),
        event_type=event_type,
        schema_version=1,
        occurred_at=NOW,
        payload=payload,
        aggregate_sequence=sequence,
        idempotency_key=f"sandbox:{sandbox_id}:{event_type}:{sequence}",
    )


def test_replay_accepts_unknown_additive_events_and_rejects_corruption() -> None:
    uuids = UUIDs()
    sandbox_request = request(uuids)
    requested = _event(
        uuids,
        sandbox_request.sandbox_id,
        DomainEventType.SANDBOX_REQUESTED,
        1,
        {"request": sandbox_request_to_payload(sandbox_request)},
    )
    unknown = _event(
        uuids,
        sandbox_request.sandbox_id,
        "sandbox.future_additive_event",
        2,
        {"future": True},
    )
    state = replay_sandbox((requested, unknown))
    assert state.status is SandboxStatus.REQUESTED
    assert state.version == 2

    with pytest.raises(SandboxReplayError, match="empty"):
        replay_sandbox(())
    with pytest.raises(SandboxReplayError, match="gapless"):
        replay_sandbox((requested, replace(unknown, aggregate_sequence=3)))
    with pytest.raises(SandboxReplayError, match="linkage changed"):
        replay_sandbox(
            (
                requested,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_POLICY_EVALUATED,
                    2,
                    {
                        "outcome": "allow",
                        "policy_digest": "d" * 64,
                    },
                    tenant_id="tenant-other",
                ),
            )
        )


def test_replay_rejects_illegal_transition_stale_scope_and_result_sequence() -> None:
    uuids = UUIDs()
    sandbox_request = request(uuids)
    requested = _event(
        uuids,
        sandbox_request.sandbox_id,
        DomainEventType.SANDBOX_REQUESTED,
        1,
        {"request": sandbox_request_to_payload(sandbox_request)},
    )
    policy_allowed = _event(
        uuids,
        sandbox_request.sandbox_id,
        DomainEventType.SANDBOX_POLICY_EVALUATED,
        2,
        {"outcome": "allow", "policy_digest": "d" * 64},
    )
    approval_bound = _event(
        uuids,
        sandbox_request.sandbox_id,
        DomainEventType.SANDBOX_APPROVAL_BOUND,
        3,
        {
            "spec_digest": sandbox_request.spec.digest,
            "policy_digest": "d" * 64,
            "approval_scope_digest": "e" * 64,
        },
    )
    with pytest.raises(SandboxReplayError, match="invalid from requested"):
        replay_sandbox(
            (
                requested,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_STARTED,
                    2,
                    {},
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="stale spec"):
        replay_sandbox(
            (
                requested,
                policy_allowed,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_APPROVAL_BOUND,
                    3,
                    {
                        "spec_digest": "e" * 64,
                        "policy_digest": "d" * 64,
                        "approval_scope_digest": "f" * 64,
                    },
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="attestation lacks"):
        replay_sandbox(
            (
                requested,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_ATTESTED,
                    2,
                    {
                        "attestation_id": str(uuids()),
                        "backend": "fake",
                        "backend_reference": "fake/ref",
                        "image_digest": sandbox_request.spec.image_digest,
                        "input_digest": sandbox_request.spec.input_snapshot.digest,
                        "spec_digest": sandbox_request.spec.digest,
                        "policy_digest": "d" * 64,
                        "approval_scope_digest": "e" * 64,
                        "result_digest": "f" * 64,
                        "started_at": NOW.isoformat(),
                        "completed_at": (NOW + timedelta(seconds=1)).isoformat(),
                    },
                ),
            )
        )
    completed = (
        _event(
            uuids,
            sandbox_request.sandbox_id,
            DomainEventType.SANDBOX_DISPATCH_CLAIMED,
            4,
            {},
        ),
        _event(
            uuids,
            sandbox_request.sandbox_id,
            DomainEventType.SANDBOX_PROVISIONING_REQUESTED,
            5,
            {},
        ),
        _event(
            uuids,
            sandbox_request.sandbox_id,
            DomainEventType.SANDBOX_PROVISIONED,
            6,
            {"backend_reference": "fake/ref"},
        ),
        _event(
            uuids,
            sandbox_request.sandbox_id,
            DomainEventType.SANDBOX_START_REQUESTED,
            7,
            {},
        ),
        _event(
            uuids,
            sandbox_request.sandbox_id,
            DomainEventType.SANDBOX_STARTED,
            8,
            {},
        ),
        _event(
            uuids,
            sandbox_request.sandbox_id,
            DomainEventType.SANDBOX_COMPLETED,
            9,
            {
                "result": {
                    "artifacts": [],
                    "completed_at": (NOW + timedelta(seconds=1)).isoformat(),
                    "error_code": None,
                    "exit_code": 0,
                    "outcome": SandboxExecutionOutcome.SUCCEEDED.value,
                    "started_at": NOW.isoformat(),
                    "stderr": {
                        "captured_bytes": 0,
                        "digest": "e" * 64,
                        "redacted": True,
                        "stream": "stderr",
                        "truncated": False,
                    },
                    "stdout": {
                        "captured_bytes": 0,
                        "digest": "d" * 64,
                        "redacted": True,
                        "stream": "stdout",
                        "truncated": False,
                    },
                }
            },
        ),
    )
    with pytest.raises(SandboxReplayError, match="scope is stale"):
        replay_sandbox(
            (
                requested,
                policy_allowed,
                approval_bound,
                *completed,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_ATTESTED,
                    10,
                    {
                        "attestation_id": str(uuids()),
                        "backend_identity": "fake",
                        "image_digest": "f" * 64,
                        "input_digest": sandbox_request.spec.input_snapshot.digest,
                        "spec_digest": sandbox_request.spec.digest,
                        "policy_digest": "d" * 64,
                        "approval_scope_digest": "e" * 64,
                        "result_digest": "0" * 64,
                        "started_at": NOW.isoformat(),
                        "completed_at": (NOW + timedelta(seconds=1)).isoformat(),
                    },
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="scope is stale"):
        replay_sandbox(
            (
                requested,
                policy_allowed,
                approval_bound,
                *completed,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_ATTESTED,
                    10,
                    {
                        "attestation_id": str(uuids()),
                        "backend_identity": "fake",
                        "image_digest": sandbox_request.spec.image_digest,
                        "input_digest": "f" * 64,
                        "spec_digest": sandbox_request.spec.digest,
                        "policy_digest": "d" * 64,
                        "approval_scope_digest": "e" * 64,
                        "result_digest": "0" * 64,
                        "started_at": NOW.isoformat(),
                        "completed_at": (NOW + timedelta(seconds=1)).isoformat(),
                    },
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="scope is stale"):
        replay_sandbox(
            (
                requested,
                policy_allowed,
                approval_bound,
                *completed,
                _event(
                    uuids,
                    sandbox_request.sandbox_id,
                    DomainEventType.SANDBOX_ATTESTED,
                    10,
                    {
                        "attestation_id": str(uuids()),
                        "backend_identity": "fake",
                        "image_digest": sandbox_request.spec.image_digest,
                        "input_digest": sandbox_request.spec.input_snapshot.digest,
                        "spec_digest": sandbox_request.spec.digest,
                        "policy_digest": "d" * 64,
                        "approval_scope_digest": "e" * 64,
                        "result_digest": "f" * 64,
                        "started_at": NOW.isoformat(),
                        "completed_at": (NOW + timedelta(seconds=1)).isoformat(),
                    },
                ),
            )
        )


def test_replay_tracks_and_validates_pending_reconciliation() -> None:
    uuids = UUIDs("reconciliation-replay")
    sandbox_request = request(uuids)
    requested = _event(
        uuids,
        sandbox_request.sandbox_id,
        DomainEventType.SANDBOX_REQUESTED,
        1,
        {"request": sandbox_request_to_payload(sandbox_request)},
    )

    def reconciliation(
        event_type: DomainEventType,
        sequence: int,
        phase: str,
        *,
        attempt: int | None = None,
    ) -> EventEnvelope:
        payload: dict[str, JsonValue] = {"phase": phase}
        if attempt is not None:
            payload["attempt"] = attempt
        return _event(
            uuids,
            sandbox_request.sandbox_id,
            event_type,
            sequence,
            payload,
        )

    with pytest.raises(SandboxReplayError, match="phase is invalid"):
        replay_sandbox(
            (
                requested,
                reconciliation(
                    DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
                    2,
                    "unknown",
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="attempt is invalid"):
        replay_sandbox(
            (
                requested,
                reconciliation(
                    DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
                    2,
                    "collect",
                    attempt=0,
                ),
            )
        )
    pending_event = reconciliation(
        DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
        2,
        "collect",
        attempt=1,
    )
    pending = replay_sandbox((requested, pending_event))
    assert pending.pending_reconciliation_phase == "collect"
    assert pending.pending_reconciliation_attempt == 1
    with pytest.raises(SandboxReplayError, match="already pending"):
        replay_sandbox(
            (
                requested,
                pending_event,
                reconciliation(
                    DomainEventType.SANDBOX_RECONCILIATION_REQUESTED,
                    3,
                    "collect",
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="matching request"):
        replay_sandbox(
            (
                requested,
                reconciliation(
                    DomainEventType.SANDBOX_RECONCILED,
                    2,
                    "collect",
                ),
            )
        )
    with pytest.raises(SandboxReplayError, match="matching request"):
        replay_sandbox(
            (
                requested,
                pending_event,
                reconciliation(
                    DomainEventType.SANDBOX_RECONCILED,
                    3,
                    "cleanup",
                ),
            )
        )
    reconciled = replay_sandbox(
        (
            requested,
            pending_event,
            reconciliation(
                DomainEventType.SANDBOX_RECONCILED,
                3,
                "collect",
            ),
        )
    )
    assert reconciled.pending_reconciliation_phase is None
    assert reconciled.pending_reconciliation_attempt is None
