"""Pure, provider-neutral contracts and replay rules for bounded sandboxes."""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import IntEnum, StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from aegis_agent_platform.domain.events import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
)

MAX_ARGV_TOKENS = 64
MAX_ENVIRONMENT_VARIABLES = 64
MAX_MOUNTS = 32
MAX_OUTPUTS = 32
MAX_EGRESS_RULES = 16
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_EXPANSION_RATIO = 100
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(
    r"^(?P<registry>[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?)/"
    r"(?P<repository>[a-z0-9][a-z0-9._/-]*)@sha256:(?P<digest>[0-9a-f]{64})$"
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_SHELL_META = frozenset(";&|`$<>\n\r")
_SECRET_NAME = re.compile(r"(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)")
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]+PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16})"
)
_DEVICE_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class SandboxPurpose(StrEnum):
    CODE_ANALYSIS = "code_analysis"
    CONFIG_ANALYSIS = "config_analysis"
    TEST_EXECUTION = "test_execution"
    PATCH_PREPARATION = "patch_preparation"
    EVIDENCE_PRODUCTION = "evidence_production"


class SandboxRisk(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class MountAccess(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


class NetworkMode(StrEnum):
    NONE = "none"
    BROKERED = "brokered"


class ExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OOM_KILLED = "oom_killed"
    POLICY_VIOLATION = "policy_violation"
    CANCELLED = "cancelled"
    AMBIGUOUS = "ambiguous"


class SandboxStatus(StrEnum):
    REQUESTED = "requested"
    POLICY_APPROVED = "policy_approved"
    POLICY_DENIED = "policy_denied"
    APPROVED = "approved"
    DISPATCHED = "dispatched"
    PROVISIONING = "provisioning"
    PROVISIONED = "provisioned"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OOM_KILLED = "oom_killed"
    POLICY_VIOLATION = "policy_violation"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"
    CLEANUP_PENDING = "cleanup_pending"
    CLEANED = "cleaned"
    CLEANUP_FAILED = "cleanup_failed"


class SandboxReconciliationOutcome(StrEnum):
    ABSENT = "absent"
    PRESENT = "present"
    RUNNING = "running"
    TERMINAL = "terminal"
    DELETED = "deleted"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContentReference:
    """Tenant-bound content-addressed object reference, never inline content."""

    uri: str
    digest: str
    size_bytes: int
    media_type: str

    def __post_init__(self) -> None:
        if not self.uri.startswith(("aegis-input://", "aegis-artifact://")):
            raise ValueError("content reference must use an Aegis object scheme")
        _digest(self.digest, "content digest")
        if not 0 <= self.size_bytes <= MAX_INPUT_BYTES:
            raise ValueError("content reference size is outside the sandbox bound")
        _safe_text(self.media_type, "content media type", 128)


@dataclass(frozen=True, slots=True)
class SandboxLinkage:
    """Exact Layer 7 task and Layer 8 remediation/approval linkage."""

    tenant_id: str
    run_id: UUID
    task_id: UUID
    remediation_plan_id: UUID
    remediation_action_id: UUID
    approval_id: UUID

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "sandbox tenant")
        if any(
            value.int == 0
            for value in (
                self.run_id,
                self.task_id,
                self.remediation_plan_id,
                self.remediation_action_id,
                self.approval_id,
            )
        ):
            raise ValueError("sandbox linkage identifiers cannot be nil")


@dataclass(frozen=True, slots=True)
class MountDeclaration:
    source: ContentReference
    target: str
    access: MountAccess

    def __post_init__(self) -> None:
        _relative_path(self.target, "mount target")
        if self.target in {"workspace", "outputs"}:
            raise ValueError("reserved sandbox mount target")


@dataclass(frozen=True, slots=True)
class SecretReference:
    """Opaque broker reference; secret values never enter sandbox contracts."""

    name: str
    uri: str

    def __post_init__(self) -> None:
        if not _ENV_NAME.fullmatch(self.name):
            raise ValueError("secret environment name is invalid")
        if not self.uri.startswith("aegis-secret://"):
            raise ValueError("secret reference must use aegis-secret://")
        _safe_text(self.uri, "secret reference", 512)


@dataclass(frozen=True, slots=True)
class EgressRule:
    protocol: str
    host: str
    port: int

    def __post_init__(self) -> None:
        if self.protocol not in {"https", "tls"}:
            raise ValueError("sandbox egress requires an encrypted protocol")
        host = self.host.lower()
        if host != self.host or not _HOSTNAME.fullmatch(host):
            raise ValueError("egress host must be a canonical DNS name")
        _reject_special_host(host)
        if not 1 <= self.port <= 65_535:
            raise ValueError("egress port is invalid")


@dataclass(frozen=True, slots=True)
class SandboxResources:
    cpu_millis: int
    memory_bytes: int
    pids: int
    ephemeral_storage_bytes: int
    timeout_seconds: int
    max_output_bytes: int
    max_files: int
    max_artifact_bytes: int

    def __post_init__(self) -> None:
        bounds = (
            (self.cpu_millis, 50, 8_000, "cpu"),
            (self.memory_bytes, 32 * 1024 * 1024, 16 * 1024**3, "memory"),
            (self.pids, 1, 1_024, "pid"),
            (
                self.ephemeral_storage_bytes,
                16 * 1024 * 1024,
                32 * 1024**3,
                "ephemeral storage",
            ),
            (self.timeout_seconds, 1, 3_600, "time"),
            (self.max_output_bytes, 1, 16 * 1024 * 1024, "output"),
            (self.max_files, 1, 10_000, "file count"),
            (self.max_artifact_bytes, 1, 512 * 1024 * 1024, "artifact"),
        )
        for value, minimum, maximum, name in bounds:
            if not minimum <= value <= maximum:
                raise ValueError(f"sandbox {name} limit is outside the hard bound")


@dataclass(frozen=True, slots=True)
class IsolationConstraints:
    run_as_user: int = 65_532
    run_as_group: int = 65_532
    read_only_root_filesystem: bool = True
    no_new_privileges: bool = True
    privileged: bool = False
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    automount_service_account_token: bool = False
    capability_drop: tuple[str, ...] = ("ALL",)
    capability_add: tuple[str, ...] = ()
    seccomp_profile: str = "RuntimeDefault"
    apparmor_profile: str = "runtime/default"

    def __post_init__(self) -> None:
        if self.run_as_user < 10_000 or self.run_as_group < 10_000:
            raise ValueError("sandbox user and group must be non-system identities")
        if (
            not self.read_only_root_filesystem
            or not self.no_new_privileges
            or self.privileged
            or self.host_network
            or self.host_pid
            or self.host_ipc
            or self.automount_service_account_token
        ):
            raise ValueError(
                "sandbox isolation constraints cannot weaken hard controls"
            )
        if self.capability_drop != ("ALL",) or self.capability_add:
            raise ValueError("sandbox must drop all Linux capabilities")
        if self.seccomp_profile != "RuntimeDefault":
            raise ValueError("sandbox requires the RuntimeDefault seccomp profile")
        if self.apparmor_profile != "runtime/default":
            raise ValueError("sandbox requires the runtime/default AppArmor profile")


@dataclass(frozen=True, slots=True)
class ExpectedOutput:
    path: str
    media_type: str
    required: bool
    max_bytes: int

    def __post_init__(self) -> None:
        _relative_path(self.path, "expected output path")
        if not self.path.startswith("outputs/"):
            raise ValueError("sandbox outputs must stay below outputs/")
        _safe_text(self.media_type, "output media type", 128)
        if not 1 <= self.max_bytes <= MAX_INPUT_BYTES:
            raise ValueError("expected output size is outside the hard bound")


@dataclass(frozen=True, slots=True)
class SandboxRetryPolicy:
    max_attempts: int = 2
    initial_backoff_seconds: float = 1
    maximum_backoff_seconds: float = 30
    reconcile_before_retry: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("sandbox retry attempts must be between 1 and 5")
        if not 0 <= self.initial_backoff_seconds <= 60:
            raise ValueError("sandbox initial backoff is invalid")
        if not self.initial_backoff_seconds <= self.maximum_backoff_seconds <= 300:
            raise ValueError("sandbox maximum backoff is invalid")
        if not self.reconcile_before_retry:
            raise ValueError("sandbox retries must reconcile first")
        object.__setattr__(
            self,
            "initial_backoff_seconds",
            float(self.initial_backoff_seconds),
        )
        object.__setattr__(
            self,
            "maximum_backoff_seconds",
            float(self.maximum_backoff_seconds),
        )


@dataclass(frozen=True, slots=True)
class CleanupPolicy:
    maximum_retention_seconds: int = 86_400
    max_attempts: int = 5
    quarantine_on_failure: bool = True

    def __post_init__(self) -> None:
        if not 60 <= self.maximum_retention_seconds <= 30 * 86_400:
            raise ValueError("sandbox retention is outside the hard bound")
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("sandbox cleanup attempts are invalid")
        if not self.quarantine_on_failure:
            raise ValueError("sandbox cleanup must fail closed into quarantine")


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    """Immutable execution specification with a canonical SHA-256 digest."""

    image: str
    argv: tuple[str, ...]
    working_directory: str
    input_snapshot: ContentReference
    mounts: tuple[MountDeclaration, ...]
    environment: Mapping[str, str]
    secret_environment: Mapping[str, SecretReference]
    network_mode: NetworkMode
    egress_rules: tuple[EgressRule, ...]
    resources: SandboxResources
    isolation: IsolationConstraints
    expected_outputs: tuple[ExpectedOutput, ...]
    retry_policy: SandboxRetryPolicy
    cleanup_policy: CleanupPolicy
    schema_version: int = 1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not _IMAGE.fullmatch(self.image):
            raise ValueError("sandbox image must be pinned by immutable OCI digest")
        if not 1 <= len(self.argv) <= MAX_ARGV_TOKENS:
            raise ValueError("sandbox argv token count is invalid")
        for token in self.argv:
            _argv_token(token)
        _relative_path(self.working_directory, "working directory")
        if not self.working_directory.startswith("workspace"):
            raise ValueError("working directory must remain below workspace/")
        if len(self.mounts) > MAX_MOUNTS:
            raise ValueError("sandbox mount count exceeds the hard bound")
        mount_targets = [mount.target for mount in self.mounts]
        _unique_paths(mount_targets, "mount")
        if len(self.environment) > MAX_ENVIRONMENT_VARIABLES:
            raise ValueError("sandbox environment exceeds the hard bound")
        if len(self.secret_environment) > MAX_ENVIRONMENT_VARIABLES:
            raise ValueError("sandbox secret environment exceeds the hard bound")
        _validate_environment(self.environment, self.secret_environment)
        if self.network_mode is NetworkMode.NONE and self.egress_rules:
            raise ValueError("network-none sandboxes cannot declare egress")
        if self.network_mode is NetworkMode.BROKERED and not self.egress_rules:
            raise ValueError("brokered network requires exact egress rules")
        if len(self.egress_rules) > MAX_EGRESS_RULES:
            raise ValueError("sandbox egress rules exceed the hard bound")
        if len(set(self.egress_rules)) != len(self.egress_rules):
            raise ValueError("sandbox egress rules must be unique")
        if not 1 <= len(self.expected_outputs) <= MAX_OUTPUTS:
            raise ValueError("sandbox expected output count is invalid")
        output_paths = [output.path for output in self.expected_outputs]
        _unique_paths(output_paths, "output")
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(
            self,
            "mounts",
            tuple(sorted(self.mounts, key=lambda item: item.target)),
        )
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(dict(sorted(self.environment.items()))),
        )
        object.__setattr__(
            self,
            "secret_environment",
            MappingProxyType(dict(sorted(self.secret_environment.items()))),
        )
        object.__setattr__(
            self,
            "egress_rules",
            tuple(
                sorted(
                    self.egress_rules,
                    key=lambda item: (item.protocol, item.host, item.port),
                )
            ),
        )
        object.__setattr__(
            self,
            "expected_outputs",
            tuple(sorted(self.expected_outputs, key=lambda item: item.path)),
        )
        object.__setattr__(self, "digest", _canonical_digest(_spec_plain(self)))

    @property
    def image_digest(self) -> str:
        match = _IMAGE.fullmatch(self.image)
        if match is None:
            raise RuntimeError("validated image unexpectedly became invalid")
        return match.group("digest")

    @property
    def image_registry(self) -> str:
        match = _IMAGE.fullmatch(self.image)
        if match is None:
            raise RuntimeError("validated image unexpectedly became invalid")
        return match.group("registry")

    @property
    def command_family(self) -> str:
        return posixpath.basename(self.argv[0])


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    sandbox_id: UUID
    linkage: SandboxLinkage
    purpose: SandboxPurpose
    risk: SandboxRisk
    spec: SandboxSpec
    requested_by: str
    requested_at: datetime
    idempotency_key: str
    schema_version: int = 1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.sandbox_id.int == 0:
            raise ValueError("sandbox_id cannot be nil")
        _identifier(self.requested_by, "sandbox requester")
        _aware(self.requested_at, "sandbox request time")
        _identifier(self.idempotency_key, "sandbox idempotency key")
        if self.schema_version != 1:
            raise ValueError("new sandbox schemas require an additive contract")
        tenant_prefix = f"aegis-input://{self.linkage.tenant_id}/"
        if not self.spec.input_snapshot.uri.startswith(tenant_prefix):
            raise ValueError("sandbox input snapshot is not tenant-bound")
        if any(
            not mount.source.uri.startswith(
                (
                    tenant_prefix,
                    f"aegis-artifact://{self.linkage.tenant_id}/",
                )
            )
            for mount in self.spec.mounts
        ):
            raise ValueError("sandbox mount source is not tenant-bound")
        secret_prefix = f"aegis-secret://{self.linkage.tenant_id}/"
        if any(
            not reference.uri.startswith(secret_prefix)
            for reference in self.spec.secret_environment.values()
        ):
            raise ValueError("sandbox secret reference is not tenant-bound")
        object.__setattr__(self, "digest", _canonical_digest(_request_plain(self)))


@dataclass(frozen=True, slots=True)
class SandboxApprovalBinding:
    """Layer 8 approval scope extended with the exact Layer 9 spec digest."""

    approval_id: UUID
    plan_id: UUID
    action_id: UUID
    plan_digest: str
    action_digest: str
    policy_digest: str
    spec_digest: str
    purpose: SandboxPurpose
    risk: SandboxRisk
    approver_ids: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    schema_version: int = 1
    scope_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if any(
            value.int == 0 for value in (self.approval_id, self.plan_id, self.action_id)
        ):
            raise ValueError("sandbox approval identifiers cannot be nil")
        for value, name in (
            (self.plan_digest, "approval plan digest"),
            (self.action_digest, "approval action digest"),
            (self.policy_digest, "approval policy digest"),
            (self.spec_digest, "approval spec digest"),
        ):
            _digest(value, name)
        if not self.approver_ids or len(self.approver_ids) > 5:
            raise ValueError("sandbox approval requires bounded approvers")
        if len(set(self.approver_ids)) != len(self.approver_ids):
            raise ValueError("sandbox approvers must be distinct")
        for approver_id in self.approver_ids:
            _identifier(approver_id, "sandbox approver")
        _aware(self.issued_at, "sandbox approval issue time")
        _aware(self.expires_at, "sandbox approval expiry")
        if self.expires_at <= self.issued_at:
            raise ValueError("sandbox approval expiry must follow issuance")
        object.__setattr__(
            self,
            "scope_digest",
            _canonical_digest(
                {
                    "action_digest": self.action_digest,
                    "action_id": str(self.action_id),
                    "approval_id": str(self.approval_id),
                    "plan_digest": self.plan_digest,
                    "plan_id": str(self.plan_id),
                    "policy_digest": self.policy_digest,
                    "purpose": self.purpose.value,
                    "risk": int(self.risk),
                    "schema_version": self.schema_version,
                    "spec_digest": self.spec_digest,
                }
            ),
        )

    def valid_for(
        self,
        request: SandboxRequest,
        *,
        policy_digest: str,
        at: datetime,
    ) -> bool:
        linkage = request.linkage
        return (
            self.approval_id == linkage.approval_id
            and self.plan_id == linkage.remediation_plan_id
            and self.action_id == linkage.remediation_action_id
            and self.spec_digest == request.spec.digest
            and self.policy_digest == policy_digest
            and self.purpose is request.purpose
            and self.risk is request.risk
            and at < self.expires_at
        )


@dataclass(frozen=True, slots=True)
class CapturedOutput:
    stream: str
    digest: str
    captured_bytes: int
    truncated: bool
    redacted: bool

    def __post_init__(self) -> None:
        if self.stream not in {"stdout", "stderr"}:
            raise ValueError("sandbox output stream is invalid")
        _digest(self.digest, "sandbox output digest")
        if self.captured_bytes < 0:
            raise ValueError("sandbox captured output size cannot be negative")
        if not self.redacted:
            raise ValueError("sandbox output metadata must be redacted")


@dataclass(frozen=True, slots=True)
class CapturedArtifact:
    artifact_id: UUID
    path: str
    digest: str
    size_bytes: int
    media_type: str
    quarantined: bool

    def __post_init__(self) -> None:
        if self.artifact_id.int == 0:
            raise ValueError("sandbox artifact_id cannot be nil")
        _relative_path(self.path, "sandbox artifact path")
        _digest(self.digest, "sandbox artifact digest")
        if not 0 <= self.size_bytes <= MAX_INPUT_BYTES:
            raise ValueError("sandbox artifact size is outside the hard bound")
        _safe_text(self.media_type, "sandbox artifact media type", 128)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    outcome: ExecutionOutcome
    exit_code: int | None
    started_at: datetime
    completed_at: datetime
    stdout: CapturedOutput
    stderr: CapturedOutput
    artifacts: tuple[CapturedArtifact, ...]
    error_code: str | None = None

    def __post_init__(self) -> None:
        _aware(self.started_at, "sandbox result start")
        _aware(self.completed_at, "sandbox result completion")
        if self.completed_at < self.started_at:
            raise ValueError("sandbox completion cannot precede start")
        if self.exit_code is not None and not -255 <= self.exit_code <= 255:
            raise ValueError("sandbox exit code is invalid")
        if self.error_code is not None:
            _identifier(self.error_code, "sandbox result error code")
        if len(self.artifacts) > MAX_OUTPUTS:
            raise ValueError("sandbox result artifact count exceeds the hard bound")


@dataclass(frozen=True, slots=True)
class SandboxAttestation:
    spec_digest: str
    image_digest: str
    input_digest: str
    result_digest: str
    backend_identity: str
    policy_digest: str
    approval_scope_digest: str
    recorded_at: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.spec_digest, "attestation spec digest"),
            (self.image_digest, "attestation image digest"),
            (self.input_digest, "attestation input digest"),
            (self.result_digest, "attestation result digest"),
            (self.policy_digest, "attestation policy digest"),
            (self.approval_scope_digest, "attestation approval digest"),
        ):
            _digest(value, name)
        _identifier(self.backend_identity, "sandbox backend identity")
        _aware(self.recorded_at, "sandbox attestation time")


@dataclass(frozen=True, slots=True)
class SandboxState:
    """Authoritative state reconstructed only from additive ledger events."""

    request: SandboxRequest
    status: SandboxStatus
    version: int
    policy_digest: str | None = None
    approval_scope_digest: str | None = None
    backend_reference: str | None = None
    result: SandboxResult | None = None
    attestation: SandboxAttestation | None = None
    cleanup_attempts: int = 0
    quarantine_reason: str | None = None
    pending_reconciliation_phase: str | None = None
    pending_reconciliation_attempt: int | None = None
    event_ids: frozenset[UUID] = frozenset()
    idempotency_keys: frozenset[str] = frozenset()


class SandboxReplayError(RuntimeError):
    """Committed sandbox history violates a deterministic invariant."""


def sandbox_request_to_payload(request: SandboxRequest) -> Mapping[str, JsonValue]:
    return cast(Mapping[str, JsonValue], _request_plain(request))


def sandbox_request_from_payload(value: Mapping[str, JsonValue]) -> SandboxRequest:
    linkage = _mapping(value["linkage"])
    spec = _spec_from_plain(_mapping(value["spec"]))
    return SandboxRequest(
        sandbox_id=UUID(_string(value["sandbox_id"])),
        linkage=SandboxLinkage(
            tenant_id=_string(linkage["tenant_id"]),
            run_id=UUID(_string(linkage["run_id"])),
            task_id=UUID(_string(linkage["task_id"])),
            remediation_plan_id=UUID(_string(linkage["remediation_plan_id"])),
            remediation_action_id=UUID(_string(linkage["remediation_action_id"])),
            approval_id=UUID(_string(linkage["approval_id"])),
        ),
        purpose=SandboxPurpose(_string(value["purpose"])),
        risk=SandboxRisk(_integer(value["risk"])),
        spec=spec,
        requested_by=_string(value["requested_by"]),
        requested_at=datetime.fromisoformat(_string(value["requested_at"])),
        idempotency_key=_string(value["idempotency_key"]),
        schema_version=_integer(value["schema_version"]),
    )


def sandbox_result_to_payload(result: SandboxResult) -> Mapping[str, JsonValue]:
    return cast(
        Mapping[str, JsonValue],
        {
            "artifacts": [
                {
                    "artifact_id": str(artifact.artifact_id),
                    "digest": artifact.digest,
                    "media_type": artifact.media_type,
                    "path": artifact.path,
                    "quarantined": artifact.quarantined,
                    "size_bytes": artifact.size_bytes,
                }
                for artifact in result.artifacts
            ],
            "completed_at": result.completed_at.isoformat(),
            "error_code": result.error_code,
            "exit_code": result.exit_code,
            "outcome": result.outcome.value,
            "started_at": result.started_at.isoformat(),
            "stderr": {
                "captured_bytes": result.stderr.captured_bytes,
                "digest": result.stderr.digest,
                "redacted": result.stderr.redacted,
                "stream": result.stderr.stream,
                "truncated": result.stderr.truncated,
            },
            "stdout": {
                "captured_bytes": result.stdout.captured_bytes,
                "digest": result.stdout.digest,
                "redacted": result.stdout.redacted,
                "stream": result.stdout.stream,
                "truncated": result.stdout.truncated,
            },
        },
    )


def sandbox_result_digest(result: SandboxResult) -> str:
    payload = sandbox_result_to_payload(result)
    return _canonical_digest(
        {
            "artifacts": [
                {
                    "digest": _string(_mapping(item)["digest"]),
                    "media_type": _string(_mapping(item)["media_type"]),
                    "quarantined": _boolean(_mapping(item)["quarantined"]),
                    "size_bytes": _integer(_mapping(item)["size_bytes"]),
                }
                for item in _sequence(payload["artifacts"])
            ],
            "completed_at": _string(payload["completed_at"]),
            "error_code": payload["error_code"],
            "exit_code": payload["exit_code"],
            "outcome": _string(payload["outcome"]),
            "started_at": _string(payload["started_at"]),
            "stderr": {
                "captured_bytes": _integer(
                    _mapping(payload["stderr"])["captured_bytes"]
                ),
                "digest": _string(_mapping(payload["stderr"])["digest"]),
                "truncated": _boolean(_mapping(payload["stderr"])["truncated"]),
            },
            "stdout": {
                "captured_bytes": _integer(
                    _mapping(payload["stdout"])["captured_bytes"]
                ),
                "digest": _string(_mapping(payload["stdout"])["digest"]),
                "truncated": _boolean(_mapping(payload["stdout"])["truncated"]),
            },
        }
    )


def sandbox_result_from_payload(value: Mapping[str, JsonValue]) -> SandboxResult:
    stdout = _mapping(value["stdout"])
    stderr = _mapping(value["stderr"])
    return SandboxResult(
        outcome=ExecutionOutcome(_string(value["outcome"])),
        exit_code=(
            None if value.get("exit_code") is None else _integer(value["exit_code"])
        ),
        started_at=datetime.fromisoformat(_string(value["started_at"])),
        completed_at=datetime.fromisoformat(_string(value["completed_at"])),
        stdout=CapturedOutput(
            stream=_string(stdout["stream"]),
            digest=_string(stdout["digest"]),
            captured_bytes=_integer(stdout["captured_bytes"]),
            truncated=_boolean(stdout["truncated"]),
            redacted=_boolean(stdout["redacted"]),
        ),
        stderr=CapturedOutput(
            stream=_string(stderr["stream"]),
            digest=_string(stderr["digest"]),
            captured_bytes=_integer(stderr["captured_bytes"]),
            truncated=_boolean(stderr["truncated"]),
            redacted=_boolean(stderr["redacted"]),
        ),
        artifacts=tuple(
            CapturedArtifact(
                artifact_id=UUID(_string(_mapping(item)["artifact_id"])),
                path=_string(_mapping(item)["path"]),
                digest=_string(_mapping(item)["digest"]),
                size_bytes=_integer(_mapping(item)["size_bytes"]),
                media_type=_string(_mapping(item)["media_type"]),
                quarantined=_boolean(_mapping(item)["quarantined"]),
            )
            for item in _sequence(value["artifacts"])
        ),
        error_code=(
            None if value.get("error_code") is None else _string(value["error_code"])
        ),
    )


def replay_sandbox(events: Sequence[EventEnvelope]) -> SandboxState:
    """Fold one sandbox stream and reject illegal transitions or corruption."""
    if not events:
        raise SandboxReplayError("sandbox stream is empty")
    state: SandboxState | None = None
    seen_events: set[UUID] = set()
    seen_keys: set[str] = set()
    expected_sequence = 1
    seen_types: set[DomainEventType] = set()
    for event in events:
        if event.event_id in seen_events:
            raise SandboxReplayError("duplicate sandbox event identifier")
        seen_events.add(event.event_id)
        if event.idempotency_key is not None:
            if event.idempotency_key in seen_keys:
                raise SandboxReplayError("duplicate sandbox idempotency key")
            seen_keys.add(event.idempotency_key)
        if event.aggregate_sequence:
            if event.aggregate_sequence != expected_sequence:
                raise SandboxReplayError("sandbox sequence is not gapless")
            expected_sequence += 1
        try:
            event_type = DomainEventType(event.event_type)
        except ValueError:
            continue
        if not event_type.value.startswith("sandbox."):
            continue
        if event_type is DomainEventType.SANDBOX_REQUESTED:
            if state is not None:
                raise SandboxReplayError("sandbox was requested twice")
            request_value = event.payload.get("request")
            if not isinstance(request_value, Mapping):
                raise SandboxReplayError("sandbox request event lacks a request")
            try:
                request = sandbox_request_from_payload(request_value)
            except (KeyError, TypeError, ValueError) as error:
                raise SandboxReplayError(
                    "sandbox request payload is invalid"
                ) from error
            request_digest = event.payload.get("request_digest")
            if request_digest is not None and request_digest != request.digest:
                raise SandboxReplayError("sandbox request digest is corrupt")
            if (
                event.tenant_id != request.linkage.tenant_id
                or event.aggregate_id != str(request.sandbox_id)
            ):
                raise SandboxReplayError("sandbox request linkage is corrupt")
            state = SandboxState(request, SandboxStatus.REQUESTED, 0)
        elif state is not None:
            if (
                event.tenant_id != state.request.linkage.tenant_id
                or event.aggregate_id != str(state.request.sandbox_id)
            ):
                raise SandboxReplayError("sandbox event linkage changed")
            state = _fold_sandbox_event(state, event_type, event, seen_types)
        seen_types.add(event_type)
    if state is None:
        raise SandboxReplayError("sandbox stream has no request")
    return replace(
        state,
        version=len(events),
        event_ids=frozenset(seen_events),
        idempotency_keys=frozenset(seen_keys),
    )


def _fold_sandbox_event(
    state: SandboxState,
    event_type: DomainEventType,
    event: EventEnvelope,
    seen_types: set[DomainEventType],
) -> SandboxState:
    status = state.status
    if event_type is DomainEventType.SANDBOX_POLICY_EVALUATED:
        _require_status(status, {SandboxStatus.REQUESTED}, event_type)
        policy_digest = _payload_digest(event, "policy_digest")
        outcome = _payload_string(event, "outcome")
        if outcome not in {"allow", "deny"}:
            raise SandboxReplayError("sandbox policy outcome is invalid")
        return replace(
            state,
            status=(
                SandboxStatus.POLICY_APPROVED
                if outcome == "allow"
                else SandboxStatus.POLICY_DENIED
            ),
            policy_digest=policy_digest,
        )
    if event_type is DomainEventType.SANDBOX_APPROVAL_BOUND:
        _require_status(status, {SandboxStatus.POLICY_APPROVED}, event_type)
        if _payload_digest(event, "spec_digest") != state.request.spec.digest:
            raise SandboxReplayError("sandbox approval bound a stale spec")
        if _payload_digest(event, "policy_digest") != state.policy_digest:
            raise SandboxReplayError("sandbox approval bound a stale policy")
        return replace(
            state,
            status=SandboxStatus.APPROVED,
            approval_scope_digest=_payload_digest(event, "approval_scope_digest"),
        )
    if event_type is DomainEventType.SANDBOX_EGRESS_DECIDED:
        _require_status(status, {SandboxStatus.APPROVED}, event_type)
        _payload_digest(event, "policy_digest")
        _payload_digest(event, "rule_digest")
        if not isinstance(event.payload.get("allowed"), bool):
            raise SandboxReplayError("sandbox egress decision is invalid")
        _payload_string(event, "reason")
        return state
    transitions: dict[
        DomainEventType,
        tuple[set[SandboxStatus], SandboxStatus],
    ] = {
        DomainEventType.SANDBOX_DISPATCH_CLAIMED: (
            {SandboxStatus.APPROVED},
            SandboxStatus.DISPATCHED,
        ),
        DomainEventType.SANDBOX_PROVISIONING_REQUESTED: (
            {SandboxStatus.DISPATCHED},
            SandboxStatus.PROVISIONING,
        ),
        DomainEventType.SANDBOX_PROVISIONED: (
            {SandboxStatus.PROVISIONING},
            SandboxStatus.PROVISIONED,
        ),
        DomainEventType.SANDBOX_START_REQUESTED: (
            {SandboxStatus.PROVISIONED},
            SandboxStatus.STARTING,
        ),
        DomainEventType.SANDBOX_STARTED: (
            {SandboxStatus.STARTING},
            SandboxStatus.RUNNING,
        ),
        DomainEventType.SANDBOX_COMPLETED: (
            {SandboxStatus.RUNNING},
            SandboxStatus.COMPLETED,
        ),
        DomainEventType.SANDBOX_FAILED: (
            {
                SandboxStatus.PROVISIONING,
                SandboxStatus.STARTING,
                SandboxStatus.RUNNING,
                SandboxStatus.CANCELLING,
            },
            SandboxStatus.FAILED,
        ),
        DomainEventType.SANDBOX_TIMED_OUT: (
            {SandboxStatus.RUNNING},
            SandboxStatus.TIMED_OUT,
        ),
        DomainEventType.SANDBOX_OOM_KILLED: (
            {SandboxStatus.RUNNING},
            SandboxStatus.OOM_KILLED,
        ),
        DomainEventType.SANDBOX_POLICY_VIOLATION: (
            {
                SandboxStatus.APPROVED,
                SandboxStatus.DISPATCHED,
                SandboxStatus.PROVISIONING,
                SandboxStatus.PROVISIONED,
                SandboxStatus.STARTING,
                SandboxStatus.RUNNING,
            },
            SandboxStatus.POLICY_VIOLATION,
        ),
        DomainEventType.SANDBOX_CANCELLATION_REQUESTED: (
            {
                SandboxStatus.DISPATCHED,
                SandboxStatus.PROVISIONING,
                SandboxStatus.PROVISIONED,
                SandboxStatus.STARTING,
                SandboxStatus.RUNNING,
            },
            SandboxStatus.CANCELLING,
        ),
        DomainEventType.SANDBOX_CANCELLED: (
            {SandboxStatus.CANCELLING},
            SandboxStatus.CANCELLED,
        ),
        DomainEventType.SANDBOX_QUARANTINED: (
            {
                SandboxStatus.RUNNING,
                SandboxStatus.COMPLETED,
                SandboxStatus.FAILED,
                SandboxStatus.TIMED_OUT,
                SandboxStatus.OOM_KILLED,
                SandboxStatus.POLICY_VIOLATION,
                SandboxStatus.CANCELLED,
                SandboxStatus.CLEANUP_FAILED,
            },
            SandboxStatus.QUARANTINED,
        ),
        DomainEventType.SANDBOX_CLEANUP_REQUESTED: (
            {
                SandboxStatus.COMPLETED,
                SandboxStatus.FAILED,
                SandboxStatus.TIMED_OUT,
                SandboxStatus.OOM_KILLED,
                SandboxStatus.POLICY_VIOLATION,
                SandboxStatus.CANCELLED,
                SandboxStatus.QUARANTINED,
                SandboxStatus.CLEANUP_FAILED,
            },
            SandboxStatus.CLEANUP_PENDING,
        ),
        DomainEventType.SANDBOX_CLEANUP_COMPLETED: (
            {SandboxStatus.CLEANUP_PENDING},
            SandboxStatus.CLEANED,
        ),
        DomainEventType.SANDBOX_CLEANUP_FAILED: (
            {SandboxStatus.CLEANUP_PENDING},
            SandboxStatus.CLEANUP_FAILED,
        ),
    }
    transition = transitions.get(event_type)
    if transition is not None:
        _require_status(status, transition[0], event_type)
        updated = replace(state, status=transition[1])
        if event_type is DomainEventType.SANDBOX_PROVISIONED:
            reference = _payload_string(event, "backend_reference")
            _safe_text(reference, "sandbox backend reference", 512)
            updated = replace(updated, backend_reference=reference)
        if event_type is DomainEventType.SANDBOX_QUARANTINED:
            updated = replace(
                updated,
                quarantine_reason=_payload_string(event, "reason"),
            )
        if event_type is DomainEventType.SANDBOX_CLEANUP_REQUESTED:
            updated = replace(updated, cleanup_attempts=state.cleanup_attempts + 1)
        result_value = event.payload.get("result")
        if event_type in {
            DomainEventType.SANDBOX_COMPLETED,
            DomainEventType.SANDBOX_FAILED,
            DomainEventType.SANDBOX_TIMED_OUT,
            DomainEventType.SANDBOX_OOM_KILLED,
            DomainEventType.SANDBOX_POLICY_VIOLATION,
            DomainEventType.SANDBOX_CANCELLED,
        } and isinstance(result_value, Mapping):
            try:
                updated = replace(
                    updated,
                    result=sandbox_result_from_payload(result_value),
                )
            except (KeyError, TypeError, ValueError) as error:
                raise SandboxReplayError("sandbox result payload is invalid") from error
        return updated
    if event_type in {
        DomainEventType.SANDBOX_OUTPUT_CAPTURED,
        DomainEventType.SANDBOX_ARTIFACT_CAPTURED,
    }:
        _require_status(
            status,
            {SandboxStatus.RUNNING, SandboxStatus.COMPLETED},
            event_type,
        )
        return state
    if event_type is DomainEventType.SANDBOX_ATTESTED:
        if DomainEventType.SANDBOX_COMPLETED not in seen_types:
            raise SandboxReplayError("sandbox attestation lacks a completed execution")
        if state.result is None:
            raise SandboxReplayError("sandbox attestation lacks a completed result")
        attestation = _attestation_from_event(event)
        if (
            attestation.spec_digest != state.request.spec.digest
            or attestation.image_digest != state.request.spec.image_digest
            or attestation.input_digest != state.request.spec.input_snapshot.digest
            or attestation.result_digest != sandbox_result_digest(state.result)
            or attestation.policy_digest != state.policy_digest
            or attestation.approval_scope_digest != state.approval_scope_digest
        ):
            raise SandboxReplayError("sandbox attestation scope is stale")
        return replace(state, attestation=attestation)
    if event_type is DomainEventType.SANDBOX_RECONCILIATION_REQUESTED:
        phase = _payload_string(event, "phase")
        if phase not in {"cleanup", "collect", "provision"}:
            raise SandboxReplayError("sandbox reconciliation phase is invalid")
        if state.pending_reconciliation_phase is not None:
            raise SandboxReplayError("sandbox reconciliation is already pending")
        attempt_value = event.payload.get("attempt")
        attempt = None if attempt_value is None else _integer(attempt_value)
        if attempt is not None and attempt < 1:
            raise SandboxReplayError("sandbox reconciliation attempt is invalid")
        return replace(
            state,
            pending_reconciliation_phase=phase,
            pending_reconciliation_attempt=attempt,
        )
    if event_type is DomainEventType.SANDBOX_RECONCILED:
        phase = _payload_string(event, "phase")
        if (
            state.pending_reconciliation_phase is None
            or phase != state.pending_reconciliation_phase
        ):
            raise SandboxReplayError("sandbox reconciliation lacks a matching request")
        return replace(
            state,
            pending_reconciliation_phase=None,
            pending_reconciliation_attempt=None,
        )
    raise SandboxReplayError(f"{event_type.value} is invalid from {status.value}")


def _request_plain(request: SandboxRequest) -> dict[str, object]:
    return {
        "idempotency_key": request.idempotency_key,
        "linkage": {
            "approval_id": str(request.linkage.approval_id),
            "remediation_action_id": str(request.linkage.remediation_action_id),
            "remediation_plan_id": str(request.linkage.remediation_plan_id),
            "run_id": str(request.linkage.run_id),
            "task_id": str(request.linkage.task_id),
            "tenant_id": request.linkage.tenant_id,
        },
        "purpose": request.purpose.value,
        "requested_at": request.requested_at.isoformat(),
        "requested_by": request.requested_by,
        "risk": int(request.risk),
        "sandbox_id": str(request.sandbox_id),
        "schema_version": request.schema_version,
        "spec": _spec_plain(request.spec),
    }


def _spec_plain(spec: SandboxSpec) -> dict[str, object]:
    return {
        "argv": list(spec.argv),
        "cleanup_policy": {
            "max_attempts": spec.cleanup_policy.max_attempts,
            "maximum_retention_seconds": spec.cleanup_policy.maximum_retention_seconds,
            "quarantine_on_failure": spec.cleanup_policy.quarantine_on_failure,
        },
        "egress_rules": [
            {"host": item.host, "port": item.port, "protocol": item.protocol}
            for item in spec.egress_rules
        ],
        "environment": dict(spec.environment),
        "expected_outputs": [
            {
                "max_bytes": item.max_bytes,
                "media_type": item.media_type,
                "path": item.path,
                "required": item.required,
            }
            for item in spec.expected_outputs
        ],
        "image": spec.image,
        "input_snapshot": _content_plain(spec.input_snapshot),
        "isolation": {
            "apparmor_profile": spec.isolation.apparmor_profile,
            "automount_service_account_token": (
                spec.isolation.automount_service_account_token
            ),
            "capability_add": list(spec.isolation.capability_add),
            "capability_drop": list(spec.isolation.capability_drop),
            "host_ipc": spec.isolation.host_ipc,
            "host_network": spec.isolation.host_network,
            "host_pid": spec.isolation.host_pid,
            "no_new_privileges": spec.isolation.no_new_privileges,
            "privileged": spec.isolation.privileged,
            "read_only_root_filesystem": spec.isolation.read_only_root_filesystem,
            "run_as_group": spec.isolation.run_as_group,
            "run_as_user": spec.isolation.run_as_user,
            "seccomp_profile": spec.isolation.seccomp_profile,
        },
        "mounts": [
            {
                "access": item.access.value,
                "source": _content_plain(item.source),
                "target": item.target,
            }
            for item in spec.mounts
        ],
        "network_mode": spec.network_mode.value,
        "resources": {
            "cpu_millis": spec.resources.cpu_millis,
            "ephemeral_storage_bytes": spec.resources.ephemeral_storage_bytes,
            "max_artifact_bytes": spec.resources.max_artifact_bytes,
            "max_files": spec.resources.max_files,
            "max_output_bytes": spec.resources.max_output_bytes,
            "memory_bytes": spec.resources.memory_bytes,
            "pids": spec.resources.pids,
            "timeout_seconds": spec.resources.timeout_seconds,
        },
        "retry_policy": {
            "initial_backoff_seconds": spec.retry_policy.initial_backoff_seconds,
            "max_attempts": spec.retry_policy.max_attempts,
            "maximum_backoff_seconds": spec.retry_policy.maximum_backoff_seconds,
            "reconcile_before_retry": spec.retry_policy.reconcile_before_retry,
        },
        "schema_version": spec.schema_version,
        "secret_environment": {
            name: {"name": reference.name, "uri": reference.uri}
            for name, reference in spec.secret_environment.items()
        },
        "working_directory": spec.working_directory,
    }


def _spec_from_plain(value: Mapping[str, JsonValue]) -> SandboxSpec:
    input_value = _mapping(value["input_snapshot"])
    resources = _mapping(value["resources"])
    isolation = _mapping(value["isolation"])
    retry = _mapping(value["retry_policy"])
    cleanup = _mapping(value["cleanup_policy"])
    environment = _mapping(value["environment"])
    secret_environment = _mapping(value["secret_environment"])
    return SandboxSpec(
        image=_string(value["image"]),
        argv=tuple(_string(item) for item in _sequence(value["argv"])),
        working_directory=_string(value["working_directory"]),
        input_snapshot=_content_from_plain(input_value),
        mounts=tuple(
            MountDeclaration(
                source=_content_from_plain(_mapping(item_value["source"])),
                target=_string(item_value["target"]),
                access=MountAccess(_string(item_value["access"])),
            )
            for item in _sequence(value["mounts"])
            for item_value in (_mapping(item),)
        ),
        environment={key: _string(item) for key, item in environment.items()},
        secret_environment={
            key: SecretReference(
                name=_string(reference["name"]),
                uri=_string(reference["uri"]),
            )
            for key, item in secret_environment.items()
            for reference in (_mapping(item),)
        },
        network_mode=NetworkMode(_string(value["network_mode"])),
        egress_rules=tuple(
            EgressRule(
                protocol=_string(item_value["protocol"]),
                host=_string(item_value["host"]),
                port=_integer(item_value["port"]),
            )
            for item in _sequence(value["egress_rules"])
            for item_value in (_mapping(item),)
        ),
        resources=SandboxResources(
            cpu_millis=_integer(resources["cpu_millis"]),
            memory_bytes=_integer(resources["memory_bytes"]),
            pids=_integer(resources["pids"]),
            ephemeral_storage_bytes=_integer(resources["ephemeral_storage_bytes"]),
            timeout_seconds=_integer(resources["timeout_seconds"]),
            max_output_bytes=_integer(resources["max_output_bytes"]),
            max_files=_integer(resources["max_files"]),
            max_artifact_bytes=_integer(resources["max_artifact_bytes"]),
        ),
        isolation=IsolationConstraints(
            run_as_user=_integer(isolation["run_as_user"]),
            run_as_group=_integer(isolation["run_as_group"]),
            read_only_root_filesystem=_boolean(isolation["read_only_root_filesystem"]),
            no_new_privileges=_boolean(isolation["no_new_privileges"]),
            privileged=_boolean(isolation["privileged"]),
            host_network=_boolean(isolation["host_network"]),
            host_pid=_boolean(isolation["host_pid"]),
            host_ipc=_boolean(isolation["host_ipc"]),
            automount_service_account_token=_boolean(
                isolation["automount_service_account_token"]
            ),
            capability_drop=tuple(
                _string(item) for item in _sequence(isolation["capability_drop"])
            ),
            capability_add=tuple(
                _string(item) for item in _sequence(isolation["capability_add"])
            ),
            seccomp_profile=_string(isolation["seccomp_profile"]),
            apparmor_profile=_string(isolation["apparmor_profile"]),
        ),
        expected_outputs=tuple(
            ExpectedOutput(
                path=_string(item_value["path"]),
                media_type=_string(item_value["media_type"]),
                required=_boolean(item_value["required"]),
                max_bytes=_integer(item_value["max_bytes"]),
            )
            for item in _sequence(value["expected_outputs"])
            for item_value in (_mapping(item),)
        ),
        retry_policy=SandboxRetryPolicy(
            max_attempts=_integer(retry["max_attempts"]),
            initial_backoff_seconds=_number(retry["initial_backoff_seconds"]),
            maximum_backoff_seconds=_number(retry["maximum_backoff_seconds"]),
            reconcile_before_retry=_boolean(retry["reconcile_before_retry"]),
        ),
        cleanup_policy=CleanupPolicy(
            maximum_retention_seconds=_integer(cleanup["maximum_retention_seconds"]),
            max_attempts=_integer(cleanup["max_attempts"]),
            quarantine_on_failure=_boolean(cleanup["quarantine_on_failure"]),
        ),
        schema_version=_integer(value["schema_version"]),
    )


def _content_plain(reference: ContentReference) -> dict[str, object]:
    return {
        "digest": reference.digest,
        "media_type": reference.media_type,
        "size_bytes": reference.size_bytes,
        "uri": reference.uri,
    }


def _content_from_plain(value: Mapping[str, JsonValue]) -> ContentReference:
    return ContentReference(
        uri=_string(value["uri"]),
        digest=_string(value["digest"]),
        size_bytes=_integer(value["size_bytes"]),
        media_type=_string(value["media_type"]),
    )


def _attestation_from_event(event: EventEnvelope) -> SandboxAttestation:
    return SandboxAttestation(
        spec_digest=_payload_digest(event, "spec_digest"),
        image_digest=_payload_digest(event, "image_digest"),
        input_digest=_payload_digest(event, "input_digest"),
        result_digest=_payload_digest(event, "result_digest"),
        backend_identity=_payload_string(event, "backend_identity"),
        policy_digest=_payload_digest(event, "policy_digest"),
        approval_scope_digest=_payload_digest(event, "approval_scope_digest"),
        recorded_at=event.occurred_at,
    )


def _canonical_digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return sha256(encoded).hexdigest()


def _safe_text(value: str, name: str, maximum: int) -> None:
    if (
        not value
        or value != value.strip()
        or unicodedata.normalize("NFKC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
        or len(value.encode()) > maximum
    ):
        raise ValueError(f"{name} must be bounded canonical text")


def _identifier(value: str, name: str) -> None:
    _safe_text(value, name, 256)
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} is not a safe identifier")


def _digest(value: str, name: str) -> None:
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase sha256 digest")


def _aware(value: datetime, name: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")


def _argv_token(value: str) -> None:
    _safe_text(value, "argv token", 4_096)
    if "$(" in value or "${" in value:
        raise ValueError("argv token contains shell interpolation")
    if any(character in _SHELL_META for character in value):
        raise ValueError("argv token contains denied shell metacharacters")
    if value in {"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"}:
        raise ValueError("interactive shell command families are denied")


def _relative_path(value: str, name: str) -> None:
    _safe_text(value, name, 1_024)
    if "\\" in value or value.startswith(("/", "~")) or "://" in value:
        raise ValueError(f"{name} must be a relative POSIX path")
    path = PurePosixPath(value)
    if (
        value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(part.lower() in _DEVICE_NAMES for part in path.parts)
        or any(":" in part for part in path.parts)
    ):
        raise ValueError(f"{name} is unsafe")
    lowered = f"/{value.lower()}/"
    if any(
        denied in lowered
        for denied in (
            "/proc/",
            "/sys/",
            "/dev/",
            "/var/run/",
            "/run/",
            "docker.sock",
            "containerd.sock",
        )
    ):
        raise ValueError(f"{name} reaches a denied host path")


def _unique_paths(paths: Sequence[str], name: str) -> None:
    if len(set(paths)) != len(paths):
        raise ValueError(f"sandbox {name} paths must be unique")
    sorted_paths = sorted(paths)
    for index, left in enumerate(sorted_paths):
        for right in sorted_paths[index + 1 :]:
            if right.startswith(f"{left}/") or left.startswith(f"{right}/"):
                raise ValueError(f"sandbox {name} paths conflict")


def _validate_environment(
    environment: Mapping[str, str],
    secrets: Mapping[str, SecretReference],
) -> None:
    if set(environment).intersection(secrets):
        raise ValueError("sandbox environment and secret names conflict")
    total_bytes = 0
    for name, value in environment.items():
        if not _ENV_NAME.fullmatch(name):
            raise ValueError("sandbox environment name is invalid")
        _safe_text(value, "sandbox environment value", 4_096)
        if _SECRET_NAME.search(name) or _SECRET_VALUE.search(value):
            raise ValueError("secret-like values must use opaque secret references")
        total_bytes += len(name.encode()) + len(value.encode())
    for name, reference in secrets.items():
        if name != reference.name:
            raise ValueError("sandbox secret environment name changed")
        total_bytes += len(name.encode()) + len(reference.uri.encode())
    if total_bytes > 16_384:
        raise ValueError("sandbox environment exceeds the byte bound")


def _reject_special_host(host: str) -> None:
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".localhost", ".local")
    ):
        raise ValueError("loopback egress is denied")
    if host in {
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data.ec2.internal",
    } or host.endswith(".internal"):
        raise ValueError("metadata and internal egress destinations are denied")
    parsed = urlsplit(f"//{host}")
    candidate = parsed.hostname
    if candidate is None:
        raise ValueError("egress destination is invalid")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError("private or special-address egress is denied")


def _require_status(
    current: SandboxStatus,
    allowed: set[SandboxStatus],
    event_type: DomainEventType,
) -> None:
    if current not in allowed:
        raise SandboxReplayError(f"{event_type.value} is invalid from {current.value}")


def _payload_string(event: EventEnvelope, key: str) -> str:
    value = event.payload.get(key)
    if not isinstance(value, str):
        raise SandboxReplayError(f"sandbox event lacks {key}")
    return value


def _payload_digest(event: EventEnvelope, key: str) -> str:
    value = _payload_string(event, key)
    try:
        _digest(value, key)
    except ValueError as error:
        raise SandboxReplayError(str(error)) from error
    return value


def _mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise TypeError("expected an object")
    return value


def _sequence(value: JsonValue) -> Sequence[JsonValue]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise TypeError("expected an array")
    return value


def _string(value: JsonValue) -> str:
    if not isinstance(value, str):
        raise TypeError("expected a string")
    return value


def _integer(value: JsonValue) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("expected an integer")
    return value


def _number(value: JsonValue) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError("expected a number")
    return float(value)


def _boolean(value: JsonValue) -> bool:
    if not isinstance(value, bool):
        raise TypeError("expected a boolean")
    return value


__all__ = [
    "MAX_ARCHIVE_EXPANSION_RATIO",
    "MAX_INPUT_BYTES",
    "CapturedArtifact",
    "CapturedOutput",
    "CleanupPolicy",
    "ContentReference",
    "EgressRule",
    "ExecutionOutcome",
    "ExpectedOutput",
    "IsolationConstraints",
    "MountAccess",
    "MountDeclaration",
    "NetworkMode",
    "SandboxApprovalBinding",
    "SandboxAttestation",
    "SandboxLinkage",
    "SandboxPurpose",
    "SandboxReconciliationOutcome",
    "SandboxReplayError",
    "SandboxRequest",
    "SandboxResources",
    "SandboxResult",
    "SandboxRetryPolicy",
    "SandboxRisk",
    "SandboxSpec",
    "SandboxState",
    "SandboxStatus",
    "SecretReference",
    "replay_sandbox",
    "sandbox_request_from_payload",
    "sandbox_request_to_payload",
    "sandbox_result_digest",
    "sandbox_result_from_payload",
    "sandbox_result_to_payload",
]
