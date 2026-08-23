"""Deny-by-default tenant policy for bounded sandbox execution."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256

from aegis_agent_platform.domain import (
    EgressRule,
    MountAccess,
    SandboxPurpose,
    SandboxRequest,
    SandboxResources,
    SandboxRisk,
)
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class SandboxQuotaUsage:
    runs_in_period: int
    active_runs: int
    cpu_millis_seconds: int
    artifact_bytes: int

    def __post_init__(self) -> None:
        if (
            min(
                self.runs_in_period,
                self.active_runs,
                self.cpu_millis_seconds,
                self.artifact_bytes,
            )
            < 0
        ):
            raise ValueError("sandbox quota usage cannot be negative")


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Versioned exact allowlist and hard ceilings for one tenant."""

    tenant_id: str
    policy_version: str
    allowed_image_digests: frozenset[str]
    allowed_registries: frozenset[str]
    allowed_command_families: frozenset[str]
    allowed_purposes: frozenset[SandboxPurpose]
    allowed_read_only_mount_prefixes: frozenset[str]
    allowed_read_write_mount_prefixes: frozenset[str]
    resource_ceiling: SandboxResources
    allowed_output_media_types: frozenset[str]
    allowed_egress: frozenset[EgressRule]
    allowed_secret_references: frozenset[str]
    maximum_risk: SandboxRisk
    maximum_lifetime_seconds: int
    max_runs_per_period: int
    max_concurrent_runs: int
    max_cpu_millis_seconds_per_period: int
    max_artifact_bytes_per_period: int
    runtime_isolation_verified: bool
    runtime_egress_verified: bool
    admission_controls_verified: bool
    schema_version: int = 1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.policy_version:
            raise ValueError("sandbox policy tenant and version are required")
        if not self.allowed_image_digests or not self.allowed_registries:
            raise ValueError("sandbox policy requires exact image allowlists")
        if not self.allowed_command_families or not self.allowed_purposes:
            raise ValueError("sandbox policy requires command and purpose allowlists")
        for digest in self.allowed_image_digests:
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError("sandbox policy image digest is invalid")
        if not 1 <= self.maximum_lifetime_seconds <= 3_600:
            raise ValueError("sandbox policy lifetime is outside the hard bound")
        if (
            min(
                self.max_runs_per_period,
                self.max_concurrent_runs,
                self.max_cpu_millis_seconds_per_period,
                self.max_artifact_bytes_per_period,
            )
            < 1
        ):
            raise ValueError("sandbox policy quotas must be positive")
        if self.schema_version != 1:
            raise ValueError("new sandbox policies require an additive contract")
        object.__setattr__(
            self,
            "digest",
            sha256(
                json.dumps(
                    {
                        "admission_controls_verified": (
                            self.admission_controls_verified
                        ),
                        "allowed_command_families": sorted(
                            self.allowed_command_families
                        ),
                        "allowed_egress": [
                            {
                                "host": rule.host,
                                "port": rule.port,
                                "protocol": rule.protocol,
                            }
                            for rule in sorted(
                                self.allowed_egress,
                                key=lambda item: (
                                    item.protocol,
                                    item.host,
                                    item.port,
                                ),
                            )
                        ],
                        "allowed_image_digests": sorted(self.allowed_image_digests),
                        "allowed_output_media_types": sorted(
                            self.allowed_output_media_types
                        ),
                        "allowed_purposes": sorted(
                            purpose.value for purpose in self.allowed_purposes
                        ),
                        "allowed_read_only_mount_prefixes": sorted(
                            self.allowed_read_only_mount_prefixes
                        ),
                        "allowed_read_write_mount_prefixes": sorted(
                            self.allowed_read_write_mount_prefixes
                        ),
                        "allowed_registries": sorted(self.allowed_registries),
                        "allowed_secret_references": sorted(
                            self.allowed_secret_references
                        ),
                        "max_artifact_bytes_per_period": (
                            self.max_artifact_bytes_per_period
                        ),
                        "max_concurrent_runs": self.max_concurrent_runs,
                        "max_cpu_millis_seconds_per_period": (
                            self.max_cpu_millis_seconds_per_period
                        ),
                        "max_runs_per_period": self.max_runs_per_period,
                        "maximum_lifetime_seconds": self.maximum_lifetime_seconds,
                        "maximum_risk": int(self.maximum_risk),
                        "policy_version": self.policy_version,
                        "resource_ceiling": {
                            "cpu_millis": self.resource_ceiling.cpu_millis,
                            "ephemeral_storage_bytes": (
                                self.resource_ceiling.ephemeral_storage_bytes
                            ),
                            "max_artifact_bytes": (
                                self.resource_ceiling.max_artifact_bytes
                            ),
                            "max_files": self.resource_ceiling.max_files,
                            "max_output_bytes": (
                                self.resource_ceiling.max_output_bytes
                            ),
                            "memory_bytes": self.resource_ceiling.memory_bytes,
                            "pids": self.resource_ceiling.pids,
                            "timeout_seconds": (self.resource_ceiling.timeout_seconds),
                        },
                        "runtime_egress_verified": self.runtime_egress_verified,
                        "runtime_isolation_verified": (self.runtime_isolation_verified),
                        "schema_version": self.schema_version,
                        "tenant_id": self.tenant_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class SandboxPolicyDecision:
    allowed: bool
    reasons: tuple[str, ...]
    policy_digest: str
    spec_digest: str
    evaluated_at: datetime

    def __post_init__(self) -> None:
        if not self.reasons or len(self.reasons) > 32:
            raise ValueError("sandbox policy decision requires bounded reasons")
        if self.evaluated_at.tzinfo is None:
            raise ValueError("sandbox policy decision time must be timezone-aware")


class SandboxPolicyEvaluator:
    def evaluate(
        self,
        context: TenantContext,
        request: SandboxRequest,
        policy: SandboxPolicy,
        usage: SandboxQuotaUsage,
        *,
        at: datetime,
    ) -> SandboxPolicyDecision:
        if at.tzinfo is None:
            raise ValueError("sandbox policy evaluation time must be timezone-aware")
        spec = request.spec
        reasons: list[str] = []
        if request.linkage.tenant_id != str(
            context.tenant_id
        ) or policy.tenant_id != str(context.tenant_id):
            reasons.append("cross_tenant_policy")
        if spec.image_digest not in policy.allowed_image_digests:
            reasons.append("image_digest_not_allowed")
        if spec.image_registry not in policy.allowed_registries:
            reasons.append("image_registry_not_allowed")
        if spec.command_family not in policy.allowed_command_families:
            reasons.append("command_family_not_allowed")
        if request.purpose not in policy.allowed_purposes:
            reasons.append("purpose_not_allowed")
        if request.risk > policy.maximum_risk:
            reasons.append("risk_threshold_exceeded")
        if spec.resources.timeout_seconds > policy.maximum_lifetime_seconds:
            reasons.append("maximum_lifetime_exceeded")
        _resource_reasons(spec.resources, policy.resource_ceiling, reasons)
        for mount in spec.mounts:
            prefixes = (
                policy.allowed_read_only_mount_prefixes
                if mount.access is MountAccess.READ_ONLY
                else policy.allowed_read_write_mount_prefixes
            )
            if not any(
                mount.target == prefix or mount.target.startswith(f"{prefix}/")
                for prefix in prefixes
            ):
                reasons.append("mount_not_allowed")
                break
        if any(
            output.media_type not in policy.allowed_output_media_types
            for output in spec.expected_outputs
        ):
            reasons.append("output_type_not_allowed")
        if not set(spec.egress_rules).issubset(policy.allowed_egress):
            reasons.append("egress_destination_not_allowed")
        if spec.egress_rules and not policy.runtime_egress_verified:
            reasons.append("egress_enforcement_unverified")
        if any(
            reference.uri not in policy.allowed_secret_references
            for reference in spec.secret_environment.values()
        ):
            reasons.append("secret_reference_not_allowed")
        if usage.runs_in_period >= policy.max_runs_per_period:
            reasons.append("period_run_limit_exceeded")
        if usage.active_runs >= policy.max_concurrent_runs:
            reasons.append("sandbox_concurrency_limit_exceeded")
        estimated_cpu = spec.resources.cpu_millis * spec.resources.timeout_seconds
        if (
            usage.cpu_millis_seconds + estimated_cpu
            > policy.max_cpu_millis_seconds_per_period
        ):
            reasons.append("sandbox_cpu_budget_exceeded")
        estimated_artifacts = sum(output.max_bytes for output in spec.expected_outputs)
        if (
            usage.artifact_bytes + estimated_artifacts
            > policy.max_artifact_bytes_per_period
        ):
            reasons.append("sandbox_artifact_budget_exceeded")
        if not policy.runtime_isolation_verified:
            reasons.append("runtime_isolation_unverified")
        if not policy.admission_controls_verified:
            reasons.append("admission_controls_unverified")
        return SandboxPolicyDecision(
            allowed=not reasons,
            reasons=tuple(reasons or ("exact_scope_allowed",)),
            policy_digest=policy.digest,
            spec_digest=spec.digest,
            evaluated_at=at,
        )


def _resource_reasons(
    requested: SandboxResources,
    ceiling: SandboxResources,
    reasons: list[str],
) -> None:
    checks = (
        ("cpu", requested.cpu_millis, ceiling.cpu_millis),
        ("memory", requested.memory_bytes, ceiling.memory_bytes),
        ("pids", requested.pids, ceiling.pids),
        (
            "ephemeral_storage",
            requested.ephemeral_storage_bytes,
            ceiling.ephemeral_storage_bytes,
        ),
        ("time", requested.timeout_seconds, ceiling.timeout_seconds),
        ("output", requested.max_output_bytes, ceiling.max_output_bytes),
        ("file_count", requested.max_files, ceiling.max_files),
        ("artifact", requested.max_artifact_bytes, ceiling.max_artifact_bytes),
    )
    reasons.extend(
        f"{name}_limit_exceeded" for name, value, maximum in checks if value > maximum
    )


__all__ = [
    "SandboxPolicy",
    "SandboxPolicyDecision",
    "SandboxPolicyEvaluator",
    "SandboxQuotaUsage",
]
