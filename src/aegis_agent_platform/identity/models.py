"""Immutable provider-neutral identity and tenancy types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


def _validate_identifier(value: str, name: str) -> None:
    if not value or value != value.strip() or len(value) > 128:
        raise ValueError(f"{name} must be a non-empty normalized identifier")


@dataclass(frozen=True, slots=True, order=True)
class TenantId:
    """Stable tenant identifier, never inferred from mutable resource data."""

    value: str

    def __post_init__(self) -> None:
        _validate_identifier(self.value, "tenant_id")

    def __str__(self) -> str:
        return self.value


PLATFORM_TENANT_ID = TenantId("platform")


@dataclass(frozen=True, slots=True, order=True)
class UserId:
    """Stable internal user identifier."""

    value: str

    def __post_init__(self) -> None:
        _validate_identifier(self.value, "user_id")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class ServiceIdentity:
    """Stable workload identity established by the identity directory."""

    value: str

    def __post_init__(self) -> None:
        _validate_identifier(self.value, "service_identity")

    def __str__(self) -> str:
        return self.value


class PrincipalKind(StrEnum):
    """Kinds of authenticated subjects accepted by the control plane."""

    USER = "user"
    SERVICE = "service"


class Role(StrEnum):
    """Fixed roles whose permissions are defined centrally."""

    VIEWER = "viewer"
    INVESTIGATOR = "investigator"
    APPROVER = "approver"
    OPERATOR = "operator"
    TENANT_ADMIN = "tenant_admin"
    PLATFORM_ADMIN = "platform_admin"


class Permission(StrEnum):
    """Fine-grained actions used by deny-by-default authorization."""

    TENANT_READ = "tenant:read"
    RESOURCE_READ = "resource:read"
    INVESTIGATION_CREATE = "investigation:create"
    APPROVAL_DECIDE = "approval:decide"
    OPERATION_PROPOSE = "operation:propose"
    POLICY_READ = "policy:read"
    POLICY_MANAGE = "policy:manage"
    QUOTA_MANAGE = "quota:manage"
    AUDIT_READ = "audit:read"
    IDENTITY_MANAGE = "identity:manage"
    ROLE_BINDING_MANAGE = "role_binding:manage"
    SECRET_REFERENCE_MANAGE = "secret_reference:manage"  # noqa: S105
    PLATFORM_TENANT_CREATE = "platform:tenant:create"
    PLATFORM_AUDIT_READ = "platform:audit:read"


@dataclass(frozen=True, slots=True)
class RoleBinding:
    """Server-side role assignment with explicit lifetime and tenant scope."""

    tenant_id: TenantId
    role: Role
    assigned_by: UserId | ServiceIdentity
    assigned_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.assigned_at.tzinfo is None:
            raise ValueError("assigned_at must be timezone-aware")
        if (
            self.role is Role.PLATFORM_ADMIN
            and self.tenant_id != PLATFORM_TENANT_ID
        ):
            raise ValueError("platform_admin bindings require the platform tenant")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise ValueError("expires_at must be timezone-aware")
            if self.expires_at <= self.assigned_at:
                raise ValueError("expires_at must follow assigned_at")
        if self.revoked_at is not None and self.revoked_at.tzinfo is None:
            raise ValueError("revoked_at must be timezone-aware")

    def is_active(self, at: datetime) -> bool:
        """Return whether the binding is active at a caller-supplied time."""
        if at.tzinfo is None:
            raise ValueError("authorization time must be timezone-aware")
        return (
            self.assigned_at <= at
            and (self.expires_at is None or at < self.expires_at)
            and (self.revoked_at is None or at < self.revoked_at)
        )


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated subject resolved against authoritative identity records."""

    subject: str
    issuer: str
    tenant_id: TenantId
    kind: PrincipalKind
    role_bindings: tuple[RoleBinding, ...]
    user_id: UserId | None = None
    service_identity: ServiceIdentity | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.subject, "subject")
        if not self.issuer:
            raise ValueError("issuer is required")
        has_user = self.user_id is not None
        has_service = self.service_identity is not None
        if has_user == has_service:
            raise ValueError("principal must have exactly one internal identity")
        if self.kind is PrincipalKind.USER and not has_user:
            raise ValueError("user principal requires user_id")
        if self.kind is PrincipalKind.SERVICE and not has_service:
            raise ValueError("service principal requires service_identity")
        if any(binding.tenant_id != self.tenant_id for binding in self.role_bindings):
            raise ValueError("role bindings must match the principal tenant")

    @property
    def actor_id(self) -> str:
        """Return the internal actor identifier for audit records."""
        identity = self.user_id or self.service_identity
        if identity is None:  # guarded by __post_init__
            raise RuntimeError("principal has no internal identity")
        return str(identity)
