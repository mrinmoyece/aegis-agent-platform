"""Pure deny-by-default authorization policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

from aegis_agent_platform.identity.models import Permission, Principal, Role, TenantId

ROLE_PERMISSIONS: MappingProxyType[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.VIEWER: frozenset(
            {
                Permission.TENANT_READ,
                Permission.RESOURCE_READ,
                Permission.POLICY_READ,
                Permission.MODEL_READ,
            }
        ),
        Role.INVESTIGATOR: frozenset(
            {
                Permission.TENANT_READ,
                Permission.RESOURCE_READ,
                Permission.POLICY_READ,
                Permission.INVESTIGATION_CREATE,
                Permission.MODEL_READ,
                Permission.MODEL_DIAGNOSTIC,
            }
        ),
        Role.APPROVER: frozenset(
            {
                Permission.TENANT_READ,
                Permission.RESOURCE_READ,
                Permission.POLICY_READ,
                Permission.APPROVAL_DECIDE,
                Permission.MODEL_READ,
            }
        ),
        Role.OPERATOR: frozenset(
            {
                Permission.TENANT_READ,
                Permission.RESOURCE_READ,
                Permission.POLICY_READ,
                Permission.OPERATION_PROPOSE,
                Permission.QUEUE_READ,
                Permission.WORK_CANCEL,
                Permission.MODEL_READ,
                Permission.MODEL_DIAGNOSTIC,
            }
        ),
        Role.TENANT_ADMIN: frozenset(
            {
                Permission.TENANT_READ,
                Permission.RESOURCE_READ,
                Permission.POLICY_READ,
                Permission.POLICY_MANAGE,
                Permission.QUOTA_MANAGE,
                Permission.AUDIT_READ,
                Permission.IDENTITY_MANAGE,
                Permission.ROLE_BINDING_MANAGE,
                Permission.SECRET_REFERENCE_MANAGE,
                Permission.QUEUE_READ,
                Permission.WORK_CANCEL,
                Permission.DLQ_REQUEUE,
                Permission.WORK_RECONCILE,
                Permission.MODEL_READ,
                Permission.MODEL_DIAGNOSTIC,
            }
        ),
        Role.PLATFORM_ADMIN: frozenset(
            {
                Permission.TENANT_READ,
                Permission.PLATFORM_TENANT_CREATE,
                Permission.PLATFORM_AUDIT_READ,
            }
        ),
    }
)


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Complete decision suitable for additive audit recording."""

    allowed: bool
    reason: str
    tenant_id: TenantId
    permission: str
    active_roles: tuple[Role, ...]


class AuthorizationService:
    """Evaluate tenant ownership and active server-side role bindings."""

    def decide(
        self,
        *,
        principal: Principal,
        tenant_id: TenantId,
        permission: Permission | str,
        at: datetime,
    ) -> AuthorizationDecision:
        """Deny cross-tenant and unrecognized actions before checking roles."""
        permission_name = (
            permission.value if isinstance(permission, Permission) else permission
        )
        if principal.tenant_id != tenant_id:
            return AuthorizationDecision(
                allowed=False,
                reason="cross_tenant_access_denied",
                tenant_id=tenant_id,
                permission=permission_name,
                active_roles=(),
            )
        if not isinstance(permission, Permission):
            return AuthorizationDecision(
                allowed=False,
                reason="unknown_permission",
                tenant_id=tenant_id,
                permission=permission_name,
                active_roles=(),
            )
        active_roles = tuple(
            sorted(
                {
                    binding.role
                    for binding in principal.role_bindings
                    if binding.tenant_id == tenant_id and binding.is_active(at)
                },
                key=lambda role: role.value,
            )
        )
        granted = any(
            permission in ROLE_PERMISSIONS.get(role, frozenset())
            for role in active_roles
        )
        return AuthorizationDecision(
            allowed=granted,
            reason="role_permission_granted" if granted else "permission_not_granted",
            tenant_id=tenant_id,
            permission=permission.value,
            active_roles=active_roles,
        )
