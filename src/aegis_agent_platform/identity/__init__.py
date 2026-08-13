"""Identity, authentication, and authorization boundaries."""

from aegis_agent_platform.identity.authentication import (
    AuthenticationError,
    AuthenticationErrorCode,
    AuthenticationService,
    IdentityDirectory,
    IdentityRecord,
    InMemoryIdentityDirectory,
    JwtValidationConfig,
    JwtVerifier,
    RemoteJwksProvider,
    StaticJwksProvider,
    VerificationKey,
    VerifiedClaims,
)
from aegis_agent_platform.identity.authorization import (
    AuthorizationDecision,
    AuthorizationService,
)
from aegis_agent_platform.identity.models import (
    PLATFORM_TENANT_ID,
    Permission,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    ServiceIdentity,
    TenantId,
    UserId,
)

__all__ = [
    "PLATFORM_TENANT_ID",
    "AuthenticationError",
    "AuthenticationErrorCode",
    "AuthenticationService",
    "AuthorizationDecision",
    "AuthorizationService",
    "IdentityDirectory",
    "IdentityRecord",
    "InMemoryIdentityDirectory",
    "JwtValidationConfig",
    "JwtVerifier",
    "Permission",
    "Principal",
    "PrincipalKind",
    "RemoteJwksProvider",
    "Role",
    "RoleBinding",
    "ServiceIdentity",
    "StaticJwksProvider",
    "TenantId",
    "UserId",
    "VerificationKey",
    "VerifiedClaims",
]
