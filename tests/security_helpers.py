"""Shared deterministic-shape security fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis_agent_platform.identity import (
    AuthenticationService,
    IdentityRecord,
    InMemoryIdentityDirectory,
    JwtValidationConfig,
    JwtVerifier,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    StaticJwksProvider,
    TenantId,
    UserId,
    VerificationKey,
)
from aegis_agent_platform.policy import QuotaLimits, RiskLevel, TenantPolicy

ISSUER = "https://identity.example/realms/aegis"
AUDIENCE = "aegis-control-plane"
KEY_ID = "test-key-1"
TENANT_ID = TenantId("tenant-alpha")
USER_ID = UserId("user-alice")


@dataclass(frozen=True, slots=True)
class SigningFixture:
    """Ephemeral RSA fixture with stable claims and identifiers."""

    private_key: rsa.RSAPrivateKey
    public_pem: bytes


def signing_fixture() -> SigningFixture:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return SigningFixture(private_key=private_key, public_pem=public_pem)


def binding(
    role: Role = Role.VIEWER,
    *,
    tenant_id: TenantId = TENANT_ID,
    assigned_at: datetime | None = None,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> RoleBinding:
    return RoleBinding(
        tenant_id=tenant_id,
        role=role,
        assigned_by=UserId("admin"),
        assigned_at=assigned_at or datetime.now(UTC) - timedelta(hours=1),
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


def principal(
    role_bindings: tuple[RoleBinding, ...] | None = None,
    *,
    tenant_id: TenantId = TENANT_ID,
) -> Principal:
    return Principal(
        subject="oidc-alice",
        issuer=ISSUER,
        tenant_id=tenant_id,
        kind=PrincipalKind.USER,
        role_bindings=role_bindings or (binding(tenant_id=tenant_id),),
        user_id=USER_ID,
    )


def identity_record(
    role_bindings: tuple[RoleBinding, ...] | None = None,
    *,
    enabled: bool = True,
) -> IdentityRecord:
    return IdentityRecord(
        issuer=ISSUER,
        subject="oidc-alice",
        tenant_id=TENANT_ID,
        kind=PrincipalKind.USER,
        role_bindings=role_bindings or (binding(),),
        enabled=enabled,
        user_id=USER_ID,
    )


def authentication_service(
    signing: SigningFixture,
    *,
    records: tuple[IdentityRecord, ...] | None = None,
    clock_skew: timedelta = timedelta(seconds=30),
) -> AuthenticationService:
    verifier = JwtVerifier(
        JwtValidationConfig(
            issuer=ISSUER,
            audience=AUDIENCE,
            clock_skew=clock_skew,
        ),
        StaticJwksProvider((VerificationKey(KEY_ID, "RS256", signing.public_pem),)),
    )
    return AuthenticationService(
        verifier,
        InMemoryIdentityDirectory(records or (identity_record(),)),
    )


def token(
    signing: SigningFixture,
    *,
    issuer: str = ISSUER,
    audience: str | list[str] = AUDIENCE,
    subject: str = "oidc-alice",
    expires_at: datetime | None = None,
    issued_at: datetime | None = None,
    tenant_id: str | None = TENANT_ID.value,
    key_id: str = KEY_ID,
    private_key: rsa.RSAPrivateKey | None = None,
    extra_claims: dict[str, object] | None = None,
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": expires_at or now + timedelta(minutes=5),
        "iat": issued_at or now,
    }
    if tenant_id is not None:
        claims["tenant_id"] = tenant_id
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(
        claims,
        private_key or signing.private_key,
        algorithm="RS256",
        headers={"kid": key_id},
    )


def tenant_policy() -> TenantPolicy:
    return TenantPolicy(
        tenant_id=TENANT_ID,
        version="policy-1",
        allowed_models=frozenset({"model-safe"}),
        allowed_tools=frozenset({"search", "remediate"}),
        allowed_connectors=frozenset({"dynatrace"}),
        allowed_environments=frozenset({"production"}),
        max_risk=RiskLevel.HIGH,
        approval_from_risk=RiskLevel.HIGH,
        tools_requiring_approval=frozenset({"remediate"}),
        approver_roles=frozenset({Role.APPROVER}),
        quotas=QuotaLimits(
            max_run_tokens=1_000,
            max_run_cost_usd=Decimal("2.00"),
            max_tenant_tokens_per_period=10_000,
            max_tenant_cost_usd_per_period=Decimal("20.00"),
            max_concurrent_runs=3,
        ),
    )
