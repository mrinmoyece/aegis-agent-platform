# Identity, tenancy, and governance tutorial

This is a hands-on walkthrough of the Layer 2 vertical slice: how a bearer
token becomes a trusted, tenant-scoped `Principal`; how that principal is
authorized against a fixed role/permission model; how a tenant's governance
policy and quotas are evaluated; and how every step leaves a redacted,
append-only audit trail. Every code path below is real and importable today —
none of it is aspirational. Where a step is genuinely still planned, this
document says so explicitly.

## Prerequisites

Follow [Getting started](getting-started.md) first to install dependencies and
run `make check`. This tutorial only needs the Python environment; it does not
require Docker Compose or a running Keycloak instance, because authentication
here is exercised against **deterministic fixtures** — a locally generated RSA
key pair and an in-memory identity directory — not a live identity provider.

## 1. Why authentication and tenant authorization are separate steps

`AGENTS.md` and ADR 0004 require that authentication (proving *who* is
calling) never be treated as sufficient authority for *what tenant, what
action*. Two packages enforce this split:

- `aegis_agent_platform.identity` — verifies a JWT and resolves it to an
  authoritative internal `Principal` (subject, issuer, tenant, roles).
- `aegis_agent_platform.identity.authorization` — separately decides, given a
  principal, a target tenant, and a requested permission, whether the action
  is allowed.

A verified token proves an issuer trusts a subject. It does **not** by itself
prove which tenant that subject may act in — that binding lives in the local
`IdentityDirectory`, not in whatever the token happens to claim.

## 2. Build a deterministic JWT fixture and verify it

No network call and no running Keycloak are needed to exercise standards-correct
verification. `StaticJwksProvider` and a locally generated RSA key pair stand
in for a real JWKS endpoint:

```python
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis_agent_platform.identity import (
    JwtValidationConfig, JwtVerifier, StaticJwksProvider, VerificationKey,
)

# A real deployment points RemoteJwksProvider at a Keycloak realm's JWKS URL
# (AEGIS_OIDC_JWKS_URL); tests and local development use this fixture instead.
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_pem = key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
private_pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

now = datetime.now(UTC)
token = jwt.encode(
    {
        "iss": "https://idp.example/realms/aegis",
        "sub": "user-1",
        "aud": "aegis-control-plane",
        "exp": now + timedelta(minutes=5),
        "iat": now,
        "tenant_id": "acme",
    },
    private_pem,
    algorithm="RS256",
    headers={"kid": "k1"},
)

jwks = StaticJwksProvider(
    (VerificationKey(key_id="k1", algorithm="RS256", pem=public_pem),)
)
config = JwtValidationConfig(
    issuer="https://idp.example/realms/aegis", audience="aegis-control-plane"
)
verifier = JwtVerifier(config, jwks)
claims = verifier.verify(token)
print(claims.subject, claims.asserted_tenant_id)  # user-1 acme
```

`JwtVerifier.verify` checks the signing algorithm against an allowlist, looks
up the key by `kid`, and validates signature, `iss`, `aud`, and `exp`/`iat`
with a bounded clock-skew leeway. Any failure raises a classified
`AuthenticationError` (`AuthenticationErrorCode`) whose `repr` never includes
token material — try mutating the audience, issuer, or expiry above and
observe which error code comes back.

## 3. Resolve verified claims to an authoritative principal

A verified token is not yet authority. `AuthenticationService` resolves the
claims against a local, authoritative `IdentityDirectory` — it never trusts a
client-asserted tenant or role:

```python
from aegis_agent_platform.identity import (
    AuthenticationService, IdentityRecord, InMemoryIdentityDirectory,
    PrincipalKind, Role, RoleBinding, TenantId, UserId,
)

tenant = TenantId("acme")
directory = InMemoryIdentityDirectory((
    IdentityRecord(
        issuer="https://idp.example/realms/aegis",
        subject="user-1",
        tenant_id=tenant,
        kind=PrincipalKind.USER,
        role_bindings=(
            RoleBinding(
                tenant_id=tenant,
                role=Role.INVESTIGATOR,
                assigned_by=UserId("admin"),
                assigned_at=now - timedelta(days=1),
            ),
        ),
        user_id=UserId("user-1"),
    ),
))

authentication = AuthenticationService(verifier, directory)
principal = authentication.authenticate(f"Bearer {token}")
print(principal.tenant_id, [b.role.value for b in principal.role_bindings])
```

If the token asserts a `tenant_id` claim that disagrees with the identity
record, `AuthenticationService` raises `TENANT_MISMATCH` rather than trusting
the token's claim — the directory is authoritative, not the bearer.

## 4. Deny-by-default authorization

`AuthorizationService.decide` denies cross-tenant access *before* it even
looks at permissions, then checks only role bindings active at a given
instant against a fixed permission table:

```python
from aegis_agent_platform.identity import AuthorizationService, Permission

authorization = AuthorizationService()

decision = authorization.decide(
    principal=principal, tenant_id=tenant,
    permission=Permission.INVESTIGATION_CREATE, at=datetime.now(UTC),
)
print(decision.allowed, decision.reason)  # True role_permission_granted

cross_tenant = authorization.decide(
    principal=principal, tenant_id=TenantId("other-tenant"),
    permission=Permission.INVESTIGATION_CREATE, at=datetime.now(UTC),
)
print(cross_tenant.allowed, cross_tenant.reason)  # False cross_tenant_access_denied
```

There are six fixed roles (`viewer`, `investigator`, `approver`, `operator`,
`tenant_admin`, `platform_admin`), each mapped to a fixed permission set in
`ROLE_PERMISSIONS`. Adding a permission to a role is a reviewed code change,
not runtime configuration — this is deliberate, matching the fixed-role
philosophy used for incident specialists elsewhere in the platform.

## 5. Tenant governance: policy, risk, and quotas

`policy.PolicyEvaluator` is a pure function: given a tenant's `TenantPolicy`
(allowlists, risk ceiling, approval threshold, quotas) and a proposed
`PolicyRequest`, plus a caller-supplied `QuotaUsage` snapshot, it returns a
deterministic `PolicyDecision`:

```python
from decimal import Decimal

from aegis_agent_platform.policy import (
    PolicyEvaluator, PolicyRequest, QuotaLimits, QuotaUsage, RiskLevel,
    TenantPolicy,
)

policy = TenantPolicy(
    tenant_id=tenant, version="v1",
    allowed_models=frozenset({"gpt"}), allowed_tools=frozenset({"rollback"}),
    allowed_connectors=frozenset({"dynatrace"}), allowed_environments=frozenset({"prod"}),
    max_risk=RiskLevel.HIGH, approval_from_risk=RiskLevel.MEDIUM,
    tools_requiring_approval=frozenset({"rollback"}),
    approver_roles=frozenset({Role.APPROVER}),
    quotas=QuotaLimits(
        max_run_tokens=1000, max_run_cost_usd=Decimal("5"),
        max_tenant_tokens_per_period=100_000,
        max_tenant_cost_usd_per_period=Decimal("500"),
        max_concurrent_runs=5,
    ),
)

request = PolicyRequest(
    tenant_id=tenant, model="gpt", tool="rollback", connector="dynatrace",
    environment="prod", risk=RiskLevel.HIGH,
    estimated_tokens=200, estimated_cost_usd=Decimal("1"),
)
usage = QuotaUsage(tenant_tokens_used=0, tenant_cost_usd=Decimal("0"), active_runs=0)

decision = PolicyEvaluator().evaluate(policy, request, usage)
print(decision.decision, decision.reasons, decision.required_approver_roles)
# require_approval ('approval_required',) (<Role.APPROVER: 'approver'>,)
```

Change `request.tool` to something outside `allowed_tools`, or push
`usage.tenant_tokens_used` past `max_tenant_tokens_per_period`, and the
decision becomes `Decision.DENY` with an explicit reason — try both. Note what
this evaluator does **not** do: it does not track usage itself. A real
deployment must supply `QuotaUsage` from an authoritative counter, which is
durable-runtime work planned for later layers, not something this pure
function invents.

## 6. Audit: redacted, additive, append-only

Every authentication and authorization outcome above should leave a durable,
tenant-scoped trail. `audit.AuditEvent` redacts sensitive fields unconditionally
in its constructor — you cannot opt out:

```python
from uuid import uuid4

from aegis_agent_platform.audit import (
    AuditEvent, AuditEventType, AuditOutcome, InMemoryAuditStore,
)
from aegis_agent_platform.tenancy import TenantContext

store = InMemoryAuditStore()
event = AuditEvent(
    event_id=uuid4(), tenant_id=tenant,
    event_type=AuditEventType.AUTHORIZATION_DECISION,
    occurred_at=datetime.now(UTC), outcome=AuditOutcome.SUCCESS,
    actor_id=principal.actor_id, action="investigation:create",
    resource="tenant/acme/investigation", correlation_id=uuid4(),
    details={"authorization_header": "Bearer sensitive-token-value"},
)
store.append(TenantContext(tenant), event)
print(event.details)  # {'authorization_header': '[REDACTED]'}
```

`event_type` values look like `security.authorization_decision.v1` — the
trailing version means a future schema change adds a new event type instead of
silently changing what an existing one means, matching the platform-wide
additive-event invariant. `InMemoryAuditStore.append` also rejects an event
whose `tenant_id` disagrees with the trusted `TenantContext` it was given.

## 7. Secrets: references, not material

Tools and adapters should never carry raw secret bytes through general
application code. A `SecretReference` is safe to log or store; only an
explicit `.reveal()` call at the one adapter boundary that needs bytes exposes
them:

```python
from aegis_agent_platform.secrets_boundary import (
    EnvironmentSecretProvider, SecretReference,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.tenancy import TenantContext

provider = EnvironmentSecretProvider({"AEGIS_SECRET_DYNATRACE_TOKEN": "local-only-example"})
tenant_id = TenantId("tenant-alpha")
context = TenantContext(tenant_id)
reference = SecretReference(
    tenant_id=tenant_id,
    provider="env",
    name="AEGIS_SECRET_DYNATRACE_TOKEN",
)
value = provider.resolve(context, reference)
print(value)              # [REDACTED]
print(repr(value))        # SecretValue([REDACTED])
print(value.reveal())     # b'local-only-example'
```

`EnvironmentSecretProvider` deliberately requires the `AEGIS_SECRET_` prefix so
a typo cannot accidentally resolve an unrelated environment variable. This is a
local-development provider; every resolution also requires a matching trusted
`TenantContext`. It is not a secret broker — there is no rotation,
versioning, or centralized access audit yet; see
[Limitations](limitations.md).

## 8. The whole slice behind one API

`control_plane.api.ControlPlaneApp` wires every piece above behind a small
route set. `/healthz` and `/health/live` (liveness) and `/readyz` and
`/health/ready` (configuration readiness) stay unauthenticated, matching Layer
1. Everything under `/v1/` requires a valid bearer token:

| Route | Requires | Returns |
| --- | --- | --- |
| `/v1/me` | valid bearer token | the caller's tenant and active roles |
| `/v1/tenants/{tenant_id}` | `tenant:read` in that tenant | the tenant record |
| `/v1/tenants/{tenant_id}/policy` | `policy:read` in that tenant | the tenant's governance policy and quotas |

Every authentication attempt and every authorization decision is recorded as
an audit event before a response is returned — a 401 or 403 is not a silent
failure. Construct a `ControlPlaneApp` with the pieces above (or its
in-memory defaults) and drive it directly, the same way
`tests/test_api.py` drives the Layer 1 health surface, to see this end to end.

## What this tutorial does not prove

This walkthrough exercises the identity/tenancy/governance/audit/secrets code
paths by hand with deterministic fixtures. It intentionally does not
demonstrate, and you should not assume from it, any of the following:

- A live round trip against a running Keycloak realm. `RemoteJwksProvider`
  exists and is Keycloak-compatible, but whether a real realm is reachable,
  populated, and correctly rotated is a deployment concern validated
  separately — see `getting-started.md` and `limitations.md`.
- This walkthrough uses in-memory stores. Layer 3 separately provides durable
  PostgreSQL repositories and live forced-RLS tests; see `durable-execution.md`.
- Quota *enforcement* against real usage. `QuotaUsage` was supplied by hand
  here; an authoritative usage source is durable-runtime work for later
  layers.
- A live Keycloak proof. A committed automated test suite
  (`tests/test_identity_security.py`, `tests/test_policy_security.py`,
  `tests/test_audit_secrets.py`, `tests/test_migrations.py`) does prove
  cross-tenant denial, malformed/expired/rotated-key tokens, and revoked-role
  handling — but against deterministic fixtures and a mocked JWKS transport,
  not a running Postgres or Keycloak instance. That live-infrastructure proof
  is the outstanding Layer 2 acceptance-gate work tracked in `roadmap.md`.

## Where to go next

- `architecture.md` — "Identity, tenancy, and governance boundary" for the
  system-level view and sequence diagram.
- `threat-model.md` — the Layer 2 residual-risk section for exactly what is
  and is not proven.
- `adr/0004-identity-and-tenancy-boundary.md` and
  `adr/0009-tenant-governance-audit-and-secrets.md` — the binding decisions
  and their consequences.
- `interview-question-bank.md` — the identity/tenancy deep dive for how to
  defend these tradeoffs under follow-up questions.
