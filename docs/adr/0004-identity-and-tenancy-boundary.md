# ADR 0004: Separate identity from tenant authorization

- Status: Accepted
- Date: 2026-08-13

## Context

An authenticated subject may belong to multiple tenants with different roles.
Treating an identity token as sufficient tenant authority enables confused
deputy and cross-tenant failures.

## Decision

OIDC authentication establishes a principal; a separate authorization step
binds that principal, an explicit tenant, an action, and a resource. Tenant
context is carried through storage, queues, policy, telemetry, and audit.

Concretely: `JwtVerifier` performs standards-correct local validation of
signature, algorithm, issuer, audience, and expiry against a `JwksProvider`
addressed by `kid`. Configuration (issuer, JWKS URL, audience) is
Keycloak-compatible but provider-neutral — any OIDC-conformant issuer can be
substituted without code changes. Verified claims never become authority by
themselves: `AuthenticationService` resolves them against an authoritative
local `IdentityDirectory`, which is the only source of a principal's tenant and
role bindings. `AuthorizationService` then denies cross-tenant access before
evaluating any permission, using only role bindings active at the current
time. Both the JWKS lookup and the identity directory are ports: a
`StaticJwksProvider`/`InMemoryIdentityDirectory` pair gives deterministic,
network-free fixtures for tests and local development, while
`RemoteJwksProvider` is the Keycloak-compatible adapter for a live realm.
Whether a live Keycloak instance is reachable is a deployment concern, not a
property of the verification logic itself.

## Consequences

No data or work API may infer a tenant from mutable content or use a global
default; `TenantContext` and every tenant-scoped repository port enforce this.
A committed automated test suite (`tests/test_identity_security.py`,
`tests/test_policy_security.py`, `tests/test_audit_secrets.py`, and
cross-tenant/authentication cases in `tests/test_api.py`) proves cross-tenant
denial, malformed/expired/wrong-issuer/wrong-audience/unsupported-algorithm
tokens, and expired/revoked role bindings against these in-memory ports. The
Postgres migration (`migrations/0001_identity_governance.sql`) already adds
row-level security forcing `tenant_id` equality on every tenant-scoped table,
and `tests/test_migrations.py` asserts that schema statically, but the durable
adapter wiring those tables to the in-memory ports above does not exist yet,
and the row-level-security policies have not been exercised against a running
Postgres instance — that remains outstanding before the Layer 2 acceptance
gate is fully met. Live-network Keycloak behavior is out of scope for the
fast local checks (`RemoteJwksProvider` is tested against a mocked HTTPS
transport) and must be validated separately per deployment.
