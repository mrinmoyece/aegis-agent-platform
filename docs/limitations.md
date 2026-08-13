# Limitations and production gaps

## Current Layer 1 implementation

- No event-store adapter, projection, migration, or durable orchestration
  exists beyond the identity/tenancy/governance schema described below.
- No queue backend, renewal implementation, fencing enforcement, retry, or
  reconciliation exists.
- Dynatrace and GitHub packages are interfaces, not working connectors.
- Kubernetes, runbook, incident-management, and remediation adapters do not
  exist.
- Agent roles, artifacts, plans, budgets, and ledger are types only. There is no
  scheduler, model invocation, deterministic aggregation, critic enforcement,
  approval workflow, or specialist execution.
- Sandbox, tools, memory, evaluation, and observability packages are
  boundaries only.
- Three-tier memory is a documented design only. No pgvector retrieval,
  provenance pipeline, PII handling, retention/deletion, or context compaction
  is implemented.
- No MCP or A2A endpoint exists. Neither protocol currently provides discovery,
  tool access, external task exchange, streaming, cancellation, or status.
- CI scans and builds a baseline but does not yet emit an SBOM, provenance,
  signature, release artifact, or deployment.

## Current Layer 2 implementation (identity, tenancy, and governance)

- JWT signature/issuer/audience/expiry/algorithm verification, deny-by-default
  tenant authorization, tenant policy/quota evaluation, redacted append-only
  audit events, and a secret-reference abstraction are implemented and proven
  by a committed automated test suite (`tests/test_identity_security.py`,
  `tests/test_policy_security.py`, `tests/test_audit_secrets.py`,
  `tests/test_migrations.py`, and cross-tenant/authentication cases in
  `tests/test_api.py`) covering cross-tenant denial, malformed/expired/
  wrong-issuer/wrong-audience/unsupported-algorithm tokens, and expired/revoked
  role bindings. That suite runs against deterministic fixtures and a mocked
  JWKS transport, not a live database or identity provider — proving the same
  guarantees against a running Postgres and Keycloak instance is the remaining
  Layer 2 acceptance-gate work in `roadmap.md`.
- `RemoteJwksProvider` can call a real Keycloak-compatible JWKS endpoint and
  refreshes its cache after a bounded TTL, but
  live network reachability, realm population, and key rotation against an
  actual running identity provider are deployment concerns, not something the
  fast local checks exercise. The imported local Keycloak realm has no users.
- The control plane's default identity, tenant, policy, and audit repositories
  are deterministic in-memory adapters. `migrations/0001_identity_governance.sql`
  defines the durable Postgres schema (tenants, identities, role bindings,
  tenant policies, tenant quotas, an append-only audit table) with row-level
  security, and its constraints are asserted statically by
  `tests/test_migrations.py`, but no adapter connects the in-memory ports to a
  running Postgres yet — state does not survive a process restart.
- `PolicyEvaluator` deterministically evaluates quota *limits* against a
  caller-supplied `QuotaUsage` snapshot; there is no authoritative usage
  accounting yet, since that requires the durable runtime planned for Layers
  3–4.
- Secrets are handled only by `EnvironmentSecretProvider`, a local-development
  provider requiring an `AEGIS_SECRET_` prefix. There is no vault-backed
  broker, rotation, or centralized access audit. Example Compose credentials
  remain deliberately local-only.
- Keycloak, PostgreSQL, Redis, Collector, Prometheus, and Grafana configuration
  is for local learning. It is not hardened, highly available, backed up, or
  suitable for real tenant data.

## Claims deliberately not made

Aegis does not currently diagnose checkout failures, protect production data,
guarantee exactly-once effects, provide a secure code sandbox, satisfy a
compliance framework, meet an SLO, or support multi-region recovery. Passing a
JWT verification and authorization check locally does not mean tenant
isolation, quota enforcement, or audit durability have been proven against a
real deployment.

## Closing gaps

`roadmap.md` defines the acceptance gate for each layer and
`enterprise-checklist.md` tracks capability status. A gap moves to Implemented
only with code, tests, and operational evidence linked from its curriculum
document. `enterprise-implementation-plan.md` specifies the implementation
sequence, data and security contracts, failure tests, SLO hypotheses, deployment
evidence, and production-readiness review needed to close every gap.
