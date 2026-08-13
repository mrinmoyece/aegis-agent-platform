# Limitations and production gaps

## Remaining platform gaps

- Dynatrace and GitHub packages are interfaces, not working connectors.
- Kubernetes, runbook, incident-management, and remediation adapters do not
  exist.
- Agent roles, artifacts, plans, budgets, and ledger are types only. There is no
  scheduler, model invocation, deterministic aggregation, critic enforcement,
  approval workflow, or specialist execution.
- Sandbox, tools, memory, and evaluation packages are boundaries only.
- Runtime spans and bounded metric instruments exist, but no production
  collector dashboards, alert rules, or SLO evidence are claimed.
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
  guarantees against a running Keycloak instance remains deployment work.
- `RemoteJwksProvider` can call a real Keycloak-compatible JWKS endpoint and
  refreshes its cache after a bounded TTL, but
  live network reachability, realm population, and key rotation against an
  actual running identity provider are deployment concerns, not something the
  fast local checks exercise. The imported local Keycloak realm has no users.
- The module-level demo application defaults to deterministic in-memory
  repositories and fail-closed authentication. Production PostgreSQL
  repositories exist, but deployment composition must inject connections and
  authentication explicitly.
- `PolicyEvaluator` deterministically evaluates quota *limits* against a
  caller-supplied `QuotaUsage` snapshot; there is no authoritative usage
  accounting emission yet. Layer 3 provides the rebuildable usage projection;
  later runtime events must populate it.
- Secrets are handled only by `EnvironmentSecretProvider`, a local-development
  provider requiring an `AEGIS_SECRET_` prefix. There is no vault-backed
  broker, rotation, or centralized access audit. Example Compose credentials
  remain deliberately local-only.
- Keycloak, PostgreSQL, Redis, Collector, Prometheus, and Grafana configuration
  is for local learning. It is not hardened, highly available, backed up, or
  suitable for real tenant data.

## Current Layer 3 implementation (durable persistence and eventing)

- PostgreSQL event append, expected-version concurrency, inbox/outbox,
  projections, replay, durable Layer 2 repositories, forced RLS, immutable
  event/audit rows, and authorized ledger inspection are implemented and tested.
- The fast 90% coverage suite excludes live-database adapter lines; a separate
  six-test PostgreSQL 16 suite executes migrations and those adapters in CI.
- Global positions provide ordering, not a no-gap promise after rolled-back
  identity allocations. Aggregate sequence is gapless.
- The outbox remains delivery state only. Layer 4 publishes it to Redis, but
  model/provider calls, live connectors, agent execution, approval, and external
  effect adapters do not exist.
- Exactly-once effects are not claimed. Intent/result contracts and idempotency
  keys exist, but later adapters must implement idempotency or reconciliation.
- Projections cover generic run status, artifacts, approvals, usage, and tenant
  listings. They do not imply the incident-specific state machine exists.
- Backup/restore, retention, partitioning, high availability, maintenance-role
  brokering, and migration downgrade automation are not implemented. Security
  migrations are forward-only; correction uses additive migrations.

## Current Layer 4 implementation (distributed work)

- `work.*.v1` events, deterministic transport envelopes, one shared Redis
  Stream/consumer group, explicit acknowledgement, pending inspection/reclaim,
  poison rejection, and deterministic inbox message identity are implemented.
- `work_items`, `work_leases`, `work_dead_letters`, and durable two-actor
  `work_requeue_approvals` are tenant-RLS
  projections. PostgreSQL CAS claims issue renewable UUID tokens plus monotonic
  generations; `append_fenced` rejects stale, released, or expired workers.
- The supervisor bounds global and per-tenant concurrency, schedules tenants
  round-robin, drains gracefully, polls cooperative cancellation, contains
  handler exceptions, enforces timeout, and records classified retry or DLQ
  outcomes before acknowledgement.
- Live tests prove two-worker claim exclusion, renewal/reclaim, stale fencing,
  duplicate delivery/inbox behavior, ack ordering, poison handling, and RLS.
- A shared stream bounds Redis key/group cardinality and preserves global
  transport order. It does not provide strict tenant fairness across independent
  worker processes; the in-process scheduler is round-robin.
- Redis loss can delay delivery but cannot erase work truth. Reconciliation
  releases expired PostgreSQL leases; a deployment must continuously run both
  publisher and reconciliation loops. There is no tested Redis Sentinel/Cluster,
  PostgreSQL failover, multi-region ordering, or HA claim.
- No external side effect is implemented. The intent/result protocol represents
  the crash window, but downstream adapters must use target idempotency keys or
  reconcile target state; Aegis does not claim exactly-once effects.

## Claims deliberately not made

Aegis does not currently diagnose checkout failures, protect production data,
guarantee exactly-once effects, provide a secure code sandbox, satisfy a
compliance framework, meet an SLO, or support multi-region recovery. Live local
PostgreSQL tests prove specific RLS and durability controls, not production
deployment hardening or operational readiness.

## Closing gaps

`roadmap.md` defines the acceptance gate for each layer and
`enterprise-checklist.md` tracks capability status. A gap moves to Implemented
only with code, tests, and operational evidence linked from its curriculum
document. `enterprise-implementation-plan.md` specifies the implementation
sequence, data and security contracts, failure tests, SLO hypotheses, deployment
evidence, and production-readiness review needed to close every gap.
