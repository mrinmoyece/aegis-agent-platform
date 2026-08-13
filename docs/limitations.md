# Limitations and production gaps

## Remaining platform gaps

- Dynatrace, GitHub, Kubernetes, and runbook adapters exist, but are disabled by
  default and have only mocked/hermetic verification. No external account,
  cluster, private endpoint, certificate chain, permission set, quota, or SLA is
  certified by this repository.
- GitHub/Dynatrace webhook intake, Kubernetes watches, incident-management, and
  remediation adapters do not exist.
- Agent roles, artifacts, and plans are types only. There is no specialist
  scheduler, deterministic aggregation, critic enforcement, approval workflow,
  or specialist execution. Model invocation and model-call budgets are
  implemented independently of that future orchestration.
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

## Current Layer 5 implementation (model gateway)

- Provider-neutral immutable contracts cover messages/content, tools, schemas,
  capabilities, identity, safety/refusal, finish reasons, five usage token
  classes, latency, versioned pricing, and classified failures.
- Official OpenAI and Anthropic Python SDK adapters are isolated at the provider
  edge and tested through mocked SDK clients. They are production-capable
  translations, but CI performs no live provider call and proves no provider
  account, regional endpoint, quota, or SLA.
- Routing fails closed for unknown models/prices and enforces tenant model/
  provider/environment/residency/retention policy, capability/context/output
  limits, bounded catalog health, and cost/latency ordering.
- PostgreSQL fenced reservations serialize tenant capacity and atomically commit
  route/request/reservation events before network. Usage/charge/release commits
  after response. Stale workers cannot call before a failed reservation or
  charge/surface a response after a failed result fence.
- Only metadata and a content digest enter model events. Raw prompts, tool
  arguments/results, images, keys, and SDK errors are not persisted or logged.
  There is no encrypted prompt/response artifact store yet.
- Prompt token estimates are conservative caller input; exact preflight
  tokenizers are not implemented. Reservation drift is observable.
- Provider timeouts can be billing-ambiguous. Idempotency is forwarded where
  supported, but exactly-once provider billing is not claimed. Automated
  reconciliation with provider billing exports is not implemented.
- Automatic structured-output repair is not implemented. Invalid JSON/schema or
  tool arguments fail explicitly; a future repair must be a separately durable,
  budgeted call.
- The read-only model catalog, usage, and health APIs are implemented. Live
  completion is deliberately not an HTTP shortcut; production invocation must
  enter through durable worker execution. The CLI diagnostic uses only the
  scripted mock.

## Current Layer 6 implementation (evidence connectors)

- Frozen provider-neutral contracts cover source/resource identities, UTC
  timestamps, query windows, structured content, severity/source confidence,
  provenance/digests, redaction/classification/retention, typed references,
  cursors, explicit partial metadata, correlation links, timelines, and bundles.
- Durable query intent precedes network I/O. Query/results/cursors are
  tenant-scoped and fenced; stale lease generations cannot append or advance a
  source cursor.
- Dynatrace supports OAuth2 client credentials and bounded logs, spans, metrics,
  problems/events, topology/entities, and deployment/change reads. GitHub uses
  GitHub App installation authentication and repository allowlists for delivery
  metadata. Kubernetes isolates the official client and performs read-only
  workload/event/status and policy-gated bounded-log reads. Runbooks are
  schema/trust validated retrieval-only knowledge.
- Canonical SHA-256 addressing, tenant deduplication, redaction hooks,
  quarantine, immutable PostgreSQL projections, citations, retention metadata,
  and deterministic correlation are implemented and tested without external
  network access.
- Correlation orders UTC evidence and links exact IDs plus bounded
  time/resource/runbook heuristics. It preserves ambiguity and conflict and
  makes no causal claim.
- Connector configuration is disabled by default. No live credentials are in CI
  and no production environment has been verified. GitHub/Dynatrace webhooks,
  Kubernetes watch continuity, encrypted object storage, deletion/legal hold,
  external capability probes, dashboards/alerts, and credential rotation drills
  remain gaps.

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
  live connectors, agent execution, approval, and external remediation effect
  adapters do not exist. Layer 5 model calls use their own durable fenced path.
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
guarantee exactly-once effects or provider billing, provide a secure code
sandbox, satisfy a
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
