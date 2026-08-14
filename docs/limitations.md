# Limitations and production gaps

## Remaining platform gaps

- Dynatrace, GitHub, Kubernetes, and runbook adapters exist, but are disabled by
  default and have only mocked/hermetic verification. No external account,
  cluster, private endpoint, certificate chain, permission set, quota, or SLA is
  certified by this repository.
- GitHub/Dynatrace webhook intake, Kubernetes watches, and incident-management
  writers do not exist. The only write adapter is fixed-shape Kubernetes
  deployment rollout restart and it is not certified against a live cluster.
- Fixed agent roles, typed artifacts, deterministic DAG scheduling, critic gates,
  and fake specialist execution are implemented. Agents cannot approve actions
  or create dynamic peers.
- Exact-scope human approval, fenced controlled effects, reconciliation,
  post-action verification, bounded Layer 9 analysis sandbox execution, and
  Layer 10 event-grounded memory/RAG are implemented. Arbitrary tools and
  Layer 11 deterministic evaluation contracts/harness are implemented. This is
  a hermetic release-evidence system, not live production qualification.
- Runtime spans, bounded metric instruments, local dashboards, and alert rules
  exist, but no production telemetry qualification or SLO attainment is claimed.
- Three-tier memory, pgvector/lexical retrieval, provenance, scanner/redaction
  hooks, retention/deletion, and context compaction are implemented. Live model
  verification, encrypted production blob/key storage, external DLP/malware
  services, backup expiry, and production load evidence are not.
- No MCP or A2A endpoint exists. Neither protocol currently provides discovery,
  tool access, external task exchange, streaming, cancellation, or status.
- CI emits a frontend CycloneDX SBOM and builds images, but does not emit signed
  provenance, a promoted release artifact, or deployment evidence.

## Current Layer 11 implementation (evaluation and release evidence)

- [ADR 0018](adr/0018-layered-deterministic-evaluation-gates.md) and
  [evaluation.md](evaluation.md) define immutable provider-neutral contracts,
  the governed synthetic scenario/adversarial/recovery corpus, all 22 named
  fault cuts, fixture tamper/quarantine checks, hard gates, canonical baseline,
  scoped expiring non-safety waivers, bounded reports, and telemetry.
- The `aegis_agent_platform.evals` CLI supports list, run with repeatable
  `--case`/`--tag` filters, replay, compare, explicit baseline update,
  `check-fixtures`, and `write-manifest`; `make evals` and focused
  `make eval-*` targets cover the required deterministic, adversarial, recovery,
  baseline, fixture, and meta paths. The catalog contains 91 cases, including 12
  adversarial cases, and
  `tests/test_evaluation_platform.py` contains 22 evaluator meta-tests.
- Required execution is hermetic with no live secrets, network, model judge, or
  production effect. A capped opt-in live/statistical adapter boundary and
  confidence calculation exist, but no adapter is registered by default and no
  live production qualification is claimed.
- Evaluator artifacts/results are release evidence only. They do not
  authorize actions, reconstruct run state, or replace code-enforced production
  safety and the event ledger.
- `ModelJudgeConfig` enforces disabled-by-default, versioned, delimited,
  never-sole-safety-gate configuration. Model judge execution and large-scale
  human-label calibration do not exist.
- Full production model/connector qualification, independent penetration/
  accessibility testing, large-scale human labeling, live production
  identity/browser qualification, MCP/A2A, production SLO evidence, HA/DR and
  multi-region, and final load/chaos certification remain deferred.

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

## Current Layer 7 implementation (governed specialist DAG)

- One immutable bounded investigation plan declares ten canonical checkout tasks
  across eight fixed roles. Code-defined capability and artifact-transition
  policies deny undeclared authority; specialists cannot spawn agents or peer
  chat.
- The pure fold rebuilds run/task/artifact state only from additive ledger events
  and rejects sequence gaps, duplicate IDs/keys, cycles, premature dispatch,
  invalid role transitions, unavailable provenance, critic bypass, and corrupt
  linkage.
- The coordinator records dispatch/start intent before execution, uses the
  existing work lease and event-store fence for every result, reserves global
  token capacity deterministically, and contains timeout, cancellation, provider,
  malformed-output, and implementation failures.
- Typed redacted artifacts include evidence assessment, primary/alternative
  hypothesis, contradiction/critique, causal/timeline references, proposal-only
  remediation, verification plan, coordinator decision, and final assessment.
  Finalization requires a cited above-threshold hypothesis and accepted critic;
  otherwise the result abstains or escalates.
- PostgreSQL run/task/artifact projections use forced RLS, expected versions,
  indexes, and maintenance-only rebuild. Authorized APIs expose only bounded
  redacted status, task, and artifact cursor pages. Metrics/spans have fixed
  names and role labels without prompt, evidence, tenant, run, or secret content.
- `python -m aegis_agent_platform.agents` and `make evals` use deterministic fake
  providers/connectors only. They prove success, ambiguity/abstention,
  contradiction/critic rejection, budget exhaustion, and crash recovery without
  live network or credentials.
- These controls do not prove that a model's semantic conclusion is correct.
  Layer 8 supplies the separate human approval and execution boundary. There is
  no live connector/model/action verification, production-qualified operator UI,
  MCP/A2A adapter, broad autonomous remediation, production deployment, HA,
  backup/restore, or operational SLO evidence.

## Current Layer 8 implementation (approval-gated remediation)

- Immutable provider-neutral plans bind versioned actions, exact target
  fingerprints, risk/blast radius, conditions, retry/reconciliation policy,
  rollback references, evidence, policy snapshots, and canonical digests.
- Policy defaults deny and evaluates tenant/action/target allowlists,
  maintenance windows, risk/blast thresholds, quotas, evidence, critic status,
  and the current plan digest. Plan or policy changes invalidate approval.
- Authenticated tenant-scoped decisions enforce role permissions, separation of
  duties, distinct quorum, expiry, revocation, optimistic concurrency,
  idempotency, and immutable audit. Raw operator comments persist only as a
  redacted marker.
- The executor rechecks current authorization, policy, approval, target,
  cancellation, preconditions, and PostgreSQL fence immediately before durable
  effect intent. Effects are at-least-once with a stable tenant idempotency key,
  explicit ambiguous outcomes, reconciliation-before-retry, duplicate
  suppression, conflicts, and operator escalation. Exactly-once is not claimed.
- Fresh evidence is compared with explicit postconditions and records success,
  failure, partial, or unknown. Provider acceptance is not recovery.
- Migration `0007_remediation_approvals.sql` supplies forced-RLS rebuildable
  projections, immutable decision records, quotas, and effect claims.
  Authenticated APIs expose bounded redacted cursor pages and readiness reports
  configured capability without secrets.
- `python -m aegis_agent_platform.remediation` and Layer 8 evals use only a
  deterministic fake. The official Kubernetes adapter accepts no arbitrary
  patch, command, shell input, code, or credential and is tested with a fake
  official client.
- Unrestricted interactive sandboxing, capability credential brokering,
  arbitrary or destructive actions, live external verification,
  production-qualified operator UI, MCP/A2A, production Kubernetes deployment,
  HA/DR, multi-region,
  and broad autonomous remediation remain deferred.

## Current Layer 9 implementation (hardened ephemeral sandbox)

- Immutable contracts bind tenant/run/task/remediation/approval, approved
  purpose, canonical spec/policy digests, digest-pinned image, argv, workspace,
  content-addressed inputs/mounts, secret references, environment, egress,
  resources, isolation, outputs, retries, cleanup, result, and attestation.
- Validation rejects shell construction, unsafe Unicode/control characters,
  traversal/device/host paths, sockets/namespaces, privilege/capabilities,
  mutable images, secret literals, oversized/conflicting inputs, unsafe archives,
  special/private egress, and weakened runtime controls. No host process, shell,
  Docker socket, `eval`, or unrestricted exec path exists.
- The sandbox fold covers request through cleanup/reconciliation and rejects
  corrupt transitions. PostgreSQL is authoritative; every external lifecycle
  operation requires durable intent and the current fence. Redis is delivery
  only and exactly-once execution is not claimed.
- Tenant policy defaults deny and binds exact images, commands, purposes, mounts,
  output types, secrets, egress, limits, risks, lifetime, concurrency, and
  budgets. PostgreSQL rechecks the current granted Layer 8 approval. A changed
  policy, spec, purpose, or risk invalidates the approval.
- Safe ZIP/TAR extraction and artifact scanner/redactor/quarantine hooks are
  implemented. These hooks do not constitute a certified malware engine or
  production object store.
- The deterministic fake never runs code. The Kubernetes adapter generates a
  suspended, digest-pinned, non-root Job with a read-only root, dropped
  capabilities, no privilege escalation, RuntimeDefault seccomp, no service
  account token/host namespaces, explicit resources/deadline, and ephemeral
  storage. It carries hashed lease-fence annotations and observes Job absence
  before cleanup completion. It is tested only through a fake official client.
- Production admission policy, authoritative PostgreSQL fence validation,
  runtime class, PID enforcement, node hardening, default-deny networking, egress
  proxy/DNS rebinding defense, CSI content
  driver, artifact collector, scanner, secret broker, copy-on-write staging,
  image signature/SBOM enforcement, and remote attestation are not deployed or
  certified. Readiness must remain false without those controls.
- APIs expose only authenticated bounded redacted request/status/artifact/
  cleanup views. There is no attach, interactive exec, log streaming, raw
  artifact download, or production mutation endpoint.
- Production-qualified operator UI, MCP/A2A, live external verification, HA/DR,
  multi-region, and broad autonomous production mutation remain deferred.

## Current Layer 10 implementation (event-grounded memory and RAG)

- Immutable working, episodic, semantic, ACL, retention, provenance, retrieval,
  summary, and context contracts plus pure lifecycle replay are implemented.
- Candidate acceptance is contract-digest bound. Scanning/redaction/quarantine,
  deterministic chunking, embedding/index intent, exact vector/model validation,
  fencing, reconciliation, supersession/conflict, and rebuild are executable.
- Forced-RLS PostgreSQL tables provide tenant-first lexical/pgvector search,
  atomic quota projections, jobs, and checkpoints. Redis caches tenant-digested
  references only; indexes and caches are derived.
- Retrieval filters tenant/ACL/purpose/lifecycle/retention/freshness before
  deterministic hybrid ranking and diversity. Citations, score components,
  freshness, and contradictions are preserved; no raw similarity API exists.
- Context construction reserves safety budget, delimits retrieved text as
  untrusted data, mitigates lost-middle placement, and abstains on contradiction
  or insufficient context. Compaction rejects unsupported claims and falls back
  deterministically without replacing source references.
- Tombstone, supersession, TTL, legal hold, tenant deletion, derived purge,
  cache invalidation, and referenced-blob erasure are implemented. Immutable
  identifier/digest ledger evidence remains; comprehensive GDPR or backup
  erasure is not claimed.
- APIs, CLI/demo, tests, and evals are deterministic and use no live external
  model. The implemented embedding profile is fixed at eight dimensions.
- Production-qualified operator identity/browser deployment, MCP/A2A, live provider
  verification, production encrypted blob/key management, advanced DLP/malware
  services, HA/DR, multi-region/global
  cache coherence, backup expiry, and final production load evidence remain
  deferred.

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
  eleven-test PostgreSQL/Redis suite executes migrations and those adapters.
- Global positions provide ordering, not a no-gap promise after rolled-back
  identity allocations. Aggregate sequence is gapless.
- The outbox remains delivery state only. Layer 4 publishes it to Redis; higher
  layers now use fenced paths for model calls, connectors, agents, and controlled
  remediation.
- Exactly-once effects are not claimed. Layer 8 implements tenant-scoped
  idempotency and reconciliation for its bounded controlled action port.
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
- Layer 4 itself performs no external provider effect. Layer 8 adds one bounded
  controlled-action port with target idempotency and reconciliation; Aegis does
  not claim exactly-once effects.

## Claims deliberately not made

Aegis does not currently diagnose live checkout failures, protect production data,
guarantee exactly-once effects, embedding, indexing, or provider billing, certify
a production code sandbox, satisfy a compliance framework, demonstrate a
production SLO, or support multi-region recovery. Live local
PostgreSQL tests prove specific RLS and durability controls, not production
deployment hardening or operational readiness.

## Closing gaps

`roadmap.md` defines the acceptance gate for each layer and
`enterprise-checklist.md` tracks capability status. A gap moves to Implemented
only with code, tests, and operational evidence linked from its curriculum
document. `enterprise-implementation-plan.md` specifies the implementation
sequence, data and security contracts, failure tests, SLO hypotheses, deployment
evidence, and production-readiness review needed to close every gap.

## Layer 12 limitations

The semantic catalog, rules, dashboards, local collector topology, APIs, replay
debugger, tests, and deterministic evals are implemented. The application does
not yet provide qualified production OTel SDK/exporter evidence, a production
trace/log backend, long-window production SLI history, external managed backend
qualification, or a proven 24/7 on-call rotation. Local collector buffering is
ephemeral. Live production identity/browser qualification, MCP/A2A, HA/DR/multi-region,
final load/chaos, independent penetration/accessibility testing, and compliance
certification remain deferred.

## Layer 13 limitations

- The BFF/session/PKCE boundary, secure cookies, CSRF/origin checks, tenant/RBAC
  behavior, derived views, polling, approvals, audit, React workspace, tests, and
  static image are implemented.
- The live OIDC authorization-code exchange, logout propagation, key rotation drill,
  encrypted distributed session store, reverse-proxy TLS deployment, and production
  identity lifecycle are not implemented or live-tested. Readiness is false.
- The canonical incident and auth adapter are deterministic and synthetic. They
  perform no production network call, effect, or credential use.
- Automated axe and Chromium tests are regression evidence, not an independent
  WCAG audit or a supported browser/assistive-technology matrix.
- Cursor polling is implemented; a production SSE/WebSocket transport is deferred.
  Either must continue through the same tenant authorization and runtime validation.
- Dependency audit, permissive-license policy, bundle/source-map/CSP checks, SBOM,
  and non-root container smoke are CI controls. Image signing, SLSA provenance,
  managed promotion/rollback, production WAF/CDN behavior, penetration testing,
  load/chaos, HA/DR/multi-region, and compliance certification remain absent.
