# Layered roadmap

Each layer must pass its gate before the next layer claims completion.
The detailed delivery design is in `enterprise-implementation-plan.md`, including
16 reviewable implementation slices, storage and security contracts, failure
tests, operational evidence, and production-readiness review criteria.
The complete document curriculum, interview track, demo scripts, and labs are
indexed in `curriculum.md`. Topic documents may be planned before they exist,
but must link code and tests before their status changes to Implemented.

## Layer 1 — Foundation

Establish package boundaries, invariants, strict tooling, local infrastructure,
documentation, supply-chain guardrails, and typed future read ports for
Dynatrace and GitHub evidence used by the checkout-failure scenario. Define the
fixed incident roles, typed ledger artifacts, specialist limits, and immutable
investigation-plan contracts without executing agents.

**Acceptance gate:** all declared checks pass; package boundaries import; the
container runs non-root; Compose renders coherently; integration contracts are
tenant-scoped and vendor objects stay at adapters; docs make no claims about
working connectors or unimplemented runtime behavior. Agent roles are fixed and
their only communication port persists typed artifacts.

## Layer 2 — Identity, tenancy, and governance

Validate OIDC/JWT tokens against a Keycloak-compatible configuration, model
principals and tenant memberships, enforce deny-by-default tenant-scoped
authorization, isolate tenant records, and add tenant governance policy/quota
decisioning, redacted append-only security audit events, and a secret-reference
abstraction.

**Status:** `identity.authentication` (JWT verification, JWKS providers),
`identity.authorization` (deny-by-default role-based decisions),
`policy.PolicyEvaluator` (allowlist/risk/quota decisions), `audit`
(redacted, additive, tenant-scoped events), and `secrets_boundary` (reference-
only secrets) are implemented and wired into an authenticated control-plane
vertical slice (`/v1/me`, `/v1/tenants/{tenant_id}`,
`/v1/tenants/{tenant_id}/policy`). A committed automated test suite
(`tests/test_identity_security.py`, `tests/test_policy_security.py`,
`tests/test_audit_secrets.py`, `tests/test_migrations.py`, and the
cross-tenant/authentication cases in `tests/test_api.py`) proves cross-tenant
denial, invalid/expired/wrong-issuer/wrong-audience/malformed tokens,
unsupported algorithms, expired and revoked role bindings, quota/policy
allow-deny-require-approval boundaries, redaction, and audit append-only
behavior — all against deterministic fixtures, not a live network. The
Postgres migration `0001_identity_governance.sql` defines tenant-isolated,
row-level-secured tables and an append-only audit trigger, and
`tests/test_migrations.py` asserts the schema contains those constraints
statically. Layer 3 now supplies PostgreSQL adapters and exercises the
row-level-security policies against PostgreSQL 16.

**Acceptance gate:** cross-tenant negative tests cover the API — done; the
same coverage against a live, row-level-secured Postgres instance is now done
in Layer 3. Issuer, audience, expiry, and unsupported-algorithm rejection are
tested — done; live Keycloak key rotation against a running IdP is a
deployment-time check, not yet exercised by these tests. No operation
defaults to an implicit tenant — done. Quota and policy decisions have
deterministic tests covering allow/deny/require-approval and limit-exceeded
cases — done. Audit events are proven redacted and append-only at the
application layer and database trigger — done.

## Layer 3 — Events and durable orchestration

Implement the append-only event store, optimistic concurrency, additive schema
evolution, projections, deterministic incident transitions, evidence references,
fixture-backed checkout-failure investigation state, and ledger persistence for
typed specialist artifacts.

**Status:** the persistence slice is implemented: immutable additive envelopes,
atomic expected-version append, transactional inbox/outbox, global cursor,
gapless aggregate sequence, deterministic replay, idempotent projections and
rebuild checkpoints, forced RLS, PostgreSQL identity/governance repositories,
authorized ledger/timeline reads, storage error classification, and bounded
telemetry interfaces. Historical Layer 1 fixtures replay. Live PostgreSQL tests
cover rollback, concurrent races, duplicate delivery, outbox claim/dead-letter,
RLS, immutable rows, audit redaction, replay, and projection rebuild.

**Acceptance gate:** persistence and replay mechanics are done. Layer 8 records
typed action intent before every controlled effect and retains the generic
`effect.intent_recorded.v1` compatibility path. Layer 7 supplies the
incident-specific deterministic fold and typed artifact replay on top of this
ledger. Redis workers are implemented separately in Layer 4.

## Layer 4 — Workers and leases

Implement durable publication/consumption, fenced renewable leases, bounded
workers, fair tenant scheduling, cancellation, retry/DLQ, and reconciliation.

**Status:** the distributed execution substrate is implemented and live-tested.
PostgreSQL remains authoritative; Redis Streams is shared at-least-once
transport. Higher layers now use these leases for provider calls, connectors,
specialist reasoning, and controlled remediation.

**Acceptance gate:** duplicate delivery, lease expiry/reclaim, stale writers,
publisher restart windows, cancellation races, timeout/retry exhaustion, poison
messages, and DLQ operations have deterministic or live-service evidence.
Provider controls and ambiguous-outcome recording are implemented separately in
Layer 5. Connector fixtures are Layer 6 and deterministic specialist aggregation
is Layer 7; neither changes the worker layer's at-least-once semantics.

## Layer 5 — Provider-neutral model gateway

Implement neutral content/message/tool/schema contracts, OpenAI and Anthropic
adapters, a deterministic fake, explicit catalog/pricing, tenant policy routing,
fenced pre-call budget reservation, usage reconciliation, structured validation,
retry/failover/rate/concurrency/circuit controls, redacted telemetry, and bounded
operator views.

**Status:** implemented in `domain.model`, `providers`, `gateway`, migration
`0004_model_gateway.sql`, and deterministic adapter/routing/budget evaluations.
No live provider call runs in CI.

**Acceptance gate:** unknown models/prices deny; intent and reservation precede
network; stale workers cannot call/charge/surface responses; permanent failures
do not retry; fallback is bounded; usage retains its price version; prompts and
keys never enter model events or telemetry; ambiguous provider billing is
reported rather than treated as exactly once.

## Layer 6 — Evidence connectors and deterministic correlation

Add provider-neutral evidence contracts, durable query intent, bounded
Dynatrace/GitHub/Kubernetes/runbook adapters, immutable tenant-scoped ingestion,
provenance/redaction/quarantine, cursor fencing, asynchronous operator APIs, and
non-LLM timeline correlation.

**Status:** implemented in `domain.evidence`, `evidence`, `integrations`,
migration `0005_evidence_connectors.sql`, and deterministic mocked transport,
ingestion, fencing, API, and correlation tests. Live external environments are
not configured or verified.

**Acceptance gate:** intent precedes network; stale workers cannot query,
append, or advance cursors; source and environment allowlists fail closed;
records are bounded, redacted, content-addressed, and cited; partial results are
explicit; ambiguity/conflict survives deterministic correlation; no vendor type,
credential, unrestricted source content, or unbounded payload enters core
contracts/events.

## Layer 7 — Governed durable specialist DAG

Implement the Incident Coordinator and fixed Telemetry, Change, Runtime,
Knowledge, Critic, Remediation Planner, and Verification roles. Persist the
bounded immutable plan, scheduling intent, typed reasoning artifacts, task
outcomes, coordinator decision, and final assessment in the existing event
ledger. Enforce code-defined capabilities, DAG bounds, citations, provenance,
budgets, timeouts, cancellation, retries, fencing, deterministic ordering,
critic review, confidence thresholds, and safe abstention.

**Status:** implemented in `agents`, migration
`0006_specialist_orchestration.sql`, authorized investigation read APIs, the
fake-only checkout CLI, deterministic unit/integration tests, and CI-gated
behavioral evals.

**Acceptance gate:** cycles, premature dispatch, duplicate events/artifacts,
role escalation, unknown citations, stale workers, malformed/hostile model
output, prompt injection in evidence, cancellation, timeout/retry, provider
budget denial, critic rejection, contradictions, projection rebuild, tenant
isolation, and completion-order variance fail closed or reach the same explicit
terminal state. Finalization requires a cited above-threshold hypothesis and an
accepted critique. Layer 7 itself remains proposal-only; Layer 8 consumes that
immutable proposal without allowing an agent to approve it.

## Layer 8 — Approval-gated controlled remediation

Add immutable provider-neutral plan/action/target contracts, exact policy-bound
approvals, an authenticated tenant-scoped proposal/decision workflow, fenced
intent-before-effect execution, stable idempotency, reconciliation, and explicit
postcondition verification.

**Status:** implemented for a deterministic fake action and one fixed-shape
Kubernetes deployment rollout-restart adapter. Policy defaults deny; approval
binds immutable plan/action/policy digests, exact target, risk, requester,
quorum, and expiry. Separation of duties, distinct approvers, role changes,
revocation, stale fences, cancellation, ambiguous effects, reconciliation,
duplicate delivery, adapter bugs, and verification failure are executable test
cases. PostgreSQL forced-RLS projections are rebuildable and Redis remains
transport only.

**Acceptance gate:** hostile model/evidence content cannot create authority;
current policy, approval, target, preconditions, and fence are rechecked before
durable intent; every effect is attributable to that intent; ambiguous effects
are reconciled before retry; fresh evidence, not adapter acceptance, determines
verification. Exactly-once is not claimed.

General sandbox/code execution, arbitrary commands, capability credential
brokering, broad autonomous remediation, production credentials, and live
external verification remain deferred.

## Layer 9 — Sandbox, memory, and retrieval

Add policy-isolated general code execution plus tenant-scoped short- and
long-term memory, pgvector retrieval, provenance,
classification, retention, export, and deletion workflows. Index runbooks and
past incident evidence without turning retrieved text into authority. Implement
three explicit tiers: bounded working state/context, authoritative episodic event
history, and derived semantic incident knowledge. Add PII controls,
relevance/recency policy, and citation-preserving context compaction.

**Acceptance gate:** adversarial cross-tenant retrieval tests pass; every
retrieved item has provenance; deletion and retention behavior is auditable.
Compaction tests preserve material evidence, uncertainty, conflict, approval
state, and budgets, and semantic retrieval cannot cross tenants.

## Layer 9 — Evaluation and observability

Add versioned datasets, offline and online evaluation, release gates, traces,
metrics, logs, cost accounting, and safe content handling. Score hypothesis
evidence coverage, unsupported claims, remediation choice, approval compliance,
and recovery verification on checkout-failure variants.

Layer 7 includes only a bounded deterministic behavioral regression matrix; this
layer adds production datasets, semantic quality measurement, and operational
release gates.

**Acceptance gate:** a reproducible evaluation blocks a known regression;
event-to-trace correlation works; telemetry contains no disallowed content or
unbounded tenant labels.

## Layer 10 — Enterprise operations

Add deployment automation, SLOs, alerting, runbooks, backup and restore, HA,
capacity tests, software provenance, signing, governance evidence, and incident
system integration for durable status updates. Add optional external A2A
interoperability with Agent Cards, authenticated tasks/messages/artifacts,
streaming, status, cancellation, and tenant/policy propagation. MCP may support
controlled tool/context adapters but is never an internal coordination bus.

**Acceptance gate:** restore and failover drills meet documented objectives;
signed artifacts include SBOM and provenance; operators can diagnose and
contain the simulated checkout incident from runbooks with a complete evidence,
approval, action, verification, and incident-update audit trail.
The A2A adapter passes conformance, authentication, authorization,
tenant-isolation, idempotency, replay, cancellation, downgrade, and malicious
peer tests; every external task transition is replayable from the event ledger.

## Curriculum documentation gates

Each layer must update its curriculum topic with system context, detailed
design, alternatives, threat considerations, failure modes, operations,
hands-on exercises, interview prompts, and links to code and tests. Later layers
must deliver the planned documents named in `curriculum.md`: durable execution;
reliable work; provider routing; safe tools; identity/tenancy; memory/RAG;
connector design; evaluation; observability/SLOs; failure modes; scaling and
multi-region; privacy/compliance; deployment/supply chain; and an ADR index.
The protocol curriculum in `protocols.md` must remain explicit that internal
typed ledger protocols—not A2A or MCP—provide correctness.
