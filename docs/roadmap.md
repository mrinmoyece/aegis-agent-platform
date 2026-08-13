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

## Layer 2 — Identity and tenancy

Validate OIDC tokens, model principals and tenant memberships, enforce
tenant-scoped authorization, and isolate tenant records.

**Acceptance gate:** cross-tenant negative tests cover API and persistence;
issuer, audience, expiry, and key rotation are tested; no operation defaults to
an implicit tenant.

## Layer 3 — Events and durable orchestration

Implement the append-only event store, optimistic concurrency, additive schema
evolution, projections, deterministic incident transitions, evidence references,
fixture-backed checkout-failure investigation state, and ledger persistence for
typed specialist artifacts.

**Acceptance gate:** crash-point tests prove replay; committed historical events
remain readable; every external effect path requires a committed intent.

## Layer 4 — Workers, leases, and providers

Implement durable work claiming, fenced renewable leases, retry policy,
provider-neutral model adapters, metering, idempotent provider calls, and
read-only Dynatrace/GitHub connectors for telemetry, topology, changes, pull
requests, and deployments. Add coordinator scheduling for a validated dependency
DAG with fixed per-role capability, budget, and timeout envelopes.

**Acceptance gate:** duplicate delivery, lease expiry, worker death, timeout,
rate-limit, and ambiguous provider outcomes recover without concurrent ownership
or lost work. Connector contract tests replay the canonical incident without
requiring live vendor accounts. Parallel investigation tests prove deterministic
aggregation regardless of completion order, and failed or timed-out specialists
cannot exceed their limits or silently disappear from the incident record.

## Layer 5 — Tools, policy, and sandbox

Add typed tool contracts, policy decisions, approvals, capability-scoped
credentials, an incident proposal/approval workflow, and isolated execution with
resource and network controls. Add controlled rollback/remediation adapters for
the demo only after approval is durable.

**Acceptance gate:** prompt injection or hostile runbook content cannot bypass
authorization; sandbox escape and egress tests fail closed; every effect is
attributable to an approved intent; the checkout rollback cannot execute before
valid approval.

## Layer 6 — Memory and retrieval

Add tenant-scoped short- and long-term memory, pgvector retrieval, provenance,
classification, retention, export, and deletion workflows. Index runbooks and
past incident evidence without turning retrieved text into authority. Implement
three explicit tiers: bounded working state/context, authoritative episodic event
history, and derived semantic incident knowledge. Add PII controls,
relevance/recency policy, and citation-preserving context compaction.

**Acceptance gate:** adversarial cross-tenant retrieval tests pass; every
retrieved item has provenance; deletion and retention behavior is auditable.
Compaction tests preserve material evidence, uncertainty, conflict, approval
state, and budgets, and semantic retrieval cannot cross tenants.

## Layer 7 — Evaluation and observability

Add versioned datasets, offline and online evaluation, release gates, traces,
metrics, logs, cost accounting, and safe content handling. Score hypothesis
evidence coverage, unsupported claims, remediation choice, approval compliance,
and recovery verification on checkout-failure variants.

**Acceptance gate:** a reproducible evaluation blocks a known regression;
event-to-trace correlation works; telemetry contains no disallowed content or
unbounded tenant labels.

## Layer 8 — Enterprise operations

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
