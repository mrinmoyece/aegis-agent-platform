# Staff-level learning curriculum

## Elevator pitch

Aegis is an enterprise incident-response agent reference platform. In the
canonical scenario, checkout failures rise after a deployment. Fixed,
least-privilege specialists correlate Dynatrace telemetry, GitHub delivery
changes, Kubernetes/runtime state, and runbooks; challenge the causal
hypothesis; propose an exact rollback; wait for scoped human approval; execute
through a controlled tool; verify recovery; and update the incident record.

The curriculum teaches the platform decisions behind that story: durable
execution, multi-tenant authorization, evidence provenance, bounded multi-agent
coordination, safe effects, evaluation, and operations.

> **Current status:** Layers 1–4 provide boundaries, governance, the ledger, and
> distributed workers. Layer 5 implements the provider-neutral model gateway.
> Layer 6 implements bounded evidence connectors, immutable cited ingestion, and
> deterministic timeline correlation. Layer 7 implements the governed durable
> specialist DAG, critic gates, typed reasoning artifacts, safe abstention, and
> fake-only behavioral evals. Layer 8 implements exact-scope human approval,
> fenced controlled effects, at-least-once reconciliation, and explicit
> verification with a fake and one fixed-shape Kubernetes adapter. Layer 9
> implements approval-bound hardened ephemeral analysis, safe artifacts,
> lifecycle reconciliation, fake evals, and a locked-down Kubernetes Job
> adapter. Layer 10 implements event-grounded memory, pgvector RAG, cited
> compaction, retention lifecycle, fake evals, and a deterministic demo. Layer
> 11 implements the unified deterministic harness, governed 91-case corpus,
> release gates, bounded reports/telemetry, baseline/waiver and fixture
> governance, CLI, and focused `make eval-*` targets. Layer 12 adds safe
> observability, SLO configuration, dashboards, and ledger replay. Layer 13 adds
> the secure derived operator BFF, strict React workspace, exact-scope approval
> UX, accessibility/security/supply-chain gates, and six operator invariants.
> Layer 14 implements governed MCP tool/context and A2A external-agent
> boundaries, digest-pinned trust, durable reconciliation, deterministic demos,
> and eight protocol invariants. Production federation and PKI remain unverified.
> Live identity/browser environments and production operations remain unverified.

The curriculum is backed by the concrete delivery slices and acceptance
evidence in `enterprise-implementation-plan.md`; the roadmap is not merely a
topic list.

## How to study

For each module, explain the invariant, trace the relevant contract, identify
failure modes, run the available lab, and defend the tradeoff. A module becomes
Implemented only when its document links executable code and tests.

| Module and planned document | Staff-level learning outcomes | Layer | Status/evidence |
| --- | --- | --- | --- |
| System overview and elevator pitch (`README.md`, this document) | Frame the product, users, trust boundaries, and non-goals in two minutes | 1 | Documented |
| Canonical incident and demo scripts (`demo-script.md`) | Narrate evidence-to-verification without overstating automation | 1–8 | Foundation script documented |
| Architecture walkthrough (`architecture.md`) | Explain control/data planes, boundaries, authoritative state, and trust crossings | 1 | Documented; architecture tests |
| Multi-agent workflow and artifacts (`architecture.md`, ADR 0008/0014) | Defend fixed roles, DAG scheduling, ledger communication, critique, and bounded authority | 7 | Implemented; unit/live-Postgres tests and fake evals |
| Durable execution and event sourcing (`durable-execution.md`) | Design replay, additive schemas, projections, crash recovery, and intent-before-effect | 3 | Implemented persistence mechanics; ADR 0002/0010 and live PostgreSQL tests |
| Leases, fencing, and idempotency (`worker-runtime.md`) | Explain at-least-once delivery, fencing, reconciliation, backpressure, cancellation, and DLQ operations | 4 | Implemented; ADR 0003/0011 and live PostgreSQL/Redis tests |
| Model/provider routing and cost governance (`model-gateway.md`) | Normalize providers, route by policy, meter cost, enforce budgets, and handle uncertain outcomes | 5 | Implemented; mocked SDK transports and deterministic evals |
| Controlled remediation (`architecture.md`, ADR 0015) | Apply exact policy/approval, fencing, intent events, idempotency, reconciliation, and verification | 8 | Implemented for fake execution and fixed-shape Kubernetes rollout restart |
| Hardened sandbox execution (`sandbox-execution.md`, ADR 0016) | Isolate bounded analysis/test/patch work with exact approval, fencing, egress, artifacts, reconciliation, and cleanup | 9 | Implemented boundary; production cluster controls unverified |
| Identity, tenancy, and RBAC (`identity-tenancy.md`) | Separate authentication from tenant authorization and prove isolation | 2–3 | PostgreSQL repositories and live RLS denial implemented; live-Keycloak drills planned |
| Memory, RAG, and compaction (`memory-and-rag.md`, `protocols.md`, ADR 0017) | Design working, episodic, and semantic tiers with provenance, PII controls, retention, relevance/recency, and faithful compaction | 10 | Implemented; deterministic and live pgvector/RLS evidence |
| Evidence connectors and correlation (`evidence-connectors.md`) | Translate Dynatrace, GitHub, Kubernetes, and runbooks into stable evidence; preserve provenance, partial results, ambiguity, and conflict | 6 | Implemented with mocked transports; live environments unverified |
| Agent and tool protocols (`protocols.md`, ADR 0022) | Distinguish internal correctness ports, MCP adapters, and external A2A interoperability | 14 | Implemented deterministic/local; production federation deferred |
| Evaluation strategy (`evaluation.md`, ADR 0018) | Separate hermetic CI, integration, live/statistical qualification, and production evidence; govern datasets, gates, waivers, judges, reports, and lifecycle | 11 | Implemented deterministic suite/CLI; optional-live boundary limited and no production qualification |
| Observability and SLOs (`observability-and-slos.md`) | Correlate events/traces safely, select SLIs, control cardinality, and operate alerting | 12 | Local topology scaffolded; production layer planned |
| Threat model (`threat-model.md`) | Analyze tenant, evidence, model, swarm, tool, memory, sandbox, provider, evaluation, and supply-chain threats | 1–11 | Layer 11 evaluation controls and environment gaps documented |
| Failure modes and runbooks (`failure-modes.md`, `runbook.md`) | Diagnose crashes, stale leases, partial effects, provider faults, poisoned memory/evidence/evaluation data, and regional failure | 3–12 | Runtime and Layer 11 evaluation responses documented; regional sections planned |
| Scaling and multi-region (`scaling-and-multi-region.md`) | Estimate capacity, partition tenants, preserve ordering, and choose recovery objectives | 8 | Planned |
| Privacy, retention, and compliance (`privacy-and-compliance.md`) | Classify data, minimize collection, enforce deletion/legal hold, and produce evidence | 6–8 | Planned |
| Deployment and supply chain (`deployment-and-supply-chain.md`) | Build least-privilege releases with SBOM, provenance, signing, promotion, and rollback | 8 | CI/container baseline only |
| Alternatives and ADR index (`adr/README.md`) | Compare orchestration, queues, identity, sandbox, provider, and evaluation choices | 1–11 | Planned index; eighteen ADRs exist |
| Interview question bank (`interview-question-bank.md`) | Communicate tradeoffs and defend design under follow-up pressure | 1–11 | Layer 11 release-evidence boundary questions documented |
| Hands-on labs (`labs.md`) | Turn each invariant into executable evidence and inject realistic failures | 1–12 | Layers 1–11 deterministic labs runnable |
| Terminology (`glossary.md`) | Use durability, evidence, tenancy, evaluation, and operations terms precisely | 1 | Documented |
| Limitations and production gaps (`limitations.md`) | State what is absent, unsafe, local-only, or not yet proven | Every layer | Documented and maintained |

## Staff review rubric

A strong learner can:

1. Separate facts, hypotheses, decisions, intents, effects, and verification.
2. Explain why each authoritative transition survives process failure.
3. Trace tenant and identity context through every boundary.
4. Bound model and specialist authority independently of prompt behavior.
5. State delivery semantics and ambiguous-outcome handling without claiming
   exactly-once execution.
6. Define executable evidence for quality, safety, resilience, privacy, and
   operations claims.
7. Quantify capacity, latency, cost, and recovery tradeoffs.
8. Present limitations and alternatives before proposing complexity.

## Layer 12 learning outcomes

Learners define low-cardinality semantics, propagate W3C context safely across
at-least-once work, design measurable SLIs and burn alerts, provision dashboards
that treat no-data honestly, contain exporter failure, and debug from immutable
ledger facts. The demo explicitly distinguishes configured/local objectives
from production-measured attainment.

## Layer 13 learning outcomes

Learners can defend a BFF/HttpOnly session architecture over browser bearer tokens,
explain why UI and caches are derived, design anti-enumerating tenant/RBAC flows,
validate OpenAPI responses at runtime, and keep exact approval scope visible without
moving authority client-side. They can test ambiguous action semantics, cursor
resume/deduplication/tenant teardown, XSS/download/CSV/clipboard defenses, WCAG 2.2
AA patterns, CSP/static serving, dependency policy, SBOM, and honest readiness
gaps. Use [operator-ui.md](operator-ui.md),
[operator-accessibility.md](operator-accessibility.md), and ADR 0021.

## Layer 14 learning outcomes

Learners can defend why MCP/A2A remain adapters rather than internal
orchestration; design exact tenant peer registries, capability/card/schema
digest pinning, signed Agent Cards, proposal-only remediation, and
intent-before-network at-least-once reconciliation; prevent poisoning,
confused-deputy, SSRF/DNS/redirect, replay, schema/Unicode/MIME, tenant, and
denial-of-wallet attacks; and distinguish deterministic interoperability from
production PKI/federation evidence. Use [protocols.md](protocols.md),
[MCP/A2A security](mcp-a2a-security.md), and ADR 0022.
