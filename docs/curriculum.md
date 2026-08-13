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
> adapter. Live environments, memory, and production
> operations remain unverified or planned.

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
| Memory, RAG, and compaction (`memory-and-rag.md`, `protocols.md`) | Design working, episodic, and semantic tiers with provenance, PII controls, retention, relevance/recency, and faithful compaction | 9 | Protocol documented; storage planned |
| Evidence connectors and correlation (`evidence-connectors.md`) | Translate Dynatrace, GitHub, Kubernetes, and runbooks into stable evidence; preserve provenance, partial results, ambiguity, and conflict | 6 | Implemented with mocked transports; live environments unverified |
| Agent and tool protocols (`protocols.md`) | Distinguish internal correctness ports, MCP adapters, and external A2A interoperability | 6–8 | Position documented; MCP/A2A planned |
| Evaluation strategy (`evaluation.md`) | Combine deterministic, live, adversarial, quality, safety, latency, and cost evaluation | 7/10 | Layers 7–9 deterministic behavior gates implemented; production harness planned |
| Observability and SLOs (`observability-and-slos.md`) | Correlate events/traces safely, select SLIs, control cardinality, and operate alerting | 7–8 | Local topology scaffolded |
| Threat model (`threat-model.md`) | Analyze tenant, evidence, model, swarm, tool, sandbox, provider, and supply-chain threats | 1–9 | Layer 9 attacks and environment gaps documented |
| Failure modes and runbooks (`failure-modes.md`, `runbook.md`) | Diagnose crashes, stale leases, partial effects, provider faults, poisoned evidence, and regional failure | 3–9 | Storage, worker, and provider failures implemented; regional sections planned |
| Scaling and multi-region (`scaling-and-multi-region.md`) | Estimate capacity, partition tenants, preserve ordering, and choose recovery objectives | 8 | Planned |
| Privacy, retention, and compliance (`privacy-and-compliance.md`) | Classify data, minimize collection, enforce deletion/legal hold, and produce evidence | 6–8 | Planned |
| Deployment and supply chain (`deployment-and-supply-chain.md`) | Build least-privilege releases with SBOM, provenance, signing, promotion, and rollback | 8 | CI/container baseline only |
| Alternatives and ADR index (`adr/README.md`) | Compare orchestration, queues, identity, sandbox, provider, and evaluation choices | 1–9 | Planned index; eleven ADRs exist |
| Interview question bank (`interview-question-bank.md`) | Communicate tradeoffs and defend design under follow-up pressure | 1–9 | Layer 9 sandbox boundary questions documented |
| Hands-on labs (`labs.md`) | Turn each invariant into executable evidence and inject realistic failures | 1–11 | Layers 1–9 tests runnable |
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
