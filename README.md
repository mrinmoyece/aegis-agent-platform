# Aegis Agent Platform

Aegis is a public learning project for building an enterprise-grade, multi-tenant
agent operations platform from first principles. Its concrete product and demo
is an **enterprise incident-response agent** that correlates operational and
delivery evidence, forms evidence-backed hypotheses, proposes remediation,
waits for approval, executes through controlled tools, verifies recovery, and
updates the incident record.

The canonical learning incident is **checkout failures after a deployment**.
The finished platform will correlate Dynatrace logs, distributed traces,
metrics, topology, problems, and events with Git/GitHub commits, pull requests,
deployments, Kubernetes/runtime changes, and runbooks. This narrow story makes
durability, evidence provenance, authorization, and safe effects testable end
to end.

> **Current status: Layer 12 - Enterprise observability and replay.** Layers 1-4 add
> tenant-bound work events, a crash-reconcilable PostgreSQL outbox publisher,
> Redis Streams consumer groups, inbox deduplication, PostgreSQL renewable
> leases and fencing, fair bounded supervision, quota enforcement, cancellation,
> timeout/retry/DLQ handling, authorized operations, and live PostgreSQL/Redis
> race tests. Layer 5 adds OpenAI/Anthropic adapters, a deterministic mock,
> capability/policy routing, versioned pricing, fenced budget accounting,
> structured validation, and resilience controls. Layer 6 adds bounded
> Dynatrace, GitHub, Kubernetes, and runbook adapters, immutable cited ingestion,
> durable query intent, and deterministic timeline correlation. Layer 7 adds a
> fixed coordinator/specialist DAG, durable typed reasoning artifacts, critic
> gates, deterministic replay/aggregation, fenced scheduling, and fake-only
> checkout evaluations. Layer 8 adds immutable exact-scope remediation plans,
> deny-by-default action policy, expiring separation-of-duties approvals, fenced
> intent-before-effect execution, at-least-once reconciliation, explicit
> postcondition verification, forced-RLS projections, and a bounded Kubernetes
> rollout-restart adapter. Layer 9 adds immutable provider-neutral sandbox
> contracts, strict command/path/archive validation, exact Layer 7/8 linkage,
> current approval and policy rechecks, fenced intent-before-backend execution,
> content-addressed artifacts, default-deny egress, bounded telemetry,
> forced-RLS projections, deterministic fake scenarios, and a hardened suspended
> Kubernetes Job adapter. Layer 10 adds immutable three-tier memory contracts,
> durable scan/embed/index/retrieval/compaction lifecycle, tenant quotas,
> forced-RLS pgvector/lexical retrieval, exact provenance/citations,
> contradiction-aware bounded context, retention/legal hold/deletion, deterministic
> demos/evals, and rebuildable indexes/caches. Layer 11 adds immutable
> provider-neutral evaluation contracts, a governed synthetic corpus
> including 12 adversarial cases and all 22 named fault cuts, hermetic execution,
> hard safety gates, canonical baselines, scoped expiring non-safety waivers,
> fixture governance, bounded reports/telemetry, and a developer CLI. Evaluation
> is release evidence, never runtime truth. Layer 12 adds versioned semantic
> conventions, strict context propagation and telemetry redaction, bounded
> cardinality metrics, structured logs, configured SLOs and burn-rate alerts,
> provisioned dashboards, component health, tenant/operator observability APIs,
> and ledger-grounded read-only replay debugging. The evaluation catalog now has
> 97 deterministic cases, including six observability invariants. These are
> configured and locally validated controls, not evidence of production SLO
> attainment. Live model/connector and production telemetry qualification,
> model-judge execution, independent penetration testing, human labeling,
> operator UI, MCP/A2A, external managed backends, 24/7 on-call evidence,
> production deployment, HA/DR/multi-region, compliance certification, and final
> load/chaos certification remain deferred. See
> [Limitations and production gaps](docs/limitations.md) for the complete,
> honest gap list.

## Foundational invariants

- The append-only event log is the source of truth.
- Every external side effect requires a durable intent recorded first.
- Event schemas evolve additively and remain readable.
- Domain code is pure and cannot depend on infrastructure.
- Provider-neutral request and response types prevent vendor leakage.
- Safety controls are enforced by the runtime, not entrusted to prompts.
- Tenant and identity context is explicit at every boundary.
- No agent framework is used; orchestration mechanics remain visible.

## Learning path

1. **Foundation:** boundaries, invariants, tooling, local stack.
2. **Identity and tenancy:** authenticated principals, deny-by-default
   tenant authorization, policy/quota governance, and audit evidence.
3. **Durable persistence:** event ledger, inbox/outbox, projections,
   replay, and PostgreSQL tenant controls.
4. **Workers and leases:** reliable delivery, fencing, retries,
   cancellation, DLQ, and recovery.
5. **Model gateway:** provider abstraction, routing, budgets, metering,
   retry/failover, and structured outputs.
6. **Evidence connectors:** bounded acquisition, immutable provenance,
   redaction, and deterministic correlation.
7. **Specialist orchestration:** fixed roles, durable artifacts,
   deterministic DAG scheduling, critic gates, and safe abstention.
8. **Controlled remediation:** exact approvals, fenced effects,
   reconciliation, and explicit verification.
9. **Hardened sandbox execution:** bounded analysis/test/patch preparation with
   isolation, exact approval, artifacts, and cleanup.
10. **Memory and retrieval:** event-grounded three-tier memory,
    provenance-preserving pgvector RAG, cited compaction, and privacy lifecycle.
11. **Evaluation (current):** deterministic release gates, governed synthetic
    datasets, fault injection, baselines, waivers, and bounded reports.
12. **Observability and enterprise operations:** production signals, resilience,
    governance, and deployment evidence.

Across these layers the checkout-failure demo grows from fixture-backed evidence
to durable investigation, approval-gated rollback, recovery verification, and
an auditable incident update.

## Deliberate multi-agent design

Aegis is multi-agent because incident investigation has genuinely separable,
parallel, least-privilege work: telemetry, changes, runtime state, and knowledge
sources require different tools and budgets. It is not a free-form swarm.

An Incident Coordinator owns the plan, dependency DAG, state, budget, and
deterministic aggregation. Fixed specialist roles produce typed evidence,
findings, hypotheses, remediation proposals, and verification results. They
communicate only by committing those artifacts to the event ledger—never by
peer chat—and cannot spawn other agents. Read-only investigations can run in
parallel; risky tools remain approval-gated. Layer 7 implements the durable
scheduler, fixed-role execution boundary, deterministic aggregation, and
critic/finalization gates. Layer 8 consumes the proposal through policy,
authenticated human approval, a current lease fence, a provider-neutral action
port, reconciliation, and fresh-evidence verification. Specialists and models
cannot approve or expand the action.

Each layer has an acceptance gate in [the roadmap](docs/roadmap.md). The
[enterprise checklist](docs/enterprise-checklist.md) distinguishes implemented
capabilities from planned work. The
[enterprise implementation blueprint](docs/enterprise-implementation-plan.md)
defines the concrete contracts, dependencies, failure tests, rollout slices,
SLO hypotheses, and production-readiness evidence required to close every
current gap.

## Quick start

Requirements: Python 3.12+, GNU Make, and Docker with Compose.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make check
```

Run the deterministic checkout investigation with fake providers and connectors:

```bash
python -m aegis_agent_platform.agents --scenario success
python -m aegis_agent_platform.remediation --scenario approved-success
python -m aegis_agent_platform.sandbox --scenario approved-analysis
python -m aegis_agent_platform.evals check-fixtures
python -m aegis_agent_platform.evals compare
make eval-adversarial
make eval-recovery
make eval-baseline
```

These commands perform no live network call. The remediation demo executes only
a deterministic fake action and explicitly reports that it does not use
production credentials or claim exactly-once delivery. Evaluation reports are
release evidence only and do not replace event truth or runtime safety.

To inspect the local infrastructure configuration:

```bash
cp .env.example .env
make compose-config
```

See [Getting started](docs/getting-started.md) for the tutorial,
[Architecture](docs/architecture.md) for the system boundaries, and the
[identity and tenancy tutorial](docs/identity-tenancy.md) for a hands-on
walkthrough of authentication, authorization, policy, quotas, audit, and
secrets. [Reliable distributed work](docs/worker-runtime.md) covers Redis
Streams, fencing, backpressure, cancellation, reconciliation, and DLQ
operations. The [Staff-level curriculum](docs/curriculum.md),
[demo scripts](docs/demo-script.md), and
[interview question bank](docs/interview-question-bank.md) turn the roadmap
into a structured learning path.
[Provider-neutral model gateway](docs/model-gateway.md) covers provider
translation, routing, fenced budgets, structured output, failover, and billing
ambiguity.
[Evidence connectors and deterministic correlation](docs/evidence-connectors.md)
covers live-adapter configuration, bounded ingestion, provenance/redaction,
timeline correlation, webhook security requirements, and connector extension.
[Evaluation and release evidence](docs/evaluation.md) covers the deterministic
suite, fault cuts, governance, gates, reports, CLI, and explicit live gaps.

## Repository map

```text
src/aegis_agent_platform/  Importable platform boundaries
  integrations/            Dynatrace, GitHub, Kubernetes, and runbook adapters
  evidence/                Ingestion, persistence, operations, and correlation
  agents/                  Governed DAG, artifacts, engines, and projections
  event_store/             PostgreSQL ledger, inbox/outbox, and projections
  queueing/                Redis Streams and outbox publication
  runtime/                 Fenced leases, supervisor, and operator controls
  gateway/                 Catalog, routing, budgets, resilience, and metering
  providers/               Neutral protocol plus OpenAI/Anthropic/mock adapters
  evals/                   Layer 11/12 contracts, catalog, gates, and reporting
  persistence/             PostgreSQL identity/governance repositories
evals/                     Governed fixtures, dataset, baseline, and waivers
tests/                     Deterministic unit, adapter, API, and architecture tests
docs/                      Architecture, threat model, roadmap, and ADRs
deploy/                    Local observability configuration
docker/                    Container initialization assets
```

## Security and production use

The Compose stack is for local learning only. Its example values are not
production credentials or production configuration. Do not deploy this layer
as an agent platform. Report vulnerabilities according to [SECURITY.md](SECURITY.md).

## Contributing

Read [AGENTS.md](AGENTS.md) for binding design invariants and
[CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.
