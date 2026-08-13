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

> **Current status: Layer 3 — Durable PostgreSQL ledger.** Layer 2 identity and
> governance now have production PostgreSQL repositories and live forced-RLS
> tests. Layer 3 adds additive immutable event envelopes, expected-version
> atomic append, transactional inbox/outbox, deterministic replay, rebuildable
> projections/checkpoints, append-only event/audit enforcement, tenant-scoped
> ledger/timeline read APIs, and PostgreSQL 16 migration/concurrency tests.
> Redis workers, model calls, live evidence connectors, agent execution, and
> external effects remain planned. See
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
2. **Identity and tenancy (current):** authenticated principals, deny-by-default
   tenant authorization, policy/quota governance, and audit evidence.
3. **Durable persistence (current):** event ledger, inbox/outbox, projections,
   replay, and PostgreSQL tenant controls.
4. **Workers and leases:** reliable claiming, retries, and recovery.
5. **Tools and sandboxing:** policy-gated effects and isolation.
6. **Memory and retrieval:** tenant-safe context with provenance.
7. **Evaluation and observability:** quality gates, traces, and cost signals.
8. **Enterprise operations:** resilience, governance, and deployment evidence.

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
parallel; risky tools remain approval-gated. These contracts are defined, but
the durable scheduler, agent execution, and deterministic aggregation that
would run the workflow remain planned.

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

To inspect the local infrastructure configuration:

```bash
cp .env.example .env
make compose-config
```

See [Getting started](docs/getting-started.md) for the tutorial,
[Architecture](docs/architecture.md) for the system boundaries, and the
[identity and tenancy tutorial](docs/identity-tenancy.md) for a hands-on
walkthrough of authentication, authorization, policy, quotas, audit, and
secrets. The [Staff-level curriculum](docs/curriculum.md),
[demo scripts](docs/demo-script.md), and
[interview question bank](docs/interview-question-bank.md) turn the roadmap
into a structured learning path.

## Repository map

```text
src/aegis_agent_platform/  Importable platform boundaries
  integrations/            Typed future integration ports; no connectors yet
  agents/                  Fixed roles and typed coordination artifacts
  event_store/             PostgreSQL ledger, inbox/outbox, and projections
  persistence/             PostgreSQL identity/governance repositories
tests/                     Fast foundation and architecture tests
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
