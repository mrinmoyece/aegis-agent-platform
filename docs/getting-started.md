# Getting started with Layers 1–10

This repository teaches the less visible part of agent engineering: deciding
where durability, security, and vendor boundaries live before writing
orchestration logic. Layer 1 built the package contracts and local
infrastructure. Layer 2 adds identity, tenancy, and governance. Layer 3 adds a
durable PostgreSQL ledger, inbox/outbox, projections, and production repositories.
Layer 4 adds Redis Streams delivery and fenced worker execution. Layer 5 adds
the model gateway and cost governance. Layer 6 adds bounded evidence connectors
and deterministic correlation. Layer 7 adds the governed durable specialist DAG.
Layer 8 adds exact-scope approval, fenced controlled effects, reconciliation,
and explicit postcondition verification. Layer 9 adds approval-bound hardened
ephemeral analysis, safe artifacts, reconciliation, and cleanup. Layer 10 adds
event-grounded working/episodic/semantic memory, deterministic context
compaction, and tenant-safe provenance-preserving pgvector RAG.

## What you will inspect

- `domain` owns immutable, provider-neutral event data.
- `event_store` defines ports plus the PostgreSQL ledger, inbox/outbox, and
  projection adapters; `queueing` and `runtime` implement delivery and workers.
- `identity` verifies bearer JWTs and resolves authoritative, tenant-scoped
  principals; `identity.authorization` makes deny-by-default access decisions.
- `tenancy` carries validated tenant context through every tenant-scoped port.
- `policy` evaluates tenant governance policy, risk, and quotas as a pure
  function.
- `audit` records redacted, additive, append-only security events.
- `secrets_boundary` carries secret references and opaque values, never raw
  material, through general application code.
- `control_plane` composes the above behind an authenticated `/v1/*` API plus
  liveness/readiness routes.
- `agents` defines the fixed roles, bounded DAG/replay fold, typed reasoning
  artifacts, coordinator, strict model/fake engines, and read operations.
- `remediation` defines policy, authenticated approvals, controlled execution,
  reconciliation, verification, operations, and the deterministic fake demo.
- `sandbox` defines strict contracts, policy, fenced lifecycle orchestration,
  safe workspace/artifacts, fake/Kubernetes backends, and redacted operations.
- `memory` defines authorized ingestion, neutral embedding/summarization, hybrid
  retrieval, context construction, lifecycle, quotas, and redacted operations.
- migrations `0001`–`0009` define governance, ledger, work state, leases, DLQ,
  model budgets, evidence, specialist projections, roles, grants, triggers,
  forced RLS, inbox/outbox, and projections.
- `compose.yaml` describes the local dependencies later layers will integrate.
- architecture tests prevent infrastructure from leaking into the pure domain.

The durable store, worker substrate, gateway, evidence acquisition, specialist
reasoning, and controlled remediation runtime are implemented. No live
Dynatrace/GitHub/Kubernetes/model/action call runs in the deterministic tutorial.

## Run the fast checks

Install Python 3.12+, then:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make check
```

The checks cover formatting, linting, strict typing, tests with coverage,
documentation links, repository manifests, and (from Layer 2) ordered SQL
migration validation. They do not require network services or a running
identity provider — JWT verification is exercised against deterministic
fixtures, not a live Keycloak realm.

`make check` also runs `make evals`, which gates the fake checkout
investigation, remediation, sandbox, and memory matrices, including approval
denial/expiry, policy attack, malicious input, ambiguous reconciliation,
verification failure, cleanup recovery, and crash recovery.

Run the live PostgreSQL/Redis suite against disposable services:

```bash
AEGIS_TEST_DATABASE_URL=postgresql://... \
AEGIS_TEST_REDIS_URL=redis://... \
  python -m pytest tests/integration
```

The fixture resets that database's `public` schema. Never point it at shared or
production data.

## Run the governed checkout investigation

```bash
python -m aegis_agent_platform.agents --scenario success
python -m aegis_agent_platform.agents --scenario contradiction
```

The output is a bounded redacted projection of committed typed artifacts. It
explicitly declares that it uses no live network and executes no remediation.
Try `ambiguity`, `budget_exhaustion`, and `recovery`, then compare their terminal
status and artifact list. The coordinator can propose a rollback and verification
plan, but there is no approval service, write-capable tool, sandbox, or
post-action verification inside Layer 7.

## Run the fake-only controlled remediation

```bash
python -m aegis_agent_platform.remediation --scenario approved-success
python -m aegis_agent_platform.remediation --scenario denied
python -m aegis_agent_platform.remediation --scenario ambiguous-reconciled
python -m aegis_agent_platform.remediation --scenario crash-recovery
```

Also try `expired`, `verification-failure`, and `policy-attack`. The output is a
bounded event/status summary and explicitly reports fake capability. It uses no
network or production credential. Arbitrary production commands do not exist;
the only official action adapter is fixed-shape
Kubernetes deployment rollout restart and is not invoked by this tutorial.

## Run the fake-only hardened sandbox

```bash
python -m aegis_agent_platform.sandbox --scenario approved-analysis
python -m aegis_agent_platform.sandbox --scenario policy-denied
python -m aegis_agent_platform.sandbox --scenario prompt-injection
python -m aegis_agent_platform.sandbox --scenario ambiguous-provisioning
python -m aegis_agent_platform.sandbox --scenario output-quarantine
```

Also try `malicious-archive`, `timeout`, `oom`, `cancellation`, and
`cleanup-recovery`. The fake launches no process and uses no network. Follow the
event ordering and redacted result, then read the
[sandbox tutorial and runbook](sandbox-execution.md). The official Kubernetes
adapter is not invoked and no cluster isolation is claimed.

## Run the fake-only memory and RAG demo

```bash
python -m aegis_agent_platform.memory
```

Inspect cited prior-incident/runbook retrieval, contradiction and poisoning
handling, untrusted context delimiters, compaction, tenant denial, and derived
purge. The demo uses deterministic eight-dimensional embeddings and no network,
credential, or live model. Continue with [memory and RAG](memory-and-rag.md).

## Try the identity, tenancy, and governance slice

The [identity and tenancy tutorial](identity-tenancy.md) walks through
building a deterministic signed JWT, verifying it, resolving it to a
principal, making a deny-by-default authorization decision, evaluating a
tenant policy and quotas, and inspecting the resulting redacted audit trail —
all without any external service. Read it after this page for a hands-on tour
of the newest code.

## Inspect the local stack

Docker Compose substitutes local-only values from `.env.example`:

```bash
cp .env.example .env
make compose-config
docker compose up --build
```

After startup:

| Surface | URL | Purpose |
| --- | --- | --- |
| Aegis liveness | <http://localhost:8080/healthz> or `/health/live` | Process liveness |
| Aegis readiness | <http://localhost:8080/readyz> or `/health/ready` | Configuration readiness |
| Aegis authenticated API | <http://localhost:8080/v1/me> | Requires a valid bearer token; see below |
| Keycloak | <http://localhost:8081> | Local identity provider |
| Prometheus | <http://localhost:9090> | Metrics inspection |
| Grafana | <http://localhost:3000> | Local dashboards |

The imported Keycloak realm has no users and self-registration disabled, so it
demonstrates the expected configuration shape (issuer, JWKS URL, audience) for
`RemoteJwksProvider` rather than a ready-to-use login flow. Calling `/v1/me`
on the module-level demo application returns `503 authentication_not_configured`;
obtaining a real token and wiring an authentication service through
`RemoteJwksProvider` is a deployment exercise, not something the fast local
checks assume works. PostgreSQL initializes all forward migrations. Production
composition must explicitly inject the PostgreSQL repositories and event store;
the module-level demo application remains fail-closed and does not invent
development identities.

Stop and remove containers with `docker compose down`. Add `--volumes` only when
you intentionally want to delete local data.

## Read next

Read `durable-execution.md`, `worker-runtime.md`, ADR 0010/0011,
ADR 0014, `failure-modes.md`, and `runbook.md`, then
compare roadmap gates with `enterprise-checklist.md`.
