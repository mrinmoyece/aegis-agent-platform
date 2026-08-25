# Start-to-expert Aegis learning path

This is the canonical route through Aegis. Do not read files randomly: at each
stage state the invariant, follow one event sequence, run the evidence, inject a
failure, and explain the tradeoff.

## 1. Foundation and authority

Read [AGENTS.md](../AGENTS.md), [architecture](architecture.md), and ADRs
[0001](adr/0001-python-monorepo.md) and
[0002](adr/0002-event-sourcing-and-durable-orchestration.md). Then inspect
`domain/events.py`, `event_store/__init__.py`, and `tests/test_architecture.py`.

Learn why the ledger is truth, projections are disposable, schemas are additive,
the domain is pure, and external effects require intent. Alternatives include
CRUD state machines and framework checkpoints; they are simpler initially but
cannot replace explicit replay, audit, and ambiguity semantics.

## 2. Identity, tenancy, and durable work

Follow [the identity tutorial](identity-tenancy.md),
[durable execution](durable-execution.md), and
[worker runtime](worker-runtime.md). Trace JWT verification to authoritative
principal resolution, tenant authorization, policy, RLS, outbox/Redis/inbox,
lease token/generation, and fenced append.

Run:

```bash
python -m pytest tests/test_identity_security.py tests/test_event_store_contracts.py
make integration-test
```

Explain why authentication does not grant tenant authority, why Redis is not
truth, and why time-based leases require fencing.

## 3. Models and evidence

Read [model gateway](model-gateway.md) and
[evidence connectors](evidence-connectors.md). Follow route/request/reservation
before provider execution, then usage/charge/release. Follow query intent,
bounded adapter response, canonical redaction/digest/provenance, cursor fencing,
and deterministic correlation.

Run `tests/test_model_gateway.py`, `tests/test_evidence.py`, and
`tests/test_evidence_adapters.py`. Compare bounded adapters with exposing vendor
SDK objects or general query languages.

## 4. Governed multi-agent investigation

Read ADR [0014](adr/0014-governed-durable-specialist-dag.md) and inspect
`agents/coordination.py`, `agents/service.py`, `agents/engines.py`, and
`tests/test_specialist_orchestration.py`.

The Incident Coordinator exclusively owns the fixed DAG, lifecycle, global
budget, and deterministic aggregation. Four read-only specialists fan out;
typed cited artifacts fan in; a critic preserves contradictions; remediation
and verification remain proposals. Specialists do not spawn, peer-chat, share
authoritative scratchpads, or acquire authority from text.

## 5. Approval, effects, and sandbox

Read ADRs [0015](adr/0015-exact-approvals-at-least-once-effects.md) and
[0016](adr/0016-hardened-ephemeral-sandbox-boundary.md), then the
[sandbox guide](sandbox-execution.md). Trace exact plan/action/policy digests,
SoD/quorum/expiry/revocation, effect intent, stable idempotency, ambiguity,
observe-before-retry, and fresh verification.

The sandbox is a separate approval-bound fixed-spec backend, not a shell. Study
argv/path/archive validation, immutable images, no network/token/host access,
resource bounds, artifact quarantine, and cleanup reconciliation.

## 6. Working, episodic, and semantic memory

Read [memory and RAG](memory-and-rag.md) and ADR
[0017](adr/0017-event-grounded-memory-and-derived-rag.md).

- **Working memory** is bounded current context and disposable projection.
- **Episodic memory** is the authoritative event history.
- **Semantic memory** is curated, tenant-scoped, cited retrieval data; its
  lexical/vector indexes and cache are derived.

Trace acceptance, scan, chunk, embedding/index intent, ACL/purpose/retention
filtering, ranking, contradiction, compaction validation, legal hold, deletion,
cache invalidation, blob erasure, and rebuild.

## 7. Evaluation, observability, UI, and protocols

Read [evaluation](evaluation.md), [observability](observability-and-slos.md),
[operator UI](operator-ui.md), and [MCP/A2A](protocols.md).

Evaluation is release evidence, telemetry is diagnostic, and the UI is a
derived BFF view. None can reconstruct or authorize runtime state. MCP adapts
curated tools/context; A2A adapts external agents. Neither replaces the internal
ledger, coordinator, policy, approvals, or fencing.

Run `make eval-adversarial eval-recovery`, `make frontend-check frontend-e2e`,
and `make protocol-check`.

## 8. Production foundations and final qualification

Read [deployment/supply chain](deployment-and-supply-chain.md),
[backup/restore](backup-restore-dr.md), [scaling](scaling-and-multi-region.md),
and [Layer 16 qualification](final-qualification.md). Inspect Kustomize,
Terraform, migration, promotion, restore, readiness, risk, performance, chaos,
compliance, and operations manifests.

Run:

```bash
make qualification
make kubernetes-check terraform-check restore-drill
```

State what each result proves locally and which live gates remain.

## Why no agent framework?

**Benefits of remaining framework-free:** event truth, retries, fences, budgets,
tool authority, citations, and failure cuts remain visible and directly
testable; provider lock-in is minimized; learners see the mechanics.

**Costs:** more custom scheduling, checkpoint, retry, visibility, and evaluation
code; slower access to ecosystem tooling; higher maintenance burden.

Reconsider only when a framework passes
[`qualification/framework-parity.json`](../qualification/framework-parity.json),
exports neutral authoritative state, preserves deterministic replay, and has a
tested escape hatch. See the
[framework comparison handoff](framework-comparison-handoff.md).

## Failure walkthrough and security exercises

1. Run `make qualification-demo`; inspect intent ordering and the archive.
2. Tamper one archive line; verify hash-chain rejection.
3. Run `make qualification-chaos` and one `fault.*` eval.
4. Replay an ambiguous action; explain why no retry occurs before observation.
5. Attempt cross-tenant evidence/memory/protocol/UI access.
6. Inject prompt-shaped evidence, schema smuggling, SSRF, path traversal,
   symlink/archive bombs, stale approvals, and capability drift through tests.
7. Drop projections/cache/Redis and rebuild from events.
8. Use the support report without treating it as truth.

## Labs, interview, glossary, and troubleshooting

Use [labs](labs.md), [interview bank](interview-question-bank.md), and
[glossary](glossary.md). For failures, start with [failure modes](failure-modes.md)
and [the runbook](runbook.md), then the boundary-specific document. If a
projection, UI, trace, cache, queue, or model transcript disagrees with the
ledger, stop and treat the ledger fold as authoritative.
