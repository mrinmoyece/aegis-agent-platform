# ADR 0014: Govern specialist work through a durable deterministic DAG

- Status: Accepted
- Date: 2026-08-13

## Context

Incident investigation benefits from parallel telemetry, change, runtime, and
knowledge analysis, but free-form agent swarms hide authority, state, retries,
cost, and disagreement. Model output and evidence are untrusted. At-least-once
delivery, worker crashes, provider failures, and completion-order races must not
change the authoritative incident conclusion.

## Decision

The Incident Coordinator exclusively owns one immutable, bounded, acyclic
investigation plan. Assignments use eight fixed roles, code-defined capability
sets, declared dependencies, output artifact kinds, token/step/size/iteration
budgets, and timeouts. Specialists cannot spawn peers, change the graph, transfer
authority, or communicate outside typed artifacts in the event ledger.

Record dispatch and model-call intent before execution. Append artifact and task
outcomes only under the active Layer 4 lease token and generation. Rebuild the
investigation by folding additive events; PostgreSQL run/task/artifact
projections are tenant-RLS read models, not truth. Stable plan ordinal and
artifact ordering make fan-out/fan-in independent of task completion order.

Artifacts are immutable, provider-neutral, tenant/incident/run/task linked,
schema-versioned, redacted, bounded, event-timestamped, and carry provenance,
citations, and calibrated confidence where applicable. A critic gate rejects
unsupported claims and unresolved contradictions. Finalization requires a cited
hypothesis above the configured confidence threshold and an accepted critique;
otherwise the coordinator abstains or escalates.

Layer 7 may emit only a remediation proposal and a verification plan. It has no
approval service, write-capable tool, remediation executor, sandbox, memory/RAG,
operator UI, MCP/A2A endpoint, or live provider/connector claim.

## Consequences

Replay, retries, cancellation, stale workers, budget exhaustion, malformed model
output, and specialist bugs fail explicitly without crashing the supervisor or
creating a second state store. Contradictions remain visible instead of being
averaged into false certainty. Deterministic fake scenarios can exercise the
checkout workflow without credentials or network access.

The fixed graph is less flexible than self-organizing agents, and every new role
or transition requires an additive contract and policy review. PostgreSQL
projection rebuild uses the maintenance role. Provider acceptance can still
create billing ambiguity, so existing model-gateway reconciliation rules apply.
Actual remediation and post-action verification remain later-layer effects with
durable approval, intent, idempotency, and reconciliation requirements.
