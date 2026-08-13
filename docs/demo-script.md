# Canonical incident and demo scripts

## Current implementation

Layers 1–10 can demonstrate architecture contracts, local
infrastructure, tests, and an authenticated control-plane vertical slice for
identity, tenancy, and governance (JWT verification, deny-by-default
authorization, policy/quota decisions, redacted audit events), plus live
PostgreSQL append/replay, Redis publication/consumption, duplicate inbox
delivery, lease races, stale fencing, cancellation/retry/DLQ, forced RLS,
projection rebuild, and redacted ledger/timeline APIs. Layer 5 also demonstrates
the mock model diagnostic, route/request/reservation event ordering, strict
structured output, bounded retry/fallback/circuits, normalized usage, versioned
cost, and authorized model/usage/health views. Layer 6 adds mocked connector
queries, redaction/dedup/quarantine, citations, and deterministic timelines. The
Layer 7 CLI runs a fixed ten-node checkout DAG, durable typed artifacts,
critic/finalization gates, abstention, budget exhaustion, and retry recovery.
The Layer 8 CLI adds deny-by-default policy, exact two-person approval, fenced
controlled effects, ambiguous reconciliation, and explicit verification. The
Layer 9 CLI adds approval-bound analysis, malicious input denial, bounded
resource outcomes, artifact quarantine, ambiguous provisioning, and cleanup
recovery. The demos use fake providers/connectors/actions/sandboxes only and
cannot update a real incident.
Layer 10 adds curated memory ingestion, cited hybrid retrieval, contradiction/
poisoning handling, bounded compaction, tenant isolation, and derived purge with
deterministic providers.
The identity/tenancy slice runs against deterministic fixtures rather than a
live-network Keycloak realm. Those omissions are later-layer acceptance work.
Layer 11 adds the unified `aegis_agent_platform.evals` harness, governed 91-case
dataset/baseline/waiver artifacts, all 22 named fault cuts, deterministic hard
gates, bounded reports/telemetry, and the current CLI. It makes no live provider,
connector, production, or model-judge qualification claim.

## Canonical story: checkout failures after deployment

1. A new checkout deployment completes.
2. Dynatrace reports elevated checkout failures and latency.
3. The coordinator creates a bounded investigation DAG.
4. Telemetry, change, runtime, and knowledge investigators collect cited,
   read-only evidence in parallel.
5. A hypothesis links a specific deployed change to the failing trace path.
6. The reviewer challenges timing, topology, counter-evidence, and confidence.
7. The remediation planner proposes an exact controlled action and expected recovery.
8. An operator approves that proposal for that tenant, incident, version, and
   expiry.
9. The runtime records intent, invokes the controlled action idempotently, and
   records the outcome.
10. The verification agent checks errors, latency, traces, and topology over a
    defined window, then the incident record is updated.

## Run the Layer 7 fake checkout demo

```bash
python -m aegis_agent_platform.agents --scenario success
python -m aegis_agent_platform.agents --scenario contradiction
python -m aegis_agent_platform.agents --scenario budget_exhaustion
make evals
```

The JSON explicitly reports `uses_live_network: false` and
`executes_remediation: false`. Inspect the redacted artifact list and terminal
status; do not present the fixture conclusion as a live diagnosis.

## Run the Layer 8 fake controlled-action demo

```bash
python -m aegis_agent_platform.remediation --scenario approved-success
python -m aegis_agent_platform.remediation --scenario denied
python -m aegis_agent_platform.remediation --scenario ambiguous-reconciled
python -m aegis_agent_platform.remediation --scenario verification-failure
python -m aegis_agent_platform.remediation --scenario policy-attack
python -m aegis_agent_platform.remediation --scenario crash-recovery
```

This performs only deterministic fake effects. Show that two distinct approvers
bind the exact digest/target, intent precedes effect, ambiguous completion is
reconciled, and provider acceptance does not establish verification.

## 15-minute implementation demo

- **0–2:** Give the elevator pitch and state current Layer 11 limitations.
- **2–5:** Walk the package map and pure-domain dependency test.
- **5–8:** Show the fixed DAG, role policies, typed artifacts, and replay fold.
- **8–10:** Run the PostgreSQL/Redis race tests; show stale-fence rejection and
  explain why Redis, outbox state, and acknowledgements are not truth.
- **10–12:** Run specialist success; inspect citations, critique, proposal-only
  authority, and deterministic ordering.
- **12–15:** Run remediation and sandbox success/ambiguity; show exact approval,
  lifecycle intent, reconciliation, fake-only execution, and cleanup.

## Run the Layer 9 fake sandbox demo

```bash
python -m aegis_agent_platform.sandbox --scenario approved-analysis
python -m aegis_agent_platform.sandbox --scenario policy-denied
python -m aegis_agent_platform.sandbox --scenario prompt-injection
python -m aegis_agent_platform.sandbox --scenario malicious-archive
python -m aegis_agent_platform.sandbox --scenario ambiguous-provisioning
python -m aegis_agent_platform.sandbox --scenario output-quarantine
python -m aegis_agent_platform.sandbox --scenario cleanup-recovery
```

Show exact Layer 7/8 linkage and digest approval, provisioning/start/cleanup
intent ordering, stable reconciliation identity, bounded redacted outputs, and
quarantine. State explicitly that the fake launches no process and that the
Kubernetes manifest is not evidence of deployed cluster isolation.

## Run the Layer 10 fake memory demo

```bash
python -m aegis_agent_platform.memory
```

Show proposal/acceptance and intent ordering, exact citations, deterministic
hybrid ranking, injection-as-data delimiters, contradiction abstention,
compaction fallback, cross-tenant denial, and deletion. State that the embedding
profile is deterministic/eight-dimensional and no live provider or production
blob store is used.

## Run the Layer 11 deterministic evaluation demo

```bash
python -m aegis_agent_platform.evals list
python -m aegis_agent_platform.evals check-fixtures
python -m aegis_agent_platform.evals run --tag adversarial
python -m aegis_agent_platform.evals run --case fault.after_intent_append
python -m aegis_agent_platform.evals compare
make eval-adversarial
make eval-recovery
make eval-baseline
```

Walk through a synthetic checkout regression at a named crash cut. Show the
hard safety gate, immutable baseline comparison, non-waivable safety behavior,
scoped expiring non-safety waiver, and fixture digest/quarantine checks. Contrast
required hermetic CI with the guarded optional-live boundary. State that no live
adapter is registered, no model judge executes, and no evaluator result becomes
runtime truth.

## 30-minute architecture interview demo

- **0–5:** Product, current status, and canonical incident.
- **5–10:** Trust boundaries, tenancy, identity, and evidence provenance.
- **10–16:** Multi-agent DAG, limits, ledger-only communication, and critique.
- **16–22:** Durable events, duplicate delivery, intent, fencing, and recovery.
- **22–26:** Approval, controlled rollback, verification, and threat controls.
- **26–30:** Implemented deterministic evaluation gates, deferred SLOs,
  production gaps,
  alternatives, and questions.

## 60-minute end-to-end target demo

- **0–10:** Architecture and adversarial assumptions.
- **10–20:** Ingest the checkout problem and inspect cited Dynatrace evidence.
- **20–30:** Run parallel read-only specialists and inspect deterministic merge.
- **30–38:** Challenge the hypothesis with conflicting evidence.
- **38–46:** Review the exact rollback, approval binding, and durable intent.
- **46–52:** Execute the controlled action and inject a duplicate delivery.
- **52–57:** Verify recovery over multiple signals and update the incident.
- **57–60:** Show event replay, cost, and redacted evaluation/baseline evidence;
  close with unresolved production gaps.

Investigation, critique, proposal, approval, fake controlled execution,
reconciliation, postcondition verification, bounded fake sandbox analysis, and
event-grounded memory/RAG and Layer 11 deterministic evaluation are implemented.
Live systems, production credentials/cluster sandbox controls, live model/
connector qualification, production encrypted blob/key storage, model-judge
execution, independent penetration testing, large-scale human labeling, operator
UI, MCP/A2A, observability/SLOs, HA/DR/multi-region, final load/chaos
certification, and incident update remain planned, so the full production
narrative is not yet claimable.
