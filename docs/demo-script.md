# Canonical incident and demo scripts

## Current implementation

Layers 1–7 can demonstrate architecture contracts, local
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
The demo uses fake providers/connectors only and cannot approve actions, roll
back a deployment, verify a post-action recovery, or update a real incident.
The identity/tenancy slice runs against deterministic fixtures rather than a
live-network Keycloak realm. Those omissions are later-layer acceptance work.

## Canonical story: checkout failures after deployment

1. A new checkout deployment completes.
2. Dynatrace reports elevated checkout failures and latency.
3. The coordinator creates a bounded investigation DAG.
4. Telemetry, change, runtime, and knowledge investigators collect cited,
   read-only evidence in parallel.
5. A hypothesis links a specific deployed change to the failing trace path.
6. The reviewer challenges timing, topology, counter-evidence, and confidence.
7. The remediation planner proposes an exact rollback and expected recovery.
8. An operator approves that proposal for that tenant, incident, version, and
   expiry.
9. The runtime records intent, invokes the controlled rollback idempotently, and
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

## 15-minute implementation demo

- **0–2:** Give the elevator pitch and state current Layer 7 limitations.
- **2–5:** Walk the package map and pure-domain dependency test.
- **5–8:** Show the fixed DAG, role policies, typed artifacts, and replay fold.
- **8–10:** Run the PostgreSQL/Redis race tests; show stale-fence rejection and
  explain why Redis, outbox state, and acknowledgements are not truth.
- **10–13:** Run success then contradiction; inspect cited hypothesis, critic,
  safe abstention, proposal-only remediation, and deterministic ordering.
- **13–15:** Run recovery and budget exhaustion; show durable retry/budget
  outcomes and that no network or effect adapter was invoked.

## 30-minute architecture interview demo

- **0–5:** Product, current status, and canonical incident.
- **5–10:** Trust boundaries, tenancy, identity, and evidence provenance.
- **10–16:** Multi-agent DAG, limits, ledger-only communication, and critique.
- **16–22:** Durable events, duplicate delivery, intent, fencing, and recovery.
- **22–26:** Approval, controlled rollback, verification, and threat controls.
- **26–30:** Evaluation, SLOs, production gaps, alternatives, and questions.

## 60-minute end-to-end target demo

- **0–10:** Architecture and adversarial assumptions.
- **10–20:** Ingest the checkout problem and inspect cited Dynatrace evidence.
- **20–30:** Run parallel read-only specialists and inspect deterministic merge.
- **30–38:** Challenge the hypothesis with conflicting evidence.
- **38–46:** Review the exact rollback, approval binding, and durable intent.
- **46–52:** Execute the controlled action and inject a duplicate delivery.
- **52–57:** Verify recovery over multiple signals and update the incident.
- **57–60:** Show event replay, cost/evaluation results, and unresolved gaps.

The investigation/critique/proposal portion is implemented with fakes. Approval,
rollback execution, post-action verification, live systems, and incident update
remain planned, so the full 60-minute production narrative is not yet claimable.
