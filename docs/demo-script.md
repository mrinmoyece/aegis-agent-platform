# Canonical incident and demo scripts

## Current implementation

Layer 1 and Layer 2 can demonstrate architecture contracts, local
infrastructure, tests, and an authenticated control-plane vertical slice for
identity, tenancy, and governance (JWT verification, deny-by-default
authorization, policy/quota decisions, redacted audit events — see
`identity-tenancy.md`). The demo cannot yet query Dynatrace or GitHub, run
specialists, approve actions, roll back a deployment, or update a real
incident, and the identity/tenancy slice runs against deterministic fixtures
rather than a live-network Keycloak realm. Future steps below are the
acceptance narrative for later layers.

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

## 15-minute foundation demo

- **0–2:** Give the elevator pitch and state current Layer 1/2 limitations.
- **2–5:** Walk the package map and pure-domain dependency test.
- **5–8:** Show typed evidence adapters and fixed agent artifacts.
- **8–11:** Explain event truth, intent-before-effect, and fenced leases.
- **11–13:** Render Compose, call `/healthz`/`/readyz`, then present a signed
  JWT fixture to `/v1/me` and `/v1/tenants/{tenant_id}/policy`.
- **13–15:** Trace the future checkout scenario and point to roadmap gates.

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

The 60-minute version is entirely planned until its referenced layers and tests
exist.
