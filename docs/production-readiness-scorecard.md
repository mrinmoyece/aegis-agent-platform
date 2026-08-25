# Production-readiness scorecard

The canonical scorecard is
[`qualification/release-readiness.json`](../qualification/release-readiness.json).
It intentionally has **no aggregate percentage or score**: a green average could
hide one critical identity, isolation, recovery, sandbox, or supply-chain
blocker.

## Status semantics

| Status | Meaning |
| --- | --- |
| Implemented | Code/config exists; execution is not implied |
| Locally Verified | Bounded deterministic local or CI evidence passed |
| Environment-Gated | Code fails closed until deployment prerequisites pass |
| Live Evidence Required | A live or production-like control must be exercised |
| Deferred/Not Claimed | Capability is absent or intentionally outside scope |

Each category names an owner, evidence commands, blockers, and rollback
criterion. Categories cover architecture, security, identity, tenancy,
reliability, data, model safety, connectors, agents, approvals/actions,
sandbox, memory, evals, observability/SLO, operator UI, MCP/A2A, supply chain,
deployment, HA/DR, multi-region, performance, compliance, operations, and
repository governance.

## Current decision

Layer 16 is locally qualified but `production_ready` remains `false`.
Architecture, core security contracts, tenancy, deterministic reliability,
data/replay, model gateway, connectors, agents, approvals, memory, evals, UI,
protocol boundaries, and bounded performance are locally verified.

Identity, sandbox, observability/SLO, supply-chain promotion, deployment, and
operations are environment-gated. Managed HA/DR, compliance, and branch-policy
evidence are live requirements. Multi-region operation and active-active writes
are not claimed.

## Hard go-live gates

The manifest fails closed on six independent gates:

1. enforced branch protection/rulesets and required checks;
2. live identity, key rotation, session revocation, and tenant binding;
3. managed restore with keys, hashes, sequences, fences, rebuild, and redrive;
4. live sandbox admission/runtime/network/artifact enforcement;
5. representative capacity, SLO, paging, and rollback evidence;
6. protected-branch signed, attested, scanned immutable promotion and admission.

No PR check can prove those live outcomes. The PR publish/sign job is expected to
remain skipped; protected-branch-only signing is explicitly unproven here.
