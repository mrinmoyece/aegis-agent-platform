# Future framework-first comparison handoff

This specification is for a **separate future repository**. Aegis must not add
LangGraph, LangSmith, Langfuse, Temporal, LangChain, CrewAI, or AutoGen merely to
claim parity.

The canonical reusable contract is
[`qualification/framework-parity.json`](../qualification/framework-parity.json).
Candidate experiments may evaluate LangGraph with LangSmith or Langfuse,
Temporal, or a carefully bounded hybrid.

## Comparison rule

Measure the same checkout fixture, event contracts, eval case IDs, chaos matrix,
performance profiles, readiness categories, and residual risks. Compare code
removed, operational burden, replay digest, latency/throughput/error/cost,
failure convergence, tenant isolation, safety, citations, approval, sandbox,
protocols, supply chain, and upgrade/hosting/lock-in.

A framework may remove generic graph scheduling, checkpoint, retry/timer,
visibility, and experiment plumbing. It cannot own or weaken tenant identity,
RLS, authorization, policy, event schemas, intent, fencing, idempotency,
reconciliation, citations, critic policy, deterministic aggregation, budgets,
approvals, controlled adapters, sandbox, deletion, protocol trust, telemetry
redaction, or go-live evidence.

## Lock-in and escape

Reject a framework if replay requires opaque serialized objects, authoritative
state cannot export through neutral versioned contracts, outage can bypass
policy/effects, self-hosting/data ownership is unacceptable, or a migration
cannot rebuild identical projections. Rehearse export and replacement before
adoption, not after an outage or pricing change.
