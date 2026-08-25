# ADR 0027: Final local enterprise qualification boundary

- **Status:** Accepted
- **Date:** 2026-08-14

## Context

Layers 1-15 implement the architecture in reviewable slices, but their
deterministic demos are separate and their release evidence is spread across
tests, evaluation reports, runbooks, and deployment manifests. A final layer
must prove that the implemented boundaries compose without turning release
evidence into runtime authority or claiming live production results.

## Decision

Layer 16 adds a no-network checkout-incident qualification runner. It drives
authenticated intake, tenant policy, durable evidence queries and correlation,
the budgeted model gateway, the fixed specialist DAG and critic, memory,
two-person approval, ambiguous-effect reconciliation, verification, sandbox
quarantine, MCP, A2A, the operator view, audit, replay, and a signed support
report through existing service boundaries and deterministic fakes.

Every subsystem retains its own authoritative event stream. The runner exports
the complete redacted envelopes into an atomic hash-chained JSONL archive. That
archive is release evidence, not a second runtime ledger. A disposable
qualification projection is built from the captured envelopes, the archive is
reloaded and verified, and the projection digest must rebuild identically.
`ReplayDebugger` reads the specialist stream from the verified archive and
performs no mutation, model, tool, sandbox, or external call.

Machine-readable readiness, residual-risk, chaos, performance, compliance, and
future-framework parity manifests are validated in required CI. Local load
numbers are regression smoke only. Environment and live gates remain explicit.

## Consequences

- One command demonstrates the implemented checkout flow and persists replayable
  evidence without production credentials.
- Intent ordering, citation, tenant, ambiguity, quarantine, replay, and
  projection-convergence assertions become release gates.
- The Python 3.14.7 base is confirmed fixed upstream; the temporary risk waiver
  becomes exact, short-lived, per-platform Grype false-positive evidence.
- The repository still does not prove production SLOs, scale, identity,
  sandbox isolation, PKI/federation, cloud apply, managed recovery, on-call
  operation, compliance, or certification.
- A future framework-first repository must meet the same parity manifests. Aegis
  does not add an agent framework.

## Evidence

- `make qualification`
- `tests/test_final_qualification.py`
- `qualification/release-readiness.json`
- `qualification/residual-risks.json`
- `qualification/chaos-matrix.json`
- `qualification/performance-budgets.json`
- `qualification/compliance-map.json`
- `qualification/framework-parity.json`
