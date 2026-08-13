# ADR 0008: Use ledger-mediated fixed-role multi-agent coordination

- Status: Accepted
- Date: 2026-08-13

## Context

Incident investigation has independent telemetry, change, runtime, and
knowledge work that benefits from parallelism and least-privilege access.
Free-form agent swarms introduce recursive spawning, opaque peer conversations,
race-dependent outcomes, authority creep, and unbounded cost.

## Decision

Use a fixed set of incident roles coordinated by one Incident Coordinator. The
coordinator owns an explicit dependency DAG, state, aggregate budget, and
deterministic merge policy. Every specialist receives a capability allowlist,
step/token budget, and timeout. Specialists cannot spawn agents or communicate
directly.

Specialists exchange only typed, tenant- and incident-scoped artifacts committed
to the event ledger. Findings and hypotheses cite immutable evidence and state
confidence and conflicts. Independent read-only assignments may run in
parallel. A reviewer challenges hypotheses before a remediation planner emits a
proposal. Risky action requires separately persisted human approval, durable
intent, controlled execution, and post-action verification.

## Consequences

The design is multi-agent because work and authority are genuinely separable,
not to simulate a conversational organization. Ledger mediation adds latency
but makes communication replayable and auditable. Fixed roles constrain
adaptability; changing them requires a reviewed contract. Tests must vary task
completion order, timeouts, conflicting evidence, and duplicate delivery while
proving deterministic state and bounded authority.

Layer 1 defines only roles, artifact types, assignments, limits, and a ledger
port. It does not implement agent execution or claim these controls are enforced.
