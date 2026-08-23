# ADR 0020: Ledger-grounded replay debugging

**Status:** Accepted

## Decision

Debug authoritative run state only from tenant-scoped event streams. The replay
debugger is read-only by default, validates ordering/schema/cursor/hash facts,
folds at bounded points, compares projections as derived state, and separates
event facts from interpretations. It has no tool, model, connector, sandbox, or
effect execution capability.

## Consequences

Investigations remain complete when telemetry is absent. Support reports are
bounded, pseudonymized, digested, optionally signed, and access-audited.
Corruption stops replay and projection rebuilding; history is never repaired by
editing committed events.
