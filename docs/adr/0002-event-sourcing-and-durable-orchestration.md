# ADR 0002: Use event sourcing for durable orchestration

- Status: Accepted
- Date: 2026-08-13

## Context

Agent runs include long waits, external effects, retries, and uncertain
outcomes. In-memory orchestration cannot explain or recover these states.

## Decision

The append-only event log is authoritative. Domain state is a deterministic
fold of events. Record a durable intent before each side effect, then record its
outcome. Event schemas evolve additively and old events remain readable.

## Consequences

Recovery and audit become explicit. Implementations must handle optimistic
concurrency, idempotency, projections, and ambiguous outcomes. Added complexity
is accepted rather than hidden behind best-effort task execution.
