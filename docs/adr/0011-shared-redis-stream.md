# ADR 0011: Use one shared tenant-bound Redis work stream

- Status: Accepted
- Date: 2026-08-13

## Context

A stream per tenant isolates transport ordering but creates unbounded Redis
key/consumer-group cardinality and makes fleet-wide pending inspection expensive.
A shared stream has bounded topology but requires tenant validation and an
explicit fairness policy.

## Decision

Use one versioned shared Redis Stream and consumer group. Every envelope carries
validated tenant and deterministic message identity. PostgreSQL RLS, inbox
deduplication, work state, leases, and fencing remain the correctness boundary.
Workers schedule decoded tenant queues round-robin and enforce the Layer 2
concurrency quota.

## Consequences

Redis provides global transport order but no authoritative work order. Fairness
is process-local and approximate across a fleet. A noisy tenant can occupy Redis
pending entries, so reads/reclaim are bounded and pending depth/age are monitored.
If strict distributed weighted fairness becomes necessary, it requires a new
additive scheduler design rather than silently creating per-tenant streams.
