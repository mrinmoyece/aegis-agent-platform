# ADR 0003: Use durable work with fenced leases

- Status: Accepted
- Date: 2026-08-13

## Context

Workers crash and networks partition. A queue acknowledgement alone cannot
prove exclusive ownership during long agent operations.

## Decision

Use at-least-once durable delivery with time-bounded, renewable leases. Every
lease carries a fencing token checked by authoritative writes. Expired work is
recoverable; acknowledgement requires the current lease.

PostgreSQL is the initial correctness store. Redis may optimize notification or
ephemeral coordination but cannot become a source of truth.

Layer 4 implements this decision with a shared Redis Stream, deterministic
message identity, PostgreSQL inbox deduplication, `work_leases` token/generation
CAS, fenced event append, heartbeat, expiry/reclaim, bounded retry, cancellation,
and DLQ projections. ADR 0011 records the shared-stream cardinality tradeoff.

## Consequences

Handlers must be idempotent or reconcilable. Lease expiry and worker pauses are
normal test cases. Exactly-once processing is not claimed.
