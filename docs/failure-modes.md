# Durable-storage failure modes

| Failure | Detection | Safe response |
| --- | --- | --- |
| Stale aggregate version | `ConcurrencyError(expected, actual)` and conflict counter | Re-read and re-decide; never blind-retry a command |
| PostgreSQL unavailable, serialization failure, or deadlock | `TransientStorageError` | Retry the whole transaction with bounded policy |
| Constraint, schema, or malformed projection event | `PermanentStorageError` | Stop, quarantine input, and investigate |
| Process exits during append | Transaction rollback | Replay; no partial event batch or outbox row commits |
| Duplicate incoming delivery | Inbox primary key | Return first committed version without reapplying |
| Publisher dies while leased | Lease expiry | Claim again only below max attempts; otherwise dead-letter |
| Publisher dies after Redis `XADD` | Outbox remains leased/pending | Republish deterministic message identity; inbox deduplicates |
| Redis outage or timeout | Classified retryable queue error and publish-failure metric | Release outbox lease with bounded backoff; do not invent publication |
| Poison Redis envelope | Size/schema decoder rejection | Quarantine/inspect bounded metadata; never pass payload to a handler |
| Delivery committed to Redis but inbox transaction rolls back | Pending entry remains unacknowledged | Reclaim after idle threshold and retry the inbox transaction |
| Two workers claim one item | PostgreSQL `FOR UPDATE SKIP LOCKED` and CAS state | One lease wins; the loser records a claim conflict and does not execute |
| Heartbeat stops | PostgreSQL expiry and oldest-active-lease metric | Reconcile to retry state and publish again |
| Stale worker resumes after reclaim | Token/generation mismatch in `append_fenced` | Reject every state-changing append; preserve conflict evidence |
| Worker handler raises unexpectedly | Supervisor exception boundary | Append classified `worker_bug` failure; keep supervisor alive |
| Retry limit exhausted | Durable attempt reaches max | Append failure and dead-letter events; require approved requeue |
| Cancellation races success | Durable cancellation flag checked before outcome | Record cancelled; never let a late success overwrite it |
| Graceful drain times out | Active-task count remains nonzero | Stop new claims, preserve leases, then allow expiry/recovery |
| Orphan Redis pending entry | Pending idle age exceeds threshold | Bounded `XAUTOCLAIM`; PostgreSQL claim/fence still decides authority |
| Outbox exhausts attempts | `dead_letter` projection row and bounded error code | Operator investigates; event truth is unchanged |
| Projection crashes | Checkpoint remains at prior committed page | Resume or rebuild from ledger |
| Sequence/cursor corruption | Replay gap/ordering exception | Stop consumption and invoke storage incident runbook |
| Cross-tenant context or confused deputy | Forced RLS returns no row or rejects write | Deny and audit; never retry under broader role |
| Event/audit mutation | Missing grants and append-only trigger | Treat attempt as an integrity/security incident |
| Ambiguous external completion | Intent exists without result | Reconcile using idempotency key and target state; never invent success |

Global event positions order commits but may contain numbers unused after a
rolled-back PostgreSQL identity allocation. That is not corruption. A per-
aggregate sequence gap is corruption.

The unresolved window is an external target accepting a future effect after its
intent but before Aegis records the result. Target idempotency or explicit
reconciliation is mandatory; Redis/inbox deduplication alone cannot solve it.
