# Durable-storage failure modes

| Failure | Detection | Safe response |
| --- | --- | --- |
| Stale aggregate version | `ConcurrencyError(expected, actual)` and conflict counter | Re-read and re-decide; never blind-retry a command |
| PostgreSQL unavailable, serialization failure, or deadlock | `TransientStorageError` | Retry the whole transaction with bounded policy |
| Constraint, schema, or malformed projection event | `PermanentStorageError` | Stop, quarantine input, and investigate |
| Process exits during append | Transaction rollback | Replay; no partial event batch or outbox row commits |
| Duplicate incoming delivery | Inbox primary key | Return first committed version without reapplying |
| Publisher dies while leased | Lease expiry | Claim again only below max attempts; otherwise dead-letter |
| Outbox exhausts attempts | `dead_letter` projection row and bounded error code | Operator investigates; event truth is unchanged |
| Projection crashes | Checkpoint remains at prior committed page | Resume or rebuild from ledger |
| Sequence/cursor corruption | Replay gap/ordering exception | Stop consumption and invoke storage incident runbook |
| Cross-tenant context or confused deputy | Forced RLS returns no row or rejects write | Deny and audit; never retry under broader role |
| Event/audit mutation | Missing grants and append-only trigger | Treat attempt as an integrity/security incident |
| Ambiguous external completion | Intent exists without result | Reconcile using idempotency key and target state; never invent success |

Global event positions order commits but may contain numbers unused after a
rolled-back PostgreSQL identity allocation. That is not corruption. A per-
aggregate sequence gap is corruption.
