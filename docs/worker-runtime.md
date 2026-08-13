# Reliable distributed work

Layer 4 implements delivery and worker reliability only. It does not invoke
models, run specialists, call live connectors, retrieve memory, or perform
remediation.

## Delivery semantics

A request appends `work.requested.v1` and an outbox row before execution is
possible. `OutboxPublisher` claims at most 100 PostgreSQL rows with a renewable
database lease, serializes a tenant-bound `MessageEnvelope`, and `XADD`s it to
Redis. Only then does it mark the outbox row published.

The message UUID is deterministic across publication retries. A crash after
`XADD` and before database acknowledgement produces a duplicate stream entry
with the same logical identity. `append_from_inbox` commits
`(tenant, source, message_id)` with the published transition; duplicate
deliveries do not repeat the transition. Workers `XACK` and `XDEL` only after a
durable outcome or retry/DLQ schedule commits. The deployment supports one
enforced consumer group, so acknowledged-entry deletion does not bypass another
group.

This is **at-least-once delivery**, never exactly-once execution.

## Redis Streams topology and backpressure

ADR 0011 selects one shared stream and consumer group. This bounds stream/group
cardinality and provides a single pending-entry list. Envelopes carry tenant,
work, correlation, causation, event, schema, and deterministic message identity.
Malformed, excessively nested, over-256-KiB, or PostgreSQL-mismatched envelopes
are quarantined with payload-free reason metadata, acknowledged, and deleted
from the source stream.

Reads, pending inspection, and reclaim are bounded. Reclaim requires an idle
threshold and exposes Redis delivery count for diagnosis. The supervisor queues
decoded work FIFO per tenant and schedules non-empty tenants round-robin, then
enforces a global semaphore and Layer 2 `max_concurrent_runs` per tenant.
Fairness is process-local, not a strict distributed tenant service guarantee.

Production Redis must use authentication, TLS (`rediss://`), bounded pools and
timeouts, AOF persistence, and `noeviction`. Redis loss delays notification but
cannot erase authoritative work. Redis Cluster/Sentinel and failover have not
been tested; no HA claim is made.

## PostgreSQL leases and fencing

`work_leases` stores tenant/work, opaque token, monotonically increasing
generation, owner, acquisition, heartbeat, expiry, release, and reason.
Claiming locks an eligible `work_items` row, checks tenant concurrency, increments
the durable attempt, and creates the next generation.

Heartbeats compare token, generation, owner, release state, and expiry before
renewal. Every claimed/started/heartbeat/outcome append includes the token and
generation. `PostgresEventStore.append_fenced` locks the current lease and rejects
stale, released, or expired workers against PostgreSQL server time before
appending. Lease expiry is derived from server time plus a bounded duration;
worker wall clocks do not extend authority. Redis consumer ownership is never
sufficient authority.

## Cancellation, timeout, retry, and DLQ

Cancellation is a durable `work.cancel_requested.v1` transition plus a projection
flag. The heartbeat loop sets a cooperative cancellation event. A completion
racing cancellation rechecks PostgreSQL before success and records cancellation
instead. Future untrusted code must still run behind a sandbox; cooperative
cancellation is not a sandbox.

The supervisor classifies explicit retryable/permanent failures, timeouts,
cooperative shutdown, and unexpected worker bugs. Bugs become
`work.failed.v1`; they do not terminate the supervisor. Retryable failures use
bounded exponential backoff with injectable deterministic jitter and append
`work.retry_scheduled.v1` plus a new outbox row. Permanent or exhausted work
appends `work.dead_lettered.v1`.

DLQ reads are payload-free and bounded. Requeue requires tenant-admin permission
and a durable, unexpired, tenant/work-bound `dlq:requeue` approval from a
different actor. Requeue consumes that approval, appends retry intent, and adds
a new outbox row in one transaction; it never deletes failure history.

## Reconciliation and residual ambiguity

| Crash window | Recovery |
| --- | --- |
| Outbox claimed, no `XADD` | Database lease expires; publisher retries |
| `XADD`, no database acknowledgement | Same message identity is republished; inbox deduplicates |
| Published row, Redis entry lost before delivery | Reconciliation resets the old unclaimed publication and republishes it |
| Redis delivered, inbox transaction rolled back | No `XACK`; pending entry is reclaimed |
| Worker dies after claim, before start | PostgreSQL lease expires; reconciliation returns work to retry |
| Worker dies after intent, before result | Reconciler must query the future target by idempotency key; no result is invented |
| Lease expires while old worker runs | New generation fences every old append |
| Pending Redis entry has no live owner | Bounded idle-threshold reclaim |
| Cancellation races success | Current durable cancellation state is checked before success |

External target acceptance can remain ambiguous after a network loss. A future
effect adapter must pass the durable intent idempotency key where supported or
implement target-state reconciliation. The platform cannot manufacture
exactly-once semantics.

## Operations and observability

`WorkerOperations` authorizes tenant-scoped status, PostgreSQL-authoritative
pending state, cancel, DLQ approval/requeue, and reconciliation. Reads cap at
200 and return no work payload. Reconciliation requires administrator authority;
requeue additionally requires durable two-actor approval.

OpenTelemetry spans use fixed operation names. Metrics cover outbox lag,
publication failures, pending depth/age, claim conflict, active lease, heartbeat
failure, retry, DLQ, latency, cancellation, and reconciliation. The API accepts
no tenant, run, work, or message label.

## Executable evidence

- `tests/test_worker_runtime.py`: state transitions, immutability, fairness,
  backoff, publication classification, exception containment, cancellation,
  operations authorization, and bounded telemetry.
- `tests/integration/test_worker_delivery.py`: live Redis/PostgreSQL publish,
  claim race, heartbeat, reclaim, stale fence, duplicate inbox, acknowledgement,
  poison payload, and RLS isolation.
- `tests/integration/test_postgres_storage.py`: transaction rollback, outbox
  claims, inbox idempotency, append races, and immutable ledger behavior.
