# Durable delivery and worker operator runbook

## Triage

1. Confirm PostgreSQL and Redis readiness separately. Redis readiness means
   reachable transport, not authoritative-state health.
2. Classify the failure: concurrency conflict, transient database failure,
   permanent schema/data failure, replay corruption, outbox lag, pending depth,
   oldest pending age, claim conflict, heartbeat failure, retry, or DLQ growth.
   Do not log payloads or credentials.
3. Preserve the tenant, aggregate ID, event ID, bounded error code, and cursor.
   Do not copy full sensitive payloads into tickets.
4. Use the application role for tenant-scoped inspection. Use the maintenance
   role only through an approved, time-bound administrative path. Confirm the API
   login is `aegis_runtime`, never the PostgreSQL initialization superuser.

## Projection recovery

Pause the affected projection consumer, record its tenant/name/checkpoint, verify
ledger replay first, then call `ProjectionEngine.rebuild`. Compare the rebuilt
checkpoint and read-model count before resuming. Never edit a projection to
repair authoritative run state.

## Outbox recovery

Inspect publishable age, attempts, lease owner/expiry, destination, and bounded
error code. An expired lease may be reclaimed. A dead-letter row needs an
operator decision and, in later effect layers, reconciliation. Do not mark
published merely to clear lag. If Redis recovered after an outage, resume
bounded publication; duplicates are expected and safe through inbox identity.

## Pending entries and leases

Tenant operations inspect bounded PostgreSQL `work_items`/`work_leases` pages,
never the shared global pending-entry list. Fleet operators may inspect bounded
Redis entry, consumer, idle-age, and delivery-count diagnostics, but Redis
ownership is not authority. Reclaim only above the configured idle threshold. An expired PostgreSQL lease must be reconciled before new execution;
the next generation fences the old worker.

## Cancellation and graceful drain

Cancellation is cooperative. Confirm `work.cancel_requested.v1` exists, then
observe heartbeat polling and the terminal cancelled event. During deployment,
stop new reads, allow the configured drain interval, and leave unfinished entries
pending. Never acknowledge work merely to make drain complete.

## DLQ operation

List payload-free DLQ rows by tenant and bounded cursor. Confirm the durable
failure class, attempts, and whether the underlying dependency is repaired.
Persist a scoped, expiring `dlq:requeue` approval bound to the tenant and work,
then requeue with a different authorized actor. The transaction consumes the
approval, appends retry intent, and creates a new outbox message; do not delete
or edit failure history.

## Reconciliation

Run tenant-scoped reconciliation as an administrator. Record counts only.
Reconciliation releases expired leases and records its outcome. For a future
intent without result, query the target using the intent idempotency key. If the
target cannot answer, leave the outcome ambiguous and escalate; never synthesize
success.

## Integrity or RLS incident

Stop writers if an aggregate sequence gap, event mutation, or cross-tenant row is
observed. Preserve database logs and transaction IDs, verify the application is
not using a bypass-RLS role, and escalate as a security incident. Restore from a
tested backup only after identifying the bad boundary; backup/restore drills are
still Layer 8 work.

## Rollback policy

Migrations `0002_durable_ledger.sql` and
`0003_distributed_worker_runtime.sql` are forward-only. They create authoritative
facts and security roles; automated downgrade would destroy evidence or weaken
isolation. Roll forward with an additive corrective migration. Disaster restore
uses a separately tested backup, not `DROP TABLE` downgrade SQL.
