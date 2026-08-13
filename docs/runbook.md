# Durable-storage operator runbook

## Triage

1. Confirm `/health/ready` reports the configured storage dependency.
2. Classify the failure: concurrency conflict, transient database failure,
   permanent schema/data failure, replay corruption, outbox lag, or projection
   lag. Do not log payloads or credentials.
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
published merely to clear lag.

## Integrity or RLS incident

Stop writers if an aggregate sequence gap, event mutation, or cross-tenant row is
observed. Preserve database logs and transaction IDs, verify the application is
not using a bypass-RLS role, and escalate as a security incident. Restore from a
tested backup only after identifying the bad boundary; backup/restore drills are
still Layer 8 work.

## Rollback policy

Migration `0002_durable_ledger.sql` is forward-only. It creates authoritative
facts and security roles; automated downgrade would destroy evidence or weaken
isolation. Roll forward with an additive corrective migration. Disaster restore
uses a separately tested backup, not `DROP TABLE` downgrade SQL.
