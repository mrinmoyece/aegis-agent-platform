# Database lifecycle, compatibility, and retention

## Expand, migrate, contract

Every database change is additive while old and new application revisions overlap.

1. **Expand:** add nullable/defaulted columns, new tables/indexes/policies/functions, and
   dual-readable contracts. Do not rename/drop, tighten a constraint before backfill,
   or rewrite a large table in one transaction.
2. **Migrate:** bounded idempotent backfill by tenant/range with checkpoints, rate
   limits, lock/replication-lag monitoring, checksums, pause/resume, and no effect on
   event authority.
3. **Contract:** only after all application versions reject the old shape, backfill and
   replay evidence passes, retention/legal-hold review completes, and a later approved
   migration is safe. Event schemas remain readable forever.

Application builds advertise `AEGIS_SCHEMA_MIN_VERSION` and
`AEGIS_SCHEMA_MAX_VERSION`; production readiness fails on mismatch. The migration Job
uses `scripts/migrate.py`, an advisory lock, contiguous filenames, SHA-256 history,
15-minute deadline, and one retry. Each migration body and its history row commit in one
transaction. Preflight rejects gaps, name/checksum drift, and a database newer than the
application. The checked-in Job refuses a legacy schema without history.
`--adopt-existing` is a one-time manual override only after independent
verification that migrations 0001-0010 are complete; it is never a default argument.
Only the maintenance identity applies migrations. Runtime identities remain
non-superuser, `NOBYPASSRLS`, and forced-RLS tests are mandatory.

Production and staging readiness read the contiguous migration history and require its
maximum version to fall inside the build's advertised window. Migration `0011` creates
tenant fences with enforcement disabled so a Layer 14 writer can overlap the expand
phase. A rollout must deploy fence-aware writers that resolve credentials from the
trusted `TenantContext` through the externally mounted
`AEGIS_WRITER_FENCES_FILE`, seed and verify every tenant row, drain all pre-fence
writers, and only then approval-gate `enforcement_enabled = true`. Once enabled, every
event insert is database-triggered through `aegis_assert_writer_fence`; missing, stale,
non-home-region, or non-active tenant credentials fail before append commits. A single
process-wide generation is prohibited because generations are tenant scoped.
New tenant creation atomically seeds a disabled, fenced row. Database triggers reject
missing rows, generation rollback/skips, unsafe state transitions, region changes
without a new generation (except first bootstrap assignment), timestamp rollback, and
disabling enforcement after activation. Runtime resolvers reload atomically mounted
credentials and compare them with the active database row before reporting readiness.

## Roll-forward decision table

| Observation | Application action | Database action |
| --- | --- | --- |
| Expand migration failed before commit | Keep old revision | Fix and rerun idempotently |
| Expand committed, new app unhealthy | Roll back app digest | Keep additive schema |
| Backfill incomplete | Run compatible app, pause feature | Resume from checkpoint |
| Contract not yet applied | Roll back app digest if compatible | Do not downgrade |
| Contract or irreversible data transform applied | Maintenance/read-only mode | Roll forward or isolated restore after incident review |
| RLS/ledger integrity uncertain | Stop writers | Preserve evidence and restore only after root cause/fence |

Never blindly undo an irreversible schema migration during an automated deployment
rollback.

## Large tables and partitioning

Build indexes concurrently outside a migration transaction where supported, enforce a
short lock timeout, preflight free space and replica lag, and use shadow tables plus
checksums for structural changes. Existing `events` is not repartitioned by migration
`0011`. [ADR 0025](adr/0025-ledger-retention-and-partitioning.md) requires a separate
online plan.

Candidate ranges are completion month for outbox/inbox, tenant/time for audit and
rebuildable projections, and recorded-time range for new ledger installations only
when aggregate uniqueness and global ordering remain enforceable. Connection budgets
reserve capacity for migrations, API, workers, publishers, reconcilers, observability,
and operator access; autoscaling cannot exceed the database pool budget.

## Retention and archive

Ledger mode defaults to `retain`. No event deletion is authorized by Layer 15.
`tenant_retention_policies` records reviewed online windows and legal hold;
`ledger_archive_manifests` records immutable encrypted archive position range, count,
checksum, object/key references, and verification time. Archive retrieval restores into
isolation, verifies ordered row hashes and aggregate sequences, rebuilds projections and
indexes, and records access. Missing key, object, manifest, checksum, or approval blocks
deletion and return to service.

Outbox/inbox cleanup requires terminal ledger outcome, reconciliation completion, and a
duplicate horizon. Projections/indexes/cache can use shorter windows because replay
rebuilds them. Security audit follows the tenant policy and legal hold, never an
unreviewed cron deletion.
