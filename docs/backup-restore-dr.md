# Backup, restore, and disaster recovery

## Objectives, not attained claims

Initial objectives are ledger RPO <= 5 minutes with managed point-in-time recovery,
artifact/config RPO <= 24 hours, and isolated restore RTO <= 4 hours for a reference
tenant. Regional writer failover objective is RTO <= 2 hours. These are review inputs,
not measured production achievements.

## Protected dependencies

| Asset | Protection and recovery |
| --- | --- |
| PostgreSQL ledger and control tables | encrypted managed backups/PITR, cross-account access, restore in isolation, row/order/hash/sequence checks |
| Projections/indexes | backed up for convenience but rebuilt and compared from ledger |
| Object artifacts and archives | versioning, KMS, immutable retention where required, object manifest/checksum |
| Config/trust registries | Git history plus database backup; trust revisions and approvals remain ledger-mediated |
| Signing/encryption keys | provider-managed rotation, separately authorized recovery, key reference inventory; missing keys block service |
| Redis | no authoritative restore dependency; recreate, republish outbox, reclaim leases, redrive, reconcile |

Backups are encrypted, access-audited, retention-locked, copied according to residency,
and never written to logs or CI artifacts. Backup operators cannot approve production
restore alone. Restore credentials are short-lived and rotated afterward.

## Local executable drill

`make restore-drill` starts pinned PostgreSQL/Redis containers, applies all migrations
through the locked runner,
creates deterministic ledger/projection facts, produces a private custom-format dump,
restores to a separate database, compares migration history and every event column by
count/max position/ordered SHA-256, deletes and rebuilds a projection, loses Redis, and
uses the production `OutboxPublisher` and `RedisStreamQueue` adapters to claim one
restored PostgreSQL outbox row, republish it, mark it published, and consume the
tenant-bound delivery. It emits only bounded integrity/redrive metadata to
`.aegis-evidence/restore-drill.json`. CI retains the report for 30 days.

This proves script behavior on a small local fixture. It does not prove managed PITR,
cross-account/KMS recovery, production volume, live RPO/RTO, object-store restore, or
regional failover.

## Return-to-service gates

1. Declare incident and fence writers/effects.
2. Select a recovery point and record approved scope without exposing contents.
3. Restore into an isolated account/VPC/cluster with blocked external effects.
4. Verify migrations, role/superuser status, forced RLS, event count/hash/ranges,
   aggregate sequences, archive manifests, and key/object availability.
5. Rebuild and compare projections/indexes; recreate Redis and redrive outbox/inbox.
6. Reconcile every ambiguous external operation using original idempotency identity.
7. Rotate restore/admin/application/provider credentials and advance writer generation.
8. Run auth, tenant-isolation, readiness, synthetic, SLO/error-budget, and operator
   smoke gates.
9. Approve traffic shift, monitor, and retain the evidence bundle.

See [backup/restore runbook](runbooks/backup-restore.md) and
[regional failover runbook](runbooks/regional-failover.md).
