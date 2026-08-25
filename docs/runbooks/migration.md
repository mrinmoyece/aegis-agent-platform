# Migration runbook

1. Review expand/migrate/contract phase, lock/rewrite risk, disk/WAL/replica capacity,
   schema windows, RLS grants, backup point, and rollback/roll-forward table.
2. Use the maintenance identity through a short-lived secret reference. Run
   `python scripts/migrate.py --preflight-only`; gaps, future versions, and name/checksum
   drift must fail. Never pass credentials as arguments.
3. Admit one suspended Kubernetes Job. A second runner must fail the advisory lock.
4. Monitor locks, replication lag, application readiness, pool saturation, and
   migration deadline. Pause bounded backfills rather than extending lock scope.
5. Verify each migration and history row committed atomically,
   `aegis_schema_migrations` checksums, expected schema version, runtime
   non-superuser/NOBYPASSRLS, forced policies, replay, and old/new app compatibility.
6. On failure before commit, fix/rerun. After additive commit, keep schema and roll back
   only compatible app code. After irreversible transformation, maintenance mode plus
   roll-forward or isolated restore is required.
