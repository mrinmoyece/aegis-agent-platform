# Backup and restore runbook

1. Declare scope and owners; fence writers/effects and preserve logs/audit without
   copying backup contents.
2. Select encrypted recovery point/object/key references under two-person review.
3. Restore to an isolated account/VPC/database with egress and effects disabled.
4. Verify contiguous migration name/checksum history, roles, forced RLS, event
   ranges/count/hash across every event column, aggregate sequences, archive manifests,
   objects, and keys.
5. Rebuild projections/indexes, recreate Redis, republish/redrive, and reconcile every
   ambiguous effect with original idempotency keys.
6. Rotate restore/admin/runtime/provider credentials and advance writer generation.
7. Run identity/tenant/readiness/synthetic/SLO gates and obtain return-to-service
   approval before traffic.
8. Retain only the bounded report. Record observed RPO/RTO as a measurement, not a
   permanent guarantee.

For the local proof, run `make restore-drill` and review
`.aegis-evidence/restore-drill.json`.
