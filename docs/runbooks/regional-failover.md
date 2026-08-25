# Regional failover and failback runbook

1. Declare incident, tenant/residency scope, data loss estimate, provider locality, and
   authorized failover owner. Freeze new mutations.
2. Prove the old database and regional writers fenced. If proof is unavailable, remain
   read-only/unavailable.
3. Restore/promote the approved recovery point, verify ledger sequence/hash and keys,
   then atomically advance each tenant writer generation.
4. Rotate regional/runtime/provider credentials; rebuild caches/Redis/projections and
   reconcile ambiguous work.
5. Shift internal routing, then DNS/traffic gradually. Readiness must verify region and
   generation; stale workers must be denied.
6. Run tenant isolation, append/replay, provider, budget, synthetic, and error-budget
   gates. Record actual RPO/RTO and all unresolved gaps.
7. Failback is a new approved failover with another generation after resynchronization
   and integrity proof. Never reverse DNS while both regions can write.
