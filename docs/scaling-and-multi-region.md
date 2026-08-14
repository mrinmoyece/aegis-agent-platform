# Scaling, capacity, HA, and multi-region

## Capacity model

Size independently for incident arrival rate, events per incident, evidence bytes,
provider calls, mean and p95 service time, tenant skew, projection lag, database
connections, Redis stream lag, object throughput, telemetry volume, and sandbox demand.
A starting concurrency estimate is `peak_arrivals_per_second * p95_service_seconds`,
then cap by tenant quota, provider quota, database pool, global budget, and safety
limits. It is a hypothesis until the documented profile is measured.

Profiles include steady baseline, 10x five-minute burst, one tenant at quota, provider
429/timeout, Redis loss/redrive, PostgreSQL standby promotion, worker restart during
effect ambiguity, projection rebuild, telemetry outage, and sandbox exhaustion. Report
throughput, p50/p95/p99 latency, queue age, retries, duplicate/reconciliation count,
connection saturation, per-tenant fairness, cost, and safety violations.

## Single-region HA

- Multiple stateless API and worker replicas spread across zones/nodes.
- PostgreSQL primary/standby is the only writer authority; failover must preserve
  committed ledger rows and writer fencing.
- Redis HA improves delivery availability but never establishes work truth.
- Publishers use database row claims; reconcilers/workers use durable leases and
  generations. Kubernetes Lease objects are not correctness authority.
- Tenant-fair in-process scheduling, tenant quotas, provider/connector concurrency,
  sandbox quota, pool budgets, and overload shedding contain noisy neighbors.
- API rejects excess work before durable acceptance only with an explicit response;
  accepted work is never silently dropped. Retry-After, bounded queues, circuit
  breaking, and provider budgets prevent retry storms.

HPA scale-up is deliberately slow and bounded. Queue-lag scaling needs a metric that
deduplicates retries and separates tenants; CPU is the safe checked-in baseline. Scale
down waits longer than leases/drain windows.

## Queue partitioning and connections

Start with shared Redis Streams because PostgreSQL tenant/fence state remains
authoritative. Shard transport only after hot-tenant evidence: stable tenant hash,
versioned routing, dual-publish migration with inbox deduplication, per-shard lag, and
reconciliation. Shards do not change event ordering or tenant authority.

Set a total database connection budget below managed limits. Reserve pools for API,
worker classes, publisher/reconciler, migration, observability, and emergency operator
access. Autoscaling ceilings must fit that budget; use a transaction pooler only after
session settings for tenant RLS and writer generation are proven safe.

## Bounded multi-region

[ADR 0024](adr/0024-single-writer-multi-region.md) permits one writer home region per
tenant, read-only/reporting replicas, and stateless regional edges. Mutation routes to
home. Regional caches are disposable and invalidated by versioned events; stale reads
cannot approve or reconcile effects.

Failover requires old-writer fencing, a new monotonic generation, database
restore/promotion and integrity proof, credential rotation, provider locality checks,
DNS/traffic shift, queue redrive/reconciliation, and return-to-service approval.
Failback repeats the process with another generation. If the old region cannot be
proven fenced, writes remain unavailable.

Residency policy binds tenant home/backup/replica regions, provider endpoints, approved
cross-border transfers, keys, retention, and transfer spend. Transport and backups use
encryption in transit/at rest. Active-active global writes, conflict-free approval
merges, and exact cross-region spend are not implemented or claimed.
