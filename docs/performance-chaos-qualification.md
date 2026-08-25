# Performance, capacity, chaos, and recovery qualification

## Methodology and claim boundary

`qualification/performance-budgets.json` is the canonical machine-readable
method. `make qualification-load` runs one warm-up and at least three bounded
samples per CI profile, reporting p50/p95/p99 milliseconds, completed samples
per second, error rate, threshold, and pass/fail.

The fixture, revision, Python/Node/database/cache versions, CPU, memory,
operating system, and concurrent host load must accompany retained evidence.
The default 5-second p95 ceiling is a regression/safety timeout, not a product
latency objective. Local numbers must never be extrapolated to production
throughput, capacity, or SLO attainment.

## Bounded profiles

The required local runner covers API/event export/read/replay, outbox plus worker
DAG flow, model gateway budgets, evidence queries/correlation, DAG fan-out and
fan-in, two-person approval/effect reconciliation, sandbox scheduling model,
memory retrieval/compaction, the evaluation runner, protocol exchange, a large
derived operator timeline, and restore/projection rebuild.

Fresh PostgreSQL/pgvector/Redis throughput and lag, real connector pagination,
cluster sandbox scheduling, browser transfer/render, managed restore volume, and
sustained skew/soak remain environment-gated. Their evidence must use the same
statistics plus resource saturation, queue depth/age, database connections/WAL,
cache hit/eviction, provider tokens/cost, and recovery-point/time observations.

```bash
make qualification-load
jq '.profiles[] | {name,p50_ms,p95_ms,p99_ms,throughput_per_second,error_rate}' \
  .aegis-qualification/load.json
```

## Chaos and recovery

`qualification/chaos-matrix.json` is the canonical matrix linking each failure
to expected invariants, tests/evals, runbook, and alert. Required CI executes 17
deterministic branches across specialist recovery/abstention/budget denial,
action ambiguity/crash/policy/verification, sandbox ambiguity/cleanup/timeout/
quarantine/archive denial, protocol ambiguity/drift/revocation/tenant denial,
and memory rebuild/purge.

```bash
make qualification-chaos
make eval-recovery
```

The complete matrix additionally covers PostgreSQL transient failure, Redis
loss, cursor corruption, projection loss, telemetry outage, node/zone restart,
and regional generation fencing through existing deterministic and integration
tests.

Every scenario must preserve:

- ledger convergence and audit history;
- tenant isolation and current authorization;
- intent before any possible effect;
- stale generation denial;
- explicit ambiguity, bounded duplicates, and observe-before-retry;
- cancellation/drain/recovery without success-shaped fallback;
- quarantined unsafe evidence/artifacts;
- rebuildable projections/indexes/caches;
- telemetry remaining diagnostic rather than authoritative.

## Production acceptance

Production load/chaos remains a hard live gate. Use representative topology,
traffic shape, tenant skew, payloads, model/provider quotas, database/cache
sizes, failure duration, and restore volume. Stop immediately on cross-tenant
access, missing intent, stale/unauthorized effect, ledger divergence, unbounded
duplicate, lost audit, or unsafe fallback. Record limitations and raw
environment facts; do not normalize a failing safety assertion into a baseline.
