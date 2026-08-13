# Durable execution and PostgreSQL ledger

Layer 3 implements persistence mechanics, not agent execution. PostgreSQL is the
authoritative event ledger; workers, models, live evidence connectors, Redis work
claims, and remediation remain planned.

## Event sourcing instead of mutable run state

A mutable `runs.status` row loses how and why a run changed. Aegis appends a
versioned `EventEnvelope` containing tenant, aggregate, sequence, event type,
schema version, actor, causation/correlation, identity/policy/audit references,
idempotency key, trace context, occurrence time, and database record time. A
stream replays in aggregate-sequence order; a tenant commit lock serializes
position allocation so the global cursor is commit-safe for tenant projections.
Legacy Layer 1 envelopes decode with defaults for every
additive Layer 3 field.

`events` rejects update and delete physically. The application role also lacks
those grants. `event_stream_heads` is locked in the append transaction, so an
expected-version mismatch loses the race without creating a sequence gap.
PostgreSQL identity values can have global-number gaps after rollback; only their
order is meaningful. Per-aggregate sequence is the gapless invariant. Appends
for different tenants remain independent.

## Optimistic concurrency

Callers read aggregate version `N`, decide against that state, and append with
`expected_version=N`. The adapter locks the tenant/aggregate head, compares the
version, inserts the whole batch, and advances the head in one transaction.
Concurrent writers cannot both commit against the same version. A conflict is a
classified permanent decision conflict, not a transient database retry.

## Inbox, outbox, and exactly-once limits

`append_from_inbox` inserts `(tenant, source, message_id)` before recording the
resulting events. A duplicate returns the first committed aggregate version.
Events and outbox rows commit together. Publishers claim outbox rows with
`FOR UPDATE SKIP LOCKED`, a bounded lease, retry count, and error code. Exhausted
failed or expired leases become dead-letter **projection state** and cannot be
claimed again; this does not rewrite event truth.

This is at-least-once delivery. It is not exactly-once execution. A crash after an
external system accepts a request but before Aegis records the result remains
ambiguous. Later effect adapters must send the durable intent's idempotency key
or reconcile target state. No external effect adapter exists in Layer 3.

## Projections and checkpoints

Run status, artifact/evidence index, pending approvals, usage/quota totals, and
tenant listings are disposable read models. `ProjectionEngine` reads bounded
global pages and advances a tenant/projection checkpoint only after the page is
applied transactionally. Position overlap, non-monotonic positions, and aggregate
sequence gaps fail closed. Applying an already checkpointed page is idempotent.
`rebuild` deletes one tenant's view and checkpoint, then replays the ledger.

Events that later layers have not defined are ignored, not represented with fake
fields. Current typed handlers cover run status, artifacts, approvals, usage, and
tenant registration.

## Tenant isolation and privileged maintenance

Every adapter accepts `TenantContext` and calls transaction-local
`set_config('aegis.tenant_id', ..., true)`. Every tenant table has forced RLS.
`aegis_runtime` is a non-superuser login granted the `aegis_app`
`NOBYPASSRLS` role; `aegis_maintenance` is a separate `BYPASSRLS`
`NOLOGIN` role intended only for explicitly brokered migration, repair, and
rebuild operations. Application code never switches into that role.

The read-only API surfaces are:

- `/v1/tenants/{tenant_id}/ledger?cursor={global_position}`
- `/v1/tenants/{tenant_id}/runs/{run_id}/timeline?cursor={aggregate_sequence}`
- `/v1/tenants/{tenant_id}/projections/run-status`

They require Layer 2 authorization, cap results at 100, and redact sensitive
payload keys. The projection service provides rebuild tooling; rebuild is not an
unauthenticated HTTP operation.

## Tests and observability

`make check` runs the fast deterministic suite at a 90% coverage gate while
excluding live-database adapter lines. `tests/integration/test_postgres_storage.py`
executes those adapters against PostgreSQL 16 in CI and proves migrations,
rollback, races, duplicate delivery, dead-letter transition, RLS, immutability,
replay, projection rebuild, durable audit redaction, and repository isolation.

`StorageTelemetry` defines bounded signals for append latency/conflicts, outbox
lag, and projection lag. It accepts counts and durations only—never tenant IDs,
payloads, idempotency keys, or invented production measurements.
