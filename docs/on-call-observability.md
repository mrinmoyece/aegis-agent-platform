# Observability on-call runbook

This runbook defines actions for the configured local alert rules. Production
paging evidence and a 24/7 rotation are not yet established.

## API fast burn

Confirm both burn windows, dependency health, deployment changes, and ledger
append success. Stop a harmful rollout. Do not weaken authorization or durable
intent requirements to restore availability.

## API slow burn and error budget

Open a reliability incident, inspect error classes and ledger timelines, and
freeze risky releases when the 30-day budget is exhausted.

## Safety

Treat any hard safety violation as a page. Disable the affected capability,
preserve evaluation and ledger evidence, and require explicit review. Safety is
not an availability budget.

## Queue lag, outbox, DLQ, and fencing

Check PostgreSQL/outbox age, Redis reachability, consumer pending state, leases,
and clock skew. Never manually acknowledge uncommitted work. DLQ redrive
requires scoped approval. A fence spike indicates stale workers; do not bypass
fencing.

## Reconciliation and verification

For ambiguous effects, inspect durable intent and result events, run only the
approved reconciliation adapter, and preserve ambiguity until verified. Never
repeat an effect solely because a trace is missing.

## Sandbox cleanup

Quarantine the backend resource, deny reuse, preserve its attestation and
cleanup events, and reconcile through the controlled cleanup path.

## Tenant denials

Check identity bindings and attempted action classes. Do not expose whether a
different tenant resource exists. Escalate a cross-tenant pattern to security.

## Provider budget and circuit

Check budget reservation/charge events, provider-family health, fallback policy,
and catalog state. Do not bypass tenant budgets.

## Evidence and memory index

Check connector cursor/source timestamps or accepted-memory/index-completion
events. Derived evidence and memory indexes may be rebuilt only from ledger
truth after the dependency recovers.

## Exporter and drops

Telemetry is optional to correctness. Check the collector health endpoint,
queues, retry circuit, Prometheus target, and drop counters. Do not restart the
agent runtime solely to recover export. Use the replay debugger while telemetry
is absent.

## Evaluation

Reproduce the exact deterministic case and source fingerprint. Hard safety
failures block release and cannot be waived.

## Deployment and regional change

Correlate region, environment, service, and immutable version attributes. Halt a
canary on safety/correctness alerts, readiness failure, fast burn, retry storm,
queue growth, or pool saturation. Automatic application rollback is allowed only
across the declared schema window; never reverse an irreversible migration
automatically. Regional traffic shift requires writer-fence proof, a new durable
generation, reconciliation, and scoped approval.

## Backup and restore

Backup job success is informational until an isolated restore proves decryptable
dependencies, ledger count/hash/sequence integrity, RLS/role safety, projection
rebuild, Redis redrive, ambiguous-effect reconciliation, credential rotation, and
return-to-service smoke. Never export payload or secret content into alerts.
