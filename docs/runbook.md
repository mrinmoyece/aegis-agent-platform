# Durable delivery and worker operator runbook

## Triage

1. Confirm PostgreSQL and Redis readiness separately. Redis readiness means
   reachable transport, not authoritative-state health.
2. Classify the failure: concurrency conflict, transient database failure,
   permanent schema/data failure, replay corruption, outbox lag, pending depth,
   oldest pending age, claim conflict, heartbeat failure, retry, or DLQ growth.
   Do not log payloads or credentials.
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
published merely to clear lag. If Redis recovered after an outage, resume
bounded publication; duplicates are expected and safe through inbox identity.

## Pending entries and leases

Tenant operations inspect bounded PostgreSQL `work_items`/`work_leases` pages,
never the shared global pending-entry list. Fleet operators may inspect bounded
Redis entry, consumer, idle-age, and delivery-count diagnostics, but Redis
ownership is not authority. Reclaim only above the configured idle threshold. An expired PostgreSQL lease must be reconciled before new execution;
the next generation fences the old worker.

## Cancellation and graceful drain

Cancellation is cooperative. Confirm `work.cancel_requested.v1` exists, then
observe heartbeat polling and the terminal cancelled event. During deployment,
stop new reads, allow the configured drain interval, and leave unfinished entries
pending. Never acknowledge work merely to make drain complete.

## DLQ operation

List payload-free DLQ rows by tenant and bounded cursor. Confirm the durable
failure class, attempts, and whether the underlying dependency is repaired.
Persist a scoped, expiring `dlq:requeue` approval bound to the tenant and work,
then requeue with a different authorized actor. The transaction consumes the
approval, appends retry intent, and creates a new outbox message; do not delete
or edit failure history.

## Reconciliation

Run tenant-scoped reconciliation as an administrator. Record counts only.
Reconciliation releases expired leases and records its outcome. For a future
intent without result, query the target using the intent idempotency key. If the
target cannot answer, leave the outcome ambiguous and escalate; never synthesize
success.

## Model gateway triage

1. Use the tenant-scoped model catalog, model-usage, and provider-health views.
   Capture bounded provider/model, circuit state, pricing version, error code,
   reservation ID, and event positions. Never copy prompts, tool arguments,
   provider keys, or raw SDK exceptions into a ticket.
2. Confirm `model.route_decided.v1`, `model.call_requested.v1`, and
   `model.budget_reserved.v1` precede `model.call_started.v1`. A started call
   without those committed facts is an integrity incident.
3. For budget denial, compare active reservations and current-period usage to
   tenant/run quota. Rebuild projections from ledger events if drift is suspected;
   do not edit a charged usage row or increase quota to clear an alert.
4. For an open circuit, repair provider reachability/auth/configuration and wait
   for the bounded half-open probe. Do not manually mark the circuit healthy.
5. For malformed/schema/safety/auth failures, do not retry. Correct catalog,
   schema, policy, or credentials and create new durable work.
6. For `billing_ambiguous=true`, preserve the provider request ID and Aegis
   idempotency key. Compare provider usage/billing exports. Leave the outcome
   ambiguous when the provider cannot prove it; never synthesize tokens or cost.
7. Rotate a key by updating its versioned secret reference and calling the client
   reload boundary. Verify the old reference is revoked. The current environment
   provider is local-only; production needs a vault-backed provider.

## Evidence connector triage

1. Inspect the tenant-scoped query status, source kind, bounded error code,
   partial/truncated flags, counts, and event positions. Do not copy query
   content, URLs, logs, traces, diffs, runbooks, or credentials into tickets.
2. Confirm `evidence.query_requested.v1` committed before
   `evidence.query_started.v1`. A network read without durable intent is an
   integrity incident.
3. For rate limiting, honor the bounded retry-after and tenant deadline. For
   timeout/cancellation, create no success-shaped result.
4. For partial results, retain ingested pages and explicit omission reasons.
   Resume only from a cursor committed by the current lease generation.
5. For quarantine, inspect source kind, record ID, reason, size, digest, and trust
   metadata only. Correct policy/schema/trust and submit new work; do not edit an
   immutable record or bypass validation.
6. For cursor lag, compare the source cursor's query and lease generation with
   current durable work. Never manually advance a cursor to hide lag.
7. For correlation conflict, inspect citations, typed identifiers, clock-skew
   tolerance, confidence, and rationale. Preserve unresolved ambiguity rather
   than selecting a causal story.
8. Keep a connector disabled while rotating credentials or correcting
   allowlists. Verify least-privilege source permissions, TLS/private egress, and
   residency before re-enabling.

## Approval, action ambiguity, or verification incident

1. Stop new action claims for the tenant. Do not revoke a lease by editing Redis
   or a projection; PostgreSQL work/ledger state remains authoritative.
2. Inspect only bounded proposal/status pages: plan/action/policy digests, exact
   target fingerprint, risk, quorum, expiry/revocation, attempt, lease
   generation, idempotency digest, outcome class, and verification status. Do
   not copy comments, credentials, raw evidence, prompts, or provider bodies.
3. If approval is stale, expired, revoked, cross-tenant, forged, lacks current
   role/quorum, or no longer matches policy/target, append no action intent.
   Create a new immutable revision and request new approval.
4. If an execution intent has no terminal outcome, reconcile target state with
   the same tenant idempotency key and fingerprint before any retry. Never
   generate a new key to hide ambiguity or claim exactly once.
5. If reconciliation is conflicting or unknown, stop automatic retries and
   escalate. Preserve the ambiguity in the ledger.
6. If adapter acceptance succeeded but verification is failure, partial, or
   unknown, keep the incident unresolved. A rollback/compensation requires its
   own durable proposal/approval/intent and fresh verification.
7. A stale lease holder must not act or append success. Investigate any fencing
   rejection as expected containment first; repair only through current durable
   work ownership.

## Sandbox lifecycle, quarantine, or cleanup incident

1. Stop new sandbox claims for the tenant and inspect bounded redacted status.
   PostgreSQL events and the current lease are authoritative; Redis, pod phase,
   logs, and projections are not.
2. Confirm request, policy decision, exact approval binding, dispatch,
   provisioning intent, start intent, terminal result, and cleanup intent order.
   A backend call without its preceding durable intent is an integrity incident.
3. For a provisioning gap, observe the stable backend name and spec digest before
   create/retry. For a cleanup gap, observe absence/presence before delete/retry.
   Record reconciliation and never invent success or claim exactly once.
4. For timeout, OOM, cancellation, output limit, or backend failure, preserve the
   explicit terminal event and drive cleanup under the current fence. Do not let
   a stale worker terminate or append.
5. For artifact quarantine, inspect only tenant, sandbox/artifact ID, digest,
   media type, size, scanner reason, and provenance. Never open raw bytes on an
   operator workstation or treat output as instructions.
6. Redrive cleanup within the declared attempt bound. Exhaustion remains
   quarantined and requires escalation; do not delete a provider object without
   durable intent or edit cleanup projections.
7. If readiness reports verified controls that are not deployed (admission,
   runtime class, PID, default-deny networking, artifact driver), disable the
   backend and treat it as a security incident.

## Memory, pgvector, compaction, or retention incident

1. Stop new memory claims for the tenant. Inspect bounded status/provenance and
   the memory/retrieval event streams; never use Redis, pgvector rows, traces, or
   model transcripts as authoritative state.
2. Verify candidate acceptance, source digest, scan, chunk, embedding, indexing,
   and current lease generation. For an intent without a result, observe the
   content/version key before retry. Do not claim exactly-once embedding/indexing.
3. Quarantine dimension, non-finite vector, scanner, citation, contract-digest,
   or unsupported-summary mismatches. Preserve only bounded identifiers, digests,
   versions, and error codes in operator output.
4. For suspected cross-tenant access, disable the memory API, preserve database
   and audit evidence, confirm the runtime is `aegis_app` rather than a bypass-RLS
   role, and invalidate all affected tenant cache keys.
5. Rebuild lexical/vector projections and checkpoints from ledger events plus
   authorized source blobs under `aegis_maintenance`. Compare counts/digests,
   then re-enable reads; never edit events to repair an index.
6. For tombstone/deletion, check legal hold first, record intent, purge derived
   index/cache, erase the referenced blob, and record completion. Immutable
   identifier/digest events and unexpired backups are not claimed erased.

## Evaluation gate, dataset, or report incident

The Layer 11 CLI is `python -m aegis_agent_platform.evals`; `make evals` runs
the required fake-only gates. Use `check-fixtures`, `run`, `replay`, and
`compare`, or focused `make eval-fixtures`, `eval-deterministic`, and
`eval-baseline` targets for triage. `update-baseline` and `write-manifest`
require explicit `--yes`;
baseline updates also require `--review-reference`.

1. Stop release promotion, identify the dataset/case/gate, baseline/candidate
   digests, execution class, contract/grader versions, and bounded error code.
   Evaluator output is release evidence, not runtime or production truth.
2. If required CI attempted network, secret access, a model judge, or an external
   effect, fail the run and investigate the hermetic boundary. Never add live
   credentials to make a required gate pass.
3. On provenance/schema/digest mismatch or suspected leakage/poisoning,
   quarantine the dataset version. Preserve bounded hashes and review metadata;
   do not edit the manifest or historical result.
4. Replay only with recorded fixed inputs and named fault cut points. If replay
   differs, preserve both redacted results and investigate nondeterminism before
   changing a baseline.
5. A baseline change requires a complete passing run and a review reference. Hard
   safety failures are non-waivable. A non-safety waiver must match exact
   case/metric scope, owner, reason, and expiry; missing, broadened, or expired
   waivers block comparison.
6. For sensitive report output, quarantine/delete derived copies, rotate exposed
   material when applicable, and retain only approved identifiers/digests. Never
   paste raw prompts, evidence, credentials, tenant data, or judge transcripts
   into a ticket.
7. For dataset deletion, check legal hold, record approval/tombstone, purge
   source and derived evaluator/judge/report data, and mark historical evidence
   unavailable rather than rewriting it.

## Integrity or RLS incident

Stop writers if an aggregate sequence gap, event mutation, or cross-tenant row is
observed. Preserve database logs and transaction IDs, verify the application is
not using a bypass-RLS role, and escalate as a security incident. Restore from a
tested backup only after identifying the bad boundary; production backup/restore
drills remain Layer 12 work.

## Rollback policy

Migrations `0002_durable_ledger.sql` through
`0009_event_grounded_memory_pgvector.sql` are forward-only.
They create authoritative
facts and security roles; automated downgrade would destroy evidence or weaken
isolation. Roll forward with an additive corrective migration. Disaster restore
uses a separately tested backup, not `DROP TABLE` downgrade SQL.
