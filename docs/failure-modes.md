# Durable-storage failure modes

| Failure | Detection | Safe response |
| --- | --- | --- |
| Stale aggregate version | `ConcurrencyError(expected, actual)` and conflict counter | Re-read and re-decide; never blind-retry a command |
| PostgreSQL unavailable, serialization failure, or deadlock | `TransientStorageError` | Retry the whole transaction with bounded policy |
| Constraint, schema, or malformed projection event | `PermanentStorageError` | Stop, quarantine input, and investigate |
| Process exits during append | Transaction rollback | Replay; no partial event batch or outbox row commits |
| Duplicate incoming delivery | Inbox primary key | Return first committed version without reapplying |
| Publisher dies while leased | Lease expiry | Claim again only below max attempts; otherwise dead-letter |
| Publisher dies after Redis `XADD` | Outbox remains leased/pending | Republish deterministic message identity; inbox deduplicates |
| Redis outage or timeout | Classified retryable queue error and publish-failure metric | Release outbox lease with bounded backoff; do not invent publication |
| Poison Redis envelope | Size/schema decoder rejection | Quarantine/inspect bounded metadata; never pass payload to a handler |
| Delivery committed to Redis but inbox transaction rolls back | Pending entry remains unacknowledged | Reclaim after idle threshold and retry the inbox transaction |
| Two workers claim one item | PostgreSQL `FOR UPDATE SKIP LOCKED` and CAS state | One lease wins; the loser records a claim conflict and does not execute |
| Heartbeat stops | PostgreSQL expiry and oldest-active-lease metric | Reconcile to retry state and publish again |
| Stale worker resumes after reclaim | Token/generation mismatch in `append_fenced` | Reject every state-changing append; preserve conflict evidence |
| Worker handler raises unexpectedly | Supervisor exception boundary | Append classified `worker_bug` failure; keep supervisor alive |
| Retry limit exhausted | Durable attempt reaches max | Append failure and dead-letter events; require approved requeue |
| Cancellation races success | Durable cancellation flag checked before outcome | Record cancelled; never let a late success overwrite it |
| Graceful drain times out | Active-task count remains nonzero | Stop new claims, preserve leases, then allow expiry/recovery |
| Orphan Redis pending entry | Pending idle age exceeds threshold | Bounded `XAUTOCLAIM`; PostgreSQL claim/fence still decides authority |
| Outbox exhausts attempts | `dead_letter` projection row and bounded error code | Operator investigates; event truth is unchanged |
| Projection crashes | Checkpoint remains at prior committed page | Resume or rebuild from ledger |
| Sequence/cursor corruption | Replay gap/ordering exception | Stop consumption and invoke storage incident runbook |
| Cross-tenant context or confused deputy | Forced RLS returns no row or rejects write | Deny and audit; never retry under broader role |
| Event/audit mutation | Missing grants and append-only trigger | Treat attempt as an integrity/security incident |
| Ambiguous external completion | Intent exists without result | Reconcile using idempotency key and target state; never invent success |
| Unknown provider, model, or pricing | Catalog lookup fails | Deny before reservation; never select a default or assume price |
| Tenant/capability/retention/residency denial | No eligible route | Record bounded denial reason; do not call a provider |
| Model budget race | Tenant budget lock serializes reservations | One reservation commits; losers deny before network |
| Model rate or concurrency limit | Local admission control denies | Back off/fail over within bounds; do not bypass limits |
| Provider outage | Retryable classified error and circuit failures | Bounded backoff, then bounded fallback; open circuit |
| Provider auth/safety/schema error | Permanent classified error | Do not retry or fail over as a transient success |
| Provider timeout after acceptance | `billing_ambiguous=true` | Preserve failure evidence; reconcile provider billing before replay |
| Malformed/oversized SDK response | Adapter containment error | Fail explicitly, release local reservation, never coerce success |
| Usage exceeds reservation | Provider-bug classification | Do not surface response; preserve active evidence for reconciliation |
| Stale worker after provider response | Result fence rejects append | Do not emit response or charge from stale worker; reconcile ambiguity |
| Invalid structured output/tool arguments | Strict JSON Schema failure | No parser fallback; a repair would be a new budgeted durable call |
| Evidence intent committed but connector never starts | Requested query age and outbox/work state | Recover through durable delivery; never issue an unrecorded synchronous read |
| Stale evidence worker | Lease token/generation rejection before query/result/cursor | Stop; a current worker may retry from durable intent |
| Connector rate limit | Classified rate-limited event plus bounded retry-after | Record explicit outcome; retry only within policy and deadline |
| Connector returns some pages then fails | Partial/truncated metadata and cursor | Persist `partially_succeeded`; never label it success |
| Malformed or oversized source response | Adapter/ingestion containment | Quarantine bounded metadata; never store the unbounded raw body |
| Duplicate evidence | Tenant/content-digest uniqueness | Emit deduplicated metadata and reuse the immutable tenant record |
| Source cursor race | Fenced compare-and-advance fails | Preserve the winner; stale generation cannot overwrite progress |
| Runbook trust/schema failure | Digest/signature/front-matter validation | Reject or quarantine; never execute retrieved instructions |
| Correlation tie or contradiction | Ambiguous or source-conflict link | Preserve every candidate/conflict; do not fabricate causality |
| Investigation DAG cycle, unknown dependency, or excessive depth/fan-out | Plan validation error before request | Reject the plan; no work or projection is created |
| Specialist dispatch before dependency completion | Replay corruption error | Stop replay/supervision; never infer readiness from task completion messages |
| Duplicate event, idempotency key, assignment, or artifact ID | Replay/append uniqueness rejection | Preserve the first committed identity and investigate producer corruption |
| Specialist requests undeclared capability or artifact transition | Deny-by-default role-policy error | Record invalid output/failure within retry bounds; never broaden authority |
| Unknown or mismatched evidence citation | Artifact-policy rejection | Reject the claim; require a new cited artifact rather than repairing silently |
| Hostile evidence/model output contains instructions | Bounded untrusted-data context plus strict structured decoder | Treat as data, enforce runtime policy/citations, and fail malformed output |
| Specialist/model implementation raises | Coordinator exception boundary | Append classified failure, retry within assignment bound, keep supervisor alive |
| Specialist timeout | Runtime `wait_for` and durable timed-out task event | Release reservation, retry within bound, then fail explicitly |
| Investigation token budget cannot reserve a ready node | Deterministic global reservation check | Append `investigation.budget_exhausted.v1`; make no model call |
| Parallel specialists complete in a different order | Stable assignment ordinal and artifact-kind/ID ordering | Append/fold the same deterministic order |
| Unsupported or low-confidence hypothesis | Critic/finalization gate | Abstain or escalate with unresolved questions; emit no success-shaped conclusion |
| Unresolved contradiction | Typed contradiction and critique references | Preserve the conflict and block finalization |
| Specialist projection loss/corruption | Projection/ledger version mismatch or missing rows | Rebuild under maintenance authority from the tenant event stream |
| Stale specialist result after lease reclaim | Existing token/generation event-store fence | Reject the entire event/projection transaction |
| Duplicate action request | Tenant effect claim or adapter idempotency conflict | Suppress an identical duplicate; stop on mismatched scope and never widen authority |
| Action succeeds but outcome append is lost | In-flight requested attempt remains in replay | Reconcile target state before any redelivery retry |
| Approval changes while work is queued | Current digest, expiry, role, quorum, or revocation check fails | Deny before action intent; require a new exact approval |
| Stale action worker | PostgreSQL lease token/generation check or fenced append fails | Make no provider call and never append success |
| Action timeout after provider acceptance | Ambiguous execution event | Reconcile by exact target fingerprint and stable idempotency key; escalate if unknown |
| Adapter raises or returns malformed data | Adapter containment and strict result validation | Append classified failure/ambiguity within the active fence; keep supervisor alive |
| Target precondition changed | Fresh target fingerprint or explicit condition mismatch | Record preflight failure; do not execute under stale approval |
| Provider accepts action but postcondition fails | Fresh verification result is failure, partial, or unknown | Keep incident unresolved; invoke approved reversal only through a new durable intent |
| Cancellation races action | Cancellation recheck before intent and fenced terminal append | Cancel before effect where possible; reconcile an already-requested attempt |
| Projection loses Layer 8 rows | Ledger/projection mismatch | Rebuild forced-RLS read models under maintenance authority |
| Sandbox policy/spec/purpose/risk/approval changed while queued | Runtime digest or current approval recheck fails | Append no execution intent and require a newly reviewed exact scope |
| Sandbox approval expires after lifecycle intent | New execution remains denied | Reconcile existing identity, terminate active work, and redrive cleanup under the current fence |
| Output collection transport is transiently unavailable | Completed evidence could be lost by premature cleanup | Persist collection reconciliation, observe the stable workload, and retry within the approved bound before cleanup |
| Sandbox worker fence is stale | PostgreSQL token/generation check fails before backend readiness/provision/start/result/cleanup | Make no backend call and append no stale outcome |
| Crash before/after sandbox provision | Provisioning intent exists without a terminal observation | Observe stable backend name before create/retry; record reconciliation |
| Ambiguous sandbox create/delete | Backend timeout/unavailable after request | Reconcile presence/spec digest or absence; never assume success or exactly once |
| Mutable/privileged sandbox request | Canonical validation rejects image tag, shell/meta token, host path/socket/namespace, capability, or weakened isolation | Deny before durable work/backend access |
| Sandbox timeout/OOM/output/file/resource limit | Runtime result or enforced deadline/limit event | Terminate, persist explicit terminal class, request cleanup, preserve bounded evidence |
| Malicious archive or symlink/device | Pre-publication archive validator | Delete atomic staging, quarantine bounded metadata, publish no snapshot |
| Artifact malware/secret scan | Scanner returns redact/quarantine | Store content-addressed redacted/quarantine reference; never treat output as instructions |
| Sandbox cleanup repeatedly fails | Cleanup projection/attempt ceiling | Reconcile and redrive within bounds, then quarantine and escalate |
| Sandbox projection loss | Ledger/projection version mismatch | Rebuild forced-RLS sandbox/artifact/claim/cleanup views; never edit authoritative state |
| Memory candidate contract changes after review | Proposal contract digest mismatch | Reject acceptance; require a new version and review |
| Scanner fails or identifies injection/poisoning | Durable scan intent without completion or quarantine disposition | Record classified failure or quarantine; never chunk/embed/index the source |
| Embedding timeout or malformed/dimension/non-finite result | Intent exists and strict response/vector validation fails | Record classified/ambiguous failure, quarantine mismatches, and reconcile before retry |
| Crash after index intent | Intent lacks terminal observation | Observe tenant/content/version key before retry; never assume absent or completed |
| Tenant memory quota race | Atomic tenant-period conditional update loses | Record rejection/failure before provider call; never bypass the limit |
| Cross-tenant/ACL/purpose retrieval | Application authorization or forced RLS/filter returns no candidates | Return bounded empty/denied result; never broaden caller scope |
| Poisoned retrieved text asks for authority | Scanner mark and untrusted context delimiters | Treat as cited data only; runtime policy/tool/approval boundaries remain unchanged |
| Retrieval tie, duplicate, stale item, or contradiction | Stable ranking/MMR/freshness/conflict metadata | Deterministically order, exclude stale by policy, preserve conflict, and require critic/abstention |
| Summary adds unsupported claim or loses citation coverage | Claim/reference validation, drift, depth, and contradiction checks | Append summary rejection and use bounded deterministic extractive fallback |
| Legal hold or tenant deletion race | Current lifecycle fold and expected version | Hold blocks erasure; otherwise tombstone, purge derived rows/cache, erase referenced blob, and retain minimal ledger evidence |
| Memory projection/index loss | Checkpoint or ledger/version mismatch | Rebuild from ledger and authorized source blobs; index/cache are never truth |
| Evaluation dataset digest or provenance mismatch | Manifest verification fails before selection | Quarantine the version, block the gate, preserve bounded metadata, and open a tamper/release incident |
| Required CI attempts live network, secret, judge, or production effect | Hermetic execution policy denies the capability | Fail the run; move explicitly approved work to an isolated environment-gated class |
| Safety assertion regresses while aggregate quality improves | Per-gate comparison records a hard failure | Block release; never offset safety with a composite score |
| Baseline update is implicit, stale, or unreviewed | Candidate/baseline digest or review binding fails | Preserve the candidate result and require an explicit reviewed new baseline version |
| Waiver is expired, broadened, or applied to safety | Exact non-safety case/metric and expiry validation fails | Treat the regression as failed; hard safety remains non-waivable |
| Named fault replay diverges | Fixed cut point, clock, IDs, seed, or fixture produces a different fold/result | Stop promotion, retain both redacted results, and investigate nondeterminism |
| Model-judge configuration attempts sole safety authority or lacks a versioned delimited rubric | `ModelJudgeConfig` rejects the request | Execute no judge; deterministic safety gates still decide and required CI remains independent |
| Evaluation report leaks sensitive/high-cardinality content | Report schema/redaction/cardinality validation fails | Quarantine/delete affected output, rotate exposed material if needed, and block publication |
| Dataset deletion races an evaluation | Lifecycle/version check changes before result publication | Abort or mark unavailable; purge derived inputs/results per policy and never silently rewrite history |

Layer 11 implements evaluator-side detection for catalog, fixture, baseline,
waiver, replay, report, and configuration failures above. It does not perform
live production qualification or external deletion/incident operations.

Global event positions order commits but may contain numbers unused after a
rolled-back PostgreSQL identity allocation. That is not corruption. A per-
aggregate sequence gap is corruption.

The unresolved window is an external target accepting a future effect after its
intent but before Aegis records the result. Target idempotency or explicit
reconciliation is mandatory; Redis/inbox deduplication alone cannot solve it.
Provider idempotency headers also do not guarantee exactly-once billing.
Read-only connectors avoid mutation effects, but network reads still require
durable intent because they consume quota, expose credentials, and advance
authoritative ingestion cursors.

## Layer 12 observability failure modes

Exporter timeout, backpressure, queue overflow, collector restart, clock skew,
duplicate delivery, and missing telemetry cannot change authoritative work.
They open a bounded circuit, drop/count derived signals, report degradation, and
fall back to ledger replay. Invalid propagation is rejected before use.
Dashboard no-data is unknown, never healthy. Ledger corruption stops replay and
projection rebuild. Optional telemetry does not fail readiness; unavailable
correctness dependencies do. See
[on-call-observability.md](on-call-observability.md).

## Layer 13 operator failure modes

- Expired/missing session returns `401` and clears tenant state before sign-in.
- Authenticated denial returns `403`; cross-tenant/resource mismatch returns an
  audited anti-enumerating `404`.
- CSRF, Origin, digest, expiry, quorum, separation-of-duties, or authorization
  failure denies server-side regardless of browser state.
- Duplicate mutation reuses its idempotency record. Version mismatch returns a
  conflict and requires a fresh review; it never overwrites.
- Ambiguous action acknowledgement remains ambiguous until reconciliation and
  fresh verification. It never renders as success.
- Invalid, oversized, out-of-order, duplicate, or cross-tenant update pages are
  rejected/deduplicated/bounded. Reconnect is capped and tenant switch aborts the
  old cursor.
- UI exception, stale browser state, offline/degraded polling, or telemetry outage
  cannot change authoritative runtime state. Operators fall back to ledger replay.
- Static-serving failure is isolated from the API/runtime; rollback uses the prior
  immutable image. Dynamic HTML is no-store and hashed assets are immutable.

See [operator-ui.md](operator-ui.md) for triage and
[operator-accessibility.md](operator-accessibility.md) for release checks.

## Layer 14 protocol boundary failures

- Peer/card/capability/schema/key/certificate digest drift quarantines before
  network I/O; reviewed authority is never expanded automatically.
- Incomplete authentication, audience, scope, proof, tenant, purpose, risk,
  quota, budget, version, content type, or schema validation denies by default.
- Invocation/task intent precedes delivery. A crash after possible delivery is
  ambiguous, not failed or complete, until observe-before-retry reconciliation.
- Stale fencing tokens cannot complete, cancel, or reconcile an operation;
  duplicate idempotency keys resolve to the established operation.
- Cancellation is requested and acknowledged explicitly. A local timeout does
  not prove remote cancellation or exactly-once behavior.
- Unknown MIME, external artifact URLs, oversized/deep JSON, control tricks,
  malicious instructions, forged progress/artifacts, and tenant mismatch are
  rejected or quarantined without persisting raw content.
- Circuit breaking, bounded retries, quotas, budgets, cancellation, and
  backpressure prevent protocol outage from corrupting local runs or creating an
  unbounded denial-of-wallet loop.
- Revocation blocks new calls immediately; ambiguous in-flight work remains
  visible for reconciliation and operator escalation.
- Production readiness fails closed without deployed PKI/mTLS/token brokerage,
  egress controls, partner identity, rotation/revocation, and capacity evidence.

## Layer 15 deployment and disaster-recovery failures

| Failure | Detection | Safe response |
| --- | --- | --- |
| Unsigned/untrusted digest | promotion/admission verification | block; no mutable-tag fallback |
| Secret/key/OIDC unavailable | production readiness `503` | keep unready; no plaintext fallback |
| Schema outside app window | readiness/migration preflight | halt; compatible digest or roll forward |
| Concurrent migration | advisory lock denied | terminate duplicate; never bypass |
| Additive migration commits, app fails | canary/readiness/SLO | roll back compatible app; keep schema |
| Pod/zone restart | health/PDB plus replay | drain/reacquire; reject stale fence |
| Redis loss | lag/connection alert, DB outbox intact | recreate, republish/redrive/reconcile |
| PostgreSQL failover ambiguity | fence/sequence/integrity alert | stop writers, prove rows/generation |
| Restore mismatch | count/hash/sequence gate | quarantine restore; investigate/select another point |
| Projection/index loss | checkpoint/replay compare | rebuild only from ledger |
| Backup/object/key unavailable | restore preflight | remain unavailable |
| Retry storm | retry/queue/provider/pool saturation | shed before acceptance, cap/open circuits |
| Egress/CNI failure | readiness/network synthetic | deny external calls; retain intent |
| OTel loss | exporter health | degrade telemetry only |
| Region isolated or returns stale | writer generation | fence before shift; deny stale appends |
| GitOps/cluster drift | rendered/live diff | halt and reconcile reviewed revision |

Automatic rollback never executes destructive schema reversal or assumes an
external effect failed. Ambiguous outcomes remain visible until reconciliation.
