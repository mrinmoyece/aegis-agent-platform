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
