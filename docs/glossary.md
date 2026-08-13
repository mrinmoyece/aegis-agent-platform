# Glossary

> Terms describe the intended architecture. A definition does not imply its
> implementation; see `enterprise-checklist.md`.

**Artifact** — Typed, tenant- and incident-scoped output committed by a
specialist to the event ledger.

**Causation ID** — Identifier linking an event to the event or command that
directly caused it.

**Controlled tool** — Runtime-mediated effect adapter with typed input, policy,
scoped authority, durable intent, and audit.

**Correlation ID** — Identifier joining events and telemetry for one workflow
without making telemetry authoritative.

**Deny-by-default** — Authorization posture in which any missing tenant match,
role, or permission produces a denial, never an implicit allow.

**Event ledger** — Append-only authoritative record from which incident state is
reconstructed.

**Fence** — Monotonically increasing token used to reject work from a stale
lease holder.

**Finding** — Specialist conclusion with explicit evidence citations and
confidence.

**Hypothesis** — Proposed causal explanation with supporting and conflicting
evidence, distinct from a fact.

**Idempotency key** — Stable identifier allowing duplicate requests to resolve
to one logical effect where the external system supports it.

**Inbox** — Tenant/source/message deduplication record committed in the same
transaction as the events produced by an incoming delivery.

**Dead-letter queue (DLQ)** — Tenant-scoped projection of work that exhausted
retry policy or failed permanently. Requeue requires authorization and explicit
approval; it never rewrites the failure events.

**Delivery count** — Redis pending-entry attempt count used for operations and
reclaim decisions. It is diagnostic transport metadata, not authoritative work
attempt state.

**Intent event** — Durable record of an exact planned side effect written before
attempting it.

**JWKS (JSON Web Key Set)** — Published set of public signing keys, keyed by
`kid`, that a `JwtVerifier` uses to check a token's signature without trusting
claims embedded in the token itself.

**Lease** — Time-bounded claim on durable work; expiry permits recovery but does
not by itself fence stale writers.

**Outbox** — Mutable delivery state committed atomically with causing events. It
supports at-least-once publication but is not authoritative run state.

**Projection** — Rebuildable query view derived from the event ledger.

**Projection checkpoint** — Monotonic per-tenant cursor advanced atomically with
a projection page; it can be deleted and recreated from the ledger.

**Row-level security (RLS)** — PostgreSQL policy restricting visible/writable rows
to transaction-local trusted tenant context. `FORCE ROW LEVEL SECURITY` also
subjects table owners unless they have explicit bypass authority.

**Provider-neutral type** — Core contract that does not expose a vendor SDK
object.

**Reconciliation** — Determining the outcome of an ambiguous external effect
from idempotency and target state.

**Shared stream** — Layer 4's single bounded Redis Stream. Tenant identity is
inside a validated envelope; PostgreSQL RLS and leases enforce isolation and
ownership. The choice bounds Redis cardinality but moves fairness to workers.

**Redaction** — Unconditional removal of credential-, token-, and secret-shaped
values from audit event details at construction time, not by caller
discipline.

**Role binding** — Tenant-scoped assignment of a role to a principal with
explicit activation and optional expiry/revocation, evaluated at decision
time rather than trusted from a token claim.

**Secret reference** — Typed pointer (provider, name, version) to secret
material that lets code request a secret without holding or logging its raw
value.

**Specialist** — Fixed-role, least-privilege agent node assigned by the Incident
Coordinator; it cannot spawn peers.

**Tenant context** — Validated tenant identity explicitly propagated with an
operation; never inferred from mutable content.

**Verification window** — Predefined post-action interval and signals used to
decide whether service recovery is sustained.
