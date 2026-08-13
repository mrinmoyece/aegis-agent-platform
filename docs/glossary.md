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

**Intent event** — Durable record of an exact planned side effect written before
attempting it.

**Lease** — Time-bounded claim on durable work; expiry permits recovery but does
not by itself fence stale writers.

**Projection** — Rebuildable query view derived from the event ledger.

**Provider-neutral type** — Core contract that does not expose a vendor SDK
object.

**Reconciliation** — Determining the outcome of an ambiguous external effect
from idempotency and target state.

**Specialist** — Fixed-role, least-privilege agent node assigned by the Incident
Coordinator; it cannot spawn peers.

**Tenant context** — Validated tenant identity explicitly propagated with an
operation; never inferred from mutable content.

**Verification window** — Predefined post-action interval and signals used to
decide whether service recovery is sustained.
