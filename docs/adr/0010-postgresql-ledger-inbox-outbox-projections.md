# ADR 0010: PostgreSQL ledger, inbox/outbox, and projections

- **Status:** Accepted
- **Layer:** 3

## Decision

Use PostgreSQL for the append-only tenant event ledger, tenant commit locks,
aggregate version heads,
transactional inbox/outbox, and rebuildable projections. Append locks one
aggregate head and enforces expected version. All tenant tables use forced RLS.
Event and security-audit rows reject update/delete through grants and triggers.
The non-superuser runtime login inherits an application role that cannot bypass
RLS; maintenance bypass is a distinct non-login role.

## Consequences

Events and outgoing messages share one commit boundary, and projections can
restart from monotonic checkpoints. `SKIP LOCKED` prevents duplicate concurrent
outbox claims but does not make external effects exactly once. The outbox and
projection tables remain mutable delivery/query state, never a second source of
truth. Global identity numbers order commits but are not promised gapless after
rollback. Schema evolution remains additive and migrations are forward-only.

Redis workers, provider calls, evidence connectors, and agent execution are
explicitly outside this decision and remain later layers.
