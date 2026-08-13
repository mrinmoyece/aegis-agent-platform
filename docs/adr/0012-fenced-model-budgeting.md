# ADR 0012: Fence model calls with durable budget reservations

- Status: Accepted
- Date: 2026-08-13

## Context

Model calls are external effects with variable cost. At-least-once workers can
race, expire, or resume after another generation owns the work. Provider
timeouts can also leave billing ambiguous.

## Decision

The worker presents its PostgreSQL lease token and generation to the gateway.
The gateway deterministically routes, then atomically appends route/request/
reservation events and creates a tenant/run reservation while validating that
fence. Network I/O starts only after commit. Result, usage, charge, and release
are appended and projected under the same fence. Pricing is explicit and
versioned; unknown model or price denies. Projection tables are rebuildable from
the append-only ledger.

Raw prompt/tool content is not stored in model events. Events contain a digest
and bounded metadata. Provider SDK types and exceptions stay in adapters.

## Consequences

A stale worker cannot start or charge a call. Capacity can be conservatively
over-reserved until reconciliation. A provider may still bill an accepted call
whose response is lost; Aegis records billing ambiguity and does not claim
exactly-once charging. Durable encrypted response artifacts and automated
provider-billing reconciliation remain future work.
