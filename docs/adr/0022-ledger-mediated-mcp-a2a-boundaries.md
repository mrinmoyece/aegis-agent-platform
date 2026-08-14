# ADR 0022: Keep MCP and A2A ledger-mediated boundaries

## Status

Accepted.

## Context

MCP provides a useful ecosystem boundary for tools and context. A2A provides an
external agent interoperability boundary. Neither protocol provides Aegis's
tenant authorization, authoritative event history, worker fencing, specialist
DAG ownership, budgets, approval semantics, deterministic aggregation, or
post-action verification.

Using either protocol as the internal specialist bus would make remote,
untrusted, delivery-at-least-once messages authoritative and would obscure
coordinator ownership and crash recovery.

## Decision

Internal specialists continue to communicate only through provider-neutral
typed artifacts committed to the append-only ledger. The Incident Coordinator
alone owns the plan, DAG, lifecycle, global budget, and aggregation.

MCP and A2A are isolated adapters around application commands and queries.
Protocol-specific types stop at those adapters. Every outbound effect records
durable intent first; every inbound message is authenticated, tenant-bound,
authorized, schema/size/purpose/policy validated, and converted through a local
command. External remediation is proposal-only and must enter Layer 8.

Peers are explicit tenant-scoped registry records with exact identity,
capability, schema, certificate/key, expiry, classification, risk, quota, and
egress pins. Drift and signature failures quarantine. Delivery is at-least-once;
idempotency and observation-before-retry reconciliation represent uncertainty
without claiming exactly once.

## Consequences

- A protocol outage cannot corrupt or reconstruct local run state.
- External agents cannot become autonomous internal peers, approve actions,
  spawn specialists, or broaden tools.
- Projections and operator views are rebuildable from events.
- Adapter code is larger because protocol lifecycle must map explicitly to
  durable application events.
- Broad federation and production PKI/token brokerage require separate
  qualification and remain unavailable until readiness dependencies pass.

## Alternatives rejected

- **MCP as internal tool/agent authority:** lacks Aegis approval, tenancy, event,
  and fencing semantics.
- **A2A peer mesh for specialists:** violates coordinator ownership,
  deterministic DAG aggregation, and ledger-only communication.
- **Synchronous proxy without durable intent:** loses crash windows and makes
  ambiguous delivery indistinguishable from failure or success.
