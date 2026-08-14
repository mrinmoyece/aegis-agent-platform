# ADR 0024: Single-writer multi-region boundary

## Status

Accepted

## Context

The PostgreSQL event ledger is authoritative and aggregate sequences, leases, budgets,
approvals, and intent-before-effect depend on one serialization authority. Active-active
global writes would require a proven conflict and ordering model that does not exist.
DNS failover without fencing can create split brain and stale effects.

## Decision

Each tenant has one home writer region and monotonic writer generation recorded in
`tenant_writer_fences`. Only the home region with the current generation may append.
Writers resolve a tenant-specific credential from the trusted tenant context; a
process-wide generation is invalid for a multi-tenant process. Fence enforcement is
initially disabled by the additive migration so old and new revisions may overlap.
Activation requires seeded credentials, fence-aware revision readiness, complete drain
of older writers, and scoped approval. After activation the database trigger rejects
missing credentials as well as stale, wrong-region, or inactive credentials.
Other regions may host stateless ingress, read-only reporting replicas, caches, and
provider-local read paths, but mutations route to the home region.

Failover is approval-gated: freeze traffic, prove the old writer fenced, advance the
generation in durable control state, restore or promote the database, verify sequence
and checksum continuity, shift traffic, reconcile ambiguous work, rotate credentials,
and then admit writes. Failback is a new failover with another generation, never a DNS
reversal. Regional workers carry the generation they acquired; stale generations are
denied. Redis is rebuilt or redriven and never promoted as truth.

Tenant residency controls routing, backup location, replica placement, provider
locality, encryption, and transfer approval. Cross-region spend is bounded by explicit
tenant policy and transfer budgets.

## Consequences

- Split-brain prevention takes precedence over availability.
- RPO/RTO are objectives until a live drill measures them.
- Read replicas can be stale and cannot authorize effects or final reconciliation.
- Provider-local operations may be unavailable during failover rather than silently
  crossing residency boundaries.
- Active-active writes and exactly-once cross-region effects are explicitly unsupported.

## Alternatives rejected

- Active-active ledger writes were rejected because no deterministic merge exists for
  approvals, budgets, leases, or aggregate sequence conflicts.
- DNS-only failover was rejected because it does not fence old writers.
- Redis-based leadership was rejected because Redis is transport, not authority.
