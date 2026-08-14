# ADR 0025: Ledger retention and partitioning

## Status

Accepted

## Context

Events and immutable audit facts are the basis for replay, investigations, approvals,
and effect reconciliation. Indefinite hot storage is costly, but deleting ledger truth
without policy, archive integrity, retrieval, and legal-hold controls would destroy
authority. Repartitioning an existing event table is a high-risk online migration.

## Decision

Default ledger retention mode is `retain`. `governed_archive` requires a tenant policy
version, legal-hold check, accepted ADR/change record, immutable encrypted object
archive, first/last position, event count, SHA-256 manifest, key reference, independent
restore test, and audited approval. `ledger_archive_manifests` is append-only.

Partition disposable or reclaimable tables first: outbox/inbox by completion month,
audit and projections by tenant/time where query plans prove value, and new event
installations by recorded-time range while preserving tenant/aggregate uniqueness and
global-position ordering. Existing event tables are not automatically repartitioned.
Use shadow partitions, dual validation, bounded backfill, checksum comparison, and a
short metadata cutover. Never use `TRUNCATE` or a downgrade migration on ledger truth.

Projection/index/cache retention may be shorter because replay rebuilds it. Outbox and
inbox rows are removed only after terminal ledger evidence, reconciliation windows, and
duplicate-delivery horizons expire.

## Consequences

- Storage reduction is slower than deleting rows but preserves evidence.
- Archive retrieval and key availability become disaster-recovery dependencies.
- Global positions need not be gapless; integrity checks compare ordered rows,
  aggregate sequences, counts, and hashes.
- No ledger deletion occurs under this ADR alone. A separate governed retention
  decision and executable restore evidence are mandatory.

## Alternatives rejected

- Time-based event deletion without archive verification was rejected because it breaks
  replay and audit.
- Treating object storage as a second writable ledger was rejected; archives are sealed
  historical copies, not an alternate authority.
- Automatic repartitioning in migration `0011` was rejected as unsafe for existing
  large tables.
