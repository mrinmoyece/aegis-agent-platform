# ADR 0013: Persist evidence intent and correlate deterministically

- Status: Accepted
- Date: 2026-08-13

## Context

Incident sources are external, mutable, tenant-scoped, rate-limited, and
untrusted. At-least-once workers may race or resume after lease expiry. Vendor
responses can be partial, oversized, malformed, or inconsistent, and temporal
proximity does not prove causality.

## Decision

Use frozen provider-neutral evidence contracts and isolate vendor types in
adapters. Atomically persist `evidence.query_requested.v1` with durable work
before external reads. Require the active PostgreSQL lease token and generation
for query start, ingestion/result events, and source cursor advancement.

Canonicalize bounded redacted content, address it by SHA-256, deduplicate only
within a tenant, and quarantine invalid, oversized, or untrusted records. Events
carry bounded metadata rather than raw payloads. Raw retention is permitted only
through an encrypted external `aegis-object://` reference.

Build timelines with deterministic UTC ordering, typed exact links, bounded
clock-skew heuristics, explicit confidence/rationale, ambiguity preservation,
and source-conflict links. Do not infer causality or invoke a model.

## Consequences

Crashes can leave durable intent without a result, but cannot create an
unrecorded query. Stale workers cannot append evidence or advance cursors.
Records and citations remain reproducible across replay, while partial source
coverage remains visible. Storage costs are bounded and sensitive raw data is
excluded from the ledger.

Live API behavior, credentials, regional endpoints, external encrypted blob
storage, webhook intake, retention deletion, and source reconciliation remain
deployment or future-layer work. The deterministic bundle is input to later
specialists; it is not a diagnosis.
