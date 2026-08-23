# ADR 0019: Provider-neutral observability semantics

**Status:** Accepted

## Decision

Adopt versioned `aegis.telemetry.v1` operations, lifecycle/error/retryability/
ambiguity/recovery taxonomies, fixed metric definitions and buckets, an
attribute allowlist, deterministic sampling, strict W3C propagation, async
links, structured logs, and bounded non-blocking export. Vendor OTel types stay
inside adapters. Metric labels never contain tenant, user, run, incident,
artifact, target, correlation identifiers, or free text.

## Consequences

Telemetry remains useful but non-authoritative and safe under at-least-once
delivery. New attributes and metrics require additive review. Exporter loss
degrades observability but cannot change run correctness. Production SLO
attainment is not claimed by checked-in configuration.
