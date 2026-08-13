# ADR 0009: Deterministic tenant governance, redact-by-construction audit, and reference-only secrets

- Status: Accepted
- Date: 2026-08-13

## Context

Layer 2 needs three more boundaries beyond authentication and tenant
authorization (ADR 0004): a way to decide whether a proposed operation is
allowed for a tenant, a way to prove *why* an authentication or authorization
outcome occurred, and a way for tools and adapters to reference credential
material without ever holding or logging it directly. Getting any of these
wrong is a common source of real incidents: policy logic entangled with I/O is
hard to test exhaustively; audit logs are only useful if credentials cannot
leak into them; and passing raw secret values through call stacks makes
accidental exposure in logs, exceptions, or telemetry likely.

## Decision

**Governance and quotas are a pure function of policy, request, and usage.**
`TenantPolicy` (allowlists, risk thresholds, approver roles, `QuotaLimits`) and
`PolicyEvaluator.evaluate` accept a `PolicyRequest` and a caller-supplied
`QuotaUsage` snapshot and return a `PolicyDecision` with no I/O, clock access,
or hidden state. Deciding *limits* is therefore fully deterministic and unit
testable; accounting the authoritative *usage* the evaluator consumes is a
separate, later durable-runtime concern and must not be conflated with the
decision logic itself.

**Audit events redact by construction, not by convention.** `AuditEvent` is
immutable and its `__post_init__` unconditionally passes `details` through
`redact_details`, which replaces any field whose key looks like a credential,
token, prompt, or secret, and scrubs inline bearer-token-shaped substrings from
remaining string content. A caller cannot construct an `AuditEvent` that skips
redaction. Event type names are additive and versioned
(`security.<name>.v1`); a schema change adds a new type rather than repurposing
an existing one, consistent with the platform-wide additive-event invariant.
`AuditStore` is tenant-scoped and append-only by contract; secret resolution
likewise requires a `TenantContext` matching the reference. The Postgres
migration backs this with a real trigger that rejects `UPDATE`/`DELETE`.

**Secrets are typed references, never material, once past the boundary that
resolves them.** `SecretReference` (provider, name, optional version) is the
only thing that should be logged, stored, or passed between components.
`SecretValue` is opaque: its `repr`/`str` are always redacted, and only an
explicit `.reveal()` call at the adapter boundary that truly needs bytes
returns them. `SecretProvider` implementations validate their own naming
conventions (for example, the environment provider requires an
`AEGIS_SECRET_` prefix and rejects arbitrary environment reads) so that a
misrouted reference fails closed instead of silently resolving the wrong
value.

## Consequences

Policy and quota changes can be tested exhaustively without a database,
network, or clock, but a decision is only as good as the usage snapshot a
future runtime supplies — this ADR does not claim quota *enforcement* exists
yet. Audit redaction adds a small, fixed cost to every event and must be kept
in sync as new sensitive field names or token shapes are identified; the
regex-based approach is a starting heuristic, not a formal data-classification
system, and should be revisited before Layer 6 data-classification work
lands. Reference-only secrets mean every adapter boundary that needs raw
material must call `.reveal()` explicitly, which keeps exposure points
grep-able, but the current `EnvironmentSecretProvider` is a local development
convenience, not a broker: it has no rotation, versioning, or centralized audit
of who resolved which secret, and a production-grade provider remains planned.
