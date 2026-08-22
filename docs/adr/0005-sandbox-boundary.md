# ADR 0005: Isolate untrusted execution outside the runtime

- Status: Accepted
- Date: 2026-08-13

## Context

Model-generated code and tool inputs are untrusted. Language-level restrictions
inside the worker process do not provide a defensible security boundary.

## Decision

Execute untrusted code in a separately enforced sandbox with least privilege,
resource limits, a read-only base, ephemeral storage, deny-by-default network
egress, and brokered scoped credentials. Runtime policy approval precedes
sandbox creation.

## Consequences

The initial implementation may use one isolation technology, but its contract
must permit stronger backends. A sandbox feature is incomplete without escape,
egress, quota, cleanup, and audit tests.
