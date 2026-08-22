# ADR 0004: Separate identity from tenant authorization

- Status: Accepted
- Date: 2026-08-13

## Context

An authenticated subject may belong to multiple tenants with different roles.
Treating an identity token as sufficient tenant authority enables confused
deputy and cross-tenant failures.

## Decision

OIDC authentication establishes a principal. A separate authorization step
binds that principal, an explicit tenant, an action, and a resource. Tenant
context is carried through storage, queues, policy, telemetry, and audit.

## Consequences

No data or work API may infer a tenant from mutable content or use a global
default. Layer 2 must prove isolation with negative tests and database controls.
