# ADR 0021: BFF sessions and derived operator views

## Status

Accepted for Layer 13.

## Context

The operator experience needs tenant-scoped timelines, approvals, action status,
support reports, and replay without moving authorization, policy, or event truth
into a browser. Browser-held bearer tokens would enlarge the XSS blast radius.
Reading database projections directly would create a second authority and bypass
purpose-bound access audit.

## Decision

Use a backend-for-frontend boundary with server-side sessions. The browser receives
only a Secure, HttpOnly, SameSite=Strict `__Host-` cookie. OIDC authorization uses
PKCE, state, and nonce records that are one-use and bounded; the live token exchange
and shared production session repository remain deployment adapters. State-changing
requests require a trusted origin, a session-bound CSRF token, an idempotency key,
and optimistic concurrency.

Operator responses are bounded, provider-neutral derived views. The OpenAPI 3.1
document in `contracts/operator-api.openapi.json` is the backend/frontend contract
source. Generated TypeScript is drift checked, and every untrusted response is
validated again at runtime. View caches are always keyed by tenant and purpose and
are discarded on tenant or session change. The append-only event ledger remains
the only run-state authority.

The BFF reuses application-service ports. It does not expose database adapters,
projection repositories, raw prompts, raw evidence, credentials, or vendor SDK
types. Authorization, current policy, approval scope, expiry, quorum, separation of
duties, and effect readiness remain server decisions. Cross-tenant authenticated
resource requests use an audited anti-enumerating `404`.

## Consequences

- XSS cannot read session tokens, and the browser cannot widen authority.
- Deployments must provide live OIDC exchange, encrypted shared session storage,
  key rotation, reverse-proxy TLS, and production identity/browser qualification
  before readiness can become true.
- Cursor polling is the implemented real-time transport. It validates, bounds,
  deduplicates, orders, resumes, backs off, and tears down on tenant change. SSE or
  WebSocket may be added later behind the same validated event-page contract.
- UI availability, telemetry, and caches are non-authoritative. Their failure
  cannot change runtime correctness.
- The deterministic demo is visibly synthetic and performs no production network
  calls or effects.

## Alternatives rejected

- Browser-stored OIDC access tokens: rejected because JavaScript compromise would
  expose reusable bearer credentials.
- Client-only authorization: rejected because UI state is attacker controlled.
- Direct projection/database access: rejected because it bypasses application
  authorization, purpose audit, response bounds, and anti-enumeration.
- GraphQL or vendor-specific browser contracts: rejected because the existing
  provider-neutral OpenAPI boundary is smaller and reviewable.
