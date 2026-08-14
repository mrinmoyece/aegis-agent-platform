# Operator UI security and operations guide

Layer 13 provides a responsive React operator workspace and a production-shaped BFF
contract. The checked-in capability is a deterministic synthetic demo and secure
boundary, not a live production identity deployment. `production_ready` is always
`false` until deployment-owned OIDC exchange, shared sessions, TLS, browser
qualification, and operational evidence exist.

## Information architecture

The workspace covers service health/SLOs, incident queue and cited timeline,
specialist DAG and hypotheses, provider-neutral usage/budgets, exact-scope
approvals, controlled action reconciliation and verification, sandbox quarantine,
memory provenance and tombstones, evaluation regressions, audit, replay, and
redacted support reports. Each record labels its authority as event fact, derived
state, model claim, operator decision, or unknown.

The append-only ledger is authoritative. Browser state, query results, polling
cursors, charts, and caches are derived and disposable. No browser path can mutate
run state directly.

## Session and authorization boundary

- The BFF uses Secure, HttpOnly, SameSite=Strict `__Host-aegis-session` cookies.
- OIDC initiation has bounded, one-use PKCE/state/nonce storage. Live exchange is
  not configured in this repository.
- Mutations require trusted Origin, session-bound CSRF, `Idempotency-Key`, and
  `If-Match`. The server rechecks tenant, role, policy, approval, expiry, quorum,
  separation of duties, and immutable digests.
- A `401` means the session is absent or expired. A `403` means the authenticated
  principal lacks an action. Tenant/resource mismatch is an audited `404` to avoid
  enumeration.
- Tenant change clears session, approval state, data, and update cursors before
  re-authentication. Cache keys include tenant and purpose.
- No bearer credential is written to local storage, session storage, JavaScript,
  logs, telemetry, or error displays.

## Safe approvals and actions

Approval requires a review dialog, immutable plan/policy digests, exact target,
risk/blast radius, evidence, expiry, quorum, and separation-of-duties context.
High-risk grants require typed confirmation. Duplicate submissions reuse an
idempotency key; stale versions surface a conflict rather than overwriting.

A recorded decision is not an effect success. Ambiguous provider acknowledgement
stays ambiguous, reconciliation precedes retry, and only fresh postcondition
verification may show recovery. Agents and UI code cannot approve, widen scope, or
mark an action verified.

## Updates, degradation, and recovery

`TenantEventPoller` provides visibility-aware bounded cursor polling because the
current BFF does not expose a live stream transport. It validates pages through the
same runtime schemas as ordinary API responses, resumes cursors, deduplicates event
IDs, rejects tenant mismatch, sorts out-of-order updates, caps retry delay/failures,
honors cancellation, and tears down on tenant change. Authentication expiry returns
to sign-in. Offline or exhausted polling is degraded/unknown, never healthy.

UI failure, browser closure, stale data, and telemetry outage do not affect ledger
truth or runtime work. Use the existing ledger replay and server-side runbooks for
authoritative diagnosis.

## Client security and privacy

- React text rendering is used; no `dangerouslySetInnerHTML` exists.
- Citations use an allowlist of `event:`, `evidence:`, `memory:`, `audit:`, and
  `artifact:` schemes. Downloads require reviewed media types, bounded size, and a
  safe filename.
- CSV cells neutralize spreadsheet formulas. Clipboard writes are bounded and
  redact bearer-shaped secrets.
- Support mode visibly redacts operational terms and hides metadata. It is
  presentation-only and is not persisted.
- Telemetry has a small event/field allowlist, 64-character values, and no payload,
  tenant, prompt, evidence, credential, or user text.
- Error boundaries emit only a fixed error code.
- CSP denies default sources, frames, inline script, and eval. HSTS, no-referrer,
  nosniff, COOP, permissions policy, immutable asset caching, and no-store HTML are
  configured by the non-root static image.

## Local deterministic demo

```bash
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend dev
```

Open `http://127.0.0.1:5173`, start the synthetic demo, and use keyboard navigation.
No production credentials or network adapters are used. The canonical checkout
incident includes SLO alerting, cited evidence, specialist reasoning, two-person
approval, an ambiguous action awaiting reconciliation, quarantine, memory citation,
evaluation regression, and replay/support views.

For the hardened static preview:

```bash
docker compose --profile operator-demo up --build operator-ui
curl --fail http://127.0.0.1:4173/healthz
```

The image runs as UID/GID `101:101`, drops all capabilities, supports a read-only
filesystem with `/tmp` tmpfs, emits no production source maps, and applies immutable
cache headers only to fingerprinted assets.

## Validation and upgrade policy

```bash
pnpm --dir frontend check
pnpm --dir frontend audit
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend e2e
make frontend-container-check
```

The lockfile and package-manager version are mandatory. Runtime and tooling
versions are exact, not ranges. TypeScript 6.0.3 is the current supported stable
compiler for the pinned `typescript-eslint`; TypeScript 7 is deferred until that
typed-lint boundary supports it. Upgrades must regenerate the lockfile, pass
contract drift, lint/types/tests/axe/Playwright, production audit/license policy,
bundle/CSP/source-map budgets, SBOM generation, and container smoke. Dependency
automation must not auto-merge major versions.

## Production readiness gaps

The repository has not live-tested OIDC login/logout/key rotation, distributed
session persistence, TLS proxy behavior, production browsers/assistive technology,
managed deployment, external telemetry/model/connectors, HA/DR/multi-region,
long-window load/chaos, independent penetration or accessibility audits, or
compliance certification. MCP and A2A remain deferred adapters. The deterministic
demo and automated axe/Playwright checks are not substitutes for those claims.
