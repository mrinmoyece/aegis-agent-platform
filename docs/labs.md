# Hands-on labs and failure injection

## Layer 1 lab: prove the foundation

**Implemented.**

1. Install development dependencies and run `make check`.
2. Break a domain boundary with a parent-relative infrastructure import and
   observe `tests/test_architecture.py` fail; then restore it.
3. Mutate a source payload after creating an event and observe the immutable
   snapshot test.
4. Render Compose with `make compose-config`.
5. Build with `make container-check`, run the image, inspect user `10001:10001`,
   and call `/healthz`.
6. Set `AEGIS_ENVIRONMENT=production` without external endpoints and observe
   readiness fail closed.

## Layer 2 lab: identity, tenancy, and governance vertical slice

**Implemented.** The manual walkthrough below is also proven by a committed
automated negative-test suite: `tests/test_identity_security.py`,
`tests/test_policy_security.py`, `tests/test_audit_secrets.py`,
`tests/test_migrations.py`, and cross-tenant/authentication cases in
`tests/test_api.py` (run `PYTHONPATH=src python -m pytest tests/ -k
"security or policy_security or audit_secrets or migrations or api"`).

1. Follow `identity-tenancy.md` to generate a deterministic RSA fixture, sign a
   JWT, and verify it with `JwtVerifier` against a `StaticJwksProvider`.
2. Mutate the token's audience, issuer, `exp`, or `kid` header one at a time
   and confirm the specific `AuthenticationErrorCode` returned for each case.
3. Resolve one principal through `InMemoryIdentityDirectory`, then call
   `AuthorizationService.decide` with a different target `tenant_id` and confirm
   `cross_tenant_access_denied` is returned before any permission is even
   considered.
4. Give a `RoleBinding` a past `expires_at` or a `revoked_at`, call
   `is_active` with a time after it, and confirm the authorization decision
   changes from allow to deny.
5. Call `PolicyEvaluator.evaluate` with a `QuotaUsage` at, then just over, each
   `QuotaLimits` field and confirm the corresponding `*_limit_exceeded` reason.
6. Construct an `AuditEvent` with an `authorization` field or an inline
   `Bearer ...` value in `details` and confirm `redact_details` scrubs it
   before the frozen dataclass exists — there is no way to construct one that
   skips redaction.
7. Run `make migration-check` and read
   `migrations/0001_identity_governance.sql`'s row-level-security policies and
   append-only audit trigger.

## Layer 3–4 lab: durable delivery and fenced workers

**Implemented.**

1. Run `tests/integration` against disposable PostgreSQL and Redis services.
2. Observe two workers race one work ID and only one PostgreSQL claim commit.
3. Renew the lease, release/reclaim it, then attempt a stale started append and
   observe `FencingError`.
4. Publish the same deterministic message identity twice and observe inbox
   deduplication and no terminal-state regression.
5. Add a malformed stream entry and observe poison rejection before a handler.
6. Run `tests/test_worker_runtime.py` to inspect fairness, backoff, cancellation,
   worker-bug containment, authorization, and bounded telemetry.

## Planned labs by layer

| Layer | Lab | Failure injection and evidence |
| --- | --- | --- |
| 2 | Live-database and live-Keycloak drill | Run the row-level-security policies and the append-only trigger against a running Postgres instance, and exercise `RemoteJwksProvider` against a real Keycloak realm with rotated keys — both are currently only asserted statically or against mocked transports |
| 3 | Incident-specific durable investigation | Crash after each coordinator transition; replay identical incident state |
| 3 | Schema evolution | Replay old checkout fixtures through additive upcasters |
| 4 | Connector ambiguity | Rate-limit and truncate Dynatrace/GitHub responses; preserve provenance and partial status |
| 4 | Deterministic parallelism | Randomize specialist completion order; obtain the same aggregate |
| 5 | Approval binding | Replay approval against another proposal, tenant, and expiry; deny all |
| 5 | Tool idempotency | Crash after accepted rollback; reconcile without duplicate effect |
| 5 | Sandbox escape | Attempt filesystem, process, privilege, and egress violations |
| 6 | Retrieval isolation | Poison a runbook and attempt cross-tenant vector retrieval |
| 7 | Adversarial evaluation | Inject misleading deployment timing and unsupported causal claims |
| 7 | Telemetry privacy | Send sensitive/high-cardinality content; prove redaction and rejection |
| 8 | Capacity | Load hot and broad tenants while measuring queue lag and projection delay |
| 8 | Regional failure | Lose a region and restore authoritative state within documented objectives |
| 8 | Supply chain | Attempt unsigned promotion and dependency/action tampering |

Every future lab must state prerequisites, expected events, pass/fail assertions,
cleanup, and the limitation it does not prove.
