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

## Layer 7 lab: durable specialist investigation

**Implemented.**

1. Run `python -m aegis_agent_platform.agents --scenario success`; confirm the
   final assessment is cited/redacted and remediation is proposal-only.
2. Run the `ambiguity` and `contradiction` scenarios; confirm the critic blocks
   finalization and the ledger preserves unresolved questions/contradictions.
3. Run `budget_exhaustion`; confirm the terminal budget event appears without a
   model/network call. Run `recovery`; confirm the change task has two attempts
   but only one committed output.
4. Run `make evals` to execute the CI-gated success, ambiguity, contradiction,
   budget, and recovery behavior matrix.
5. Run `tests/test_specialist_orchestration.py`; inspect cycle/role/citation/
   replay/cancellation/stale-fence/malformed-output/timeout/projection tests.
6. With a disposable `AEGIS_TEST_DATABASE_URL`, run
   `tests/integration/test_agent_postgres.py` to prove forced RLS, fenced writes,
   cursor pagination, and maintenance-role projection rebuild.

This lab does not call a live connector/model, approve or execute remediation,
verify a post-action recovery, or prove production deployment behavior. Layer 8
provides those controls through a separate runtime.

## Layer 8 lab: approval-gated controlled remediation

**Implemented with deterministic fakes.**

1. Run `python -m aegis_agent_platform.remediation --scenario approved-success`;
   inspect exact plan/action/policy digests, two distinct approvals, durable
   action intent, and fresh-evidence verification.
2. Run `denied`, `expired`, and `policy-attack`; confirm no action intent or
   adapter call is created.
3. Run `ambiguous-reconciled`; confirm reconciliation precedes any retry and the
   platform makes no exactly-once claim.
4. Run `verification-failure` and `crash-recovery`; confirm provider acceptance
   does not establish recovery and a lost outcome is reconciled before redelivery.
5. Run `make evals` and the remediation unit suites to inspect SoD/quorum races,
   stale digest/policy/role/revocation/fence, target substitution, cancellation,
   timeout, adapter containment, duplicate delivery, rollback/compensation, and
   hostile/oversized input tests.
6. With a disposable `AEGIS_TEST_DATABASE_URL`, run
   `tests/integration/test_remediation_postgres.py` for forced RLS, approval
   races, immutable decisions, effect claims, stale fencing, and projection
   rebuild.

This lab uses no live action endpoint or credential. It does not prove
production Kubernetes RBAC/identity, egress, API compatibility, read-after-write
semantics, sandbox isolation, HA/DR, or operator escalation.

## Layer 9 lab: hardened ephemeral sandbox

**Implemented with deterministic fakes and a mocked official client.**

1. Run the `approved-analysis`, `policy-denied`, and `prompt-injection` CLI
   scenarios. Confirm exact approval/spec/policy binding and no backend call on
   denial.
2. Run `malicious-archive`; inspect traversal/link/device/bomb validation and
   atomic publication tests in `tests/test_sandbox_workspace.py`.
3. Run `timeout`, `oom`, and `cancellation`; confirm explicit terminal state,
   cleanup intent, and no late result transition.
4. Run `ambiguous-provisioning` and `cleanup-recovery`; confirm stable identity,
   observe-before-create/delete, reconciliation events, and bounded recovery.
5. Run `output-quarantine`; verify only bounded redacted digest/size/media
   metadata is exposed.
6. Inspect `tests/test_kubernetes_sandbox_adapter.py`; assert the suspended Job
   security context and fail-closed readiness without verified external
   controls.
7. With disposable PostgreSQL/Redis URLs, run
   `tests/integration/test_sandbox_postgres.py` for canonical Layer 7/8 linkage,
   current approval, RLS, fencing, lifecycle persistence, and projection rebuild.

This lab launches no untrusted process, contacts no cluster, and does not prove
production admission/runtime/network isolation, malware scanning, secret
brokering, image signing, or supply-chain policy.

## Planned labs by layer

| Layer | Lab | Failure injection and evidence |
| --- | --- | --- |
| 2 | Live-database and live-Keycloak drill | Run the row-level-security policies and the append-only trigger against a running Postgres instance, and exercise `RemoteJwksProvider` against a real Keycloak realm with rotated keys — both are currently only asserted statically or against mocked transports |
| 3 | Schema evolution | Replay old checkout fixtures through additive upcasters |
| 4 | Connector ambiguity | Rate-limit and truncate Dynatrace/GitHub responses; preserve provenance and partial status |
| 6 | Retrieval isolation | Poison a runbook and attempt cross-tenant vector retrieval |
| 10 | Production adversarial evaluation | Add versioned datasets, semantic graders, and release baselines beyond the deterministic Layers 7–9 matrices |
| 10 | Telemetry privacy | Send sensitive/high-cardinality content; prove collector/backend redaction and rejection |
| 11 | Capacity | Load hot and broad tenants while measuring queue lag and projection delay |
| 11 | Regional failure | Lose a region and restore authoritative state within documented objectives |
| 11 | Supply chain | Attempt unsigned promotion and dependency/action tampering |

Every future lab must state prerequisites, expected events, pass/fail assertions,
cleanup, and the limitation it does not prove.
