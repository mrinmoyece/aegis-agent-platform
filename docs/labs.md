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

## Planned labs by layer

| Layer | Lab | Failure injection and evidence |
| --- | --- | --- |
| 2 | Tenant isolation | Swap tenant identifiers and signing keys; prove API and database denial |
| 3 | Durable investigation | Crash after each event append; replay identical incident state |
| 3 | Schema evolution | Replay old checkout fixtures through additive upcasters |
| 4 | Lease recovery | Pause a worker past expiry; prove stale fence rejection |
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
