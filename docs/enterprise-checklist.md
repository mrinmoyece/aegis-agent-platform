# Enterprise capability checklist

Status meanings:

- **Implemented:** executable and tested in the current repository.
- **Scaffolded:** boundary or local configuration exists, but no production
  behavior is claimed.
- **Planned:** assigned to a future roadmap layer.

| Capability | Status | Evidence or target |
| --- | --- | --- |
| Typed Python package and strict checks | Implemented | `pyproject.toml`, `Makefile`, CI |
| Architecture dependency rule | Implemented | `tests/test_architecture.py` |
| Liveness and configuration readiness | Implemented | control-plane ASGI tests |
| Local pgvector PostgreSQL | Implemented | Compose plus live PostgreSQL 16 tests |
| Local Redis transport | Implemented | Redis Streams adapter, Compose, live tests |
| Local OIDC realm | Scaffolded | Keycloak import |
| OTLP, Prometheus, and Grafana topology | Scaffolded | `deploy/` |
| Dynatrace evidence read contract | Scaffolded | `integrations.dynatrace` |
| GitHub delivery evidence read contract | Scaffolded | `integrations.github` |
| Live Dynatrace and GitHub connectors | Planned | Future connector layer |
| Checkout-failure incident investigation | Planned | Layers 3–7 |
| Approval-gated rollback and recovery verification | Planned | Layers 5–7 |
| Fixed incident specialist roles and typed artifacts | Scaffolded | `agents` |
| Ledger-only specialist communication | Scaffolded | `ArtifactLedger` port |
| Coordinator DAG, capability, budget, and timeout enforcement | Planned | Layers 3–4 |
| Deterministic aggregation and conflict resolution | Planned | Layers 4–7 |
| Recursive spawning and peer chat prohibited | Scaffolded | `AGENTS.md`, ADR 0008 |
| Staff-level curriculum index | Implemented | `docs/curriculum.md` |
| Canonical 15/30/60-minute demo scripts | Implemented | `docs/demo-script.md` |
| Staff interview question bank with answer outlines | Implemented | `docs/interview-question-bank.md` |
| Hands-on and failure-injection lab plan | Implemented | `docs/labs.md` |
| Terminology and production-gap register | Implemented | glossary and limitations docs |
| Deep topic guides linked to code and tests | Implemented | `docs/identity-tenancy.md` |
| Detailed enterprise delivery blueprint | Implemented | `docs/enterprise-implementation-plan.md` |
| OIDC/JWT signature, issuer, audience, and expiry verification | Implemented | `identity.authentication.JwtVerifier`, deterministic RSA fixtures |
| Keycloak-compatible JWKS configuration and bounded refresh | Implemented | `identity.authentication.RemoteJwksProvider`, rotation fixture |
| Authoritative identity resolution (no client-asserted identity) | Implemented | `identity.authentication.AuthenticationService`, `IdentityDirectory` |
| Deny-by-default tenant/role authorization | Implemented | `identity.authorization.AuthorizationService` |
| Tenant governance policy and quota decisioning | Implemented | `policy.PolicyEvaluator` (pure; usage accounting planned) |
| Redacted, additive, append-only security audit events | Implemented | `audit.AuditEvent`, `InMemoryAuditStore` |
| Secret-reference abstraction (no raw material in logs/telemetry) | Implemented | `secrets_boundary.SecretReference`, `SecretValue` |
| Authenticated `/v1/me`, tenant, and policy control-plane routes | Implemented | `control_plane.api.ControlPlaneApp` |
| Live Keycloak network round-trip and key-rotation drills | Planned | Layer 2, deployment-dependent |
| Cross-tenant, expired-token, revoked-role, and quota/policy negative-test suite | Implemented | `tests/test_identity_security.py`, `tests/test_policy_security.py`, `tests/test_audit_secrets.py`, `tests/test_api.py` |
| EP-01 OIDC key-rotation and emergency-revocation drill | Planned | EP-01 operational exit evidence |
| EP-02 durable Postgres RLS enforcement proven against a live database | Planned | EP-02 database exit evidence |
| Durable Postgres-backed identity/tenant/policy/audit adapters | Implemented | `persistence.postgres`, live RLS/audit tests |
| Vault-backed secret broker with rotation | Planned | Layer 5 |
| Quota usage accounting projection | Implemented | Model usage events plus rebuildable versioned-cost view |
| Append-only event store | Implemented | `PostgresEventStore`, migration `0002`, live race/immutability tests |
| Additive event compatibility | Implemented | additive defaults and legacy fixture replay |
| Deterministic incident state machine | Planned | Specialist runtime; generic run-status projection exists |
| Intent-before-model-side-effect enforcement | Implemented | fenced model request/reservation before SDK call |
| Transactional inbox/outbox | Implemented | deduplication, atomic append, claims, retry/DLQ |
| Rebuildable projections/checkpoints | Implemented | run/artifact/approval/usage/tenant views |
| Authorized ledger/timeline inspection | Implemented | tenant-scoped redacted read-only API |
| Durable queue and fenced leases | Implemented | `queueing`, `runtime.postgres`, migration `0003`, live race tests |
| Retry, timeout, dead-letter, and recovery policy | Implemented | `runtime.WorkerSupervisor`, deterministic tests |
| Authorized queue/cancel/DLQ/reconcile operations | Implemented | `runtime.operations`; payload-free bounded views |
| Bounded runtime metrics and OTel spans | Implemented | `observability.runtime`; no identifier labels |
| Provider-neutral model contracts and deterministic fake | Implemented | `domain.model`, `providers.fake` |
| OpenAI and Anthropic official-SDK adapters | Implemented | isolated adapters plus mocked-transport tests |
| Capability/policy/cost/latency routing | Implemented | deterministic fail-closed `ModelRouter` |
| Versioned pricing and fenced budget reconciliation | Implemented | migration `0004`, gateway repository/events |
| Structured output and tool-argument validation | Implemented | Draft 2020-12 strict validation |
| Provider retry/failover/rate/concurrency/circuit controls | Implemented | deterministic clocks/backoff and state tests |
| Exactly-once provider billing | Planned | providers can bill ambiguous accepted calls; reconciliation required |
| Encrypted durable prompt/response artifacts | Planned | Layer 7 privacy/memory work |
| Tool schema registry and runtime policy | Planned | Layer 5 |
| Human approval and break-glass audit | Planned | Layer 5 |
| Isolated sandbox with egress policy and quotas | Planned | Layer 5 |
| Tenant-safe memory and retrieval provenance | Planned | Layer 6 |
| Three-tier working/episodic/semantic memory | Planned | Layer 6, `docs/protocols.md` |
| PII-safe compaction, retention, and deletion | Planned | Layer 6 |
| Data retention, export, and erasure workflows | Planned | Layer 6 |
| Offline evaluation datasets and baselines | Planned | Layer 7 |
| Online quality, safety, latency, and cost signals | Planned | Layer 7 |
| Model span/metric content redaction | Implemented | bounded catalog labels; no prompt/tenant/request labels |
| End-to-end trace/event correlation | Planned | Layer 8 |
| SLOs, alerts, runbooks, backup, and restore evidence | Planned | Layer 8 |
| HA deployment and capacity evidence | Planned | Layer 8 |
| SBOM, provenance, image signing, and release policy | Planned | Layer 8 |
| Compliance evidence mapping and access review | Planned | Layer 8 |
| MCP tool/context adapters under runtime policy | Planned | Layers 5–6 |
| External A2A Agent Card and task lifecycle adapter | Planned | Layer 8 |
| Durable A2A lifecycle mapping and replay protection | Planned | Layer 8 |
| A2A conformance, tenant, and malicious-peer tests | Planned | Layer 8 |

Changing a row to Implemented requires tests or operational evidence in the
same pull request. Planned capabilities map to concrete EP-01 through EP-16
delivery slices and exit gates in the enterprise implementation blueprint.
