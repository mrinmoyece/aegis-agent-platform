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
| Dynatrace evidence adapter | Implemented | OAuth2 bounded adapter plus mocked transport tests; live environment unverified |
| GitHub delivery evidence adapter | Implemented | GitHub App bounded adapter plus mocked transport tests; live installation unverified |
| Kubernetes read-only evidence adapter | Implemented | neutral boundary and mocked official-client transport; live cluster unverified |
| Versioned runbook adapter | Implemented | schema/trust fixtures; remote repository unverified |
| Durable evidence query intent and fenced cursors | Implemented | `evidence.service`, migration `0005`, stale-generation tests |
| Immutable redacted evidence ingestion and quarantine | Implemented | canonical digest/dedup/citation tests and forced-RLS projections |
| Deterministic evidence timeline and conflict preservation | Implemented | `evidence.correlation`; no causal inference or specialist reasoning |
| Live connector environment certification | Planned | account/cluster scopes, egress, TLS, rotation, residency drills |
| Verified connector webhooks and replay protection | Planned | no webhook routes in Layer 6 |
| Checkout-failure incident investigation | Implemented | Fake-only Layer 7 workflow; no live diagnosis claim |
| Approval-gated controlled action and recovery verification | Implemented | Layer 8 fake workflow plus fixed-shape Kubernetes rollout restart; no live target claim |
| Fixed incident specialist roles and typed artifacts | Implemented | `agents.artifacts`, role/output policy tests |
| Ledger-only specialist communication | Implemented | `reasoning.artifact_recorded.v1`, replay fold |
| Coordinator DAG, capability, budget, and timeout enforcement | Implemented | `agents.coordination`, `agents.service`, ADR 0014 |
| Deterministic evidence correlation and conflict representation | Implemented | Layer 6 bundles plus Layer 7 hypothesis/contradiction/critic artifacts |
| Recursive spawning and peer chat prohibited | Implemented | Fixed DAG/runtime boundary; no spawning/chat interface |
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
| Deterministic incident state machine | Implemented | Pure Layer 7 event fold and corruption tests |
| Intent-before-model-side-effect enforcement | Implemented | fenced model request/reservation before SDK call |
| Transactional inbox/outbox | Implemented | deduplication, atomic append, claims, retry/DLQ |
| Rebuildable projections/checkpoints | Implemented | run/artifact/approval/action/usage/tenant and specialist views |
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
| Provider-neutral remediation/action contracts and strict bounds | Implemented | `domain.remediation`, canonical digest and hostile-input tests |
| Deny-by-default exact action policy | Implemented | allowlist, target, window, risk, blast-radius, quota, evidence, critic, and digest tests |
| Authenticated exact-scope human approval | Implemented | SoD, distinct quorum, roles, expiry, revocation, concurrency, idempotency, immutable audit |
| Break-glass approval | Planned | stronger authentication, notification, and retrospective review required |
| Intent-before-action-side-effect enforcement | Implemented | current fence/policy/approval/target recheck and `action.execution_requested.v1` |
| At-least-once effect idempotency and reconciliation | Implemented | tenant key, target fingerprint, effect claim, ambiguity, duplicate/conflict tests |
| Explicit fresh-evidence postcondition verification | Implemented | success/failure/partial/unknown records; API acceptance is not recovery |
| Deterministic fake controlled-action adapter and CLI | Implemented | seven fake-only scenarios; no network or credential |
| Fixed-shape Kubernetes rollout-restart adapter | Implemented | official-client boundary tests; live cluster unverified |
| Authorized bounded remediation APIs | Implemented | proposal/decision/revocation/status/cursor routes with redaction |
| Forced-RLS remediation projections and immutable decisions | Implemented | migration `0007`, environment-gated PostgreSQL race/RLS/rebuild tests |
| Remediation metrics/traces without sensitive content | Implemented | fixed operation/outcome labels; no prompt/evidence/tenant/target labels |
| General tool schema registry and arbitrary tool execution | Planned | broad tool authority is not exposed by Layer 8 |
| Immutable provider-neutral sandbox contracts and strict validation | Implemented | `domain.sandbox`; argv-only, digest-pinned image, canonical path/env/network/resource contracts |
| Isolated sandbox with egress policy and quotas | Implemented | `sandbox`, migration `0008`, deterministic fake; production enforcement readiness remains false until verified |
| Intent-before-sandbox lifecycle effects and reconciliation | Implemented | fenced provision/start/terminate/cleanup events, stable names, observe-before-create, ambiguity tests |
| Safe content-addressed workspace and artifacts | Implemented | atomic ZIP/TAR extraction, traversal/link/device/bomb denial, scanner/redactor/quarantine hooks |
| Hardened Kubernetes sandbox Job adapter | Implemented | official client boundary and locked-down suspended manifest; no live cluster certification |
| Production sandbox admission/runtime/network verification | Planned | cluster policy, runtime class, PID limit, default-deny network and egress proxy deployment evidence |
| Authenticated bounded sandbox APIs and fake CLI/evals | Implemented | request/status/artifact/cleanup cursor routes and deterministic scenarios |
| Tenant-safe memory and retrieval provenance | Implemented | `domain.memory`, `memory`, migration `0009`, deterministic and live pgvector/RLS tests |
| Three-tier working/episodic/semantic memory | Implemented | `docs/memory-and-rag.md`, ADR 0017, replay and context tests |
| PII-safe compaction, retention, and deletion | Implemented | scanner/redaction hooks, cited fallback, legal hold/tombstone/blob-erasure tests; production DLP/blob store unverified |
| Data retention, export, and erasure workflows | Implemented | TTL/legal hold/deletion/derived purge; export and backup expiry remain planned |
| Deterministic hybrid pgvector RAG | Implemented | filtered lexical/vector ranking, MMR, exact citations, tenant-safe cache and live pgvector test |
| Memory quotas and fenced lifecycle recovery | Implemented | atomic tenant-period reservations, durable intent/results, reconciliation and rebuild tests |
| Deterministic specialist behavioral evaluations | Implemented | success, ambiguity, contradiction, budget, recovery; `make evals` |
| Deterministic remediation behavioral evaluations | Implemented | approval success/denial/stale, ambiguity, verification/rollback, policy attack, crash recovery |
| Layered provider-neutral evaluation contracts and harness | Implemented | `aegis_agent_platform.evals`; ADR 0018; 91-case catalog |
| Governed synthetic scenario/adversarial/recovery corpus | Implemented | versioned manifest/fixtures; 12 adversarial cases and 22 fault cuts |
| Hermetic deterministic release gates and hard safety baselines | Implemented | no live network, secrets, judge, or production effects |
| Scoped expiring evaluation waivers and reviewed baseline changes | Implemented | non-safety waivers only; explicit reviewed update |
| Environment-gated evaluation integration | Implemented | `make eval-integration`; disposable PostgreSQL/Redis only, separate from required CI |
| Opt-in live/statistical evaluation | Scaffolded | fail-closed capped boundary; no adapter registered or production qualification |
| Isolated optional model-as-judge | Scaffolded | configuration guard only; no judge execution; never sole safety gate |
| Evaluation developer CLI and `make eval-*` targets | Implemented | list/run `--case`/`--tag`/replay/compare/update-baseline/check-fixtures/write-manifest; focused Make targets |
| Bounded redacted evaluation telemetry and reports | Implemented | JSON/Markdown/JUnit; release evidence, never runtime truth |
| Live production evaluation evidence | Planned | no live calls or production qualification |
| Online quality, safety, latency, and cost signals | Planned | observability/SLO layer |
| Model span/metric content redaction | Implemented | bounded catalog labels; no prompt/tenant/request labels |
| Specialist span/metric content redaction | Implemented | fixed operation/role labels; no evidence/prompt/tenant/run labels |
| Authorized investigation status/task/artifact APIs | Implemented | tenant authorization, redacted cursor pages |
| Tenant-RLS specialist projections and rebuild | Implemented | migration `0006`, live PostgreSQL test |
| End-to-end trace/event correlation | Planned | Layer 12 |
| SLOs, alerts, runbooks, backup, and restore evidence | Planned | Layer 12 |
| HA deployment and capacity evidence | Planned | Layer 12 |
| SBOM, provenance, image signing, and release policy | Planned | Layer 12 |
| Compliance evidence mapping and access review | Planned | Layer 12 |
| MCP tool/context adapters under runtime policy | Planned | Layer 12 |
| External A2A Agent Card and task lifecycle adapter | Planned | Layer 12 |
| Durable A2A lifecycle mapping and replay protection | Planned | Layer 12 |
| A2A conformance, tenant, and malicious-peer tests | Planned | Layer 12 |

Changing a row to Implemented requires tests or operational evidence in the
same pull request. Planned capabilities map to concrete EP-01 through EP-16
delivery slices and exit gates in the enterprise implementation blueprint.

## Layer 12 evidence

- Implemented: semantic catalog, redaction/cardinality enforcement, strict
  propagation, structured logs, metric contracts, health semantics,
  authenticated timelines/SLO summaries/support manifests, replay CLI, rules,
  dashboards, collector hardening, deterministic tests, and six CI-gated
  observability evaluation cases.
- Configured/local evidence only: SLO targets, burn alerts, dashboard panels,
  collector/Prometheus/Grafana topology.
- Not complete: production SLO attainment, live production telemetry
  qualification, external managed backends, 24/7 on-call evidence, operator
  production qualification, HA/DR/multi-region, final load/chaos, or compliance
  certification.

## Layer 13 operator evidence

| Control | Status | Evidence |
| --- | --- | --- |
| Secure BFF session/PKCE boundary | Implemented boundary | `operator.session`, secure-cookie/CSRF/origin tests; live exchange/shared sessions unverified |
| Tenant/RBAC and anti-enumeration | Implemented | server authorization and audited `401`/`403`/`404` tests |
| Bounded OpenAPI-derived contracts | Implemented | OpenAPI 3.1, deterministic TS generator, Zod rejection, drift gate |
| Exact-scope safe mutation UX | Implemented | digest/expiry/quorum/SoD review, typed confirm, idempotency/concurrency tests |
| Cursor updates and tenant teardown | Implemented polling | validation, resume, dedupe, ordering, reconnect and abort tests; SSE/WebSocket deferred |
| Client privacy/security | Implemented | URL/download/CSV/clipboard/redaction/telemetry/error/CSP tests |
| WCAG 2.2 AA target | Automated evidence | semantic tests, keyboard flows, themes/reduced motion, axe; independent/manual qualification deferred |
| Supply chain/static serving | Implemented local/CI | pinned lock/toolchain/actions/images, audit/license/bundle/source-map/CSP/SBOM and non-root smoke |
| Live production identity/browser/deployment | Planned | OIDC exchange, shared encrypted sessions, TLS proxy, browser/AT matrix, managed rollout |
