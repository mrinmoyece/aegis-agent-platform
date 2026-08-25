# Implementation status

The repository currently implements **Layer 14: secure MCP and A2A
interoperability** on top of the Layer 13 operator surface and durable runtime.

Layer 10 adds immutable working/episodic/semantic contracts, additive lifecycle
events and pure replay, authorized digest-bound ingestion, scanning/quarantine,
deterministic chunking, neutral fake embedding/summarization ports, fenced
intent-before-effect processing, atomic tenant quotas, forced-RLS pgvector and
lexical retrieval, deterministic ranking/diversity, exact citations, untrusted
context delimiters, contradiction abstention, citation-validating compaction,
retention/legal hold/tombstone/blob-erasure workflows, authenticated redacted
APIs, rebuild/reconciliation, a fake-only demo, and deterministic behavioral
evaluations.

Layer 11 implements immutable provider-neutral contracts, a governed synthetic
scenario/adversarial/recovery corpus, all 22 named deterministic fault cut
points, hard baseline gates, scoped expiring non-safety waivers, fixture
tamper/quarantine checks, bounded redacted JSON/Markdown/JUnit reports,
low-cardinality telemetry, and the list/filtered-run/replay/compare/baseline/
manifest CLI under `aegis_agent_platform.evals`, plus focused `make eval-*`
targets. The required suite contains 91
cases, including 12 adversarial cases; 22 evaluator meta-tests cover the harness.
See [evaluation.md](evaluation.md) and
[ADR 0018](adr/0018-layered-deterministic-evaluation-gates.md).
Evaluation artifacts are release evidence only; runtime safety and event truth
remain code-enforced.

The implementation does not certify a production Kubernetes cluster, live model,
production blob/key service, external DLP/malware scanner, HA/DR/multi-region
deployment, or final load profile. The executable embedding profile is fixed at
eight dimensions for deterministic evidence. Live production operator
qualification and broad autonomous production mutation remain deferred.
See
[limitations](limitations.md), [memory and RAG](memory-and-rag.md), and
[sandbox execution](sandbox-execution.md).

Layer 12 is implemented: provider-neutral semantic conventions, strict
propagation and async links, central sensitive-data/cardinality enforcement,
bounded structured logs/metrics/export, component health, configured SLIs/SLOs
and burn alerts, ten provisioned dashboards, authenticated observability APIs,
ledger-grounded replay/support reports, and six deterministic observability
evaluation cases.

This is configured/local evidence, not measured production SLO attainment.
Production model/connector/telemetry qualification, external managed backends,
independent penetration testing, large-scale human labeling, live production
identity/browser qualification, public protocol federation, 24/7 on-call evidence, HA/DR,
multi-region, final load/chaos, and compliance certification are deferred.

Layer 13 implements the provider-neutral operator contracts, secure server-side
session/PKCE boundary, CSRF/origin protections, anti-enumerating tenant behavior,
bounded derived view models and polling, immutable audit, exact-scope approval
decisions, deterministic synthetic checkout data, and a React workspace covering
all implemented operator surfaces. Frontend validation includes strict TypeScript,
runtime response schemas, unit/component/security/polling tests, axe checks,
deterministic Chromium journeys, contract drift, audit/license/bundle/CSP/SBOM
gates, and a non-root read-only static image. See
[operator-ui.md](operator-ui.md), [operator-accessibility.md](operator-accessibility.md),
and [ADR 0021](adr/0021-bff-session-and-derived-operator-views.md).

The BFF's live OIDC code exchange and distributed session repository are not
configured, so production readiness remains false. Automated accessibility and
browser tests are deterministic evidence, not independent audits or production
qualification.

Layer 14 implements neutral protocol contracts and additive lifecycle events,
curated MCP Streamable HTTP/local-fixed-stdio adapters, signed A2A Agent Cards
and JSON-RPC tasks, exact tenant peer registries and drift quarantine,
intent-before-network invocation/task orchestration, at-least-once
reconciliation/cancellation, forced-RLS PostgreSQL projections, bounded
telemetry, tenant-admin trust review, deterministic fakes/demos, and eight
protocol evaluation invariants. MCP is pinned to specification `2026-07-28` and
`mcp==2.0.0`; A2A uses protocol `1.0`, specification tag `v1.0.1`, and
`a2a-sdk==1.1.2`.

Distributed production token brokerage, PKI/mTLS deployment, public federation,
partner qualification, independent conformance certification, and production
load/HA/DR evidence are not implemented. Protocol readiness therefore fails
closed outside the deterministic/local boundary.
