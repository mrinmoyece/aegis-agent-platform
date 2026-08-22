# Limitations and production gaps

## Current Layer 1 implementation

- The API exposes only unauthenticated liveness and configuration readiness.
- No event-store adapter, projection, migration, or durable orchestration exists.
- No queue backend, renewal implementation, fencing enforcement, retry, or
  reconciliation exists.
- Dynatrace and GitHub packages are interfaces, not working connectors.
- Kubernetes, runbook, incident-management, and remediation adapters do not
  exist.
- Agent roles, artifacts, plans, budgets, and ledger are types only. There is no
  scheduler, model invocation, deterministic aggregation, critic enforcement,
  approval workflow, or specialist execution.
- Policy, sandbox, tools, memory, evaluation, and observability packages are
  boundaries only.
- Three-tier memory is a documented design only. No pgvector retrieval,
  provenance pipeline, PII handling, retention/deletion, or context compaction
  is implemented.
- No MCP or A2A endpoint exists. Neither protocol currently provides discovery,
  tool access, external task exchange, streaming, cancellation, or status.
- Keycloak, PostgreSQL, Redis, Collector, Prometheus, and Grafana configuration
  is for local learning. It is not hardened, highly available, backed up, or
  suitable for real tenant data.
- Example credentials are deliberately local-only. There is no secret broker.
- CI scans and builds a baseline but does not yet emit an SBOM, provenance,
  signature, release artifact, or deployment.

## Claims deliberately not made

Aegis does not currently diagnose checkout failures, protect production data,
guarantee exactly-once effects, provide a secure code sandbox, satisfy a
compliance framework, meet an SLO, or support multi-region recovery.

## Closing gaps

`roadmap.md` defines the acceptance gate for each layer and
`enterprise-checklist.md` tracks capability status. A gap moves to Implemented
only with code, tests, and operational evidence linked from its curriculum
document. `enterprise-implementation-plan.md` specifies the implementation
sequence, data and security contracts, failure tests, SLO hypotheses, deployment
evidence, and production-readiness review needed to close every gap.
