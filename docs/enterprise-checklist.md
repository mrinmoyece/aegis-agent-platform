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
| Local pgvector PostgreSQL | Scaffolded | `compose.yaml` |
| Local Redis | Scaffolded | `compose.yaml` |
| Local OIDC realm | Scaffolded | Keycloak import |
| OTLP, Prometheus, and Grafana topology | Scaffolded | `deploy/` |
| Dynatrace evidence read contract | Scaffolded | `integrations.dynatrace` |
| GitHub delivery evidence read contract | Scaffolded | `integrations.github` |
| Live Dynatrace and GitHub connectors | Planned | Layer 4 |
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
| Deep topic guides linked to code and tests | Planned | Per-layer curriculum gates |
| Detailed enterprise delivery blueprint | Implemented | `docs/enterprise-implementation-plan.md` |
| OIDC token verification and key rotation | Planned | Layer 2 |
| Tenant membership authorization | Planned | Layer 2 |
| Tenant-isolated persistence and negative tests | Planned | Layer 2 |
| Append-only event store | Planned | Layer 3 |
| Additive event upcasting | Planned | Layer 3 |
| Deterministic run state machine | Planned | Layer 3 |
| Intent-before-side-effect enforcement | Planned | Layer 3 |
| Durable queue and fenced leases | Planned | Layer 4 |
| Retry, timeout, dead-letter, and recovery policy | Planned | Layer 4 |
| Provider adapters and normalized metering | Planned | Layer 4 |
| Tool schema registry and runtime policy | Planned | Layer 5 |
| Human approval and break-glass audit | Planned | Layer 5 |
| Isolated sandbox with egress policy and quotas | Planned | Layer 5 |
| Tenant-safe memory and retrieval provenance | Planned | Layer 6 |
| Three-tier working/episodic/semantic memory | Planned | Layer 6, `docs/protocols.md` |
| PII-safe compaction, retention, and deletion | Planned | Layer 6 |
| Data retention, export, and erasure workflows | Planned | Layer 6 |
| Offline evaluation datasets and baselines | Planned | Layer 7 |
| Online quality, safety, latency, and cost signals | Planned | Layer 7 |
| Trace/event correlation and content redaction | Planned | Layer 7 |
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
