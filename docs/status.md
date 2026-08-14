# Implementation status

The repository currently implements **Layer 11: layered deterministic
evaluation gates** on top of Layer 10 event-grounded memory, the Layer 7
specialist DAG, Layer 8 exact approval/effect boundary, and Layer 9 sandbox.

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
eight dimensions for deterministic evidence. Operator UI, MCP/A2A, and broad
autonomous production mutation remain deferred. See
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
independent penetration testing, large-scale human labeling, operator React UI,
MCP/A2A, 24/7 on-call evidence, HA/DR, multi-region, final load/chaos, and
compliance certification are deferred.
