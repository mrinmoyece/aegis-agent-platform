# Protocol and memory positioning

## Current implementation

Internal Python contracts for events, queues, agents, artifacts, providers,
integrations, tools, policy, and memory are implemented. Layer 10 supplies
ledger-grounded memory storage, pgvector/lexical retrieval, context compaction,
privacy lifecycle, and specialist context integration. MCP clients/servers and
A2A endpoints remain unimplemented.

## Three-tier agent memory

Aegis implements three deliberately different memory tiers:

| Tier | Purpose | Authority and lifecycle |
| --- | --- | --- |
| Working state and context | Current plan, selected evidence, budgets, and compacted model context | Bounded and rebuildable from durable state; never authoritative by itself |
| Episodic event history | Ordered incident events, typed specialist artifacts, approvals, intents, effects, and verification | Append-only event ledger and source of truth |
| Semantic long-term knowledge | Runbooks, resolved incident knowledge, patterns, and retrieval indexes in pgvector | Derived and curated; citations point to authoritative source/version |

Every tier is tenant-scoped. Ingestion records provenance, classification,
source version, and retention policy. PII and secrets are minimized or redacted
before model use and indexing. Deletion and legal-hold behavior covers source
references, embeddings, caches, and summaries with auditable outcomes. Production
backup expiry remains unverified.

Retrieval combines relevance, recency, source quality, incident topology, and
policy. Context compaction preserves citations, uncertainty, unresolved
conflicts, approvals, and budgets; a summary cannot silently become a fact or
replace episodic history. Layer 10 tests cross-tenant isolation, stale knowledge
handling, deletion, provenance, compaction fidelity, and bounded context behavior.
See `memory-and-rag.md` and ADR 0017.

## Three protocol classes

### Internal domain protocols: correctness

Internal specialists communicate only through typed evidence, finding,
hypothesis, remediation, and verification artifacts committed to the event
ledger. The runtime owns the dependency DAG, budgets, leases, policy, replay,
and deterministic state. These Python/domain ports are the correctness
mechanism; no network agent protocol substitutes for them.

### MCP: tool and context integration

Model Context Protocol may be used at controlled adapter boundaries for tools or
context sources where its ecosystem is useful. MCP servers and returned content
are untrusted integrations. Runtime policy, tenant authorization, schema
validation, credential brokering, intent-before-effect, sandboxing, and audit
still apply. MCP is not the event store, queue, approval system, or internal
agent messaging bus.

### A2A: external agent interoperability

Agent2Agent Protocol is planned as a later external boundary for organizations
that need Aegis to accept or delegate bounded tasks to other agent systems. The
target adapter includes:

- Agent Card discovery and trust validation
- authenticated task, message, and artifact exchange
- streaming, status observation, and cancellation
- explicit tenant, principal, policy, classification, and correlation context
- durable mapping of every A2A task transition into the Aegis event ledger
- stable idempotency keys, duplicate detection, replay protection, deadlines,
  and ambiguous-outcome reconciliation
- schema/version negotiation, allowlists, quotas, redaction, and audit
- protocol conformance, authorization, tenant-isolation, cancellation,
  duplicate-delivery, downgrade, and malicious-peer security tests

An inbound A2A message becomes validated external evidence or a requested task;
it never directly mutates authoritative incident state or grants tool authority.
An outbound task is preceded by a durable intent and is governed like any other
external effect. A2A cancellation and status are mapped to explicit ledger
events, not treated as best-effort process signals.

## Boundary rule

Use internal typed protocols for platform correctness, MCP where useful for
tool/context adaptation, and A2A only for external agent interoperability. A2A
does not permit internal peer chat, uncontrolled specialist spawning, or bypass
of coordinator, tenant, policy, approval, and verification controls.
