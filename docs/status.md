# Implementation status

The repository currently implements **Layer 10: event-grounded memory, context
compaction, and provenance-preserving pgvector RAG** on top of the Layer 7
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

The implementation does not certify a production Kubernetes cluster, live model,
production blob/key service, external DLP/malware scanner, HA/DR/multi-region
deployment, or final load profile. The executable embedding profile is fixed at
eight dimensions for deterministic evidence. Operator UI, MCP/A2A, and broad
autonomous production mutation remain deferred. See
[limitations](limitations.md), [memory and RAG](memory-and-rag.md), and
[sandbox execution](sandbox-execution.md).
