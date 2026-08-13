# ADR 0017: Event-grounded memory and derived RAG

- **Status:** Accepted
- **Date:** 2026-08-14

## Context

Incident specialists need bounded current context, cited history, and reusable
operational knowledge. Treating a vector database, cache, model transcript, or
generated summary as authoritative would bypass replay, tenancy, approvals,
retention, and evidence provenance. Embedding, summarization, and index writes are
nondeterministic or externally observable and can complete ambiguously.

## Decision

1. Use three explicit tiers. Working memory is a bounded deterministic context
   selection. Episodic memory is immutable ledger/artifact/evidence references
   plus derived cited summaries. Semantic memory is curated tenant-scoped,
   versioned knowledge with immutable provenance, ACL, retention, quality,
   conflict, supersession, and embedding metadata.
2. Keep the append-only event ledger as the sole source of truth. PostgreSQL
   pgvector, lexical indexes, projections, checkpoints, and Redis cache entries
   are derived and rebuildable.
3. Record candidate, scan, chunk, embedding, indexing, retrieval, compaction,
   summary, lifecycle, deletion, and rebuild intent before the corresponding
   nondeterministic or external operation. Fence results with the current work
   lease. Delivery is at-least-once; exactly-once embedding or indexing is not
   claimed.
4. Accept semantic memory only from authorized typed sources after
   canonicalization, digest binding, bounded scanning/redaction, deterministic
   chunking, and explicit human or policy acceptance. A model-written claim
   cannot promote itself to trusted memory.
5. Filter tenant, principal/service/role ACL, purpose, lifecycle, retention, and
   freshness before lexical/vector ranking. Rank and diversify deterministically;
   preserve exact citations, contradictions, and stable tie-breaking.
6. Render retrieved text only inside untrusted-data delimiters. It cannot grant a
   role, tool, approval, capability, policy change, or remediation authority.
7. Make compaction citation-preserving and replayable. Unsupported claims are
   rejected and replaced by a deterministic extractive fallback; raw source
   references remain available.
8. Keep deletable text in referenced erasable blobs. Immutable events contain
   identifiers, digests, versions, and minimal metadata. Tombstone and
   crypto-erasure events honestly preserve ledger metadata rather than claiming
   full erasure of immutable history.

## Consequences

Replay can reconstruct lifecycle and rebuild search state without trusting the
vector index. Cross-tenant access fails in both application authorization and
forced RLS. Retrieval remains explainable because every selected chunk retains
source citations and scores. The implementation pays additional event, fencing,
reconciliation, retention, and storage complexity.

The repository implements a deterministic eight-dimension embedding profile for
tests and the fake demo. It does not verify live model providers, production key
management or blob storage, external DLP/malware services, production load,
HA/DR, multi-region coherence, or backup expiry.

## Rejected alternatives

- **Vector store as truth:** cannot provide authoritative replay or lifecycle
  decisions.
- **Transcript memory:** mixes untrusted model text with state and has no stable
  provenance contract.
- **Model-selected authorization:** prompts cannot enforce tenant, ACL, purpose,
  retention, or approval policy.
- **Silent conflict overwrite:** hides contradictory operational evidence.
- **Summary replaces source:** destroys citation coverage and prevents drift
  investigation.
- **Exactly-once embedding/indexing claim:** provider and crash outcomes can be
  ambiguous; intent, idempotency, observation, and reconciliation are required.
