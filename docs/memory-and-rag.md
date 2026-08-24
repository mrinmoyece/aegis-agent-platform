# Event-grounded memory, compaction, and RAG

Layer 10 implements tenant-safe three-tier memory for the governed specialist
DAG. The ledger remains authoritative; pgvector, full-text search, projections,
and Redis entries are derived retrieval aids.

## The three tiers

| Tier | Contents | Authority and bounds |
| --- | --- | --- |
| Working | Active run state, selected artifact/evidence references, and cited snippets | Deterministically assembled with token/byte limits and reserved safety/system budget; replayable context selection and compaction decisions |
| Episodic | Tenant/incident/run event and artifact references plus cited summaries | Events and referenced artifacts are truth; summaries are versioned derived data and never replace sources |
| Semantic | Curated incident, runbook, and lesson chunks | Human- or policy-accepted tenant knowledge with content digest, citations, ACL/security label, schema/chunker/embedder versions, event time, quality/confidence, retention/legal hold, conflicts, supersession/tombstone state, and embedding reference |

Core contracts live in `domain.memory`. They are immutable and provider-neutral.
The pure `replay_memory` fold validates gapless sequence and legal lifecycle
transitions without I/O, environment, clock, framework, or adapter imports.

## Safe ingestion

`MemoryIngestionService` accepts only an already-authorized typed
`SemanticMemory` contract and canonical source text whose SHA-256 digest matches
the recorded snapshot.

1. Append `memory.candidate_proposed.v1`.
2. Atomically reserve tenant ingestion bytes; reject durably before blob storage
   when exhausted.
3. Put canonical text behind a tenant-bound `aegis-object://` reference.
4. Require explicit human or policy acceptance and bind it to the immutable
   contract digest.
5. Record snapshot and scan intent, then classify, redact, mark injection/
   poisoning, or quarantine through a scanner port.
6. Record chunking intent and create deterministic bounded overlapping chunks.
7. Record embedding intent, reserve tenant tokens, then call the neutral
   embedding port with exact model, version, dimension, timeout, and stable
   idempotency key.
8. Validate finite normalized vectors and response identity before recording
   completion.
9. Record indexing intent before the derived pgvector/full-text write; append
   completion only under the current PostgreSQL fence.

Unknown index outcomes remain outstanding and are observed before retry.
Duplicates use content/version keys. New versions may supersede older ones, while
contradictions remain explicit. Rejected candidates erase their unaccepted source
blob. Raw source, vectors, query text, secrets, and unnecessary PII do not enter
immutable memory events.

## Hybrid retrieval

`HybridRetriever` canonicalizes and digests the query, records retrieval intent,
reserves a tenant retrieval quota, and logs no sensitive query text. The index
applies tenant, user/service/role ACL, purpose, lifecycle, expiry, quality, and
freshness filters before ranking.

Lexical and vector candidates use deterministic score normalization with
relevance, recency, and quality weights. Stable identifiers break ties, and
MMR-style diversity suppresses duplicate chunks. Top-k, candidate, byte, and
token bounds are contract-enforced. Selected results preserve exact citations,
provenance labels, score components, freshness, and contradiction references.
Cache keys include a tenant digest, policy/query digest, caller scope, and bounds;
cached values contain selected references rather than raw text or embeddings.

There is no unrestricted similarity or raw-vector API. Stale, superseded,
tombstoned, expired, or unauthorized memory is excluded by default. Pagination
uses bounded UUID cursors and returns redacted metadata.

## Context and compaction

`ContextBuilder` reserves the safety/system budget, then allocates bounded space
to working, episodic, and semantic tiers. It deduplicates, truncates at safe text
boundaries, preserves citations, and alternates high-priority context to reduce
lost-in-the-middle placement. Semantic snippets render between
`BEGIN_UNTRUSTED_MEMORY_DATA` and `END_UNTRUSTED_MEMORY_DATA` delimiters.

Retrieved content is data, not instruction. It cannot change policy, roles,
tools, capabilities, approvals, or remediation authority. Contradictory or
insufficient context sets an explicit abstention/critic requirement.

Compaction records intent and exact source references before summarization.
Summary claims must cite the allowed sources and pass coverage, depth, drift, and
contradiction checks. Unsupported output is rejected and a deterministic
extractive fallback is used. Summary versions remain derived; raw references
stay available.

## PostgreSQL, pgvector, and recovery

Migration `0009_event_grounded_memory_pgvector.sql` installs pgvector and creates
forced-RLS candidate, source, chunk, retrieval, job, quota, and checkpoint
tables. Tenant-first composite indexes precede an HNSW cosine index and GIN
full-text index. Database checks enforce eight finite vector elements for the
implemented profile. Source rows reject updates while allowing lifecycle purge.
The runtime application role is non-superuser and cannot truncate memory tables.

`PostgresMemoryLedger` atomically checks the worker lease while appending to the
separate memory or retrieval aggregate. `PostgresMemoryQuota` serializes
tenant-period reservations with conditional updates. `PostgresMemoryIndex`
provides filtered candidates, provenance, checkpoints, purge, and full rebuild.
Redis is cache only.

Recovery follows intent:

- observe version/content keys before embedding or indexing;
- preserve ambiguous intent instead of inventing failure or success;
- reject stale lease generations;
- quarantine model/dimension/vector mismatches;
- resume partial batches from recorded references;
- rebuild derived rows deterministically from the ledger and source blobs;
- invalidate tenant cache entries after lifecycle changes.

## Retention and privacy

Policy-derived TTL, legal hold, tombstone, supersession, tenant deletion,
derived-index purge, source-blob erasure, and cache invalidation are explicit
operations. Legal hold blocks deletion. The ledger retains minimal immutable
identifiers/digests and completion evidence; deletion-required content belongs in
encrypted, erasable referenced storage in production.

The local blob store is deterministic and not encrypted durable storage. The
implementation therefore claims derived index/cache purge and referenced-blob
erasure, not comprehensive GDPR erasure, backup expiry, or production
cryptographic erasure.

## APIs and deterministic demo

Authenticated `/v1/tenants/{tenant_id}/memory/*` routes expose ingest, acceptance,
rejection, status, retrieve, context, provenance, feedback, tombstone, retention,
legal-hold, and deletion operations. `MemoryOperations` separately authorizes
principal, tenant, action, role, and purpose. Responses are bounded and redacted.

Run the fake-only demonstration:

```bash
python -m aegis_agent_platform.memory
```

It ingests a prior incident and runbook, retrieves cited lessons, quarantines
poisoned input, preserves a contradiction, builds/compacts context, denies a
cross-tenant read, and purges derived memory. It uses no network, live model,
credential, or production data.

Run deterministic tests and the environment-gated pgvector/RLS/cache test:

```bash
python -m pytest tests/test_memory.py tests/test_memory_api.py \
  tests/test_memory_demo.py tests/test_memory_evals.py

AEGIS_TEST_DATABASE_URL=postgresql://... \
AEGIS_TEST_REDIS_URL=redis://... \
  python -m pytest tests/integration/test_memory_postgres.py
```

Use only disposable integration services: the shared fixture resets the database
schema.

## Deliberate gaps

Production-qualified operator UI, MCP/A2A adapters, live embedding/summarization verification,
production key management and encrypted blob storage, external DLP/malware
services, HA/DR, multi-region/global cache coherence, backup expiry, and final
production load evidence remain deferred. The fixed eight-dimension deterministic
profile is executable test evidence, not a general production embedding claim.
