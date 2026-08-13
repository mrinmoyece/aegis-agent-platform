BEGIN;

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE memory_candidate_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    memory_id uuid NOT NULL,
    version_key char(64) NOT NULL,
    source_snapshot_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN (
        'incident', 'runbook', 'lesson', 'artifact', 'evidence'
    )),
    candidate_status text NOT NULL CHECK (candidate_status IN (
        'proposed', 'accepted', 'rejected', 'quarantined'
    )),
    lifecycle_status text NOT NULL CHECK (lifecycle_status IN (
        'active', 'superseded', 'tombstoned', 'deleted'
    )),
    security_label text NOT NULL CHECK (security_label IN (
        'public', 'internal', 'confidential', 'restricted'
    )),
    schema_version text NOT NULL,
    chunker_version text NOT NULL,
    embedder_version text NOT NULL,
    embedding_model text NOT NULL,
    embedding_dimension integer NOT NULL CHECK (embedding_dimension = 8),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    quality double precision NOT NULL CHECK (quality BETWEEN 0 AND 1),
    retention_class text NOT NULL,
    expires_at timestamptz,
    legal_hold boolean NOT NULL DEFAULT false,
    legal_hold_reference text,
    deletion_scope text NOT NULL CHECK (deletion_scope IN (
        'derived_only', 'derived_and_referenced_blob', 'crypto_erasure'
    )),
    policy_reference text NOT NULL,
    accepted_by text NOT NULL,
    memory_document jsonb NOT NULL CHECK (
        jsonb_typeof(memory_document) = 'object'
        AND octet_length(memory_document::text) <= 131072
    ),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, memory_id),
    UNIQUE (tenant_id, version_key),
    CHECK (legal_hold = (legal_hold_reference IS NOT NULL))
);

CREATE INDEX memory_candidate_status_idx
    ON memory_candidate_projection (
        tenant_id, lifecycle_status, candidate_status, security_label,
        quality DESC, created_at DESC, memory_id
    );
CREATE INDEX memory_candidate_retention_idx
    ON memory_candidate_projection (
        tenant_id, expires_at, legal_hold, memory_id
    );

CREATE TABLE memory_source_snapshots (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    snapshot_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    source_kind text NOT NULL,
    source_reference text NOT NULL CHECK (
        source_reference <> '' AND octet_length(source_reference) <= 512
    ),
    source_version text NOT NULL CHECK (
        source_version <> '' AND octet_length(source_version) <= 128
    ),
    content_digest char(64) NOT NULL,
    content_reference text NOT NULL CHECK (
        content_reference LIKE 'aegis-object://%'
        AND octet_length(content_reference) <= 2048
    ),
    citation_metadata jsonb NOT NULL CHECK (
        jsonb_typeof(citation_metadata) = 'array'
        AND jsonb_array_length(citation_metadata) BETWEEN 1 AND 64
        AND octet_length(citation_metadata::text) <= 65536
    ),
    trust_tier text NOT NULL CHECK (trust_tier IN (
        'verified', 'reviewed', 'unverified', 'hostile'
    )),
    occurred_at timestamptz NOT NULL,
    captured_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, snapshot_id),
    UNIQUE (tenant_id, memory_id, content_digest)
);

CREATE INDEX memory_source_reference_idx
    ON memory_source_snapshots (
        tenant_id, source_kind, source_reference, source_version, snapshot_id
    );

CREATE TRIGGER memory_source_snapshots_no_update
BEFORE UPDATE ON memory_source_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE memory_chunk_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    chunk_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 511),
    content text NOT NULL CHECK (
        content <> '' AND octet_length(content) <= 64000
    ),
    content_digest char(64) NOT NULL,
    token_count integer NOT NULL CHECK (token_count BETWEEN 1 AND 65536),
    byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 64000),
    start_offset integer NOT NULL CHECK (start_offset >= 0),
    end_offset integer NOT NULL CHECK (end_offset > start_offset),
    citation_metadata jsonb NOT NULL CHECK (
        jsonb_typeof(citation_metadata) = 'array'
        AND jsonb_array_length(citation_metadata) BETWEEN 1 AND 64
    ),
    embedding_reference text NOT NULL CHECK (
        embedding_reference LIKE 'aegis-embedding://%'
        AND octet_length(embedding_reference) <= 1024
    ),
    embedding_model text NOT NULL,
    embedder_version text NOT NULL,
    embedding vector(8) NOT NULL,
    contradiction_ids uuid[] NOT NULL DEFAULT '{}',
    search_document tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', content)
    ) STORED,
    indexed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, chunk_id),
    UNIQUE (tenant_id, memory_id, ordinal),
    CHECK (vector_dims(embedding) = 8),
    CHECK (vector_norm(embedding) > 0),
    CHECK (embedding::text !~* '(nan|infinity)')
);

CREATE INDEX memory_chunk_tenant_memory_idx
    ON memory_chunk_projection (tenant_id, memory_id, ordinal, chunk_id);
CREATE INDEX memory_chunk_search_idx
    ON memory_chunk_projection USING gin (search_document);
CREATE INDEX memory_chunk_vector_idx
    ON memory_chunk_projection USING hnsw (embedding vector_cosine_ops);

CREATE TABLE memory_retrieval_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    retrieval_id uuid NOT NULL,
    query_digest char(64) NOT NULL,
    purpose text NOT NULL CHECK (purpose <> '' AND octet_length(purpose) <= 128),
    policy_version text NOT NULL,
    candidate_references jsonb NOT NULL CHECK (
        jsonb_typeof(candidate_references) = 'array'
        AND jsonb_array_length(candidate_references) <= 500
        AND octet_length(candidate_references::text) <= 131072
    ),
    selected_references jsonb NOT NULL CHECK (
        jsonb_typeof(selected_references) = 'array'
        AND jsonb_array_length(selected_references) <= 50
        AND octet_length(selected_references::text) <= 65536
    ),
    status text NOT NULL CHECK (status IN (
        'requested', 'completed', 'failed'
    )),
    error_code text CHECK (
        error_code IS NULL OR octet_length(error_code) <= 128
    ),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    requested_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, retrieval_id)
);

CREATE INDEX memory_retrieval_status_idx
    ON memory_retrieval_projection (
        tenant_id, status, requested_at DESC, retrieval_id
    );

CREATE TABLE memory_job_claims (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    idempotency_key text NOT NULL CHECK (
        idempotency_key <> '' AND octet_length(idempotency_key) <= 256
    ),
    memory_id uuid NOT NULL,
    job_kind text NOT NULL CHECK (job_kind IN (
        'scan', 'chunk', 'embed', 'index', 'retrieve', 'summarize',
        'delete', 'rebuild'
    )),
    content_version_key char(64) NOT NULL,
    lease_token uuid NOT NULL,
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 10),
    status text NOT NULL CHECK (status IN (
        'intent_recorded', 'running', 'completed', 'failed', 'ambiguous'
    )),
    result_reference text,
    last_error_code text CHECK (
        last_error_code IS NULL OR octet_length(last_error_code) <= 128
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key),
    UNIQUE (tenant_id, memory_id, job_kind, content_version_key)
);

CREATE INDEX memory_job_ready_idx
    ON memory_job_claims (
        tenant_id, status, updated_at, memory_id, job_kind
    ) WHERE status IN ('intent_recorded', 'running', 'failed', 'ambiguous');

CREATE TABLE memory_quota_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    usage_period text NOT NULL,
    ingested_bytes bigint NOT NULL DEFAULT 0 CHECK (ingested_bytes >= 0),
    embedded_tokens bigint NOT NULL DEFAULT 0 CHECK (embedded_tokens >= 0),
    retrieval_count bigint NOT NULL DEFAULT 0 CHECK (retrieval_count >= 0),
    summary_tokens bigint NOT NULL DEFAULT 0 CHECK (summary_tokens >= 0),
    active_jobs integer NOT NULL DEFAULT 0 CHECK (active_jobs >= 0),
    last_global_position bigint NOT NULL DEFAULT 0 CHECK (
        last_global_position >= 0
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, usage_period)
);

CREATE TABLE memory_index_checkpoints (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    index_name text NOT NULL,
    index_version text NOT NULL,
    last_global_position bigint NOT NULL CHECK (last_global_position >= 0),
    source_digest char(64) NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, index_name)
);

CREATE TABLE memory_projection_tombstones (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    memory_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    deleted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, memory_id)
);

ALTER TABLE memory_candidate_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_candidate_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_candidate_projection_tenant_isolation
    ON memory_candidate_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_source_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_source_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_source_snapshots_tenant_isolation
    ON memory_source_snapshots
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_chunk_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_chunk_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_chunk_projection_tenant_isolation
    ON memory_chunk_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_retrieval_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_retrieval_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_retrieval_projection_tenant_isolation
    ON memory_retrieval_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_job_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_job_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_job_claims_tenant_isolation ON memory_job_claims
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_quota_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_quota_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_quota_projection_tenant_isolation
    ON memory_quota_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_index_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_index_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_index_checkpoints_tenant_isolation
    ON memory_index_checkpoints
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE memory_projection_tombstones ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_projection_tombstones FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_projection_tombstones_tenant_isolation
    ON memory_projection_tombstones
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON memory_candidate_projection,
    memory_chunk_projection, memory_retrieval_projection, memory_job_claims,
    memory_quota_projection, memory_index_checkpoints,
    memory_projection_tombstones TO aegis_app;
GRANT SELECT, INSERT, DELETE ON memory_source_snapshots TO aegis_app;
REVOKE UPDATE, TRUNCATE ON memory_source_snapshots
    FROM PUBLIC, aegis_app;
REVOKE TRUNCATE ON memory_candidate_projection, memory_chunk_projection,
    memory_retrieval_projection, memory_job_claims, memory_quota_projection,
    memory_index_checkpoints, memory_projection_tombstones FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON memory_candidate_projection,
    memory_source_snapshots, memory_chunk_projection,
    memory_retrieval_projection, memory_job_claims, memory_quota_projection,
    memory_index_checkpoints, memory_projection_tombstones TO aegis_maintenance;

COMMIT;
