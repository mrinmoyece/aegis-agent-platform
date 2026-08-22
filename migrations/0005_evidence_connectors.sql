BEGIN;

CREATE TABLE evidence_query_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    query_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN (
        'dynatrace', 'github', 'kubernetes', 'runbook'
    )),
    environment text NOT NULL CHECK (environment <> ''),
    status text NOT NULL CHECK (status IN (
        'requested', 'running', 'succeeded', 'partially_succeeded', 'failed',
        'timed_out', 'rate_limited', 'cancelled'
    )),
    requested_at timestamptz NOT NULL,
    query_event_position bigint NOT NULL CHECK (query_event_position > 0),
    updated_at timestamptz NOT NULL,
    result_count integer NOT NULL CHECK (result_count >= 0),
    partial boolean NOT NULL,
    truncated boolean NOT NULL,
    last_error_code text CHECK (
        last_error_code IS NULL OR length(last_error_code) <= 128
    ),
    PRIMARY KEY (tenant_id, query_id),
    FOREIGN KEY (tenant_id, query_id)
        REFERENCES work_items (tenant_id, work_id)
);

CREATE TABLE evidence_records (
    evidence_position bigint GENERATED ALWAYS AS IDENTITY,
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    evidence_id text NOT NULL CHECK (evidence_id <> ''),
    content_digest char(64) NOT NULL,
    source_kind text NOT NULL,
    evidence_kind text NOT NULL,
    environment text NOT NULL,
    service text,
    resource_kind text,
    resource_name text,
    resource_namespace text,
    resource_cluster text,
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    query_window_start timestamptz NOT NULL,
    query_window_end timestamptz NOT NULL CHECK (
        query_window_end > query_window_start
    ),
    summary text NOT NULL CHECK (
        summary <> '' AND octet_length(summary) <= 4096
    ),
    structured_fields jsonb NOT NULL CHECK (
        jsonb_typeof(structured_fields) = 'object'
        AND octet_length(structured_fields::text) <= 262144
    ),
    severity text NOT NULL,
    source_confidence double precision CHECK (
        source_confidence IS NULL
        OR source_confidence BETWEEN 0 AND 1
    ),
    provenance_uri text NOT NULL CHECK (
        provenance_uri <> '' AND octet_length(provenance_uri) <= 2048
    ),
    source_record_id text NOT NULL CHECK (
        source_record_id <> '' AND octet_length(source_record_id) <= 1024
    ),
    provenance_trust text NOT NULL,
    classification text NOT NULL,
    retention_class text NOT NULL,
    redaction jsonb NOT NULL,
    evidence_references jsonb NOT NULL CHECK (
        jsonb_typeof(evidence_references) = 'array'
        AND octet_length(evidence_references::text) <= 65536
    ),
    raw_payload_reference text CHECK (
        raw_payload_reference IS NULL
        OR raw_payload_reference LIKE 'aegis-object://%'
    ),
    is_knowledge boolean NOT NULL,
    PRIMARY KEY (tenant_id, evidence_id),
    UNIQUE (tenant_id, content_digest),
    UNIQUE (tenant_id, evidence_position)
);

CREATE INDEX evidence_records_timeline_idx
    ON evidence_records (tenant_id, environment, observed_at, evidence_id);
CREATE INDEX evidence_records_page_snapshot_idx
    ON evidence_records (tenant_id, ingested_at, observed_at, evidence_id);
CREATE INDEX evidence_records_source_idx
    ON evidence_records (tenant_id, source_kind, source_record_id);

CREATE TABLE evidence_quarantine (
    quarantine_id uuid NOT NULL,
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    source_kind text NOT NULL,
    source_record_id text NOT NULL CHECK (
        source_record_id <> '' AND octet_length(source_record_id) <= 320
    ),
    reason text NOT NULL CHECK (reason IN ('oversized', 'invalid', 'untrusted')),
    observed_at timestamptz NOT NULL,
    quarantined_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, quarantine_id)
);

CREATE TABLE source_cursors (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    source_kind text NOT NULL,
    environment text NOT NULL,
    cursor_value text NOT NULL CHECK (
        cursor_value <> '' AND octet_length(cursor_value) <= 2048
    ),
    query_id uuid NOT NULL,
    query_event_position bigint NOT NULL CHECK (query_event_position > 0),
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    advanced_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, source_kind, environment),
    FOREIGN KEY (tenant_id, query_id)
        REFERENCES work_items (tenant_id, work_id)
);

CREATE TABLE evidence_bundle_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    bundle_id text NOT NULL,
    environment text NOT NULL,
    generated_at timestamptz NOT NULL,
    artifact_reference text NOT NULL CHECK (
        artifact_reference LIKE 'aegis-artifact://%'
    ),
    content_digest char(64) NOT NULL,
    evidence_count integer NOT NULL CHECK (evidence_count >= 0),
    timeline_count integer NOT NULL CHECK (timeline_count >= 0),
    conflict_count integer NOT NULL CHECK (conflict_count >= 0),
    bundle_content jsonb NOT NULL CHECK (
        jsonb_typeof(bundle_content) = 'object'
        AND octet_length(bundle_content::text) <= 5242880
    ),
    PRIMARY KEY (tenant_id, bundle_id)
);

CREATE FUNCTION reject_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'evidence records are append-only';
END;
$$;

CREATE TRIGGER evidence_records_no_update
BEFORE UPDATE OR DELETE ON evidence_records
FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

CREATE TRIGGER evidence_quarantine_no_update
BEFORE UPDATE OR DELETE ON evidence_quarantine
FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

ALTER TABLE evidence_query_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_query_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_query_projection_tenant_isolation
    ON evidence_query_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE evidence_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_records FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_records_tenant_isolation ON evidence_records
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE evidence_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_quarantine_tenant_isolation ON evidence_quarantine
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE source_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY source_cursors_tenant_isolation ON source_cursors
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE evidence_bundle_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_bundle_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_bundle_projection_tenant_isolation
    ON evidence_bundle_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON evidence_query_projection, source_cursors,
    evidence_bundle_projection TO aegis_app;
GRANT SELECT, INSERT ON evidence_records, evidence_quarantine TO aegis_app;
REVOKE UPDATE, DELETE, TRUNCATE ON evidence_records, evidence_quarantine
    FROM PUBLIC, aegis_app;
REVOKE DELETE, TRUNCATE ON evidence_query_projection, source_cursors,
    evidence_bundle_projection FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_query_projection,
    source_cursors, evidence_bundle_projection TO aegis_maintenance;
GRANT SELECT, INSERT, DELETE ON evidence_records, evidence_quarantine
    TO aegis_maintenance;

COMMIT;
