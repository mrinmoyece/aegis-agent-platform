BEGIN;

CREATE TABLE protocol_peer_registry (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    peer_id text NOT NULL CHECK (peer_id <> '' AND octet_length(peer_id) <= 128),
    family text NOT NULL CHECK (family IN ('mcp', 'a2a')),
    owner text NOT NULL CHECK (owner <> '' AND octet_length(owner) <= 256),
    environment text NOT NULL CHECK (
        environment <> '' AND octet_length(environment) <= 128
    ),
    status text NOT NULL CHECK (status IN (
        'pending_review', 'active', 'quarantined', 'revoked', 'expired'
    )),
    trust_tier text NOT NULL CHECK (trust_tier IN (
        'local_deterministic', 'internal', 'partner', 'untrusted'
    )),
    transports jsonb NOT NULL CHECK (
        jsonb_typeof(transports) = 'array'
        AND jsonb_array_length(transports) BETWEEN 1 AND 4
        AND octet_length(transports::text) <= 1024
    ),
    protocol_versions jsonb NOT NULL CHECK (
        jsonb_typeof(protocol_versions) = 'array'
        AND jsonb_array_length(protocol_versions) BETWEEN 1 AND 8
        AND octet_length(protocol_versions::text) <= 2048
    ),
    auth_scheme text NOT NULL CHECK (auth_scheme IN (
        'local_process', 'oauth2_dpop', 'oidc_mtls', 'mtls'
    )),
    endpoint_origin text NOT NULL CHECK (
        endpoint_origin <> '' AND octet_length(endpoint_origin) <= 2048
    ),
    endpoint_origin_digest char(64) NOT NULL,
    server_identity text NOT NULL CHECK (
        server_identity <> '' AND octet_length(server_identity) <= 128
    ),
    secret_reference text NOT NULL CHECK (
        secret_reference LIKE 'secret-ref://%'
        AND octet_length(secret_reference) <= 512
    ),
    allowed_capability_digests jsonb NOT NULL CHECK (
        jsonb_typeof(allowed_capability_digests) = 'object'
        AND octet_length(allowed_capability_digests::text) <= 131072
    ),
    allowed_classifications jsonb NOT NULL CHECK (
        jsonb_typeof(allowed_classifications) = 'array'
        AND jsonb_array_length(allowed_classifications) BETWEEN 1 AND 4
    ),
    risk_ceiling smallint NOT NULL CHECK (risk_ceiling BETWEEN 0 AND 3),
    card_digest char(64) NOT NULL,
    schema_digest char(64) NOT NULL,
    certificate_digest char(64) NOT NULL,
    signing_key_digest char(64) NOT NULL,
    egress_destinations jsonb NOT NULL CHECK (
        jsonb_typeof(egress_destinations) = 'array'
        AND jsonb_array_length(egress_destinations) BETWEEN 1 AND 16
        AND octet_length(egress_destinations::text) <= 8192
    ),
    registered_at timestamptz NOT NULL,
    reviewed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    emergency_disabled boolean NOT NULL DEFAULT true,
    last_global_position bigint NOT NULL DEFAULT 0 CHECK (
        last_global_position >= 0
    ),
    PRIMARY KEY (tenant_id, peer_id),
    CHECK (registered_at <= reviewed_at AND reviewed_at < expires_at)
);

CREATE INDEX protocol_peer_registry_status_idx
    ON protocol_peer_registry (
        tenant_id, status, family, expires_at, peer_id
    );
CREATE INDEX protocol_peer_registry_review_idx
    ON protocol_peer_registry (
        tenant_id, reviewed_at, revision, peer_id
    );

CREATE TABLE protocol_trust_decision_history (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    decision_id uuid NOT NULL,
    peer_id text NOT NULL,
    previous_status text NOT NULL,
    next_status text NOT NULL,
    previous_revision bigint NOT NULL CHECK (previous_revision > 0),
    next_revision bigint NOT NULL CHECK (next_revision > previous_revision),
    actor_id text NOT NULL CHECK (actor_id <> '' AND octet_length(actor_id) <= 128),
    rationale_code text NOT NULL CHECK (
        rationale_code <> '' AND octet_length(rationale_code) <= 128
    ),
    peer_digest char(64) NOT NULL,
    policy_digest char(64) NOT NULL,
    ledger_position bigint NOT NULL CHECK (ledger_position > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, decision_id),
    UNIQUE (tenant_id, peer_id, next_revision)
);

CREATE INDEX protocol_trust_decision_peer_idx
    ON protocol_trust_decision_history (
        tenant_id, peer_id, next_revision DESC, decision_id
    );

CREATE TRIGGER protocol_trust_decision_history_no_mutation
BEFORE UPDATE OR DELETE ON protocol_trust_decision_history
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE protocol_capability_snapshots (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    snapshot_id uuid NOT NULL,
    peer_id text NOT NULL,
    family text NOT NULL CHECK (family IN ('mcp', 'a2a')),
    protocol_version text NOT NULL CHECK (
        protocol_version <> '' AND octet_length(protocol_version) <= 64
    ),
    card_digest char(64) NOT NULL,
    schema_digest char(64) NOT NULL,
    capability_set_digest char(64) NOT NULL,
    capability_digests jsonb NOT NULL CHECK (
        jsonb_typeof(capability_digests) = 'object'
        AND octet_length(capability_digests::text) <= 131072
    ),
    signature_verified boolean NOT NULL,
    certificate_digest char(64) NOT NULL,
    observed_at timestamptz NOT NULL,
    ledger_position bigint NOT NULL CHECK (ledger_position > 0),
    PRIMARY KEY (tenant_id, snapshot_id),
    UNIQUE (tenant_id, peer_id, capability_set_digest, card_digest)
);

CREATE INDEX protocol_capability_snapshot_peer_idx
    ON protocol_capability_snapshots (
        tenant_id, peer_id, observed_at DESC, snapshot_id
    );

CREATE TRIGGER protocol_capability_snapshots_no_mutation
BEFORE UPDATE OR DELETE ON protocol_capability_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE protocol_operation_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    operation_id uuid NOT NULL,
    family text NOT NULL CHECK (family IN ('mcp', 'a2a')),
    peer_id text NOT NULL,
    capability_id text NOT NULL CHECK (
        capability_id <> '' AND octet_length(capability_id) <= 128
    ),
    capability_digest char(64) NOT NULL,
    request_digest char(64) NOT NULL,
    policy_digest char(64) NOT NULL,
    principal_digest char(64) NOT NULL,
    idempotency_key text NOT NULL CHECK (
        idempotency_key <> '' AND octet_length(idempotency_key) <= 128
    ),
    correlation_id uuid NOT NULL,
    classification text NOT NULL CHECK (classification IN (
        'public', 'internal', 'confidential', 'restricted'
    )),
    purpose text NOT NULL CHECK (purpose <> '' AND octet_length(purpose) <= 128),
    status text NOT NULL CHECK (status IN (
        'requested', 'started', 'accepted', 'running', 'completed', 'failed',
        'ambiguous', 'cancel_requested', 'cancelled', 'quarantined'
    )),
    result_digest char(64),
    provider_reference_digest char(64),
    error_class text,
    error_code text CHECK (
        error_code IS NULL OR octet_length(error_code) <= 128
    ),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    requested_at timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (requested_at < deadline)
);

CREATE INDEX protocol_operation_status_idx
    ON protocol_operation_projection (
        tenant_id, family, status, requested_at DESC, operation_id
    );
CREATE INDEX protocol_operation_peer_idx
    ON protocol_operation_projection (
        tenant_id, peer_id, capability_id, requested_at DESC, operation_id
    );
CREATE INDEX protocol_operation_reconcile_idx
    ON protocol_operation_projection (
        tenant_id, status, updated_at, operation_id
    ) WHERE status IN ('ambiguous', 'cancel_requested', 'running');

CREATE TABLE protocol_operation_claims (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    operation_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (
        idempotency_key <> '' AND octet_length(idempotency_key) <= 128
    ),
    request_digest char(64) NOT NULL,
    capability_digest char(64) NOT NULL,
    peer_digest char(64) NOT NULL,
    lease_token uuid NOT NULL,
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 5),
    status text NOT NULL CHECK (status IN (
        'intent_recorded', 'sending', 'observing', 'completed', 'failed',
        'ambiguous', 'cancelled', 'quarantined'
    )),
    result_digest char(64),
    last_error_code text CHECK (
        last_error_code IS NULL OR octet_length(last_error_code) <= 128
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX protocol_operation_claim_ready_idx
    ON protocol_operation_claims (
        tenant_id, status, updated_at, operation_id
    ) WHERE status IN (
        'intent_recorded', 'sending', 'observing', 'ambiguous'
    );

CREATE TABLE protocol_artifact_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    operation_id uuid NOT NULL,
    artifact_id text NOT NULL CHECK (
        artifact_id <> '' AND octet_length(artifact_id) <= 128
    ),
    content_type text NOT NULL CHECK (
        content_type <> '' AND octet_length(content_type) <= 128
    ),
    content_digest char(64) NOT NULL,
    content_reference text NOT NULL CHECK (
        content_reference LIKE 'aegis-artifact://%'
        AND octet_length(content_reference) <= 2048
    ),
    classification text NOT NULL,
    trust_label text NOT NULL,
    citation_digests jsonb NOT NULL CHECK (
        jsonb_typeof(citation_digests) = 'array'
        AND jsonb_array_length(citation_digests) <= 64
        AND octet_length(citation_digests::text) <= 8192
    ),
    byte_count bigint NOT NULL CHECK (byte_count BETWEEN 0 AND 1048576),
    complete boolean NOT NULL,
    ledger_position bigint NOT NULL CHECK (ledger_position > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id, artifact_id),
    UNIQUE (tenant_id, operation_id, content_digest)
);

CREATE INDEX protocol_artifact_operation_idx
    ON protocol_artifact_projection (
        tenant_id, operation_id, recorded_at, artifact_id
    );

CREATE TRIGGER protocol_artifact_projection_no_mutation
BEFORE UPDATE OR DELETE ON protocol_artifact_projection
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE protocol_stream_cursors (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    peer_id text NOT NULL,
    stream_kind text NOT NULL CHECK (stream_kind IN (
        'mcp_subscription', 'a2a_task_stream', 'a2a_task_poll',
        'projection_rebuild'
    )),
    opaque_cursor_digest char(64) NOT NULL,
    last_global_position bigint NOT NULL CHECK (last_global_position >= 0),
    version bigint NOT NULL CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, peer_id, stream_kind)
);

CREATE TABLE protocol_quota_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    usage_period text NOT NULL,
    operation_count bigint NOT NULL DEFAULT 0 CHECK (operation_count >= 0),
    request_bytes bigint NOT NULL DEFAULT 0 CHECK (request_bytes >= 0),
    response_bytes bigint NOT NULL DEFAULT 0 CHECK (response_bytes >= 0),
    retry_count bigint NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    active_count integer NOT NULL DEFAULT 0 CHECK (active_count >= 0),
    last_global_position bigint NOT NULL DEFAULT 0 CHECK (
        last_global_position >= 0
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, usage_period)
);

CREATE TABLE protocol_audit_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    audit_id uuid NOT NULL,
    peer_id text NOT NULL,
    operation_id uuid,
    action text NOT NULL CHECK (action <> '' AND octet_length(action) <= 128),
    outcome text NOT NULL CHECK (outcome <> '' AND octet_length(outcome) <= 128),
    principal_digest char(64) NOT NULL,
    request_digest char(64),
    policy_digest char(64) NOT NULL,
    metadata jsonb NOT NULL CHECK (
        jsonb_typeof(metadata) = 'object'
        AND octet_length(metadata::text) <= 16384
    ),
    ledger_position bigint NOT NULL CHECK (ledger_position > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, audit_id)
);

CREATE INDEX protocol_audit_tenant_sequence_idx
    ON protocol_audit_projection (
        tenant_id, ledger_position DESC, audit_id
    );

CREATE TRIGGER protocol_audit_projection_no_mutation
BEFORE UPDATE OR DELETE ON protocol_audit_projection
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

ALTER TABLE protocol_peer_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_peer_registry FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_peer_registry_tenant_isolation ON protocol_peer_registry
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_trust_decision_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_trust_decision_history FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_trust_decision_history_tenant_isolation
    ON protocol_trust_decision_history
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_capability_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_capability_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_capability_snapshots_tenant_isolation
    ON protocol_capability_snapshots
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_operation_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_operation_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_operation_projection_tenant_isolation
    ON protocol_operation_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_operation_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_operation_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_operation_claims_tenant_isolation
    ON protocol_operation_claims
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_artifact_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_artifact_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_artifact_projection_tenant_isolation
    ON protocol_artifact_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_stream_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_stream_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_stream_cursors_tenant_isolation
    ON protocol_stream_cursors
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_quota_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_quota_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_quota_projection_tenant_isolation
    ON protocol_quota_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE protocol_audit_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_audit_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_audit_projection_tenant_isolation
    ON protocol_audit_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON protocol_peer_registry,
    protocol_operation_projection, protocol_operation_claims,
    protocol_stream_cursors, protocol_quota_projection TO aegis_app;
GRANT SELECT, INSERT ON protocol_trust_decision_history,
    protocol_capability_snapshots, protocol_artifact_projection,
    protocol_audit_projection TO aegis_app;
REVOKE UPDATE, DELETE, TRUNCATE ON protocol_trust_decision_history,
    protocol_capability_snapshots, protocol_artifact_projection,
    protocol_audit_projection FROM PUBLIC, aegis_app;
REVOKE TRUNCATE ON protocol_peer_registry, protocol_operation_projection,
    protocol_operation_claims, protocol_stream_cursors,
    protocol_quota_projection FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON protocol_peer_registry,
    protocol_trust_decision_history, protocol_capability_snapshots,
    protocol_operation_projection, protocol_operation_claims,
    protocol_artifact_projection, protocol_stream_cursors,
    protocol_quota_projection, protocol_audit_projection TO aegis_maintenance;

COMMIT;
