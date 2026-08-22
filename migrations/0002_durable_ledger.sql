BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app NOLOGIN NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'aegis_maintenance'
    ) THEN
        CREATE ROLE aegis_maintenance NOLOGIN NOINHERIT BYPASSRLS;
    END IF;
END;
$$;

GRANT aegis_app TO CURRENT_USER;
GRANT aegis_maintenance TO CURRENT_USER;

CREATE TABLE event_stream_heads (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    aggregate_id text NOT NULL CHECK (aggregate_id <> ''),
    current_version bigint NOT NULL DEFAULT 0 CHECK (current_version >= 0),
    PRIMARY KEY (tenant_id, aggregate_id)
);

CREATE TABLE tenant_event_commit_locks (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id)
);

CREATE TABLE events (
    global_position bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL,
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    aggregate_id text NOT NULL CHECK (aggregate_id <> ''),
    aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence > 0),
    event_type text NOT NULL CHECK (event_type <> ''),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    correlation_id uuid,
    causation_id uuid,
    actor_id text,
    actor_kind text CHECK (actor_kind IN ('user', 'service', 'system')),
    identity_reference text,
    policy_reference text,
    audit_reference uuid,
    idempotency_key text CHECK (
        idempotency_key IS NULL OR idempotency_key <> ''
    ),
    traceparent text,
    tracestate text,
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, aggregate_id, aggregate_sequence),
    CHECK ((actor_id IS NULL) = (actor_kind IS NULL)),
    FOREIGN KEY (tenant_id, aggregate_id)
        REFERENCES event_stream_heads (tenant_id, aggregate_id)
);

CREATE UNIQUE INDEX events_tenant_idempotency_idx
    ON events (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX events_tenant_global_position_idx
    ON events (tenant_id, global_position);
CREATE INDEX events_tenant_aggregate_sequence_idx
    ON events (tenant_id, aggregate_id, aggregate_sequence);
CREATE INDEX events_correlation_idx
    ON events (tenant_id, correlation_id)
    WHERE correlation_id IS NOT NULL;

CREATE FUNCTION reject_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'event records are append-only';
END;
$$;

CREATE TRIGGER events_no_update
BEFORE UPDATE OR DELETE ON events
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE inbox_messages (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    source text NOT NULL CHECK (source <> ''),
    message_id text NOT NULL CHECK (message_id <> ''),
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    aggregate_version bigint CHECK (aggregate_version >= 0),
    PRIMARY KEY (tenant_id, source, message_id),
    CHECK (
        (processed_at IS NULL AND aggregate_version IS NULL)
        OR (processed_at IS NOT NULL AND aggregate_version IS NOT NULL)
    )
);

CREATE TABLE outbox_messages (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    message_id uuid NOT NULL,
    event_id uuid,
    destination text NOT NULL CHECK (destination <> ''),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    headers jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(headers) = 'object'),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'leased', 'published', 'dead_letter')),
    available_at timestamptz NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts > 0),
    lease_owner text,
    lease_expires_at timestamptz,
    published_at timestamptz,
    last_error_code text CHECK (
        last_error_code IS NULL OR length(last_error_code) <= 128
    ),
    PRIMARY KEY (tenant_id, message_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES events (tenant_id, event_id),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (
        (status = 'leased' AND lease_owner IS NOT NULL)
        OR (status <> 'leased' AND lease_owner IS NULL)
    ),
    CHECK ((status = 'published') = (published_at IS NOT NULL))
);

CREATE INDEX outbox_publishable_idx
    ON outbox_messages (tenant_id, status, available_at)
    WHERE status IN ('pending', 'leased');

CREATE TABLE projection_checkpoints (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    projection_name text NOT NULL CHECK (projection_name <> ''),
    last_global_position bigint NOT NULL DEFAULT 0
        CHECK (last_global_position >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, projection_name)
);

CREATE TABLE run_status_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    run_id text NOT NULL CHECK (run_id <> ''),
    status text NOT NULL CHECK (status <> ''),
    aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence > 0),
    last_global_position bigint NOT NULL CHECK (last_global_position > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id)
);

CREATE INDEX run_status_tenant_position_idx
    ON run_status_projection (tenant_id, last_global_position DESC);

CREATE TABLE artifact_index_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    artifact_id uuid NOT NULL,
    run_id text NOT NULL CHECK (run_id <> ''),
    artifact_kind text NOT NULL CHECK (artifact_kind <> ''),
    source_reference text NOT NULL CHECK (source_reference <> ''),
    summary text NOT NULL,
    event_id uuid NOT NULL,
    global_position bigint NOT NULL CHECK (global_position > 0),
    PRIMARY KEY (tenant_id, artifact_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES events (tenant_id, event_id)
);

CREATE INDEX artifact_index_tenant_run_idx
    ON artifact_index_projection (tenant_id, run_id, global_position);

CREATE TABLE pending_approvals_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    approval_id uuid NOT NULL,
    run_id text NOT NULL CHECK (run_id <> ''),
    proposal_reference text NOT NULL CHECK (proposal_reference <> ''),
    requested_at timestamptz NOT NULL,
    event_id uuid NOT NULL,
    global_position bigint NOT NULL CHECK (global_position > 0),
    PRIMARY KEY (tenant_id, approval_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES events (tenant_id, event_id)
);

CREATE TABLE usage_quota_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    usage_period text NOT NULL CHECK (usage_period <> ''),
    tokens_used bigint NOT NULL DEFAULT 0 CHECK (tokens_used >= 0),
    cost_usd numeric(20, 6) NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
    last_global_position bigint NOT NULL CHECK (last_global_position > 0),
    PRIMARY KEY (tenant_id, usage_period)
);

CREATE TABLE tenant_listing_projection (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id),
    display_name text NOT NULL CHECK (display_name <> ''),
    enabled boolean NOT NULL,
    last_global_position bigint NOT NULL CHECK (last_global_position > 0)
);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

ALTER TABLE event_stream_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_stream_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY event_stream_heads_tenant_isolation ON event_stream_heads
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE tenant_event_commit_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_event_commit_locks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_event_commit_locks_tenant_isolation
    ON tenant_event_commit_locks
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
CREATE POLICY events_tenant_isolation ON events
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE inbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY inbox_messages_tenant_isolation ON inbox_messages
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE outbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_messages_tenant_isolation ON outbox_messages
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE projection_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE projection_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY projection_checkpoints_tenant_isolation ON projection_checkpoints
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE run_status_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_status_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY run_status_projection_tenant_isolation ON run_status_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE artifact_index_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_index_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY artifact_index_projection_tenant_isolation
    ON artifact_index_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE pending_approvals_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_approvals_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY pending_approvals_projection_tenant_isolation
    ON pending_approvals_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE usage_quota_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_quota_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_quota_projection_tenant_isolation
    ON usage_quota_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE tenant_listing_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_listing_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_listing_projection_tenant_isolation
    ON tenant_listing_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT USAGE ON SCHEMA public TO aegis_app;
GRANT SELECT ON tenants, identities, role_bindings, tenant_policies,
    tenant_quotas, security_audit_events, event_stream_heads,
    tenant_event_commit_locks, events,
    inbox_messages, outbox_messages, projection_checkpoints,
    run_status_projection, artifact_index_projection,
    pending_approvals_projection, usage_quota_projection,
    tenant_listing_projection TO aegis_app;
GRANT INSERT ON security_audit_events, event_stream_heads,
    tenant_event_commit_locks, events,
    inbox_messages, outbox_messages, projection_checkpoints,
    run_status_projection, artifact_index_projection,
    pending_approvals_projection, usage_quota_projection,
    tenant_listing_projection TO aegis_app;
GRANT UPDATE ON event_stream_heads, tenant_event_commit_locks,
    inbox_messages, outbox_messages,
    projection_checkpoints, run_status_projection,
    artifact_index_projection, pending_approvals_projection,
    usage_quota_projection, tenant_listing_projection TO aegis_app;
GRANT DELETE ON projection_checkpoints, run_status_projection,
    artifact_index_projection, pending_approvals_projection,
    usage_quota_projection, tenant_listing_projection TO aegis_app;
GRANT USAGE, SELECT ON SEQUENCE events_global_position_seq TO aegis_app;

REVOKE UPDATE, DELETE, TRUNCATE ON events, security_audit_events
    FROM PUBLIC, aegis_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM aegis_maintenance;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO aegis_maintenance;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_maintenance;

COMMIT;
