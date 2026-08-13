BEGIN;

CREATE TABLE work_items (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    work_id uuid NOT NULL,
    work_kind text NOT NULL CHECK (work_kind <> ''),
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    status text NOT NULL CHECK (status IN (
        'requested', 'published', 'claimed', 'running', 'retry_wait',
        'succeeded', 'failed', 'cancelled', 'dead_letter'
    )),
    requested_at timestamptz NOT NULL,
    available_at timestamptz NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 86400),
    request_event_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    request_payload jsonb NOT NULL CHECK (jsonb_typeof(request_payload) = 'object'),
    cancel_requested_at timestamptz,
    completed_at timestamptz,
    last_error_code text CHECK (
        last_error_code IS NULL OR length(last_error_code) <= 128
    ),
    PRIMARY KEY (tenant_id, work_id),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, request_event_id)
        REFERENCES events (tenant_id, event_id)
);

CREATE INDEX work_items_available_idx
    ON work_items (tenant_id, available_at, requested_at, work_id)
    WHERE status IN ('published', 'retry_wait');
CREATE INDEX work_items_status_idx
    ON work_items (tenant_id, status, requested_at DESC);

CREATE TABLE work_leases (
    tenant_id text NOT NULL,
    work_id uuid NOT NULL,
    lease_token uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    owner text NOT NULL CHECK (owner <> ''),
    acquired_at timestamptz NOT NULL,
    heartbeat_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    released_at timestamptz,
    release_reason text CHECK (
        release_reason IS NULL OR length(release_reason) <= 128
    ),
    PRIMARY KEY (tenant_id, work_id),
    UNIQUE (tenant_id, lease_token),
    FOREIGN KEY (tenant_id, work_id)
        REFERENCES work_items (tenant_id, work_id),
    CHECK (expires_at > heartbeat_at),
    CHECK ((released_at IS NULL) = (release_reason IS NULL))
);

CREATE INDEX work_leases_active_expiry_idx
    ON work_leases (expires_at)
    WHERE released_at IS NULL;

CREATE TABLE work_dead_letters (
    tenant_id text NOT NULL,
    work_id uuid NOT NULL,
    dead_lettered_at timestamptz NOT NULL,
    reason_code text NOT NULL CHECK (
        reason_code <> '' AND length(reason_code) <= 128
    ),
    attempts integer NOT NULL CHECK (attempts > 0),
    requeue_count integer NOT NULL DEFAULT 0 CHECK (requeue_count >= 0),
    last_requeued_at timestamptz,
    PRIMARY KEY (tenant_id, work_id),
    FOREIGN KEY (tenant_id, work_id)
        REFERENCES work_items (tenant_id, work_id)
);

CREATE TABLE work_requeue_approvals (
    tenant_id text NOT NULL,
    approval_id uuid NOT NULL,
    work_id uuid NOT NULL,
    approved_by text NOT NULL CHECK (approved_by <> ''),
    approved_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    consumed_by text,
    PRIMARY KEY (tenant_id, approval_id),
    FOREIGN KEY (tenant_id, work_id)
        REFERENCES work_dead_letters (tenant_id, work_id),
    CHECK (expires_at > approved_at),
    CHECK ((consumed_at IS NULL) = (consumed_by IS NULL))
);

ALTER TABLE work_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_items FORCE ROW LEVEL SECURITY;
CREATE POLICY work_items_tenant_isolation ON work_items
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE work_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY work_leases_tenant_isolation ON work_leases
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE work_dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_dead_letters FORCE ROW LEVEL SECURITY;
CREATE POLICY work_dead_letters_tenant_isolation ON work_dead_letters
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE work_requeue_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_requeue_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY work_requeue_approvals_tenant_isolation ON work_requeue_approvals
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON work_items, work_leases, work_dead_letters,
    work_requeue_approvals
    TO aegis_app;
REVOKE DELETE, TRUNCATE ON work_items, work_leases, work_dead_letters,
    work_requeue_approvals
    FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON work_items, work_leases,
    work_dead_letters, work_requeue_approvals TO aegis_maintenance;

COMMIT;
