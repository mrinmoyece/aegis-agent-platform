BEGIN;

ALTER TABLE remediation_action_projection
    DROP CONSTRAINT remediation_action_projection_action_kind_check;
ALTER TABLE remediation_action_projection
    ADD CONSTRAINT remediation_action_projection_action_kind_check CHECK (
        action_kind IN (
            'kubernetes.rollout_restart.v1',
            'sandbox.change_preparation.v1'
        )
    ),
    ADD COLUMN sandbox_spec_digest char(64),
    ADD COLUMN sandbox_policy_digest char(64),
    ADD COLUMN sandbox_purpose text,
    ADD COLUMN sandbox_risk integer,
    ADD CONSTRAINT remediation_action_sandbox_scope_check CHECK (
        (
            action_kind = 'sandbox.change_preparation.v1'
            AND sandbox_spec_digest ~ '^[0-9a-f]{64}$'
            AND sandbox_policy_digest ~ '^[0-9a-f]{64}$'
            AND sandbox_purpose IN (
                'code_analysis', 'config_analysis', 'test_execution',
                'patch_preparation', 'evidence_production'
            )
            AND sandbox_risk BETWEEN 1 AND 4
        )
        OR (
            action_kind <> 'sandbox.change_preparation.v1'
            AND sandbox_spec_digest IS NULL
            AND sandbox_policy_digest IS NULL
            AND sandbox_purpose IS NULL
            AND sandbox_risk IS NULL
        )
    );

CREATE TABLE sandbox_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    sandbox_id uuid NOT NULL,
    run_id uuid NOT NULL,
    task_id uuid NOT NULL,
    remediation_plan_id uuid NOT NULL,
    remediation_action_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    purpose text NOT NULL CHECK (purpose IN (
        'code_analysis', 'config_analysis', 'test_execution',
        'patch_preparation', 'evidence_production'
    )),
    risk integer NOT NULL CHECK (risk BETWEEN 1 AND 4),
    spec_digest char(64) NOT NULL,
    image_digest char(64) NOT NULL,
    input_digest char(64) NOT NULL,
    policy_digest char(64),
    approval_scope_digest char(64),
    status text NOT NULL CHECK (status IN (
        'requested', 'policy_approved', 'policy_denied', 'approved',
        'dispatched', 'provisioning', 'provisioned', 'starting', 'running',
        'completed', 'failed', 'timed_out', 'oom_killed', 'policy_violation',
        'cancelling', 'cancelled', 'quarantined', 'cleanup_pending', 'cleaned',
        'cleanup_failed'
    )),
    backend_reference text CHECK (
        backend_reference IS NULL OR octet_length(backend_reference) <= 512
    ),
    lease_token uuid,
    lease_generation bigint CHECK (
        lease_generation IS NULL OR lease_generation > 0
    ),
    cleanup_attempts integer NOT NULL DEFAULT 0
        CHECK (cleanup_attempts BETWEEN 0 AND 10),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    requested_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, sandbox_id)
);

CREATE INDEX sandbox_projection_status_idx
    ON sandbox_projection (tenant_id, status, updated_at, sandbox_id);
CREATE INDEX sandbox_projection_task_idx
    ON sandbox_projection (tenant_id, run_id, task_id, requested_at, sandbox_id);
CREATE INDEX sandbox_projection_spec_idx
    ON sandbox_projection (tenant_id, spec_digest, requested_at, sandbox_id);
CREATE INDEX sandbox_projection_cleanup_idx
    ON sandbox_projection (tenant_id, cleanup_attempts, updated_at, sandbox_id)
    WHERE status IN ('cleanup_pending', 'cleanup_failed', 'quarantined');

CREATE TABLE sandbox_artifact_projection (
    tenant_id text NOT NULL,
    sandbox_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    ledger_position bigint NOT NULL CHECK (ledger_position > 0),
    content_digest char(64) NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 0 AND 536870912),
    media_type text NOT NULL CHECK (
        media_type <> '' AND octet_length(media_type) <= 128
    ),
    quarantined boolean NOT NULL,
    retention_until timestamptz,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, artifact_id),
    UNIQUE (tenant_id, sandbox_id, ledger_position)
);

CREATE INDEX sandbox_artifact_digest_idx
    ON sandbox_artifact_projection (tenant_id, content_digest);
CREATE INDEX sandbox_artifact_retention_idx
    ON sandbox_artifact_projection (
        tenant_id, retention_until, sandbox_id, artifact_id
    ) WHERE retention_until IS NOT NULL;

CREATE TABLE sandbox_execution_claims (
    tenant_id text NOT NULL,
    idempotency_key text NOT NULL CHECK (
        idempotency_key <> '' AND octet_length(idempotency_key) <= 256
    ),
    sandbox_id uuid NOT NULL,
    spec_digest char(64) NOT NULL,
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 5),
    reserved_cpu_millis_seconds bigint NOT NULL CHECK (
        reserved_cpu_millis_seconds >= 0
    ),
    reserved_artifact_bytes bigint NOT NULL CHECK (
        reserved_artifact_bytes >= 0
    ),
    quota_reserved boolean NOT NULL,
    status text NOT NULL CHECK (status IN (
        'intent_recorded', 'running', 'terminal', 'ambiguous',
        'cleanup_pending', 'cleaned', 'cleanup_failed', 'quarantined'
    )),
    last_event_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key),
    UNIQUE (tenant_id, sandbox_id)
);

CREATE INDEX sandbox_execution_claim_status_idx
    ON sandbox_execution_claims (tenant_id, status, updated_at, sandbox_id);

CREATE TABLE sandbox_quota_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    usage_period text NOT NULL CHECK (
        usage_period <> '' AND octet_length(usage_period) <= 64
    ),
    runs_started integer NOT NULL DEFAULT 0 CHECK (runs_started >= 0),
    active_runs integer NOT NULL DEFAULT 0 CHECK (active_runs >= 0),
    cpu_millis_seconds bigint NOT NULL DEFAULT 0
        CHECK (cpu_millis_seconds >= 0),
    artifact_bytes bigint NOT NULL DEFAULT 0 CHECK (artifact_bytes >= 0),
    last_global_position bigint NOT NULL DEFAULT 0
        CHECK (last_global_position >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, usage_period)
);

CREATE TABLE sandbox_cleanup_projection (
    tenant_id text NOT NULL,
    sandbox_id uuid NOT NULL,
    backend_reference text NOT NULL CHECK (
        backend_reference <> '' AND octet_length(backend_reference) <= 512
    ),
    status text NOT NULL CHECK (status IN (
        'pending', 'failed', 'completed', 'quarantined'
    )),
    attempt_count integer NOT NULL CHECK (attempt_count BETWEEN 1 AND 10),
    next_attempt_at timestamptz NOT NULL,
    last_error_code text CHECK (
        last_error_code IS NULL OR (
            last_error_code <> '' AND octet_length(last_error_code) <= 128
        )
    ),
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, sandbox_id)
);

CREATE INDEX sandbox_cleanup_ready_idx
    ON sandbox_cleanup_projection (
        tenant_id, status, next_attempt_at, sandbox_id
    ) WHERE status IN ('pending', 'failed');

CREATE TABLE sandbox_attestations (
    tenant_id text NOT NULL,
    attestation_event_id uuid NOT NULL,
    sandbox_id uuid NOT NULL,
    spec_digest char(64) NOT NULL,
    image_digest char(64) NOT NULL,
    input_digest char(64) NOT NULL,
    result_digest char(64) NOT NULL,
    policy_digest char(64) NOT NULL,
    approval_scope_digest char(64) NOT NULL,
    backend_identity text NOT NULL CHECK (
        backend_identity <> '' AND octet_length(backend_identity) <= 128
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, attestation_event_id),
    UNIQUE (tenant_id, sandbox_id, result_digest)
);

CREATE TRIGGER sandbox_attestations_no_update
BEFORE UPDATE OR DELETE ON sandbox_attestations
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

ALTER TABLE sandbox_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY sandbox_projection_tenant_isolation ON sandbox_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE sandbox_artifact_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_artifact_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY sandbox_artifact_projection_tenant_isolation
    ON sandbox_artifact_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE sandbox_execution_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_execution_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY sandbox_execution_claims_tenant_isolation
    ON sandbox_execution_claims
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE sandbox_quota_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_quota_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY sandbox_quota_projection_tenant_isolation
    ON sandbox_quota_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE sandbox_cleanup_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_cleanup_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY sandbox_cleanup_projection_tenant_isolation
    ON sandbox_cleanup_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE sandbox_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_attestations FORCE ROW LEVEL SECURITY;
CREATE POLICY sandbox_attestations_tenant_isolation ON sandbox_attestations
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON sandbox_projection,
    sandbox_artifact_projection, sandbox_execution_claims,
    sandbox_quota_projection, sandbox_cleanup_projection TO aegis_app;
GRANT SELECT, INSERT ON sandbox_attestations TO aegis_app;
REVOKE UPDATE, DELETE, TRUNCATE ON sandbox_attestations
    FROM PUBLIC, aegis_app;
REVOKE TRUNCATE ON sandbox_projection, sandbox_artifact_projection,
    sandbox_execution_claims, sandbox_quota_projection,
    sandbox_cleanup_projection FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sandbox_projection,
    sandbox_artifact_projection, sandbox_execution_claims,
    sandbox_quota_projection, sandbox_cleanup_projection,
    sandbox_attestations TO aegis_maintenance;

COMMIT;
