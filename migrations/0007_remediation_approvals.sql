BEGIN;

CREATE TABLE remediation_plan_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    plan_id uuid NOT NULL,
    incident_id text NOT NULL CHECK (
        incident_id <> '' AND octet_length(incident_id) <= 256
    ),
    investigation_run_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    plan_digest char(64) NOT NULL,
    policy_digest char(64) NOT NULL,
    action_count integer NOT NULL CHECK (action_count BETWEEN 1 AND 16),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, plan_id)
);

CREATE INDEX remediation_plan_incident_idx
    ON remediation_plan_projection (
        tenant_id, incident_id, updated_at DESC, plan_id
    );
CREATE INDEX remediation_plan_digest_idx
    ON remediation_plan_projection (tenant_id, plan_digest);

CREATE TABLE remediation_action_projection (
    tenant_id text NOT NULL,
    plan_id uuid NOT NULL,
    action_id uuid NOT NULL,
    action_kind text NOT NULL CHECK (
        action_kind = 'kubernetes.rollout_restart.v1'
    ),
    action_digest char(64) NOT NULL,
    target_fingerprint char(64) NOT NULL,
    environment text NOT NULL CHECK (
        environment <> '' AND octet_length(environment) <= 256
    ),
    resource_type text NOT NULL CHECK (
        resource_type <> '' AND octet_length(resource_type) <= 256
    ),
    resource_id text NOT NULL CHECK (
        resource_id <> '' AND octet_length(resource_id) <= 256
    ),
    risk integer NOT NULL CHECK (risk BETWEEN 1 AND 4),
    blast_radius integer NOT NULL CHECK (blast_radius BETWEEN 1 AND 5),
    status text NOT NULL CHECK (status IN (
        'proposed', 'policy_denied', 'awaiting_approval', 'approved',
        'dispatched', 'preflight', 'dry_run', 'executing', 'succeeded',
        'failed', 'ambiguous', 'reconciling', 'cancelled', 'rolled_back',
        'compensated', 'verified', 'verification_failed',
        'verification_partial', 'verification_unknown'
    )),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, plan_id, action_id),
    UNIQUE (tenant_id, plan_id, action_digest),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES remediation_plan_projection (tenant_id, plan_id)
);

CREATE INDEX remediation_action_status_idx
    ON remediation_action_projection (tenant_id, status, updated_at, action_id);
CREATE INDEX remediation_action_target_idx
    ON remediation_action_projection (
        tenant_id, target_fingerprint, updated_at, action_id
    );

CREATE TABLE remediation_approval_projection (
    tenant_id text NOT NULL,
    approval_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    action_id uuid NOT NULL,
    plan_digest char(64) NOT NULL,
    action_digest char(64) NOT NULL,
    policy_digest char(64) NOT NULL,
    target_fingerprint char(64) NOT NULL,
    risk integer NOT NULL CHECK (risk BETWEEN 1 AND 4),
    requester_id text NOT NULL CHECK (
        requester_id <> '' AND octet_length(requester_id) <= 256
    ),
    status text NOT NULL CHECK (
        status IN ('pending', 'granted', 'denied', 'expired', 'revoked')
    ),
    required_quorum integer NOT NULL CHECK (required_quorum BETWEEN 1 AND 5),
    approver_ids text[] NOT NULL,
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, approval_id),
    FOREIGN KEY (tenant_id, plan_id, action_id)
        REFERENCES remediation_action_projection (tenant_id, plan_id, action_id),
    CHECK (expires_at > requested_at)
);

CREATE INDEX remediation_approval_pending_idx
    ON remediation_approval_projection (
        tenant_id, status, expires_at, approval_id
    ) WHERE status = 'pending';
CREATE INDEX remediation_approval_action_idx
    ON remediation_approval_projection (tenant_id, plan_id, action_id);

CREATE TABLE remediation_approval_decisions (
    tenant_id text NOT NULL,
    decision_event_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    actor_id text NOT NULL CHECK (
        actor_id <> '' AND octet_length(actor_id) <= 256
    ),
    decision text NOT NULL CHECK (
        decision IN ('granted', 'denied', 'expired', 'revoked')
    ),
    rationale_code text NOT NULL CHECK (
        rationale_code <> '' AND octet_length(rationale_code) <= 128
    ),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, decision_event_id)
);

CREATE INDEX remediation_approval_decision_idx
    ON remediation_approval_decisions (
        tenant_id, approval_id, occurred_at, decision_event_id
    );

CREATE TRIGGER remediation_approval_decisions_no_update
BEFORE UPDATE OR DELETE ON remediation_approval_decisions
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE remediation_effect_claims (
    tenant_id text NOT NULL,
    idempotency_key text NOT NULL CHECK (
        idempotency_key <> '' AND octet_length(idempotency_key) <= 256
    ),
    plan_id uuid NOT NULL,
    action_id uuid NOT NULL,
    action_digest char(64) NOT NULL,
    target_fingerprint char(64) NOT NULL,
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 5),
    status text NOT NULL CHECK (
        status IN ('intent_recorded', 'succeeded', 'failed', 'ambiguous')
    ),
    last_event_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key)
);

CREATE INDEX remediation_effect_status_idx
    ON remediation_effect_claims (
        tenant_id, status, updated_at, action_id
    );

CREATE TABLE remediation_quota_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    usage_period text NOT NULL CHECK (
        usage_period <> '' AND octet_length(usage_period) <= 64
    ),
    actions_started integer NOT NULL DEFAULT 0 CHECK (actions_started >= 0),
    active_actions integer NOT NULL DEFAULT 0 CHECK (active_actions >= 0),
    last_global_position bigint NOT NULL DEFAULT 0
        CHECK (last_global_position >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, usage_period)
);

ALTER TABLE remediation_plan_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_plan_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_plan_projection_tenant_isolation
    ON remediation_plan_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE remediation_action_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_action_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_action_projection_tenant_isolation
    ON remediation_action_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE remediation_approval_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_approval_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_approval_projection_tenant_isolation
    ON remediation_approval_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE remediation_approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_approval_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_approval_decisions_tenant_isolation
    ON remediation_approval_decisions
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE remediation_effect_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_effect_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_effect_claims_tenant_isolation
    ON remediation_effect_claims
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE remediation_quota_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_quota_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_quota_projection_tenant_isolation
    ON remediation_quota_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_plan_projection,
    remediation_action_projection, remediation_approval_projection,
    remediation_effect_claims, remediation_quota_projection TO aegis_app;
GRANT SELECT, INSERT ON remediation_approval_decisions TO aegis_app;
REVOKE UPDATE, DELETE, TRUNCATE ON remediation_approval_decisions
    FROM PUBLIC, aegis_app;
REVOKE TRUNCATE ON remediation_plan_projection,
    remediation_action_projection, remediation_approval_projection,
    remediation_effect_claims, remediation_quota_projection
    FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_plan_projection,
    remediation_action_projection, remediation_approval_projection,
    remediation_approval_decisions, remediation_effect_claims,
    remediation_quota_projection TO aegis_maintenance;

COMMIT;
