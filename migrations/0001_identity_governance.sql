BEGIN;

CREATE TABLE tenants (
    tenant_id text PRIMARY KEY CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    display_name text NOT NULL CHECK (display_name <> ''),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL
);

CREATE TABLE identities (
    identity_id uuid PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    issuer text NOT NULL CHECK (issuer <> ''),
    subject text NOT NULL CHECK (subject <> ''),
    identity_kind text NOT NULL CHECK (identity_kind IN ('user', 'service')),
    user_id text,
    service_identity text,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    UNIQUE (issuer, subject),
    UNIQUE (identity_id, tenant_id),
    CHECK (
        (identity_kind = 'user' AND user_id IS NOT NULL AND service_identity IS NULL)
        OR
        (identity_kind = 'service' AND service_identity IS NOT NULL AND user_id IS NULL)
    )
);

CREATE INDEX identities_tenant_idx ON identities (tenant_id, enabled);

CREATE TABLE role_bindings (
    role_binding_id uuid PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    identity_id uuid NOT NULL,
    role text NOT NULL CHECK (
        role IN (
            'viewer',
            'investigator',
            'approver',
            'operator',
            'tenant_admin',
            'platform_admin'
        )
    ),
    assigned_by text NOT NULL CHECK (assigned_by <> ''),
    assigned_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (identity_id, tenant_id)
        REFERENCES identities (identity_id, tenant_id),
    CHECK (expires_at IS NULL OR expires_at > assigned_at),
    CHECK (role <> 'platform_admin' OR tenant_id = 'platform')
);

CREATE INDEX role_bindings_tenant_identity_idx
    ON role_bindings (tenant_id, identity_id, assigned_at);

CREATE TABLE tenant_policies (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id),
    policy_version text NOT NULL CHECK (policy_version <> ''),
    policy_document jsonb NOT NULL,
    updated_by text NOT NULL CHECK (updated_by <> ''),
    updated_at timestamptz NOT NULL
);

CREATE TABLE tenant_quotas (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id),
    max_run_tokens bigint NOT NULL CHECK (max_run_tokens >= 0),
    max_run_cost_usd numeric(20, 6) NOT NULL CHECK (max_run_cost_usd >= 0),
    max_tenant_tokens_per_period bigint NOT NULL
        CHECK (max_tenant_tokens_per_period >= 0),
    max_tenant_cost_usd_per_period numeric(20, 6) NOT NULL
        CHECK (max_tenant_cost_usd_per_period >= 0),
    max_concurrent_runs integer NOT NULL CHECK (max_concurrent_runs >= 0),
    updated_at timestamptz NOT NULL
);

CREATE TABLE security_audit_events (
    sequence_number bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    event_type text NOT NULL CHECK (event_type <> ''),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    occurred_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    actor_id text NOT NULL CHECK (actor_id <> ''),
    action text NOT NULL CHECK (action <> ''),
    resource text NOT NULL CHECK (resource <> ''),
    correlation_id uuid NOT NULL,
    details jsonb NOT NULL
);

CREATE INDEX security_audit_events_tenant_sequence_idx
    ON security_audit_events (tenant_id, sequence_number);
CREATE INDEX security_audit_events_tenant_occurred_idx
    ON security_audit_events (tenant_id, occurred_at);

CREATE FUNCTION reject_security_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security audit records are append-only';
END;
$$;

CREATE TRIGGER security_audit_events_no_update
BEFORE UPDATE OR DELETE ON security_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_security_audit_mutation();

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities FORCE ROW LEVEL SECURITY;
CREATE POLICY identities_tenant_isolation ON identities
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY role_bindings_tenant_isolation ON role_bindings
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE tenant_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_policies_tenant_isolation ON tenant_policies
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE tenant_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_quotas FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_quotas_tenant_isolation ON tenant_quotas
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE security_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY security_audit_events_tenant_isolation ON security_audit_events
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

-- Seed the platform tenant so that failed-authentication audit events (which
-- always use tenant_id = 'platform') satisfy the FK reference from
-- security_audit_events → tenants even when PostgresAuditStore is wired.
INSERT INTO tenants (tenant_id, display_name, enabled, created_at)
VALUES ('platform', 'Platform', true, now())
ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;
