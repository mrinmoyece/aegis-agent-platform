BEGIN;

CREATE TABLE IF NOT EXISTS aegis_schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    migration_name text NOT NULL UNIQUE CHECK (
        migration_name <> '' AND octet_length(migration_name) <= 256
    ),
    content_sha256 char(64) NOT NULL,
    applied_at timestamptz NOT NULL,
    applied_by text NOT NULL CHECK (
        applied_by <> '' AND octet_length(applied_by) <= 128
    )
);

CREATE TABLE tenant_writer_fences (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id),
    home_region text NOT NULL CHECK (
        home_region <> '' AND octet_length(home_region) <= 64
    ),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL CHECK (state IN ('active', 'fenced', 'failover_pending')),
    enforcement_enabled boolean NOT NULL DEFAULT false,
    approved_change_reference text NOT NULL CHECK (
        approved_change_reference LIKE 'change-ref://%'
        AND octet_length(approved_change_reference) <= 512
    ),
    updated_at timestamptz NOT NULL
);

INSERT INTO tenant_writer_fences (
    tenant_id,
    home_region,
    generation,
    state,
    enforcement_enabled,
    approved_change_reference,
    updated_at
)
SELECT
    tenant_id,
    'bootstrap-unassigned',
    1,
    'fenced',
    false,
    'change-ref://migration-0011-bootstrap',
    transaction_timestamp()
FROM tenants;

CREATE FUNCTION aegis_seed_tenant_writer_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO tenant_writer_fences (
        tenant_id,
        home_region,
        generation,
        state,
        enforcement_enabled,
        approved_change_reference,
        updated_at
    ) VALUES (
        NEW.tenant_id,
        'bootstrap-unassigned',
        1,
        'fenced',
        false,
        'change-ref://tenant-bootstrap',
        transaction_timestamp()
    );
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION aegis_seed_tenant_writer_fence() FROM PUBLIC;

CREATE TRIGGER tenants_seed_writer_fence
AFTER INSERT ON tenants
FOR EACH ROW EXECUTE FUNCTION aegis_seed_tenant_writer_fence();

CREATE FUNCTION aegis_enforce_writer_fence_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    IF NEW.generation = OLD.generation THEN
        IF NEW.home_region <> OLD.home_region
           AND NOT (
               OLD.home_region = 'bootstrap-unassigned'
               AND OLD.state = 'fenced'
               AND NOT OLD.enforcement_enabled
           ) THEN
            RAISE EXCEPTION 'writer region change requires a new generation'
                USING ERRCODE = '42501';
        END IF;
        IF (OLD.state, NEW.state) NOT IN (
            ('active', 'active'),
            ('active', 'fenced'),
            ('fenced', 'fenced'),
            ('fenced', 'active'),
            ('failover_pending', 'failover_pending'),
            ('failover_pending', 'active'),
            ('failover_pending', 'fenced')
        ) THEN
            RAISE EXCEPTION 'invalid writer fence state transition'
                USING ERRCODE = '42501';
        END IF;
    ELSIF NEW.generation = OLD.generation + 1 THEN
        IF NEW.state NOT IN ('fenced', 'failover_pending') THEN
            RAISE EXCEPTION 'new writer generation must begin fenced'
                USING ERRCODE = '42501';
        END IF;
    ELSE
        RAISE EXCEPTION 'writer generation must be monotonic and contiguous'
            USING ERRCODE = '42501';
    END IF;

    IF OLD.enforcement_enabled AND NOT NEW.enforcement_enabled THEN
        RAISE EXCEPTION 'writer fence enforcement cannot be disabled'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'writer fence timestamp cannot move backward'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION aegis_enforce_writer_fence_transition() FROM PUBLIC;

CREATE TRIGGER tenant_writer_fences_require_monotonic_transition
BEFORE UPDATE ON tenant_writer_fences
FOR EACH ROW EXECUTE FUNCTION aegis_enforce_writer_fence_transition();

CREATE TABLE tenant_retention_policies (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id),
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    ledger_retention_mode text NOT NULL CHECK (
        ledger_retention_mode IN ('retain', 'governed_archive')
    ),
    online_projection_days integer NOT NULL CHECK (
        online_projection_days BETWEEN 7 AND 3650
    ),
    outbox_days integer NOT NULL CHECK (outbox_days BETWEEN 7 AND 365),
    inbox_days integer NOT NULL CHECK (inbox_days BETWEEN 7 AND 365),
    audit_days integer NOT NULL CHECK (audit_days BETWEEN 30 AND 3650),
    legal_hold boolean NOT NULL DEFAULT false,
    approved_policy_reference text NOT NULL CHECK (
        approved_policy_reference LIKE 'policy-ref://%'
        AND octet_length(approved_policy_reference) <= 512
    ),
    effective_at timestamptz NOT NULL
);

CREATE TABLE ledger_archive_manifests (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    archive_id uuid NOT NULL,
    first_global_position bigint NOT NULL CHECK (first_global_position > 0),
    last_global_position bigint NOT NULL CHECK (
        last_global_position >= first_global_position
    ),
    event_count bigint NOT NULL CHECK (event_count > 0),
    content_sha256 char(64) NOT NULL,
    object_reference text NOT NULL CHECK (
        object_reference LIKE 'aegis-object://%'
        AND octet_length(object_reference) <= 1024
    ),
    encryption_key_reference text NOT NULL CHECK (
        encryption_key_reference LIKE 'key-ref://%'
        AND octet_length(encryption_key_reference) <= 512
    ),
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    created_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, archive_id),
    UNIQUE (tenant_id, first_global_position, last_global_position),
    CHECK (created_at <= verified_at)
);

CREATE FUNCTION aegis_assert_writer_fence(
    p_tenant_id text,
    p_region text,
    p_generation bigint
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    active_fence tenant_writer_fences%ROWTYPE;
BEGIN
    SELECT *
    INTO active_fence
    FROM tenant_writer_fences
    WHERE tenant_id = p_tenant_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'writer fence missing'
            USING ERRCODE = '42501';
    END IF;

    IF NOT active_fence.enforcement_enabled THEN
        RETURN;
    END IF;

    IF p_region IS NULL
       OR p_generation IS NULL
       OR active_fence.state <> 'active'
       OR active_fence.home_region <> p_region
       OR active_fence.generation <> p_generation THEN
        RAISE EXCEPTION 'writer fence rejected'
            USING ERRCODE = '42501';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION aegis_assert_writer_fence(text, text, bigint) FROM PUBLIC;

CREATE FUNCTION aegis_enforce_event_writer_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    PERFORM aegis_assert_writer_fence(
        NEW.tenant_id,
        current_setting('aegis.writer_region', true),
        nullif(current_setting('aegis.writer_generation', true), '')::bigint
    );
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION aegis_enforce_event_writer_fence() FROM PUBLIC;

CREATE TRIGGER events_require_writer_fence
BEFORE INSERT ON events
FOR EACH ROW EXECUTE FUNCTION aegis_enforce_event_writer_fence();

CREATE TRIGGER ledger_archive_manifests_no_mutation
BEFORE UPDATE OR DELETE ON ledger_archive_manifests
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

ALTER TABLE tenant_writer_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_writer_fences FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_retention_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger_archive_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_archive_manifests FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_writer_fences_tenant_isolation
ON tenant_writer_fences
USING (tenant_id = current_setting('aegis.tenant_id', true))
WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));
CREATE POLICY tenant_retention_policies_tenant_isolation
ON tenant_retention_policies
USING (tenant_id = current_setting('aegis.tenant_id', true))
WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));
CREATE POLICY ledger_archive_manifests_tenant_isolation
ON ledger_archive_manifests
USING (tenant_id = current_setting('aegis.tenant_id', true))
WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT ON aegis_schema_migrations TO aegis_app;
GRANT SELECT ON tenant_writer_fences, tenant_retention_policies,
    ledger_archive_manifests TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON tenant_writer_fences,
    tenant_retention_policies TO aegis_maintenance;
GRANT SELECT, INSERT ON ledger_archive_manifests TO aegis_maintenance;
GRANT EXECUTE ON FUNCTION aegis_assert_writer_fence(text, text, bigint)
    TO aegis_app, aegis_maintenance;
GRANT EXECUTE ON FUNCTION aegis_enforce_event_writer_fence()
    TO aegis_app, aegis_maintenance;
GRANT EXECUTE ON FUNCTION aegis_seed_tenant_writer_fence(),
    aegis_enforce_writer_fence_transition() TO aegis_maintenance;
REVOKE UPDATE, DELETE, TRUNCATE ON ledger_archive_manifests FROM aegis_app;

COMMIT;
