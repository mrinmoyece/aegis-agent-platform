BEGIN;

CREATE TABLE tenant_model_budget_locks (
    tenant_id text PRIMARY KEY REFERENCES tenants (tenant_id)
);

CREATE TABLE model_budget_reservations (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    reservation_id uuid NOT NULL,
    run_id uuid NOT NULL,
    work_id uuid NOT NULL,
    request_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    token_limit bigint NOT NULL CHECK (token_limit > 0),
    cost_limit_usd numeric(20, 10) NOT NULL CHECK (cost_limit_usd >= 0),
    price_version text NOT NULL CHECK (price_version <> ''),
    status text NOT NULL CHECK (status IN ('active', 'charged', 'released')),
    charged_tokens bigint NOT NULL DEFAULT 0 CHECK (charged_tokens >= 0),
    charged_cost_usd numeric(20, 10) NOT NULL DEFAULT 0
        CHECK (charged_cost_usd >= 0),
    lease_token uuid NOT NULL,
    lease_generation bigint NOT NULL CHECK (lease_generation > 0),
    created_at timestamptz NOT NULL,
    reconciled_at timestamptz,
    PRIMARY KEY (tenant_id, reservation_id),
    FOREIGN KEY (tenant_id, work_id)
        REFERENCES work_items (tenant_id, work_id),
    CHECK ((status = 'active') = (reconciled_at IS NULL))
);

CREATE UNIQUE INDEX model_budget_reservations_request_active_idx
    ON model_budget_reservations (tenant_id, request_id)
    WHERE status IN ('active', 'charged');

CREATE UNIQUE INDEX model_budget_reservations_idempotency_active_idx
    ON model_budget_reservations (tenant_id, idempotency_key)
    WHERE status IN ('active', 'charged');

CREATE INDEX model_budget_reservations_active_idx
    ON model_budget_reservations (tenant_id, run_id, created_at)
    WHERE status = 'active';

-- Budget admission reads this projection. Rebuilds must replace tenant rows
-- atomically (or hold an admission lock) because delete-then-replay across
-- multiple transactions can transiently report zero historical usage.
CREATE TABLE model_usage_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    request_id uuid NOT NULL,
    run_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider <> ''),
    model text NOT NULL CHECK (model <> ''),
    price_version text NOT NULL CHECK (price_version <> ''),
    input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
    cache_read_tokens bigint NOT NULL CHECK (cache_read_tokens >= 0),
    cache_write_tokens bigint NOT NULL CHECK (cache_write_tokens >= 0),
    reasoning_tokens bigint NOT NULL CHECK (reasoning_tokens >= 0),
    total_tokens bigint NOT NULL CHECK (total_tokens >= 0),
    cost_usd numeric(20, 10) NOT NULL CHECK (cost_usd >= 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);

CREATE INDEX model_usage_projection_period_idx
    ON model_usage_projection (tenant_id, recorded_at, run_id);

ALTER TABLE tenant_model_budget_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_model_budget_locks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_model_budget_locks_tenant_isolation
    ON tenant_model_budget_locks
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE model_budget_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_budget_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY model_budget_reservations_tenant_isolation
    ON model_budget_reservations
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE model_usage_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_usage_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY model_usage_projection_tenant_isolation
    ON model_usage_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON tenant_model_budget_locks,
    model_budget_reservations TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON model_usage_projection TO aegis_app;
REVOKE DELETE, TRUNCATE ON tenant_model_budget_locks,
    model_budget_reservations FROM PUBLIC, aegis_app;
REVOKE DELETE, TRUNCATE ON model_usage_projection FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_model_budget_locks,
    model_budget_reservations, model_usage_projection TO aegis_maintenance;

COMMIT;
