BEGIN;

CREATE TABLE agent_run_projection (
    tenant_id text NOT NULL REFERENCES tenants (tenant_id),
    run_id uuid NOT NULL,
    incident_id text NOT NULL CHECK (
        incident_id <> '' AND octet_length(incident_id) <= 256
    ),
    plan_id uuid NOT NULL,
    plan_digest char(64) NOT NULL,
    status text NOT NULL CHECK (status IN (
        'requested', 'running', 'succeeded', 'abstained', 'escalated',
        'failed', 'cancelled', 'budget_exhausted'
    )),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    used_tokens bigint NOT NULL DEFAULT 0 CHECK (used_tokens >= 0),
    reserved_tokens bigint NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    final_artifact_id uuid,
    terminal_reason text CHECK (
        terminal_reason IS NULL OR octet_length(terminal_reason) <= 128
    ),
    lease_token uuid,
    lease_generation bigint CHECK (
        lease_generation IS NULL OR lease_generation > 0
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, plan_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES work_items (tenant_id, work_id)
);

CREATE INDEX agent_run_projection_incident_idx
    ON agent_run_projection (tenant_id, incident_id, updated_at, run_id);
CREATE INDEX agent_run_projection_status_idx
    ON agent_run_projection (tenant_id, status, updated_at, run_id);

CREATE TABLE agent_task_projection (
    tenant_id text NOT NULL,
    run_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    role text NOT NULL CHECK (role IN (
        'incident_coordinator', 'telemetry_investigator',
        'change_investigator', 'runtime_investigator',
        'knowledge_investigator', 'critic_reviewer',
        'remediation_planner', 'verification_agent'
    )),
    depends_on uuid[] NOT NULL,
    capabilities text[] NOT NULL,
    status text NOT NULL CHECK (status IN (
        'pending', 'dispatched', 'running', 'succeeded', 'failed',
        'timed_out', 'cancelled', 'blocked'
    )),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    reserved_tokens bigint NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    used_tokens bigint NOT NULL DEFAULT 0 CHECK (used_tokens >= 0),
    artifact_count integer NOT NULL DEFAULT 0 CHECK (artifact_count >= 0),
    last_error_code text CHECK (
        last_error_code IS NULL OR octet_length(last_error_code) <= 128
    ),
    lease_token uuid,
    lease_generation bigint CHECK (
        lease_generation IS NULL OR lease_generation > 0
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, assignment_id),
    UNIQUE (tenant_id, run_id, ordinal),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent_run_projection (tenant_id, run_id)
);

CREATE INDEX agent_task_projection_ready_idx
    ON agent_task_projection (tenant_id, run_id, status, ordinal);

CREATE TABLE reasoning_artifact_projection (
    tenant_id text NOT NULL,
    run_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    ledger_sequence bigint NOT NULL CHECK (ledger_sequence > 0),
    artifact_kind text NOT NULL CHECK (artifact_kind IN (
        'evidence_assessment', 'hypothesis', 'alternative_hypothesis',
        'contradiction', 'critique', 'causal_graph_reference',
        'timeline_reference', 'remediation_recommendation',
        'verification_plan', 'coordinator_decision',
        'final_incident_assessment'
    )),
    produced_by text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    summary text NOT NULL CHECK (
        summary <> '' AND octet_length(summary) <= 4096
    ),
    confidence double precision CHECK (
        confidence IS NULL OR confidence BETWEEN 0 AND 1
    ),
    citation_ids jsonb NOT NULL CHECK (
        jsonb_typeof(citation_ids) = 'array'
        AND octet_length(citation_ids::text) <= 16384
    ),
    artifact_content jsonb NOT NULL CHECK (
        jsonb_typeof(artifact_content) = 'object'
        AND octet_length(artifact_content::text) <= 65536
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, artifact_id),
    UNIQUE (tenant_id, run_id, ledger_sequence),
    FOREIGN KEY (tenant_id, run_id, assignment_id)
        REFERENCES agent_task_projection (tenant_id, run_id, assignment_id)
);

CREATE INDEX reasoning_artifact_projection_page_idx
    ON reasoning_artifact_projection (
        tenant_id, run_id, ledger_sequence, artifact_id
    );
CREATE INDEX reasoning_artifact_projection_kind_idx
    ON reasoning_artifact_projection (
        tenant_id, run_id, artifact_kind, ledger_sequence
    );

ALTER TABLE agent_run_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_run_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_run_projection_tenant_isolation
    ON agent_run_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE agent_task_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_task_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_task_projection_tenant_isolation
    ON agent_task_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

ALTER TABLE reasoning_artifact_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE reasoning_artifact_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY reasoning_artifact_projection_tenant_isolation
    ON reasoning_artifact_projection
    USING (tenant_id = current_setting('aegis.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON agent_run_projection, agent_task_projection
    TO aegis_app;
GRANT SELECT, INSERT ON reasoning_artifact_projection TO aegis_app;
REVOKE DELETE, TRUNCATE ON agent_run_projection, agent_task_projection,
    reasoning_artifact_projection FROM PUBLIC, aegis_app;
REVOKE UPDATE ON reasoning_artifact_projection FROM PUBLIC, aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_run_projection,
    agent_task_projection, reasoning_artifact_projection TO aegis_maintenance;

COMMIT;
