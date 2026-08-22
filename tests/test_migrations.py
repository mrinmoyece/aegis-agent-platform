"""Static migration security assertions."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from scripts.check_migrations import _validate_migration_names, security_reversals

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "0001_identity_governance.sql"
LEDGER_MIGRATION = ROOT / "migrations" / "0002_durable_ledger.sql"
GATEWAY_MIGRATION = ROOT / "migrations" / "0004_model_gateway.sql"
EVIDENCE_MIGRATION = ROOT / "migrations" / "0005_evidence_connectors.sql"
AGENT_MIGRATION = ROOT / "migrations" / "0006_specialist_orchestration.sql"


def test_identity_governance_schema_has_tenant_constraints_and_indexes() -> None:
    schema = MIGRATION.read_text(encoding="utf-8").lower()

    assert "foreign key (identity_id, tenant_id)" in schema
    assert "identities_tenant_idx" in schema
    assert "role_bindings_tenant_identity_idx" in schema
    assert "security_audit_events_tenant_sequence_idx" in schema
    assert "check (role <> 'platform_admin' or tenant_id = 'platform')" in schema


def test_tenant_tables_have_forced_row_level_security() -> None:
    schema = MIGRATION.read_text(encoding="utf-8").lower()
    protected_tables = (
        "identities",
        "role_bindings",
        "tenant_policies",
        "tenant_quotas",
        "security_audit_events",
    )

    for table in protected_tables:
        assert f"alter table {table} force row level security" in schema
        assert f"create policy {table}_tenant_isolation" in schema


def test_audit_records_are_database_append_only() -> None:
    schema = MIGRATION.read_text(encoding="utf-8").lower()

    assert "before update or delete on security_audit_events" in schema
    assert "security audit records are append-only" in schema


def test_ledger_schema_is_append_only_tenant_scoped_and_indexed() -> None:
    schema = LEDGER_MIGRATION.read_text(encoding="utf-8").lower()

    for table in (
        "events",
        "event_stream_heads",
        "tenant_event_commit_locks",
        "inbox_messages",
        "outbox_messages",
        "projection_checkpoints",
        "run_status_projection",
        "artifact_index_projection",
        "pending_approvals_projection",
        "usage_quota_projection",
        "tenant_listing_projection",
    ):
        assert f"alter table {table} force row level security" in schema
        assert f"{table}_tenant_isolation" in schema
    assert "unique (tenant_id, aggregate_id, aggregate_sequence)" in schema
    assert "before update or delete on events" in schema
    assert "event records are append-only" in schema
    assert "create policy tenants_tenant_isolation on tenants" not in schema
    adapter = (
        (ROOT / "src" / "aegis_agent_platform" / "event_store" / "postgres.py")
        .read_text(encoding="utf-8")
        .lower()
    )
    assert "from tenant_event_commit_locks" in adapter
    assert "for update skip locked" in adapter


def test_migration_declares_explicit_maintenance_role_boundary() -> None:
    schema = LEDGER_MIGRATION.read_text(encoding="utf-8").lower()

    assert "aegis_app nologin noinherit nobypassrls" in schema
    assert "aegis_maintenance nologin noinherit bypassrls" in schema
    assert "revoke update, delete, truncate on events" in schema


def test_destructive_migration_guard_rejects_optional_truncate_syntax() -> None:
    pattern = re.compile(
        r"^\s*(?:drop\s+table|truncate)\b",
        re.MULTILINE,
    )

    assert pattern.search("TRUNCATE events;".lower())
    assert pattern.search("TRUNCATE TABLE events;".lower())
    assert not pattern.search("REVOKE TRUNCATE ON events;".lower())


@pytest.mark.parametrize(
    "statement",
    [
        "DROP FUNCTION reject_event_mutation() CASCADE;",
        "DROP AGGREGATE security.aggregate_name(text);",
    ],
)
def test_security_reversal_guard_rejects_function_and_aggregate_drops(
    statement: str,
) -> None:
    reversals = security_reversals(statement.lower())

    assert len(reversals) == 1
    assert statement.lower().startswith(reversals[0])


def test_migration_name_validation_requires_pattern_and_contiguous_sequence() -> None:
    with pytest.raises(SystemExit, match=r"NNNN_description\.sql"):
        _validate_migration_names([Path("001_bad-name.sql")])
    with pytest.raises(SystemExit, match="contiguous"):
        _validate_migration_names([Path("0001_first.sql"), Path("0003_third.sql")])


def test_model_budget_schema_is_tenant_scoped_fenced_and_versioned() -> None:
    schema = GATEWAY_MIGRATION.read_text(encoding="utf-8").lower()
    for table in (
        "tenant_model_budget_locks",
        "model_budget_reservations",
        "model_usage_projection",
    ):
        assert f"alter table {table} force row level security" in schema
        assert f"{table}_tenant_isolation" in schema
    assert "model_budget_reservations_request_active_idx" in schema
    assert "model_budget_reservations_idempotency_active_idx" in schema
    assert "where status in ('active', 'charged')" in schema
    assert "price_version text not null" in schema
    assert "lease_generation bigint not null" in schema
    assert "where status = 'active'" in schema


def test_evidence_schema_is_tenant_scoped_bounded_and_append_only() -> None:
    schema = EVIDENCE_MIGRATION.read_text(encoding="utf-8").lower()
    for table in (
        "evidence_query_projection",
        "evidence_records",
        "evidence_quarantine",
        "source_cursors",
        "evidence_bundle_projection",
    ):
        assert f"alter table {table} force row level security" in schema
        assert f"{table}_tenant_isolation" in schema
    assert "unique (tenant_id, content_digest)" in schema
    assert "octet_length(summary) <= 4096" in schema
    assert "octet_length(structured_fields::text) <= 262144" in schema
    assert "raw_payload_reference like 'aegis-object://%'" in schema
    assert "query_window_start timestamptz not null" in schema
    assert "evidence_references jsonb not null" in schema
    assert "query_event_position bigint not null" in schema
    assert "bundle_content jsonb not null" in schema
    assert "artifact_reference like 'aegis-artifact://%'" in schema
    assert "before update or delete on evidence_records" in schema
    assert "before update or delete on evidence_quarantine" in schema
    assert "evidence records are append-only" in schema
    assert "lease_generation bigint not null" in schema
    assert "revoke update, delete, truncate on evidence_records" in schema


def test_specialist_schema_is_tenant_scoped_fenced_and_rebuildable() -> None:
    schema = AGENT_MIGRATION.read_text(encoding="utf-8").lower()
    for table in (
        "agent_run_projection",
        "agent_task_projection",
        "reasoning_artifact_projection",
    ):
        assert f"alter table {table} force row level security" in schema
        assert f"{table}_tenant_isolation" in schema
    assert "grant select, insert, update, delete on agent_run_projection," in schema
    maintenance_grant = (
        "agent_task_projection, reasoning_artifact_projection to aegis_maintenance"
    )
    assert maintenance_grant in schema
    assert "aggregate_version bigint not null" in schema
    assert "lease_generation bigint" in schema
    assert "octet_length(artifact_content::text) <= 65536" in schema
    assert "octet_length(summary) <= 4096" in schema
    assert "unique (tenant_id, run_id, ledger_sequence)" in schema
    assert "revoke delete, truncate on agent_run_projection" in schema
    assert "revoke update on reasoning_artifact_projection" in schema
    assert "grant usage on schema public to aegis_maintenance" in schema
