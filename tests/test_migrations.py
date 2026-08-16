"""Static migration security assertions."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.check_migrations import migration_numbers

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "0001_identity_governance.sql"


def test_identity_governance_schema_has_tenant_constraints_and_indexes() -> None:
    schema = MIGRATION.read_text(encoding="utf-8").lower()

    assert "foreign key (identity_id, tenant_id)" in schema
    assert "identities_tenant_idx" in schema
    assert "role_bindings_tenant_identity_idx" in schema
    assert "security_audit_events_tenant_sequence_idx" in schema


def test_tenant_tables_have_forced_row_level_security() -> None:
    schema = MIGRATION.read_text(encoding="utf-8").lower()
    protected_tables = (
        "tenants",
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
    assert "before truncate on security_audit_events" in schema
    assert "revoke update, delete, truncate" in schema
    assert "security audit records are append-only" in schema


def test_migration_numbers_must_be_fixed_width_unique_and_ordered() -> None:
    assert migration_numbers([Path("0001_identity.sql"), Path("0002_audit.sql")]) == [
        1,
        2,
    ]
    with pytest.raises(SystemExit, match="unique"):
        migration_numbers([Path("0001_identity.sql"), Path("0001_audit.sql")])
    with pytest.raises(SystemExit, match="NNNN"):
        migration_numbers([Path("1_identity.sql")])
