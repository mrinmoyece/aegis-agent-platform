"""Disposable live-service fixtures shared by integration evidence."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")


@pytest.fixture(scope="session", autouse=True)
def migrated_database() -> None:
    """Rebuild a disposable schema and apply all additive migrations."""
    if DATABASE_URL is None:
        return
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA public CASCADE")
        connection.execute("CREATE SCHEMA public")
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO tenants (tenant_id, display_name, enabled, created_at)
            VALUES
                ('tenant-a', 'Tenant A', true, transaction_timestamp()),
                ('tenant-b', 'Tenant B', true, transaction_timestamp())
            """
        )
        # Ensure aegis_app can read quota limits for budget admission.
        connection.execute("GRANT SELECT ON tenant_quotas TO aegis_app")
