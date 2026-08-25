"""Disposable live-service fixtures shared by integration evidence."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")


@pytest.fixture(scope="session", autouse=True)
def migrated_database() -> None:
    """Rebuild a disposable schema and apply all additive migrations."""
    if DATABASE_URL is None:
        return
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA public CASCADE")
        connection.execute("CREATE SCHEMA public")
        migrations = sorted((ROOT / "migrations").glob("*.sql"))
        for migration in migrations:
            connection.execute(migration.read_text(encoding="utf-8"))
        applied_at = datetime.now(UTC)
        for version, migration in enumerate(migrations, start=1):
            connection.execute(
                """
                INSERT INTO aegis_schema_migrations (
                    version, migration_name, content_sha256, applied_at, applied_by
                ) VALUES (%s, %s, %s, %s, 'integration-fixture')
                """,
                (
                    version,
                    migration.name,
                    sha256(migration.read_bytes()).hexdigest(),
                    applied_at,
                ),
            )
        connection.execute(
            """
            INSERT INTO tenants (tenant_id, display_name, enabled, created_at)
            VALUES
                ('tenant-a', 'Tenant A', true, transaction_timestamp()),
                ('tenant-b', 'Tenant B', true, transaction_timestamp()),
                (
                    'tenant-remediation',
                    'Tenant Remediation',
                    true,
                    transaction_timestamp()
                )
            """
        )
        connection.execute(
            """
            UPDATE tenant_writer_fences
            SET home_region = 'local-test',
                state = 'active',
                enforcement_enabled = true,
                approved_change_reference = 'change-ref://integration-writer',
                updated_at = transaction_timestamp()
            """
        )
