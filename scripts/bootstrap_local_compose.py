"""Seed the conspicuously local-only tenant fence used by Compose."""

from __future__ import annotations

import os

import psycopg


def main() -> None:
    """Create and activate only the deterministic local development tenant."""
    if os.environ.get("AEGIS_ENVIRONMENT") != "development":
        raise SystemExit("local Compose bootstrap requires development environment")
    database_url = os.environ.get("AEGIS_MIGRATION_DATABASE_URL", "")
    if not database_url:
        raise SystemExit("AEGIS_MIGRATION_DATABASE_URL is required")
    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute(
            """
            INSERT INTO tenants (tenant_id, display_name, enabled, created_at)
            VALUES (
                'local-demo',
                'Local Compose Demo',
                true,
                transaction_timestamp()
            )
            ON CONFLICT (tenant_id) DO NOTHING
            """
        )
        connection.execute(
            """
            UPDATE tenant_writer_fences
            SET home_region = 'local-development',
                state = 'active',
                enforcement_enabled = true,
                approved_change_reference = 'change-ref://local-compose-only',
                updated_at = transaction_timestamp()
            WHERE tenant_id = 'local-demo'
            """
        )


if __name__ == "__main__":
    main()
