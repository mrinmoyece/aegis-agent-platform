"""Apply additive SQL migrations under a PostgreSQL advisory lock."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from psycopg import sql

from aegis_agent_platform.config import (
    ConfigurationError,
    Environment,
    validate_protected_database_url,
)

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
LOCK_ID = 6_140_150_015
NAME_PATTERN = re.compile(r"^(?P<version>[0-9]{4})_[a-z0-9_]+\.sql$")
TRANSACTION_PATTERN = re.compile(
    r"\ABEGIN;\s*(?P<body>.*)\s*COMMIT;\s*\Z",
    flags=re.DOTALL,
)
HISTORY_DDL = """
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
)
"""


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url-env",
        default="AEGIS_MIGRATION_DATABASE_URL",
        help="environment variable containing the maintenance connection URL",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="verify lock and compatibility without applying migrations",
    )
    parser.add_argument(
        "--adopt-existing",
        action="store_true",
        help="adopt a complete pre-Layer-15 schema lacking migration history",
    )
    parser.add_argument("--applied-by", default="aegis-migration-job")
    return parser.parse_args(argv)


def _migration_files() -> tuple[tuple[int, Path, str], ...]:
    discovered: list[tuple[int, Path, str]] = []
    for path in sorted(MIGRATIONS.glob("*.sql")):
        match = NAME_PATTERN.fullmatch(path.name)
        if match is None:
            raise ValueError(f"invalid migration name: {path.name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        discovered.append((int(match.group("version")), path, digest))
    expected = list(range(1, len(discovered) + 1))
    if [version for version, _, _ in discovered] != expected:
        raise ValueError("migration versions must be contiguous")
    return tuple(discovered)


def _history_exists(connection: psycopg.Connection[tuple[object, ...]]) -> bool:
    row = connection.execute(
        "SELECT to_regclass('public.aegis_schema_migrations') IS NOT NULL"
    ).fetchone()
    return bool(row and row[0])


def _migration_body(path: Path) -> str:
    match = TRANSACTION_PATTERN.fullmatch(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"migration must have one outer transaction: {path.name}")
    return match.group("body")


def _applied_history(
    connection: psycopg.Connection[tuple[object, ...]],
) -> dict[int, tuple[str, str]]:
    applied: dict[int, tuple[str, str]] = {}
    for row in connection.execute(
        """
        SELECT version, migration_name, content_sha256
        FROM aegis_schema_migrations
        ORDER BY version
        """
    ):
        version = row[0]
        if not isinstance(version, int) or isinstance(version, bool):
            raise SystemExit("migration history contains an invalid version")
        applied[version] = (str(row[1]), str(row[2]))
    return applied


def _validate_history(
    applied: dict[int, tuple[str, str]],
    migrations: tuple[tuple[int, Path, str], ...],
) -> None:
    versions = sorted(applied)
    if versions != list(range(1, len(versions) + 1)):
        raise SystemExit("migration history must be contiguous from version 1")
    if versions and versions[-1] > len(migrations):
        raise SystemExit("database schema is newer than this application build")
    for version, path, digest in migrations:
        recorded = applied.get(version)
        if recorded is None:
            continue
        recorded_name, recorded_digest = recorded
        if recorded_name != path.name:
            raise SystemExit(f"migration name drift detected for version {version:04d}")
        if recorded_digest != digest:
            raise SystemExit(f"migration checksum drift detected for {path.name}")


def _ledger_exists(connection: psycopg.Connection[tuple[object, ...]]) -> bool:
    row = connection.execute(
        "SELECT to_regclass('public.events') IS NOT NULL"
    ).fetchone()
    return bool(row and row[0])


def _record_history(
    connection: psycopg.Connection[tuple[object, ...]],
    migrations: tuple[tuple[int, Path, str], ...],
    *,
    applied_by: str,
) -> None:
    now = datetime.now(UTC)
    for version, path, digest in migrations:
        connection.execute(
            """
            INSERT INTO aegis_schema_migrations (
                version, migration_name, content_sha256, applied_at, applied_by
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (version, path.name, digest, now, applied_by),
        )


def _validate_database_transport(database_url: str) -> None:
    environment = os.environ.get("AEGIS_ENVIRONMENT", Environment.DEVELOPMENT.value)
    if environment not in {Environment.STAGING.value, Environment.PRODUCTION.value}:
        return
    try:
        validate_protected_database_url(database_url)
    except ConfigurationError as error:
        raise SystemExit(str(error)) from error


def run(argv: Sequence[str] | None = None) -> int:
    """Run the one-writer migration contract without exposing credentials."""
    args = _arguments(argv)
    database_url = os.environ.get(str(args.database_url_env), "")
    if not database_url:
        raise SystemExit(f"{args.database_url_env} is required")
    _validate_database_transport(database_url)
    migrations = _migration_files()
    for _, path, _ in migrations:
        _migration_body(path)
    with psycopg.connect(database_url, autocommit=True) as connection:
        locked = connection.execute(
            "SELECT pg_try_advisory_lock(%s)", (LOCK_ID,)
        ).fetchone()
        if not locked or locked[0] is not True:
            raise SystemExit("another migration runner holds the schema lock")
        try:
            history_exists = _history_exists(connection)
            ledger_exists = _ledger_exists(connection)
            if ledger_exists and not history_exists and not args.adopt_existing:
                raise SystemExit(
                    "existing schema has no history; rerun with --adopt-existing "
                    "after verifying migrations 0001-0010"
                )
            applied = _applied_history(connection) if history_exists else {}
            _validate_history(applied, migrations)
            if args.preflight_only:
                return 0
            connection.execute(HISTORY_DDL)
            if ledger_exists and not history_exists:
                latest = migrations[-1]
                with connection.transaction():
                    connection.execute(sql.SQL(_migration_body(latest[1])))
                    _record_history(
                        connection,
                        migrations,
                        applied_by=str(args.applied_by),
                    )
                return 0
            for version, path, digest in migrations:
                if version in applied:
                    continue
                with connection.transaction():
                    connection.execute(sql.SQL(_migration_body(path)))
                    _record_history(
                        connection,
                        ((version, path, digest),),
                        applied_by=str(args.applied_by),
                    )
            return 0
        finally:
            connection.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))


if __name__ == "__main__":
    raise SystemExit(run())
