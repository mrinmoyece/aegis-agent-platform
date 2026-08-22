"""Validate irreversible security properties of SQL migrations."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_MIGRATION_NAME = re.compile(r"^(?P<number>\d{4})_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$")


def _validate_migration_names(migrations: list[Path]) -> None:
    for expected_number, path in enumerate(migrations, start=1):
        match = _MIGRATION_NAME.fullmatch(path.name)
        if match is None:
            raise SystemExit(
                "migration names must match NNNN_description.sql using lowercase "
                "letters, digits, and underscores"
            )
        if int(match.group("number")) != expected_number:
            raise SystemExit(
                "migration numbering must be contiguous starting at 0001"
            )


def main() -> None:
    """Require ordered migrations and durable tenant/event controls."""
    migrations = sorted((ROOT / "migrations").glob("*.sql"))
    if not migrations:
        raise SystemExit("at least one SQL migration is required")
    _validate_migration_names(migrations)
    schema = "\n".join(path.read_text(encoding="utf-8") for path in migrations).lower()
    required = (
        "create table tenants",
        "create table identities",
        "create table role_bindings",
        "create table tenant_policies",
        "create table tenant_quotas",
        "create table security_audit_events",
        "force row level security",
        "security audit records are append-only",
        "create table events",
        "create table inbox_messages",
        "create table outbox_messages",
        "create table projection_checkpoints",
        "event records are append-only",
        "aegis_maintenance",
    )
    missing = [control for control in required if control not in schema]
    if missing:
        raise SystemExit("migration controls missing: " + ", ".join(missing))
    if re.search(r"^\s*(?:drop\s+table|truncate)\b", schema, re.MULTILINE):
        raise SystemExit("destructive migration statements are prohibited")


if __name__ == "__main__":
    main()
