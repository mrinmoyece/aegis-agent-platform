"""Validate irreversible security properties of SQL migrations."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_NAME = re.compile(r"^(?P<number>\d{4})_[a-z0-9_]+\.sql$")


def migration_numbers(migrations: list[Path]) -> list[int]:
    """Return ordered unique migration numbers or fail closed."""
    numbers: list[int] = []
    for migration in migrations:
        match = MIGRATION_NAME.fullmatch(migration.name)
        if match is None:
            raise SystemExit(
                f"migration name must use NNNN_description.sql: {migration.name}"
            )
        numbers.append(int(match.group("number")))
    if numbers != sorted(numbers):
        raise SystemExit("migration numbers must be ordered")
    if len(numbers) != len(set(numbers)):
        raise SystemExit("migration numbers must be unique")
    return numbers


def main() -> None:
    """Require ordered migrations and the Layer 2 tenant/audit controls."""
    migrations = sorted((ROOT / "migrations").glob("*.sql"))
    if not migrations:
        raise SystemExit("at least one SQL migration is required")
    migration_numbers(migrations)
    schema = "\n".join(path.read_text(encoding="utf-8") for path in migrations).lower()
    required = (
        "create table tenants",
        "create table identities",
        "create table role_bindings",
        "create table tenant_policies",
        "create table tenant_quotas",
        "create table security_audit_events",
        "create policy tenants_tenant_isolation",
        "force row level security",
        "before truncate on security_audit_events",
        "revoke update, delete, truncate on security_audit_events from public",
        "security audit records are append-only",
    )
    missing = [control for control in required if control not in schema]
    if missing:
        raise SystemExit("migration controls missing: " + ", ".join(missing))
    if re.search(r"(?m)^\s*(drop\s+table|truncate\s+table)\b", schema):
        raise SystemExit("destructive migration statements are prohibited")


if __name__ == "__main__":
    main()
