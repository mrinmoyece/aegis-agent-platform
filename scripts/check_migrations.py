"""Validate irreversible security properties of SQL migrations."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_MIGRATION_NAME = re.compile(r"^(?P<number>\d{4})_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$")

# Patterns that would weaken tenant isolation or the append-only guarantee.
_DESTRUCTIVE = re.compile(
    r"""
    ^\s*(?:
        drop\s+table\b                                    # drop table
        | truncate\b                                      # truncate table
        | drop\s+trigger\b                                # remove append-only guard
        | drop\s+policy\b                                 # remove RLS policy
        | alter\s+table\s+\S+\s+disable\s+trigger\b      # silence trigger
        | alter\s+table\s+\S+\s+disable\s+row\s+level\s+security
        | alter\s+table\s+\S+\s+no\s+force\s+row\s+level\s+security
    )
    """,
    re.MULTILINE | re.VERBOSE | re.IGNORECASE,
)
SECURITY_REVERSAL_PATTERNS = (
    re.compile(r"(?im)^\s*alter\s+table\b.*\bdisable\s+row\s+level\s+security\b"),
    re.compile(r"(?im)^\s*alter\s+table\b.*\bno\s+force\s+row\s+level\s+security\b"),
    re.compile(r"(?im)^\s*drop\s+policy\b"),
    re.compile(r"(?im)^\s*drop\s+trigger\b"),
    re.compile(
        r"(?im)^\s*drop\s+function\b[^\n;]*"
        r"\b(?:[a-z_][\w$]*\.)?reject_security_audit_mutation\b"
    ),
    re.compile(r"(?im)^\s*alter\s+table\b.*\bdisable\s+trigger\b"),
    re.compile(
        r"(?im)^\s*grant\b[^\n;]*"
        r"\b(update|delete|truncate|all(?:\s+privileges)?)\b"
        r"[^\n;]*\bon\s+(?:table\s+)?"
        r"(?:[a-z_][\w$]*\.)?security_audit_events\b"
    ),
    re.compile(
        r"(?im)^\s*truncate\s+(?:table\s+)?(?:only\s+)?"
        r"(?:[a-z_][\w$]*\.)?security_audit_events\b"
    ),
)


def migration_numbers(migrations: list[Path]) -> list[int]:
    """Return ordered unique migration numbers or fail closed."""
    numbers: list[int] = []
    for migration in migrations:
        match = _MIGRATION_NAME.fullmatch(migration.name)
        if match is None:
            raise SystemExit(
                "migration names must match NNNN_description.sql using lowercase "
                "letters, digits, and underscores"
            )
        numbers.append(int(match.group("number")))
    if numbers != sorted(numbers):
        raise SystemExit("migration numbers must be ordered")
    if len(numbers) != len(set(numbers)):
        raise SystemExit("migration numbers must be unique")
    return numbers


def _validate_migration_names(migrations: list[Path]) -> None:
    numbers = migration_numbers(migrations)
    for expected_number, number in enumerate(numbers, start=1):
        if number != expected_number:
            raise SystemExit(
                "migration numbering must be contiguous starting at 0001"
            )


def security_reversals(schema: str) -> list[str]:
    """Return statements that weaken durable tenant or audit controls."""
    return [
        match.group(0).strip()
        for pattern in SECURITY_REVERSAL_PATTERNS
        if (match := pattern.search(schema)) is not None
    ]


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
        "create policy tenants_tenant_isolation",
        "force row level security",
        "before truncate on security_audit_events",
        "revoke update, delete, truncate on security_audit_events from public",
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
    match = _DESTRUCTIVE.search(schema)
    if match:
        raise SystemExit(
            "destructive migration statement prohibited: "
            + schema.splitlines()[schema[: match.start()].count("\n")]
        )
    reversals = security_reversals(schema)
    if reversals:
        raise SystemExit("security control reversal is prohibited: " + reversals[0])


if __name__ == "__main__":
    main()
