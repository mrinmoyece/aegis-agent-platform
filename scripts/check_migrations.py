"""Validate irreversible security properties of SQL migrations."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Require ordered migrations and durable tenant/event controls."""
    migrations = sorted((ROOT / "migrations").glob("*.sql"))
    if not migrations:
        raise SystemExit("at least one SQL migration is required")
    names = [path.name for path in migrations]
    if names != sorted(names) or len(names) != len(set(names)):
        raise SystemExit("migration names must be unique and lexically ordered")
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
        "create table work_items",
        "create table work_leases",
        "create table work_dead_letters",
    )
    missing = [control for control in required if control not in schema]
    if missing:
        raise SystemExit("migration controls missing: " + ", ".join(missing))
    if re.search(r"^\s*(?:drop\s+table|truncate)\b", schema, re.MULTILINE):
        raise SystemExit("destructive migration statements are prohibited")


if __name__ == "__main__":
    main()
