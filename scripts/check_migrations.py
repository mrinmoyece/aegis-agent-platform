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
    _migration_pattern = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
    for name in names:
        if not _migration_pattern.match(name):
            raise SystemExit(f"migration name does not match expected pattern: {name}")
    numbers = [int(_migration_pattern.match(name).group(1)) for name in names]  # type: ignore[union-attr]
    if len(numbers) != len(set(numbers)):
        raise SystemExit("migration sequence numbers must be unique")
    for i, num in enumerate(numbers):
        if num != i + 1:
            raise SystemExit(
                f"migration sequence must be contiguous starting at 0001; "
                f"got {names[i]!r} at position {i}"
            )
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
        "create table model_budget_reservations",
        "create table model_usage_projection",
        "create table evidence_query_projection",
        "create table evidence_records",
        "create table evidence_quarantine",
        "create table source_cursors",
        "create table evidence_bundle_projection",
        "evidence records are append-only",
        "create table agent_run_projection",
        "create table agent_task_projection",
        "create table reasoning_artifact_projection",
        "reasoning_artifact_projection_tenant_isolation",
        "create table remediation_plan_projection",
        "create table remediation_action_projection",
        "create table remediation_approval_projection",
        "create table remediation_approval_decisions",
        "create table remediation_effect_claims",
        "create table remediation_quota_projection",
        "remediation_approval_decisions_tenant_isolation",
        "create table sandbox_projection",
        "create table sandbox_artifact_projection",
        "create table sandbox_execution_claims",
        "create table sandbox_quota_projection",
        "create table sandbox_cleanup_projection",
        "create table sandbox_attestations",
        "sandbox_attestations_tenant_isolation",
        "create table protocol_peer_registry",
        "create table protocol_trust_decision_history",
        "create table protocol_capability_snapshots",
        "create table protocol_operation_projection",
        "create table protocol_operation_claims",
        "create table protocol_artifact_projection",
        "create table protocol_stream_cursors",
        "create table protocol_quota_projection",
        "create table protocol_audit_projection",
        "protocol_trust_decision_history_tenant_isolation",
        "aegis_schema_migrations",
        "create table tenant_writer_fences",
        "create table tenant_retention_policies",
        "create table ledger_archive_manifests",
        "aegis_assert_writer_fence",
        "events_require_writer_fence",
        "ledger_archive_manifests_tenant_isolation",
    )
    missing = [control for control in required if control not in schema]
    if missing:
        raise SystemExit("migration controls missing: " + ", ".join(missing))
    if re.search(r"^\s*(?:drop\s+table|truncate)\b", schema, re.MULTILINE):
        raise SystemExit("destructive migration statements are prohibited")
    _security_reversals = re.compile(
        r"^\s*(?:"
        r"drop\s+policy"
        r"|alter\s+table\s+\S+\s+disable\s+row\s+level\s+security"
        r"|drop\s+(?:trigger|function)\s+\S+"
        r")\b",
        re.MULTILINE,
    )
    if _security_reversals.search(schema):
        raise SystemExit(
            "security-reversing migration statements are prohibited "
            "(drop policy, disable rls, drop trigger/function)"
        )


if __name__ == "__main__":
    main()
