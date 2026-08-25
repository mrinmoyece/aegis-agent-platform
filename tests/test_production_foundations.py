"""Deterministic Layer 15 production-foundation contracts."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import psycopg
import pytest
import yaml
from scripts import bootstrap_local_compose
from scripts.build_spdx_index import _load_sbom
from scripts.check_license_policy import is_prohibited_license
from scripts.check_vulnerability_policy import evaluate_report, load_policy
from scripts.migrate import _validate_database_transport, _validate_history

from aegis_agent_platform.config import RDS_GLOBAL_BUNDLE_PATH
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.event_store.fencing import (
    ReloadingTenantWriterFenceResolver,
    TenantWriterFenceResolver,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.operations import (
    DeploymentPrerequisites,
    PostgresSchemaVersionProbe,
    RestoreEvidence,
    SchemaCompatibilityWindow,
    WriterFence,
)
from aegis_agent_platform.tenancy import TenantContext

ROOT = Path(__file__).resolve().parents[1]


class LocalBootstrapConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __enter__(self) -> LocalBootstrapConnection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> LocalBootstrapConnection:
        return self

    def execute(self, statement: str) -> None:
        self.statements.append(statement)


PRODUCTION_MIGRATION = ROOT / "migrations" / "0011_production_operations.sql"


class SchemaCursor:
    def __init__(self, row: tuple[int, int, int] | None) -> None:
        self._row = row

    async def fetchone(self) -> tuple[int, int, int] | None:
        return self._row


class SchemaConnection:
    def __init__(self, row: tuple[int, int, int] | None) -> None:
        self._row = row

    async def execute(self, query: str) -> SchemaCursor:
        assert "aegis_schema_migrations" in query
        return SchemaCursor(self._row)


def test_schema_compatibility_window_fails_closed() -> None:
    window = SchemaCompatibilityWindow(10, 11)

    assert window.accepts(10)
    assert window.accepts(11)
    assert not window.accepts(9)
    assert not window.accepts(12)
    with pytest.raises(ValueError, match="invalid"):
        SchemaCompatibilityWindow(12, 11)


def test_migration_history_rejects_gaps_future_versions_and_drift() -> None:
    migrations = (
        (1, Path("0001_first.sql"), "a" * 64),
        (2, Path("0002_second.sql"), "b" * 64),
    )

    _validate_history({1: ("0001_first.sql", "a" * 64)}, migrations)
    with pytest.raises(SystemExit, match="contiguous"):
        _validate_history({2: ("0002_second.sql", "b" * 64)}, migrations)
    with pytest.raises(SystemExit, match="newer"):
        _validate_history(
            {
                1: ("0001_first.sql", "a" * 64),
                2: ("0002_second.sql", "b" * 64),
                3: ("0003_future.sql", "c" * 64),
            },
            migrations,
        )
    with pytest.raises(SystemExit, match="name drift"):
        _validate_history({1: ("0001_changed.sql", "a" * 64)}, migrations)
    with pytest.raises(SystemExit, match="checksum drift"):
        _validate_history({1: ("0001_first.sql", "c" * 64)}, migrations)


def test_migration_transport_requires_pinned_rds_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_ENVIRONMENT", "production")
    with pytest.raises(SystemExit, match="sslrootcert"):
        _validate_database_transport("postgresql://database/aegis?sslmode=verify-full")

    _validate_database_transport(
        "postgresql://database/aegis?sslmode=verify-full"
        f"&sslrootcert={RDS_GLOBAL_BUNDLE_PATH}"
    )


def test_stale_or_non_home_region_writer_is_fenced() -> None:
    fence = WriterFence("eu-west-1", 8)

    assert fence.permits(region="eu-west-1", generation=8)
    assert not fence.permits(region="eu-west-1", generation=7)
    assert not fence.permits(region="us-east-1", generation=8)


def test_writer_credentials_resolve_by_trusted_tenant_context(tmp_path: Path) -> None:
    credentials = tmp_path / "writer-fences.json"
    credentials.write_text(
        json.dumps(
            {
                "tenant-a": {"home_region": "eu-west-1", "generation": 8},
                "tenant-b": {"home_region": "us-east-1", "generation": 3},
            }
        ),
        encoding="utf-8",
    )
    resolver = TenantWriterFenceResolver.from_json_file(credentials)

    assert resolver.resolve(TenantContext(TenantId("tenant-a"))).generation == 8
    assert resolver.resolve(TenantContext(TenantId("tenant-b"))).generation == 3
    with pytest.raises(FencingError):
        resolver.resolve(TenantContext(TenantId("tenant-c")))


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"tenant-a": []},
        {"tenant-a": {"home_region": "eu-west-1", "generation": "stale"}},
    ],
)
def test_writer_credentials_reject_malformed_documents(
    tmp_path: Path,
    document: object,
) -> None:
    credentials = tmp_path / "writer-fences.json"
    credentials.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="writer fence"):
        TenantWriterFenceResolver.from_json_file(credentials)


@pytest.mark.parametrize(
    ("home_region", "generation"),
    [("", 1), ("eu-west-1", 0)],
)
def test_writer_fence_requires_bounded_authority(
    home_region: str,
    generation: int,
) -> None:
    with pytest.raises(ValueError, match=r"required|positive"):
        WriterFence(home_region, generation)


def test_writer_credentials_reload_after_atomic_secret_rotation(
    tmp_path: Path,
) -> None:
    credentials = tmp_path / "writer-fences.json"
    credentials.write_text(
        '{"tenant-a":{"home_region":"eu-west-1","generation":8}}',
        encoding="utf-8",
    )
    resolver = ReloadingTenantWriterFenceResolver(credentials)
    context = TenantContext(TenantId("tenant-a"))
    assert resolver.resolve(context).generation == 8

    replacement = tmp_path / "writer-fences.next"
    replacement.write_text(
        '{"tenant-a":{"home_region":"eu-west-1","generation":9}}',
        encoding="utf-8",
    )
    replacement.replace(credentials)

    assert resolver.resolve(context).generation == 9


def test_local_compose_bootstrap_is_explicit_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = LocalBootstrapConnection()
    monkeypatch.setenv("AEGIS_ENVIRONMENT", "development")
    monkeypatch.setenv(
        "AEGIS_MIGRATION_DATABASE_URL",
        "postgresql://local-only",
    )
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda _: connection,
    )

    bootstrap_local_compose.main()

    assert len(connection.statements) == 2
    assert "local-demo" in connection.statements[0]
    assert "local-development" in connection.statements[1]


@pytest.mark.asyncio
async def test_schema_probe_rejects_missing_or_gapped_history() -> None:
    assert await PostgresSchemaVersionProbe(SchemaConnection((11, 1, 11)))() == 11
    assert await PostgresSchemaVersionProbe(SchemaConnection((10, 1, 11)))() is None
    assert await PostgresSchemaVersionProbe(SchemaConnection(None))() is None


def test_optional_high_risk_surfaces_require_explicit_prerequisites() -> None:
    core = DeploymentPrerequisites(True, True, True)
    protocol = DeploymentPrerequisites(True, True, True, protocol_trust_ready=True)
    sandbox = DeploymentPrerequisites(True, True, True, sandbox_isolation_ready=True)

    assert core.core_ready
    assert not core.protocol_enabled
    assert not core.sandbox_enabled
    assert protocol.protocol_enabled
    assert sandbox.sandbox_enabled


def test_restore_evidence_requires_exact_ledger_and_rebuild() -> None:
    digest = "a" * 64
    evidence = RestoreEvidence(2, 2, 4, 4, digest, digest, True, True)

    assert evidence.valid
    assert not RestoreEvidence(2, 1, 4, 4, digest, digest, True, True).valid


def test_production_migration_adds_only_governed_operational_state() -> None:
    schema = PRODUCTION_MIGRATION.read_text(encoding="utf-8").lower()

    for table in (
        "aegis_schema_migrations",
        "tenant_writer_fences",
        "tenant_retention_policies",
        "ledger_archive_manifests",
    ):
        assert table in schema
    for table in (
        "tenant_writer_fences",
        "tenant_retention_policies",
        "ledger_archive_manifests",
    ):
        assert f"alter table {table} force row level security" in schema
        assert f"{table}_tenant_isolation" in schema
    assert "aegis_assert_writer_fence" in schema
    assert "events_require_writer_fence" in schema
    assert "enforcement_enabled boolean not null default false" in schema
    assert "if not active_fence.enforcement_enabled" in schema
    assert "ledger_archive_manifests_no_mutation" in schema
    assert "drop table" not in schema
    assert "truncate table" not in schema


def test_all_kustomize_documents_are_parseable() -> None:
    for path in sorted((ROOT / "deploy" / "kubernetes").rglob("*.yaml")):
        assert tuple(yaml.safe_load_all(path.read_text(encoding="utf-8")))


def test_spdx_index_requires_versioned_platform_documents(tmp_path: Path) -> None:
    sbom = tmp_path / "platform.spdx.json"
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "documentNamespace": "https://example.invalid/spdx/platform",
            }
        ),
        encoding="utf-8",
    )
    namespace, checksum = _load_sbom(sbom)

    assert namespace.endswith("/platform")
    assert len(checksum) == 64
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.2",
                "documentNamespace": "https://example.invalid/spdx/legacy",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"SPDX 2\.3"):
        _load_sbom(sbom)


def test_restore_drill_executes_durable_outbox_redrive() -> None:
    restore = (ROOT / "scripts" / "restore_drill.sh").read_text(encoding="utf-8")
    redrive = (ROOT / "scripts" / "restore_redrive.py").read_text(encoding="utf-8")

    assert "redis-cli FLUSHALL" in restore
    assert "scripts/restore_redrive.py" in restore
    assert '"restored_outbox_messages_redriven"' in restore
    assert "OutboxPublisher(" in redrive
    assert "RedisStreamQueue(" in redrive


def test_production_static_gate_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_production.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_license_policy_uses_declared_identity_not_bundled_text_references() -> None:
    assert is_prohibited_license(
        expression="AGPL-3.0-only",
        license_value=None,
        classifiers=(),
    )
    assert is_prohibited_license(
        expression=None,
        license_value=None,
        classifiers=("License :: GNU Affero General Public License v3",),
    )
    assert is_prohibited_license(
        expression=None,
        license_value="GNU Affero General Public License version 3",
        classifiers=(),
    )
    assert is_prohibited_license(
        expression=None,
        license_value="AGPL-3.0-only",
        classifiers=(),
    )
    assert is_prohibited_license(
        expression=None,
        license_value="SSPL-1.0",
        classifiers=(),
    )
    assert not is_prohibited_license(
        expression=None,
        license_value=(
            "BSD-3-Clause\n" + ("x" * 600) + "GNU Affero General Public License"
        ),
        classifiers=("License :: OSI Approved :: BSD License",),
    )


def test_vulnerability_policy_reports_unfixed_and_scopes_waivers(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        """
        {
          "schema_version": 1,
          "policy": {
            "fail_severities": ["HIGH", "CRITICAL"],
            "unfixed_findings": "report",
            "require_fixed_version_when_available": true,
            "maximum_waiver_days": 30
          },
          "waivers": [{
            "vulnerability_id": "CVE-FIXABLE",
            "report": "application/linux-amd64",
            "package": "package-a",
            "package_version": "1.0",
            "issued_on": "2026-08-01",
            "expires_on": "2026-08-20",
            "approved_change_reference": "change-ref://waiver-1",
            "owner": "security",
            "reason": "bounded vendor rollout",
            "compensating_control": "network isolation"
          }]
        }
        """,
        encoding="utf-8",
    )
    report_path = tmp_path / "grype.json"
    report_path.write_text(
        """
        {
          "matches": [
            {
              "vulnerability": {
                "id": "CVE-FIXABLE",
                "severity": "High",
                "fix": {"versions": ["2.0"]}
              },
              "artifact": {"name": "package-a", "version": "1.0"}
            },
            {
              "vulnerability": {
                "id": "CVE-UNFIXED",
                "severity": "Critical",
                "fix": {"versions": []}
              },
              "artifact": {"name": "package-b", "version": "1.0"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    policy = load_policy(policy_path, today=date(2026, 8, 10))
    reported, unfixed, blocking = evaluate_report(
        label="application/linux-amd64",
        path=report_path,
        policy=policy,
    )

    assert (reported, unfixed, blocking) == (2, 1, ())


def test_false_positive_disposition_requires_scanner_and_advisory(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        """
        {
          "schema_version": 1,
          "policy": {
            "fail_severities": ["HIGH", "CRITICAL"],
            "unfixed_findings": "report",
            "require_fixed_version_when_available": true,
            "maximum_waiver_days": 30
          },
          "waivers": [{
            "vulnerability_id": "CVE-FALSE-POSITIVE",
            "report": "application/linux-amd64",
            "package": "runtime",
            "package_version": "1.2.3",
            "issued_on": "2026-08-14",
            "expires_on": "2026-08-28",
            "approved_change_reference": "change-ref://false-positive",
            "owner": "security",
            "reason": "scanner branch range is stale",
            "compensating_control": "independent advisory verification",
            "disposition": "false_positive"
          }]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="false-positive"):
        load_policy(policy_path, today=date(2026, 8, 14))
