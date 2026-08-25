"""Layer 16 integrated qualification, replay, chaos, and evidence contracts."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    EventEnvelope,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.qualification import (
    ArchivedEvent,
    QualificationArchive,
    ReadOnlyArchiveEventStore,
    projection_digest,
    rebuild_projection,
    run_chaos_smoke,
    run_load_smoke,
    run_qualification_demo,
)
from aegis_agent_platform.tenancy import TenantContext

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_canonical_qualification_persists_and_replays_complete_ledger(
    tmp_path: Path,
) -> None:
    result = await run_qualification_demo(tmp_path)

    ledger = result["ledger"]
    assertions = result["assertions"]
    journey = result["journey"]
    assert isinstance(ledger, dict)
    assert isinstance(assertions, dict)
    assert isinstance(journey, dict)
    assert ledger["event_count"] >= 200
    assert ledger["source_count"] == 9
    assert ledger["archive_chain_valid"] is True
    assert ledger["projection_rebuild_identical"] is True
    assert ledger["replay_valid"] is True
    assert all(assertions.values())
    assert journey["authenticated_intake"]["status"] == 200
    assert journey["tenant_policy"]["decision"] == "require_approval"
    assert journey["evidence"]["query_count"] == 4
    assert journey["specialist_dag"]["status"] == "succeeded"
    assert journey["remediation"]["status"] == "verified"
    assert journey["sandbox"]["status"] == "cleaned"
    assert result["production_certified"] is False
    assert result["claims_exactly_once"] is False

    archive = QualificationArchive.read(
        tmp_path / "checkout-qualification-ledger.jsonl"
    )
    assert len(archive.records) == ledger["event_count"]
    assert {
        "security-audit",
        "evidence",
        "model-gateway",
        "specialist-dag",
        "memory",
        "remediation",
        "sandbox",
        "mcp",
        "a2a",
    } == {record.source for record in archive.records}


@pytest.mark.asyncio
async def test_qualification_output_is_redacted_and_contains_no_key_material(
    tmp_path: Path,
) -> None:
    await run_qualification_demo(tmp_path)

    rendered = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(tmp_path.iterdir())
    )
    assert "BEGIN PRIVATE KEY" not in rendered
    assert "Bearer " not in rendered
    assert "qualification-local-only" not in rendered
    assert "[REDACTED]" in rendered


def test_archive_rejects_tampering_and_rebuilds_deterministically(
    tmp_path: Path,
) -> None:
    records = (
        ArchivedEvent("test-ledger", _event(1, "work.requested.v1")),
        ArchivedEvent("test-ledger", _event(2, "work.succeeded.v1")),
    )
    path = tmp_path / "ledger.jsonl"
    QualificationArchive.write(path, records)
    loaded = QualificationArchive.read(path)

    assert projection_digest(rebuild_projection(records)) == projection_digest(
        rebuild_projection(loaded.records)
    )
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "work.succeeded.v1",
            "work.failed.v1",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="digest"):
        QualificationArchive.read(path)


@pytest.mark.asyncio
async def test_archive_event_store_is_tenant_scoped_and_read_only() -> None:
    records = (
        ArchivedEvent("test-ledger", _event(1, "work.requested.v1")),
        ArchivedEvent(
            "test-ledger",
            _event(2, "work.succeeded.v1", tenant_id="tenant-beta"),
        ),
    )
    store = ReadOnlyArchiveEventStore(records, source="test-ledger")
    selected = [
        event
        async for event in store.read_stream(
            TenantContext(TenantId("tenant-alpha")),
            "qualification-run",
        )
    ]

    assert [event.event_type for event in selected] == ["work.requested.v1"]
    with pytest.raises(PermissionError, match="read-only"):
        await store.append(
            TenantContext(TenantId("tenant-alpha")),
            (_event(2, "work.failed.v1"),),
            expected_version=1,
        )


@pytest.mark.asyncio
async def test_deterministic_chaos_smoke_covers_recovery_and_denial() -> None:
    result = await run_chaos_smoke()

    assert result["scenario_count"] == 17
    assert result["passed"] == 17
    assert result["failed"] == 0
    assert result["ledger_convergence_required"] is True
    assert result["production_chaos_claimed"] is False


@pytest.mark.asyncio
async def test_bounded_load_smoke_reports_every_required_profile() -> None:
    result = await run_load_smoke(samples=3, p95_budget_ms=60_000)

    profiles = result["profiles"]
    assert isinstance(profiles, tuple)
    assert result["profile_count"] == 12
    assert result["blocking_profiles"] == ()
    assert result["production_capacity_claimed"] is False
    assert all(profile["p95_ms"] >= 0 for profile in profiles)
    assert all(profile["error_rate"] == 0 for profile in profiles)
    assert all(profile["passed"] is True for profile in profiles)


def test_qualification_manifests_and_docs_fail_closed() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_qualification.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_readiness_has_no_aggregate_score_and_names_live_blockers() -> None:
    readiness = json.loads(
        (ROOT / "qualification" / "release-readiness.json").read_text(encoding="utf-8")
    )

    assert readiness["production_ready"] is False
    assert "score" not in readiness
    statuses = {item["id"]: item["status"] for item in readiness["categories"]}
    assert statuses["ha-dr"] == "Live Evidence Required"
    assert statuses["multi-region"] == "Deferred/Not Claimed"
    assert statuses["governance"] == "Live Evidence Required"
    assert len(readiness["hard_go_live_gates"]) >= 6


def test_residual_risks_are_owned_evidenced_and_time_bounded() -> None:
    document = json.loads(
        (ROOT / "qualification" / "residual-risks.json").read_text(encoding="utf-8")
    )

    assert document["certification_claimed"] is False
    assert len(document["risks"]) >= 10
    for risk in document["risks"]:
        assert risk["owner"]
        assert risk["evidence"]
        assert risk["mitigation"]
        assert risk["trigger"]
        assert risk["target_date"] > "2026-08-14"


def test_layer16_narrows_cve_disposition_and_pins_fixed_runtime() -> None:
    policy = json.loads(
        (ROOT / "security" / "vulnerability-waivers.yaml").read_text(encoding="utf-8")
    )
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    dispositions = {
        waiver["report"]: waiver
        for waiver in policy["waivers"]
        if waiver["vulnerability_id"] == "CVE-2026-15308"
    }
    assert set(dispositions) == {
        "aegis-agent-platform/linux-amd64",
        "aegis-agent-platform/linux-arm64",
    }
    assert all(
        waiver["disposition"] == "false_positive"
        and waiver["scanner"] == "grype"
        and waiver["scanner_version"] == "0.117.0"
        and waiver["expires_on"] == "2026-08-28"
        for waiver in dispositions.values()
    )
    assert dockerfile.count("python:3.14.7-slim-bookworm@sha256:") == 2


def _event(
    sequence: int,
    event_type: str,
    *,
    tenant_id: str = "tenant-alpha",
) -> EventEnvelope:
    return EventEnvelope(
        UUID(int=sequence),
        tenant_id,
        "qualification-run",
        event_type,
        1,
        NOW,
        {"sequence": sequence},
        aggregate_sequence=sequence,
        recorded_at=NOW,
        actor=ActorReference("qualification-test", ActorKind.SYSTEM),
    )
