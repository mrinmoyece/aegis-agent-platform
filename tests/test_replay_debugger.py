"""Deterministic read-only replay, corruption, diff, and support-report tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock
from uuid import UUID

import pytest

from aegis_agent_platform.audit import InMemoryAuditStore
from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    TraceContext,
)
from aegis_agent_platform.event_store import AppendResult, EventPage, OutboxMessage
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.observability import ObservabilityOperations, SloSummary
from aegis_agent_platform.observability import replay as replay_module
from aegis_agent_platform.observability.__main__ import (
    _FileEventStore,
    _load_events,
    _state_json,
    main,
)
from aegis_agent_platform.observability.replay import (
    ReplayDebugger,
    ReplayQuery,
    SupportReportRangeError,
    SupportReportTooLargeError,
)
from aegis_agent_platform.tenancy import TenantContext

NOW = datetime(2026, 8, 13, 12, tzinfo=UTC)
TENANT = TenantContext(TenantId("tenant-a"))


def event(
    sequence: int,
    event_type: str,
    *,
    causation_id: UUID | None = None,
    metadata: dict[str, JsonValue] | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        UUID(int=sequence),
        "tenant-a",
        "run-a",
        event_type,
        1,
        NOW + timedelta(seconds=sequence),
        ({"reason_code": "dependency_unavailable"} if "failed" in event_type else {}),
        causation_id=causation_id,
        aggregate_sequence=sequence,
        global_position=sequence,
        recorded_at=NOW + timedelta(seconds=sequence),
        trace_context=TraceContext(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ),
        metadata=metadata or {},
    )


class ReadOnlyStore:
    def __init__(self, events: Sequence[EventEnvelope]) -> None:
        self.events = tuple(events)

    async def append(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> int:
        del context, events, expected_version, outbox
        raise AssertionError("replay must never append")

    async def append_from_inbox(
        self,
        context: TenantContext,
        *,
        source: str,
        message_id: str,
        events: Sequence[EventEnvelope],
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> AppendResult:
        del context, source, message_id, events, expected_version, outbox
        raise AssertionError("replay must never append")

    async def read_stream(
        self,
        context: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
        limit: int = 100,
    ) -> AsyncIterator[EventEnvelope]:
        selected = (
            item
            for item in self.events
            if item.tenant_id == str(context.tenant_id)
            and item.aggregate_id == aggregate_id
            and item.aggregate_sequence > after_version
        )
        for item in tuple(selected)[:limit]:
            yield item

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        selected = tuple(
            item
            for item in self.events
            if item.tenant_id == str(context.tenant_id)
            and (item.global_position or 0) > after_position
        )[:limit]
        return EventPage(
            selected,
            selected[-1].global_position if len(selected) == limit else None,
        )


def debugger(events: Sequence[EventEnvelope]) -> ReplayDebugger:
    return ReplayDebugger(
        ReadOnlyStore(events),
        identifier_hash_key=b"k" * 32,
        hash_key_version="test-v1",
    )


def test_replay_loads_at_sequence_folds_and_diffs_without_side_effects() -> None:
    events = (
        event(1, DomainEventType.RUN_STARTED),
        event(
            2,
            DomainEventType.WORK_FAILED,
            causation_id=UUID(int=1),
        ),
        event(3, DomainEventType.WORK_RETRY_SCHEDULED),
    )
    replay = debugger(events)

    before_events = asyncio.run(
        replay.load(TENANT, ReplayQuery("run-a", at_sequence=1))
    )
    after_events = asyncio.run(replay.load(TENANT, ReplayQuery("run-a")))
    before = replay.fold(before_events, aggregate_id="run-a")
    after = replay.fold(after_events, aggregate_id="run-a")
    difference = replay.diff(before, after)
    chain = replay.causal_chain(after_events)

    assert before.sequence == 1
    assert after.sequence == 3
    assert after.failed_reason_codes == ("dependency_unavailable",)
    assert difference.added_event_counts[DomainEventType.WORK_FAILED] == 1
    assert chain[1].causation_sequence == 1
    assert chain[1].trace_link_present is True


def test_replay_reports_corruption_and_optional_hash_coverage() -> None:
    replay = debugger(())
    corrupt = (
        event(1, DomainEventType.RUN_STARTED),
        event(
            3,
            DomainEventType.RUN_FAILED,
            metadata={"event_hash": "0" * 64},
        ),
    )

    validation = replay.validate(corrupt)

    assert validation.valid is False
    assert validation.sequence_valid is False
    assert validation.hashes_valid is False
    assert "aggregate_sequence_gap" in validation.reason_codes
    assert "partial_hash_coverage" in validation.reason_codes


def test_support_report_is_redacted_bounded_digested_and_signed() -> None:
    events = (
        event(1, DomainEventType.RUN_STARTED),
        event(2, DomainEventType.RUN_COMPLETED, causation_id=UUID(int=1)),
    )
    replay = debugger(events)

    report = replay.support_report(
        TENANT,
        events,
        signer="test-signer",
        signing_key=b"s" * 32,
    )

    assert report.validation.valid
    assert report.signature_algorithm == "hmac-sha256"
    assert report.signature is not None
    assert len(report.content_digest) == 64
    assert "tenant-a" not in report.tenant_reference
    assert "run-a" not in report.aggregate_reference


def test_support_report_rejects_oversized_content_with_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = (event(1, DomainEventType.RUN_STARTED),)
    replay = debugger(events)
    monkeypatch.setattr(replay_module, "MAX_SUPPORT_REPORT_BYTES", 1)

    with pytest.raises(SupportReportTooLargeError, match="byte bound"):
        replay.support_report(TENANT, events)


def test_projection_comparison_marks_projection_as_derived() -> None:
    replay = debugger(())
    state = replay.fold(
        (event(1, DomainEventType.RUN_STARTED),),
        aggregate_id="run-a",
    )

    differences = replay.compare_projection(
        state,
        {"sequence": 0, "lifecycle_status": "completed"},
    )

    assert differences["sequence"] == {
        "ledger_fold": 1,
        "derived_projection": 0,
    }
    assert differences["lifecycle_status"]["ledger_fold"] == "not_started"


def test_replay_query_enforces_range_and_size_bounds() -> None:
    with pytest.raises(ValueError, match="outside the replay bound"):
        ReplayQuery("run-a", max_events=5_001)
    with pytest.raises(ValueError, match="select either"):
        ReplayQuery("run-a", at_sequence=2, at_time=NOW)


def test_replay_cli_executes_diff_and_support_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    export = tmp_path / "events.json"
    export.write_text(
        json.dumps(
            [
                {
                    "event_id": str(UUID(int=1)),
                    "tenant_id": "tenant-a",
                    "aggregate_id": "run-a",
                    "event_type": str(DomainEventType.RUN_STARTED),
                    "schema_version": 1,
                    "occurred_at": (NOW + timedelta(seconds=1)).isoformat(),
                    "payload": {},
                    "aggregate_sequence": 1,
                    "global_position": 1,
                    "recorded_at": (NOW + timedelta(seconds=1)).isoformat(),
                },
                {
                    "event_id": str(UUID(int=2)),
                    "tenant_id": "tenant-a",
                    "aggregate_id": "run-a",
                    "event_type": str(DomainEventType.RUN_COMPLETED),
                    "schema_version": 1,
                    "occurred_at": (NOW + timedelta(seconds=2)).isoformat(),
                    "payload": {},
                    "causation_id": str(UUID(int=1)),
                    "aggregate_sequence": 2,
                    "global_position": 2,
                    "recorded_at": (NOW + timedelta(seconds=2)).isoformat(),
                },
            ]
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--input",
                str(export),
                "--tenant",
                "tenant-a",
                "--aggregate",
                "run-a",
                "--compare-sequence",
                "1",
                "--support-report",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["authoritative_source"] == "event_ledger"
    assert output["validation"]["event_count"] == 2
    assert output["diff"]["from_sequence"] == 1
    assert output["support_report"]["content_digest"]


def test_replay_cli_file_store_is_read_only_and_input_is_bounded(
    tmp_path: Path,
) -> None:
    store = _FileEventStore(())
    with pytest.raises(PermissionError, match="read-only"):
        asyncio.run(store.append(TENANT, (), expected_version=0))
    with pytest.raises(PermissionError, match="read-only"):
        asyncio.run(
            store.append_from_inbox(
                TENANT,
                source="test",
                message_id="message",
                events=(),
                expected_version=0,
            )
        )
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"not":"an array"}', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        main(
            [
                "--input",
                str(invalid),
                "--tenant",
                "tenant-a",
                "--aggregate",
                "run-a",
            ]
        )


def test_observability_operations_enforce_bounds_and_export_ranges() -> None:
    principal = Mock(actor_id="user-1")
    authorization = Mock()
    authorization.decide.return_value = Mock(allowed=True)
    operations = ObservabilityOperations(
        debugger(
            (
                event(1, DomainEventType.RUN_STARTED),
                event(2, DomainEventType.RUN_COMPLETED),
            )
        ),
        InMemoryAuditStore(),
        identifier_hash_key=b"h" * 32,
        hash_key_version="ops-v1",
        authorization=authorization,
        slo_reader=lambda: (SloSummary("api", "30d", "99.9%", "measured", True, "ok"),),
    )

    timeline = asyncio.run(
        operations.timeline(
            principal,
            TENANT,
            "run-a",
            at=NOW,
            after_sequence=0,
            limit=1,
        )
    )
    assert timeline["next_cursor"] == 1
    report = asyncio.run(
        operations.support_report(
            principal,
            TENANT,
            "run-a",
            at=NOW,
            signer="reviewer",
            signing_key=b"s" * 32,
        )
    )
    assert report.signature_algorithm == "hmac-sha256"
    assert operations.slo_summary(principal, TENANT, at=NOW)[0].objective == "api"
    with pytest.raises(ValueError, match="between 1 and 100"):
        asyncio.run(operations.timeline(principal, TENANT, "run-a", at=NOW, limit=101))

    large_operations = ObservabilityOperations(
        debugger(
            tuple(event(index, DomainEventType.RUN_STARTED) for index in range(1, 5002))
        ),
        InMemoryAuditStore(),
        identifier_hash_key=b"h" * 32,
        hash_key_version="ops-v1",
        authorization=authorization,
    )
    with pytest.raises(SupportReportRangeError, match="bounded replay range"):
        asyncio.run(large_operations.support_report(principal, TENANT, "run-a", at=NOW))


def test_replay_cli_helpers_cover_ndjson_state_json_and_bounds(tmp_path: Path) -> None:
    ndjson = tmp_path / "events.ndjson"
    ndjson.write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "event_id": str(UUID(int=1)),
                        "tenant_id": "tenant-a",
                        "aggregate_id": "run-a",
                        "event_type": str(DomainEventType.RUN_STARTED),
                        "schema_version": 1,
                        "occurred_at": (NOW + timedelta(seconds=1)).isoformat(),
                        "payload": {},
                        "aggregate_sequence": 1,
                        "global_position": 1,
                        "recorded_at": (NOW + timedelta(seconds=1)).isoformat(),
                    }
                ),
                json.dumps(
                    {
                        "event_id": str(UUID(int=2)),
                        "tenant_id": "tenant-a",
                        "aggregate_id": "run-a",
                        "event_type": str(DomainEventType.RUN_COMPLETED),
                        "schema_version": 1,
                        "occurred_at": (NOW + timedelta(seconds=2)).isoformat(),
                        "payload": {},
                        "aggregate_sequence": 2,
                        "global_position": 2,
                        "recorded_at": (NOW + timedelta(seconds=2)).isoformat(),
                    }
                ),
            )
        ),
        encoding="utf-8",
    )
    loaded = _load_events(ndjson)
    store = _FileEventStore(loaded)
    streamed = list(asyncio.run(_collect(store.read_stream(TENANT, "run-a", limit=1))))
    page = asyncio.run(store.read_all(TENANT, limit=1))
    state = debugger(loaded).fold(loaded, aggregate_id="run-a")

    assert len(streamed) == 1
    assert page.next_cursor == 1
    assert _state_json(state)["sequence"] == 2
    with pytest.raises(TypeError, match="invalid replay state"):
        _state_json(object())

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text(
        json.dumps(
            [
                {
                    "event_id": str(UUID(int=1)),
                    "tenant_id": "tenant-a",
                    "aggregate_id": "run-a",
                    "event_type": str(DomainEventType.RUN_STARTED),
                    "schema_version": 1,
                    "occurred_at": (NOW + timedelta(seconds=1)).isoformat(),
                    "payload": {},
                    "aggregate_sequence": 1,
                    "global_position": 1,
                    "recorded_at": (NOW + timedelta(seconds=1)).isoformat(),
                },
                "corrupt",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="JSON objects"):
        _load_events(corrupt)


async def _collect(stream: AsyncIterator[EventEnvelope]) -> list[EventEnvelope]:
    return [item async for item in stream]


def test_replay_cli_loader_rejects_missing_and_oversized_ranges(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="bounded event export file"):
        _load_events(tmp_path / "missing.json")
    oversized = tmp_path / "oversized.json"
    oversized.write_text(
        json.dumps(
            [
                {
                    "event_id": str(UUID(int=index)),
                    "tenant_id": "tenant-a",
                    "aggregate_id": "run-a",
                    "event_type": str(DomainEventType.RUN_STARTED),
                    "schema_version": 1,
                    "occurred_at": (NOW + timedelta(seconds=index)).isoformat(),
                    "payload": {},
                    "aggregate_sequence": index,
                    "global_position": index,
                    "recorded_at": (NOW + timedelta(seconds=index)).isoformat(),
                }
                for index in range(1, 5002)
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="replay event bound"):
        _load_events(oversized)
