"""Read-only deterministic replay debugger CLI."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

from aegis_agent_platform.domain import EventEnvelope
from aegis_agent_platform.event_store import AppendResult, EventPage, OutboxMessage
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.observability.replay import ReplayDebugger, ReplayQuery
from aegis_agent_platform.tenancy import TenantContext

_LOCAL_DEMO_HASH_KEY = (
    b"aegis-local-replay-debugger-only-not-a-production-secret-key-v1"
)


class _FileEventStore:
    """Read-only fixture adapter; write methods are intentionally unavailable."""

    def __init__(self, events: Sequence[EventEnvelope]) -> None:
        self._events = tuple(events)

    async def append(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> int:
        del context, events, expected_version, outbox
        raise PermissionError("replay debugger is read-only")

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
        raise PermissionError("replay debugger is read-only")

    async def read_stream(
        self,
        context: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
        limit: int = 100,
    ) -> AsyncIterator[EventEnvelope]:
        for event in self._events:
            if (
                event.tenant_id == str(context.tenant_id)
                and event.aggregate_id == aggregate_id
                and event.aggregate_sequence > after_version
            ):
                yield event
                limit -= 1
                if limit == 0:
                    return

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        events = tuple(
            event
            for event in self._events
            if event.tenant_id == str(context.tenant_id)
            and event.global_position is not None
            and event.global_position > after_position
        )[:limit]
        return EventPage(
            events,
            events[-1].global_position if len(events) == limit else None,
        )


def main(argv: list[str] | None = None) -> int:
    """Run a bounded replay, diff, or support-report demonstration."""
    arguments = _parser().parse_args(argv)
    return asyncio.run(_run(arguments))


async def _run(arguments: argparse.Namespace) -> int:
    events = _load_events(Path(str(arguments.input)))
    store = _FileEventStore(events)
    debugger = ReplayDebugger(
        store,
        identifier_hash_key=_LOCAL_DEMO_HASH_KEY,
        hash_key_version="local-demo-v1",
    )
    context = TenantContext(TenantId(str(arguments.tenant)))
    aggregate_id = str(arguments.aggregate)
    selected = await debugger.load(
        context,
        ReplayQuery(
            aggregate_id,
            at_sequence=(
                int(arguments.at_sequence)
                if arguments.at_sequence is not None
                else None
            ),
        ),
    )
    validation = debugger.validate(selected)
    state = debugger.fold(selected, aggregate_id=aggregate_id)
    output: dict[str, Any] = {
        "authoritative_source": "event_ledger",
        "validation": {
            "valid": validation.valid,
            "sequence_valid": validation.sequence_valid,
            "positions_valid": validation.positions_valid,
            "versions_valid": validation.versions_valid,
            "cursors_valid": validation.cursors_valid,
            "hashes_valid": validation.hashes_valid,
            "event_count": validation.event_count,
            "stream_digest": validation.stream_digest,
            "reason_codes": list(validation.reason_codes),
        },
        "state": _state_json(state),
    }
    if arguments.compare_sequence is not None:
        before_events = await debugger.load(
            context,
            ReplayQuery(aggregate_id, at_sequence=int(arguments.compare_sequence)),
        )
        before = debugger.fold(before_events, aggregate_id=aggregate_id)
        difference = debugger.diff(before, state)
        output["diff"] = {
            "from_sequence": difference.from_sequence,
            "to_sequence": difference.to_sequence,
            "added_event_counts": dict(difference.added_event_counts),
            "lifecycle_changed": difference.lifecycle_changed,
            "new_blocked_reasons": list(difference.new_blocked_reasons),
            "new_failed_reasons": list(difference.new_failed_reasons),
        }
    if bool(arguments.support_report):
        report = debugger.support_report(context, selected)
        output["support_report"] = {
            "schema_version": report.schema_version,
            "tenant_reference": report.tenant_reference,
            "aggregate_reference": report.aggregate_reference,
            "content_digest": report.content_digest,
            "signature_algorithm": report.signature_algorithm,
            "signer": report.signer,
            "signature": report.signature,
        }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if validation.valid else 2


def _load_events(path: Path) -> tuple[EventEnvelope, ...]:
    if not path.is_file() or path.stat().st_size > 16 * 1_048_576:
        raise ValueError("input must be a bounded event export file")
    text = path.read_text(encoding="utf-8")
    parsed: object
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(parsed, list):
        raise ValueError("event export must be a JSON array or newline-delimited JSON")
    if len(parsed) > 5_000:
        raise ValueError("event export exceeds the replay event bound")
    return tuple(
        EventEnvelope.from_mapping(item) for item in parsed if isinstance(item, dict)
    )


def _state_json(state: object) -> dict[str, object]:
    from aegis_agent_platform.observability.replay import ReplayState

    if not isinstance(state, ReplayState):
        raise TypeError("invalid replay state")
    return {
        "sequence": state.sequence,
        "last_event_type": state.last_event_type,
        "lifecycle_status": state.lifecycle_status,
        "event_counts": dict(state.event_counts),
        "blocked_reason_codes": list(state.blocked_reason_codes),
        "failed_reason_codes": list(state.failed_reason_codes),
        "facts": [dict(fact) for fact in state.facts],
        "interpretations": list(state.interpretations),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-replay",
        description=(
            "Read-only ledger replay. This command never executes providers, tools, "
            "sandboxes, or effects."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Bounded JSON/NDJSON event export",
    )
    parser.add_argument("--tenant", required=True, help="Trusted tenant scope")
    parser.add_argument("--aggregate", required=True, help="Aggregate identifier")
    parser.add_argument("--at-sequence", type=int)
    parser.add_argument("--compare-sequence", type=int)
    parser.add_argument("--support-report", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
