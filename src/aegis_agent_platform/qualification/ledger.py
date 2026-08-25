"""Tamper-evident local export and replay for qualification event streams."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from aegis_agent_platform.domain import EventEnvelope, JsonValue
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import (
    AppendResult,
    EventPage,
    OutboxMessage,
)
from aegis_agent_platform.tenancy import TenantContext

ARCHIVE_SCHEMA_VERSION = 1
_SOURCE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


@dataclass(frozen=True, slots=True)
class ArchivedEvent:
    """One original envelope plus its producing bounded subsystem."""

    source: str
    event: EventEnvelope

    def __post_init__(self) -> None:
        if _SOURCE.fullmatch(self.source) is None:
            raise ValueError("archive source must be a bounded kebab-case identifier")


@dataclass(frozen=True, slots=True)
class ArchiveReadResult:
    """Verified archive records and final chain digest."""

    records: tuple[ArchivedEvent, ...]
    chain_digest: str


class QualificationArchive:
    """Write an atomic JSONL event export and verify every hash-chain link."""

    @staticmethod
    def write(path: Path, records: Sequence[ArchivedEvent]) -> str:
        if not records:
            raise ValueError("qualification archive requires at least one event")
        path.parent.mkdir(parents=True, exist_ok=True)
        previous_digest = "0" * 64
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                for position, record in enumerate(records, start=1):
                    body = {
                        "archive_schema_version": ARCHIVE_SCHEMA_VERSION,
                        "archive_position": position,
                        "source": record.source,
                        "previous_record_digest": previous_digest,
                        "event": _event_mapping(record.event),
                    }
                    record_digest = _digest(body)
                    handle.write(
                        json.dumps(
                            {**body, "record_digest": record_digest},
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    previous_digest = record_digest
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
            temporary = None
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        return previous_digest

    @staticmethod
    def read(path: Path) -> ArchiveReadResult:
        if not path.is_file():
            raise FileNotFoundError(path)
        previous_digest = "0" * 64
        records: list[ArchivedEvent] = []
        for expected_position, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            value = json.loads(line)
            if not isinstance(value, Mapping):
                raise ValueError("archive record must be an object")
            if value.get("archive_schema_version") != ARCHIVE_SCHEMA_VERSION:
                raise ValueError("unsupported qualification archive schema")
            if value.get("archive_position") != expected_position:
                raise ValueError("qualification archive position is not contiguous")
            if value.get("previous_record_digest") != previous_digest:
                raise ValueError("qualification archive hash chain is broken")
            record_digest = value.get("record_digest")
            if not isinstance(record_digest, str):
                raise ValueError("qualification archive record digest is missing")
            body = {key: item for key, item in value.items() if key != "record_digest"}
            if not _constant_time_equal(record_digest, _digest(body)):
                raise ValueError("qualification archive record digest is invalid")
            source = value.get("source")
            event = value.get("event")
            if not isinstance(source, str) or not isinstance(event, Mapping):
                raise ValueError("qualification archive source or event is invalid")
            records.append(
                ArchivedEvent(
                    source,
                    EventEnvelope.from_mapping(cast(Mapping[str, object], event)),
                )
            )
            previous_digest = record_digest
        if not records:
            raise ValueError("qualification archive is empty")
        return ArchiveReadResult(tuple(records), previous_digest)


def rebuild_projection(records: Sequence[ArchivedEvent]) -> Mapping[str, JsonValue]:
    """Build a disposable release-evidence summary only from exported events."""
    source_counts = Counter(record.source for record in records)
    tenant_counts = Counter(record.event.tenant_id for record in records)
    event_counts = Counter(record.event.event_type for record in records)
    stream_versions: dict[str, int] = {}
    terminal_events: dict[str, str] = {}
    for record in records:
        stream = f"{record.source}:{record.event.tenant_id}:{record.event.aggregate_id}"
        stream_versions[stream] = max(
            stream_versions.get(stream, 0),
            record.event.aggregate_sequence,
        )
        if _is_terminal(record.event.event_type):
            terminal_events[stream] = record.event.event_type
    return {
        "archive_schema_version": ARCHIVE_SCHEMA_VERSION,
        "event_count": len(records),
        "sources": dict(sorted(source_counts.items())),
        "tenants": dict(sorted(tenant_counts.items())),
        "event_types": dict(sorted(event_counts.items())),
        "stream_versions": dict(sorted(stream_versions.items())),
        "terminal_events": dict(sorted(terminal_events.items())),
    }


def projection_digest(projection: Mapping[str, JsonValue]) -> str:
    """Digest one deterministic projection without making it authoritative."""
    return sha256(
        json.dumps(
            thaw_json(projection),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


class ReadOnlyArchiveEventStore:
    """Bounded EventStore reader used by the ledger-grounded replay debugger."""

    def __init__(self, records: Sequence[ArchivedEvent], *, source: str) -> None:
        self._events = tuple(
            record.event for record in records if record.source == source
        )

    async def append(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
        outbox: Sequence[OutboxMessage] = (),
    ) -> int:
        del context, events, expected_version, outbox
        raise PermissionError("qualification archive is read-only")

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
        raise PermissionError("qualification archive is read-only")

    async def read_stream(
        self,
        context: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
        limit: int = 100,
    ) -> AsyncIterator[EventEnvelope]:
        if not 1 <= limit <= 500:
            raise ValueError("archive replay limit is invalid")
        selected = tuple(
            event
            for event in self._events
            if event.tenant_id == str(context.tenant_id)
            and event.aggregate_id == aggregate_id
            and event.aggregate_sequence > after_version
        )
        for event in selected[:limit]:
            yield event

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        if after_position < 0 or not 1 <= limit <= 500:
            raise ValueError("archive page bounds are invalid")
        # `after_position` is a global commit position (EventStore contract),
        # not a tenant-filtered list offset.  Filter by global_position so the
        # cursor returned to callers is interoperable with real EventStore
        # implementations.
        selected = tuple(
            event
            for event in self._events
            if event.tenant_id == str(context.tenant_id)
            and event.global_position is not None
            and event.global_position > after_position
        )
        page = selected[:limit]
        next_cursor = page[-1].global_position if len(page) == limit else None
        return EventPage(page, next_cursor)


def _event_mapping(event: EventEnvelope) -> Mapping[str, object]:
    return {
        "event_id": str(event.event_id),
        "tenant_id": event.tenant_id,
        "aggregate_id": event.aggregate_id,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "occurred_at": event.occurred_at.isoformat(),
        "payload": thaw_json(event.payload),
        "correlation_id": (
            str(event.correlation_id) if event.correlation_id is not None else None
        ),
        "causation_id": (
            str(event.causation_id) if event.causation_id is not None else None
        ),
        "aggregate_sequence": event.aggregate_sequence,
        "global_position": event.global_position,
        "recorded_at": (
            event.recorded_at.isoformat() if event.recorded_at is not None else None
        ),
        "actor": (
            {
                "actor_id": event.actor.actor_id,
                "kind": event.actor.kind.value,
            }
            if event.actor is not None
            else None
        ),
        "identity_reference": event.identity_reference,
        "policy_reference": event.policy_reference,
        "audit_reference": (
            str(event.audit_reference) if event.audit_reference is not None else None
        ),
        "idempotency_key": event.idempotency_key,
        "trace_context": (
            {
                "traceparent": event.trace_context.traceparent,
                "tracestate": event.trace_context.tracestate,
            }
            if event.trace_context is not None
            else None
        ),
        "metadata": thaw_json(event.metadata),
    }


def _digest(value: Mapping[str, object]) -> str:
    return sha256(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _is_terminal(event_type: str) -> bool:
    return any(
        marker in event_type
        for marker in (
            ".completed.",
            ".succeeded.",
            ".failed.",
            ".cancelled.",
            ".quarantined.",
            ".finalized.",
        )
    )


__all__ = [
    "ARCHIVE_SCHEMA_VERSION",
    "ArchiveReadResult",
    "ArchivedEvent",
    "QualificationArchive",
    "ReadOnlyArchiveEventStore",
    "projection_digest",
    "rebuild_projection",
]
