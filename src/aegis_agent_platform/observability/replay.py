"""Ledger-grounded, deterministic, read-only replay debugging."""

from __future__ import annotations

import hmac
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from types import MappingProxyType

from aegis_agent_platform.domain import EventEnvelope, JsonValue
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import EventStore, ReplayCorruptionError
from aegis_agent_platform.observability.safety import hash_identifier
from aegis_agent_platform.tenancy import TenantContext

MAX_REPLAY_EVENTS = 5_000
MAX_REPLAY_PAGE = 500
MAX_SUPPORT_REPORT_BYTES = 1_048_576
REPLAY_SCHEMA_VERSION = 1


class SupportReportTooLargeError(ValueError):
    """A bounded support report cannot contain the selected event range."""


class SupportReportRangeError(ValueError):
    """The requested support export exceeds the reviewed event range."""


@dataclass(frozen=True, slots=True)
class ReplayQuery:
    """Tenant-bound event range selected by a trusted caller."""

    aggregate_id: str
    after_sequence: int = 0
    at_sequence: int | None = None
    at_time: datetime | None = None
    max_events: int = MAX_REPLAY_EVENTS

    def __post_init__(self) -> None:
        if not self.aggregate_id or len(self.aggregate_id) > 256:
            raise ValueError("aggregate_id is required and bounded")
        if self.after_sequence < 0:
            raise ValueError("after_sequence cannot be negative")
        if self.at_sequence is not None and self.at_sequence <= self.after_sequence:
            raise ValueError("at_sequence must follow after_sequence")
        if self.at_time is not None and self.at_time.tzinfo is None:
            raise ValueError("at_time must be timezone-aware")
        if self.at_sequence is not None and self.at_time is not None:
            raise ValueError("select either sequence or time, not both")
        if not 1 <= self.max_events <= MAX_REPLAY_EVENTS:
            raise ValueError("max_events is outside the replay bound")


@dataclass(frozen=True, slots=True)
class ReplayValidation:
    """Integrity findings that distinguish verified facts from unavailable checks."""

    valid: bool
    sequence_valid: bool
    positions_valid: bool
    versions_valid: bool
    cursors_valid: bool
    hashes_valid: bool | None
    event_count: int
    stream_digest: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReplayState:
    """Generic deterministic fold over ledger facts."""

    aggregate_id: str
    sequence: int
    last_event_type: str | None
    lifecycle_status: str
    event_counts: Mapping[str, int]
    blocked_reason_codes: tuple[str, ...]
    failed_reason_codes: tuple[str, ...]
    facts: tuple[Mapping[str, JsonValue], ...]
    interpretations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReplayDiff:
    """Deterministic difference between two replay points."""

    from_sequence: int
    to_sequence: int
    added_event_counts: Mapping[str, int]
    lifecycle_changed: bool
    new_blocked_reasons: tuple[str, ...]
    new_failed_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CausalEvent:
    """One redacted fact in a causation chain."""

    sequence: int
    event_type: str
    occurred_at: str
    causation_sequence: int | None
    trace_link_present: bool


@dataclass(frozen=True, slots=True)
class SupportReport:
    """Bounded redacted replay evidence with digest and optional HMAC."""

    schema_version: int
    tenant_reference: str
    aggregate_reference: str
    validation: ReplayValidation
    state: ReplayState
    causal_chain: tuple[CausalEvent, ...]
    content_digest: str
    signature_algorithm: str | None
    signer: str | None
    signature: str | None


class ReplayDebugger:
    """Read ledger truth without executing models, tools, sandboxes, or effects."""

    def __init__(
        self,
        event_store: EventStore,
        *,
        identifier_hash_key: bytes,
        hash_key_version: str,
    ) -> None:
        if len(identifier_hash_key) < 32:
            raise ValueError("replay identifier hash key must contain 32 bytes")
        self._events = event_store
        self._hash_key = identifier_hash_key
        self._hash_key_version = hash_key_version

    async def load(
        self,
        context: TenantContext,
        query: ReplayQuery,
    ) -> tuple[EventEnvelope, ...]:
        """Load one bounded tenant aggregate in committed sequence order."""
        loaded: list[EventEnvelope] = []
        cursor = query.after_sequence
        while len(loaded) < query.max_events:
            limit = min(MAX_REPLAY_PAGE, query.max_events - len(loaded))
            page = [
                event
                async for event in self._events.read_stream(
                    context,
                    query.aggregate_id,
                    after_version=cursor,
                    limit=limit,
                )
            ]
            if not page:
                break
            for event in page:
                if event.tenant_id != str(context.tenant_id):
                    raise ReplayCorruptionError(
                        "event tenant differs from trusted context"
                    )
                if event.aggregate_id != query.aggregate_id:
                    raise ReplayCorruptionError(
                        "event aggregate differs from replay query"
                    )
                if query.at_sequence is not None and (
                    event.aggregate_sequence > query.at_sequence
                ):
                    return tuple(loaded)
                if query.at_time is not None and event.occurred_at > query.at_time:
                    return tuple(loaded)
                loaded.append(event)
            next_cursor = page[-1].aggregate_sequence
            if next_cursor <= cursor:
                raise ReplayCorruptionError("event-store replay cursor did not advance")
            cursor = next_cursor
            if len(page) < limit:
                break
        return tuple(loaded)

    def validate(
        self,
        events: Sequence[EventEnvelope],
        *,
        starts_after: int = 0,
    ) -> ReplayValidation:
        """Validate sequence, positions, versions, cursor order, and optional hashes."""
        reasons: list[str] = []
        expected = starts_after + 1
        sequence_valid = True
        positions_valid = True
        versions_valid = True
        cursors_valid = True
        previous_position = 0
        previous_hash: str | None = None
        hash_count = 0
        hashes_valid = True
        canonical: list[dict[str, object]] = []
        for event in events:
            canonical_event = _canonical_event(event)
            canonical.append(canonical_event)
            if event.aggregate_sequence != expected:
                sequence_valid = False
                reasons.append("aggregate_sequence_gap")
            expected = event.aggregate_sequence + 1
            if event.schema_version < 1:
                versions_valid = False
                reasons.append("invalid_schema_version")
            if event.global_position is not None:
                if event.global_position <= previous_position:
                    positions_valid = False
                    reasons.append("global_position_not_monotonic")
                previous_position = event.global_position
            cursor = event.metadata.get("source_cursor")
            if cursor is not None and not isinstance(cursor, str | int):
                cursors_valid = False
                reasons.append("invalid_source_cursor")
            recorded_hash = event.metadata.get("event_hash")
            if recorded_hash is not None:
                hash_count += 1
                calculated = _event_digest(event)
                if recorded_hash != calculated:
                    hashes_valid = False
                    reasons.append("event_hash_mismatch")
                recorded_previous = event.metadata.get("previous_event_hash")
                if previous_hash is not None and recorded_previous != previous_hash:
                    hashes_valid = False
                    reasons.append("event_hash_chain_mismatch")
                previous_hash = str(recorded_hash)
        if 0 < hash_count < len(events):
            hashes_valid = False
            reasons.append("partial_hash_coverage")
        hash_result: bool | None = hashes_valid if hash_count else None
        digest = sha256(
            json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        unique_reasons = tuple(dict.fromkeys(reasons))
        return ReplayValidation(
            valid=(
                sequence_valid
                and positions_valid
                and versions_valid
                and cursors_valid
                and hashes_valid
            ),
            sequence_valid=sequence_valid,
            positions_valid=positions_valid,
            versions_valid=versions_valid,
            cursors_valid=cursors_valid,
            hashes_valid=hash_result,
            event_count=len(events),
            stream_digest=digest,
            reason_codes=unique_reasons,
        )

    def fold(
        self,
        events: Sequence[EventEnvelope],
        *,
        aggregate_id: str,
    ) -> ReplayState:
        """Fold only stable envelope and reason-code facts into a generic state."""
        counts = Counter(event.event_type for event in events)
        blocked: list[str] = []
        failed: list[str] = []
        facts: list[Mapping[str, JsonValue]] = []
        lifecycle = "not_started"
        for event in events:
            suffix = event.event_type.rsplit(".", maxsplit=2)[-2]
            if suffix in {
                "completed",
                "succeeded",
                "failed",
                "cancelled",
                "timed_out",
                "quarantined",
            }:
                lifecycle = suffix
            reason = event.payload.get("reason_code") or event.payload.get("error_code")
            if isinstance(reason, str) and _is_reason_code(reason):
                if "failed" in event.event_type or "timed_out" in event.event_type:
                    failed.append(reason)
                if any(
                    marker in event.event_type
                    for marker in ("denied", "budget_exhausted", "quarantined")
                ):
                    blocked.append(reason)
            facts.append(
                MappingProxyType(
                    {
                        "sequence": event.aggregate_sequence,
                        "event_type": event.event_type,
                        "schema_version": event.schema_version,
                        "occurred_at": event.occurred_at.isoformat(),
                    }
                )
            )
        interpretations = _interpretations(lifecycle, blocked, failed)
        return ReplayState(
            aggregate_id=aggregate_id,
            sequence=events[-1].aggregate_sequence if events else 0,
            last_event_type=events[-1].event_type if events else None,
            lifecycle_status=lifecycle,
            event_counts=MappingProxyType(dict(sorted(counts.items()))),
            blocked_reason_codes=tuple(dict.fromkeys(blocked)),
            failed_reason_codes=tuple(dict.fromkeys(failed)),
            facts=tuple(facts),
            interpretations=interpretations,
        )

    def diff(self, before: ReplayState, after: ReplayState) -> ReplayDiff:
        """Compare two deterministic fold states without consulting projections."""
        if before.aggregate_id != after.aggregate_id:
            raise ValueError("replay states must belong to the same aggregate")
        additions = {
            event_type: count - before.event_counts.get(event_type, 0)
            for event_type, count in after.event_counts.items()
            if count > before.event_counts.get(event_type, 0)
        }
        return ReplayDiff(
            before.sequence,
            after.sequence,
            MappingProxyType(additions),
            before.lifecycle_status != after.lifecycle_status,
            tuple(
                reason
                for reason in after.blocked_reason_codes
                if reason not in before.blocked_reason_codes
            ),
            tuple(
                reason
                for reason in after.failed_reason_codes
                if reason not in before.failed_reason_codes
            ),
        )

    def causal_chain(
        self,
        events: Sequence[EventEnvelope],
    ) -> tuple[CausalEvent, ...]:
        """Explain event causation using committed identifiers, then discard them."""
        sequence_by_id = {event.event_id: event.aggregate_sequence for event in events}
        return tuple(
            CausalEvent(
                event.aggregate_sequence,
                event.event_type,
                event.occurred_at.isoformat(),
                (
                    sequence_by_id.get(event.causation_id)
                    if event.causation_id is not None
                    else None
                ),
                event.trace_context is not None,
            )
            for event in events
        )

    def compare_projection(
        self,
        state: ReplayState,
        projection: Mapping[str, JsonValue],
    ) -> Mapping[str, Mapping[str, JsonValue]]:
        """Report projection differences; the replay fold remains authoritative."""
        replay_values: dict[str, JsonValue] = {
            "sequence": state.sequence,
            "lifecycle_status": state.lifecycle_status,
            "last_event_type": state.last_event_type,
        }
        differences: dict[str, Mapping[str, JsonValue]] = {}
        for key, expected in replay_values.items():
            actual = projection.get(key)
            if actual != expected:
                differences[key] = MappingProxyType(
                    {"ledger_fold": expected, "derived_projection": actual}
                )
        return MappingProxyType(differences)

    def support_report(
        self,
        context: TenantContext,
        events: Sequence[EventEnvelope],
        *,
        signer: str | None = None,
        signing_key: bytes | None = None,
    ) -> SupportReport:
        """Build a redacted report; optional signing requires an explicit strong key."""
        if (signer is None) != (signing_key is None):
            raise ValueError("signer and signing_key must be supplied together")
        if signing_key is not None and len(signing_key) < 32:
            raise ValueError("support report signing key must contain 32 bytes")
        aggregate_id = events[0].aggregate_id if events else "empty"
        validation = self.validate(events)
        state = self.fold(events, aggregate_id=aggregate_id)
        causal_chain = self.causal_chain(events)
        content = {
            "schema_version": REPLAY_SCHEMA_VERSION,
            "tenant_reference": hash_identifier(
                str(context.tenant_id),
                key=self._hash_key,
                key_version=self._hash_key_version,
            ),
            "aggregate_reference": hash_identifier(
                aggregate_id,
                key=self._hash_key,
                key_version=self._hash_key_version,
            ),
            "validation": _validation_mapping(validation),
            "state": _state_mapping(state),
            "causal_chain": [
                {
                    "sequence": item.sequence,
                    "event_type": item.event_type,
                    "occurred_at": item.occurred_at,
                    "causation_sequence": item.causation_sequence,
                    "trace_link_present": item.trace_link_present,
                }
                for item in causal_chain
            ],
        }
        encoded = json.dumps(content, separators=(",", ":"), sort_keys=True).encode()
        if len(encoded) > MAX_SUPPORT_REPORT_BYTES:
            raise SupportReportTooLargeError("support report exceeds the byte bound")
        digest = sha256(encoded).hexdigest()
        signature = (
            hmac.new(signing_key, digest.encode(), sha256).hexdigest()
            if signing_key is not None
            else None
        )
        return SupportReport(
            REPLAY_SCHEMA_VERSION,
            str(content["tenant_reference"]),
            str(content["aggregate_reference"]),
            validation,
            state,
            causal_chain,
            digest,
            "hmac-sha256" if signature is not None else None,
            signer,
            signature,
        )


def _canonical_event(event: EventEnvelope) -> dict[str, object]:
    return {
        "event_id": str(event.event_id),
        "tenant_id": event.tenant_id,
        "aggregate_id": event.aggregate_id,
        "aggregate_sequence": event.aggregate_sequence,
        "global_position": event.global_position,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "occurred_at": event.occurred_at.isoformat(),
        "recorded_at": (
            event.recorded_at.isoformat() if event.recorded_at is not None else None
        ),
        "payload": thaw_json(event.payload),
        "correlation_id": (
            str(event.correlation_id) if event.correlation_id is not None else None
        ),
        "causation_id": (
            str(event.causation_id) if event.causation_id is not None else None
        ),
    }


def _event_digest(event: EventEnvelope) -> str:
    return sha256(
        json.dumps(
            _canonical_event(event),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _is_reason_code(value: str) -> bool:
    return 0 < len(value) <= 64 and value.replace("_", "").replace("-", "").isalnum()


def _interpretations(
    lifecycle: str,
    blocked: Sequence[str],
    failed: Sequence[str],
) -> tuple[str, ...]:
    interpretations: list[str] = []
    if blocked:
        interpretations.append("work appears blocked by a committed policy outcome")
    if failed:
        interpretations.append("work has a committed failure outcome")
    if lifecycle not in {
        "completed",
        "succeeded",
        "failed",
        "cancelled",
        "timed_out",
        "quarantined",
    }:
        interpretations.append("no terminal event is present in the selected range")
    return tuple(interpretations)


def _validation_mapping(value: ReplayValidation) -> dict[str, object]:
    return {
        "valid": value.valid,
        "sequence_valid": value.sequence_valid,
        "positions_valid": value.positions_valid,
        "versions_valid": value.versions_valid,
        "cursors_valid": value.cursors_valid,
        "hashes_valid": value.hashes_valid,
        "event_count": value.event_count,
        "stream_digest": value.stream_digest,
        "reason_codes": list(value.reason_codes),
    }


def _state_mapping(value: ReplayState) -> dict[str, object]:
    return {
        "sequence": value.sequence,
        "last_event_type": value.last_event_type,
        "lifecycle_status": value.lifecycle_status,
        "event_counts": dict(value.event_counts),
        "blocked_reason_codes": list(value.blocked_reason_codes),
        "failed_reason_codes": list(value.failed_reason_codes),
        "facts": [dict(item) for item in value.facts],
        "interpretations": list(value.interpretations),
    }


__all__ = [
    "MAX_REPLAY_EVENTS",
    "MAX_SUPPORT_REPORT_BYTES",
    "REPLAY_SCHEMA_VERSION",
    "CausalEvent",
    "ReplayDebugger",
    "ReplayDiff",
    "ReplayQuery",
    "ReplayState",
    "ReplayValidation",
    "SupportReport",
    "SupportReportRangeError",
    "SupportReportTooLargeError",
]
