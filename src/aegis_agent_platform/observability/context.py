"""Provider-neutral W3C context validation and deterministic propagation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType

from aegis_agent_platform.domain import JsonValue, TraceContext

TRACE_CONTEXT_SCHEMA_VERSION = 1
MAX_TRACESTATE_BYTES = 512
MAX_BAGGAGE_BYTES = 512
MAX_BAGGAGE_MEMBERS = 8
_TRACEPARENT = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<span_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_BAGGAGE_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_BAGGAGE_VALUE = re.compile(r"^[A-Za-z0-9_.:/-]{1,64}$")

BAGGAGE_ALLOWLIST = frozenset(
    {
        "aegis.component",
        "aegis.environment",
        "aegis.risk_class",
        "aegis.role",
        "aegis.service",
    }
)


class TraceContextError(ValueError):
    """Untrusted propagation headers failed strict validation."""


class TraceLinkKind(StrEnum):
    """Causal relationship for async and at-least-once execution."""

    RETRY = "retry"
    REDELIVERY = "redelivery"
    FAN_OUT = "fan_out"
    FAN_IN = "fan_in"
    REPLAY_CONTINUATION = "replay_continuation"


@dataclass(frozen=True, slots=True)
class PropagationContext:
    """Validated provider-neutral propagation state."""

    trace_id: str
    parent_span_id: str
    sampled: bool
    traceparent: str
    tracestate: str | None = None
    baggage: Mapping[str, str] = MappingProxyType({})
    schema_version: int = TRACE_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TRACE_CONTEXT_SCHEMA_VERSION:
            raise TraceContextError("unsupported trace context schema")
        object.__setattr__(self, "baggage", MappingProxyType(dict(self.baggage)))


@dataclass(frozen=True, slots=True)
class TraceLink:
    """Validated link used for retry, redelivery, fan-out, and fan-in."""

    trace_id: str
    span_id: str
    kind: TraceLinkKind
    sampled: bool

    def __post_init__(self) -> None:
        _validate_hex_id(self.trace_id, 32, "trace_id")
        _validate_hex_id(self.span_id, 16, "span_id")


def extract_context(headers: Mapping[str, str]) -> PropagationContext | None:
    """Reject duplicate-normalized, malformed, oversized, or untrusted context."""
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in normalized:
            raise TraceContextError("duplicate propagation header")
        normalized[lowered] = value.strip()
    traceparent = normalized.get("traceparent")
    if traceparent is None:
        if "tracestate" in normalized or "baggage" in normalized:
            raise TraceContextError("traceparent is required with propagation metadata")
        return None
    parsed = _parse_traceparent(traceparent)
    tracestate = _parse_tracestate(normalized.get("tracestate"))
    baggage = _parse_baggage(normalized.get("baggage"))
    return PropagationContext(
        parsed["trace_id"],
        parsed["span_id"],
        bool(int(parsed["flags"], 16) & 1),
        traceparent,
        tracestate,
        baggage,
    )


def inject_context(context: PropagationContext) -> Mapping[str, JsonValue]:
    """Create safe queue/outbox headers without identifiers or arbitrary baggage."""
    headers: dict[str, JsonValue] = {
        "traceparent": context.traceparent,
        "aegis.trace_schema": TRACE_CONTEXT_SCHEMA_VERSION,
    }
    if context.tracestate is not None:
        headers["tracestate"] = context.tracestate
    if context.baggage:
        headers["baggage"] = ",".join(
            f"{key}={value}" for key, value in sorted(context.baggage.items())
        )
    return MappingProxyType(headers)


def durable_trace_context(context: PropagationContext | None) -> TraceContext | None:
    """Return only W3C state suitable for durable event intent metadata."""
    if context is None:
        return None
    return TraceContext(context.traceparent, context.tracestate)


def deterministic_sample(
    trace_id: str,
    *,
    rate: float,
    deployment_seed: str,
    force: bool = False,
) -> bool:
    """Make the same sampling decision after retries, crashes, and replay."""
    _validate_hex_id(trace_id, 32, "trace_id")
    if not 0 <= rate <= 1:
        raise ValueError("sampling rate must be between zero and one")
    if not deployment_seed or len(deployment_seed) > 128:
        raise ValueError("deployment sampling seed is required and bounded")
    if force:
        return True
    digest = sha256(f"{deployment_seed}:{trace_id}".encode()).digest()
    value = int.from_bytes(digest[:8], "big") / 2**64
    return value < rate


def linked_contexts(
    contexts: Sequence[PropagationContext],
    kind: TraceLinkKind,
) -> tuple[TraceLink, ...]:
    """Build deterministic, de-duplicated causal links for async work."""
    unique = {
        (context.trace_id, context.parent_span_id): TraceLink(
            context.trace_id,
            context.parent_span_id,
            kind,
            context.sampled,
        )
        for context in contexts
    }
    return tuple(unique[key] for key in sorted(unique))


def _parse_traceparent(value: str) -> dict[str, str]:
    matched = _TRACEPARENT.fullmatch(value)
    if matched is None:
        raise TraceContextError("invalid traceparent")
    parsed = matched.groupdict()
    if parsed["version"] == "ff":
        raise TraceContextError("reserved traceparent version")
    if parsed["version"] == "00" and len(value) != 55:
        raise TraceContextError("version 00 traceparent must have four fields")
    _validate_hex_id(parsed["trace_id"], 32, "trace_id")
    _validate_hex_id(parsed["span_id"], 16, "span_id")
    if int(parsed["flags"], 16) & 0xFE:
        raise TraceContextError("unsupported trace flags")
    return parsed


def _parse_tracestate(value: str | None) -> str | None:
    if value is None:
        return None
    if not value or len(value.encode("ascii", errors="ignore")) != len(value):
        raise TraceContextError("tracestate must be non-empty ASCII")
    if len(value.encode()) > MAX_TRACESTATE_BYTES or "\n" in value or "\r" in value:
        raise TraceContextError("tracestate is invalid or oversized")
    members = value.split(",")
    if len(members) > 32 or any("=" not in member for member in members):
        raise TraceContextError("tracestate member is invalid")
    return value


def _parse_baggage(value: str | None) -> Mapping[str, str]:
    if value is None:
        return MappingProxyType({})
    if len(value.encode()) > MAX_BAGGAGE_BYTES:
        raise TraceContextError("baggage is oversized")
    members = value.split(",") if value else []
    if len(members) > MAX_BAGGAGE_MEMBERS:
        raise TraceContextError("too many baggage members")
    baggage: dict[str, str] = {}
    for member in members:
        key, separator, raw_value = member.strip().partition("=")
        if (
            not separator
            or key not in BAGGAGE_ALLOWLIST
            or not _BAGGAGE_KEY.fullmatch(key)
            or not _BAGGAGE_VALUE.fullmatch(raw_value)
            or key in baggage
        ):
            raise TraceContextError("baggage contains an untrusted member")
        baggage[key] = raw_value
    return MappingProxyType(baggage)


def _validate_hex_id(value: str, length: int, name: str) -> None:
    if (
        len(value) != length
        or value == "0" * length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TraceContextError(f"invalid {name}")


__all__ = [
    "BAGGAGE_ALLOWLIST",
    "MAX_BAGGAGE_BYTES",
    "MAX_BAGGAGE_MEMBERS",
    "MAX_TRACESTATE_BYTES",
    "TRACE_CONTEXT_SCHEMA_VERSION",
    "PropagationContext",
    "TraceContextError",
    "TraceLink",
    "TraceLinkKind",
    "deterministic_sample",
    "durable_trace_context",
    "extract_context",
    "inject_context",
    "linked_contexts",
]
