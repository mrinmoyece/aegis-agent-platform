"""Central bounded telemetry sanitization and rotating identifier hashing."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from hmac import new as hmac_new
from types import MappingProxyType
from urllib.parse import urlsplit, urlunsplit

from aegis_agent_platform.observability.semantic import STANDARD_ATTRIBUTES

REDACTED = "[REDACTED]"
MAX_ATTRIBUTE_COUNT = 32
MAX_ATTRIBUTE_KEY_BYTES = 64
MAX_ATTRIBUTE_VALUE_BYTES = 256
MAX_EVENT_BYTES = 8_192
HASH_HEX_LENGTH = 24

_SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|credential|evidence|jwt|key|memory|password|prompt|"
    r"query|secret|token|user|tenant|target)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    re.compile(
        r"\b(?:api[_-]?key|client[_-]?secret|password|token)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
)


@dataclass(frozen=True, slots=True)
class SanitizationStats:
    """Self-observation counters without rejected content."""

    accepted: int
    redacted: int
    dropped: int
    truncated: int


class AttributeSanitizer:
    """Allowlist, redact, and bound telemetry without raising into runtime work."""

    def __init__(
        self,
        *,
        allowed: frozenset[str] = STANDARD_ATTRIBUTES,
        max_attributes: int = MAX_ATTRIBUTE_COUNT,
    ) -> None:
        if not 1 <= max_attributes <= MAX_ATTRIBUTE_COUNT:
            raise ValueError("max_attributes is outside the safe bound")
        self._allowed = allowed
        self._max_attributes = max_attributes
        self._accepted = 0
        self._redacted = 0
        self._dropped = 0
        self._truncated = 0

    def sanitize(
        self,
        attributes: Mapping[str, object],
    ) -> Mapping[str, str | int | float | bool]:
        """Return an immutable, scalar-only, bounded attribute mapping."""
        output: dict[str, str | int | float | bool] = {}
        for key in sorted(attributes):
            if len(output) >= self._max_attributes:
                self._dropped += 1
                continue
            if (
                key not in self._allowed
                or len(key.encode("utf-8")) > MAX_ATTRIBUTE_KEY_BYTES
                or _SENSITIVE_KEY.search(key)
            ):
                self._dropped += 1
                continue
            value = attributes[key]
            sanitized = self._scalar(value)
            if sanitized is None:
                self._dropped += 1
                continue
            output[key] = sanitized
            self._accepted += 1
        return MappingProxyType(output)

    def stats(self) -> SanitizationStats:
        """Return bounded aggregate sanitizer counters."""
        return SanitizationStats(
            self._accepted,
            self._redacted,
            self._dropped,
            self._truncated,
        )

    def _scalar(self, value: object) -> str | int | float | bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return value
        if not isinstance(value, str):
            return None
        redacted = redact_text(value)
        if redacted != value:
            self._redacted += 1
        encoded = redacted.encode("utf-8")
        if len(encoded) <= MAX_ATTRIBUTE_VALUE_BYTES:
            return redacted
        self._truncated += 1
        return encoded[:MAX_ATTRIBUTE_VALUE_BYTES].decode("utf-8", errors="ignore")


def redact_text(value: str) -> str:
    """Remove reviewed secret, credential, prompt, and common PII patterns."""
    redacted = value
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def sanitize_url(value: str) -> str:
    """Retain scheme, host, and path while removing credentials, query, and fragment."""
    parsed = urlsplit(value)
    hostname = parsed.hostname or ""
    if parsed.port is not None:
        hostname = f"{hostname}:{parsed.port}"
    return urlunsplit((parsed.scheme, hostname, parsed.path, "", ""))


def sanitize_headers(headers: Mapping[str, str]) -> Mapping[str, str]:
    """Drop identifying headers and redact any accidentally sensitive values."""
    safe: dict[str, str] = {}
    for key, value in headers.items():
        normalized = key.lower()
        if _SENSITIVE_KEY.search(normalized) or normalized not in {
            "content-type",
            "user-agent-family",
            "traceparent",
            "tracestate",
            "baggage",
        }:
            continue
        safe[normalized] = redact_text(value)[:MAX_ATTRIBUTE_VALUE_BYTES]
    return MappingProxyType(safe)


def hash_identifier(identifier: str, *, key: bytes, key_version: str) -> str:
    """Create a rotating, deployment-scoped pseudonym with a 96-bit boundary.

    Truncation gives a 2^-96 random collision boundary. Operators rotate ``key`` and
    ``key_version`` together; hashes are intentionally not stable across rotations.
    """
    if len(key) < 32:
        raise ValueError("identifier hash key must contain at least 32 bytes")
    if not key_version or len(key_version) > 32:
        raise ValueError("identifier hash key version is required and bounded")
    digest = hmac_new(key, identifier.encode("utf-8"), sha256).hexdigest()
    return f"{key_version}:{digest[:HASH_HEX_LENGTH]}"


def bounded_event_size(value: Mapping[str, object]) -> bool:
    """Reject an event whose canonical JSON encoding exceeds the reviewed bound."""
    encoded = json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return len(encoded) <= MAX_EVENT_BYTES


__all__ = [
    "HASH_HEX_LENGTH",
    "MAX_ATTRIBUTE_COUNT",
    "MAX_ATTRIBUTE_KEY_BYTES",
    "MAX_ATTRIBUTE_VALUE_BYTES",
    "MAX_EVENT_BYTES",
    "REDACTED",
    "AttributeSanitizer",
    "SanitizationStats",
    "bounded_event_size",
    "hash_identifier",
    "redact_text",
    "sanitize_headers",
    "sanitize_url",
]
