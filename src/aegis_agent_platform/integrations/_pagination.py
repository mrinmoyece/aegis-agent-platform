"""Opaque per-capability cursor encoding for multi-kind connector queries."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence

from aegis_agent_platform.domain import PaginationCursor
from aegis_agent_platform.evidence import ConnectorError, ConnectorErrorClass


def decode_cursor(
    cursor: PaginationCursor | None,
    *,
    allowed_keys: Sequence[str],
) -> Mapping[str, str] | None:
    if cursor is None:
        return None
    try:
        encoded = cursor.value.encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        value = json.loads(base64.urlsafe_b64decode(encoded))
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError) as error:
        raise _invalid_cursor() from error
    allowed = frozenset(allowed_keys)
    if (
        not isinstance(value, dict)
        or not value
        or any(
            key not in allowed or not isinstance(item, str) or not item
            for key, item in value.items()
        )
    ):
        raise _invalid_cursor()
    return dict(sorted(value.items()))


def encode_cursor(values: Mapping[str, str]) -> PaginationCursor | None:
    if not values:
        return None
    encoded = base64.urlsafe_b64encode(
        json.dumps(
            dict(sorted(values.items())),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).rstrip(b"=")
    return PaginationCursor(encoded.decode("ascii"))


def _invalid_cursor() -> ConnectorError:
    return ConnectorError(
        ConnectorErrorClass.INVALID_QUERY,
        "connector_cursor_invalid",
        retryable=False,
    )


__all__ = ["decode_cursor", "encode_cursor"]
