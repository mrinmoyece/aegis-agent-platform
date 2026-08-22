"""Shared strict HTTP response handling for evidence adapters."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import cast

from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.evidence import (
    ConnectorError,
    ConnectorErrorClass,
    HttpResponse,
)


def json_mapping(response: HttpResponse) -> Mapping[str, JsonValue]:
    classify_status(response)
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "connector_response_invalid_json",
            retryable=False,
        ) from error
    if not isinstance(value, dict):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "connector_response_not_object",
            retryable=False,
        )
    return cast(Mapping[str, JsonValue], value)


def json_sequence(response: HttpResponse) -> tuple[Mapping[str, JsonValue], ...]:
    classify_status(response)
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "connector_response_invalid_json",
            retryable=False,
        ) from error
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "connector_response_not_array",
            retryable=False,
        )
    return tuple(cast(Mapping[str, JsonValue], item) for item in value)


def classify_status(response: HttpResponse) -> None:
    if 200 <= response.status < 300:
        return
    if response.status == 401:
        raise ConnectorError(
            ConnectorErrorClass.AUTHENTICATION,
            "connector_authentication_failed",
            retryable=False,
        )
    if response.status == 403:
        retry_after = _retry_after(response.headers)
        if (
            "retry-after" in response.headers
            or response.headers.get("x-ratelimit-remaining") == "0"
        ):
            reset = response.headers.get("x-ratelimit-reset")
            if reset is not None and "retry-after" not in response.headers:
                try:
                    retry_after = max(0.0, float(reset) - time.time())
                except ValueError:
                    retry_after = None
            raise ConnectorError(
                ConnectorErrorClass.RATE_LIMIT,
                "connector_secondary_rate_limited",
                retryable=True,
                retry_after_seconds=retry_after,
            )
        raise ConnectorError(
            ConnectorErrorClass.AUTHORIZATION,
            "connector_authorization_failed",
            retryable=False,
        )
    if response.status == 429:
        raise ConnectorError(
            ConnectorErrorClass.RATE_LIMIT,
            "connector_rate_limited",
            retryable=True,
            retry_after_seconds=_retry_after(response.headers),
        )
    if response.status in {408, 504}:
        raise ConnectorError(
            ConnectorErrorClass.TIMEOUT,
            "connector_upstream_timeout",
            retryable=True,
        )
    if 400 <= response.status < 500:
        raise ConnectorError(
            ConnectorErrorClass.INVALID_QUERY,
            "connector_request_rejected",
            retryable=False,
        )
    raise ConnectorError(
        ConnectorErrorClass.UNAVAILABLE,
        "connector_upstream_unavailable",
        retryable=True,
    )


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = headers.get("retry-after")
    try:
        return max(0, float(raw)) if raw is not None else None
    except ValueError:
        return None


__all__ = ["classify_status", "json_mapping", "json_sequence"]
