"""Shared neutral serialization and bounded adapter response helpers."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Mapping, Sequence
from contextlib import suppress

from aegis_agent_platform.domain import (
    ImagePart,
    JsonValue,
    ModelErrorClass,
    ModelGatewayError,
    ModelMessage,
    TextPart,
    ToolCallPart,
    ToolResultPart,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.providers.protocol import CancellationToken


def message_text(message: ModelMessage) -> str:
    return "\n".join(
        part.text for part in message.content if isinstance(part, TextPart)
    )


def json_object(value: Mapping[str, JsonValue]) -> dict[str, object]:
    return {key: thaw_json(item) for key, item in value.items()}


def serialize_tool_result(part: ToolResultPart) -> str:
    return json.dumps(thaw_json(part.content), separators=(",", ":"), sort_keys=True)


def assert_supported_part(part: object) -> None:
    if not isinstance((part), (TextPart, ImagePart, ToolCallPart, ToolResultPart)):
        raise ModelGatewayError(
            ModelErrorClass.INVALID_REQUEST,
            "unsupported_content_part",
            retryable=False,
        )


def bounded_text(value: object, max_response_chars: int) -> str:
    if not isinstance(value, str):
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "provider_text_is_not_string",
            retryable=False,
            billing_ambiguous=True,
        )
    if len(value) > max_response_chars:
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "provider_response_too_large",
            retryable=False,
            billing_ambiguous=True,
        )
    return value


async def await_with_cancellation[T](
    operation: Awaitable[T],
    *,
    timeout_seconds: float,
    cancellation: CancellationToken | None,
) -> T:
    operation_task = asyncio.ensure_future(operation)
    cancellation_task: asyncio.Task[bool] | None = None
    try:
        async with asyncio.timeout(timeout_seconds):
            if cancellation is None:
                return await operation_task
            if cancellation.is_set():
                operation_task.cancel()
                raise asyncio.CancelledError
            cancellation_task = asyncio.create_task(cancellation.wait())
            done, _ = await asyncio.wait(
                (operation_task, cancellation_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancellation_task in done:
                operation_task.cancel()
                with suppress(asyncio.CancelledError):
                    await operation_task
                raise asyncio.CancelledError
            cancellation_task.cancel()
            return await operation_task
    finally:
        if cancellation_task is not None and not cancellation_task.done():
            cancellation_task.cancel()
        if not operation_task.done():
            operation_task.cancel()
            await asyncio.gather(operation_task, return_exceptions=True)


def classify_sdk_error(error: Exception) -> ModelGatewayError:
    name = type(error).__name__.lower()
    status = getattr(error, "status_code", None)
    if status == 401 or "authentication" in name:
        return ModelGatewayError(
            ModelErrorClass.AUTHENTICATION,
            "provider_authentication_failed",
            retryable=False,
        )
    if status == 403 or "permission" in name:
        return ModelGatewayError(
            ModelErrorClass.AUTHORIZATION,
            "provider_authorization_failed",
            retryable=False,
        )
    if status == 429 or "ratelimit" in name or "rate_limit" in name:
        return ModelGatewayError(
            ModelErrorClass.RATE_LIMIT,
            "provider_rate_limited",
            retryable=True,
            retry_after_seconds=_retry_after(error),
        )
    if status is not None and 400 <= int(status) < 500:
        return ModelGatewayError(
            ModelErrorClass.INVALID_REQUEST,
            "provider_rejected_request",
            retryable=False,
        )
    if "timeout" in name:
        return ModelGatewayError(
            ModelErrorClass.TIMEOUT,
            "provider_timeout",
            retryable=True,
            billing_ambiguous=True,
        )
    if "connection" in name or (status is not None and int(status) >= 500):
        return ModelGatewayError(
            ModelErrorClass.PROVIDER_UNAVAILABLE,
            "provider_unavailable",
            retryable=True,
            billing_ambiguous=status is not None,
        )
    return ModelGatewayError(
        ModelErrorClass.PROVIDER_BUG,
        "provider_sdk_failure",
        retryable=False,
        billing_ambiguous=True,
    )


def _retry_after(error: Exception) -> float | None:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if not isinstance(headers, Mapping):
        return None
    raw = headers.get("retry-after")
    try:
        return float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def all_parts(messages: Sequence[ModelMessage]) -> tuple[object, ...]:
    return tuple(part for message in messages for part in message.content)


__all__ = [
    "all_parts",
    "assert_supported_part",
    "await_with_cancellation",
    "bounded_text",
    "classify_sdk_error",
    "json_object",
    "message_text",
    "serialize_tool_result",
]
