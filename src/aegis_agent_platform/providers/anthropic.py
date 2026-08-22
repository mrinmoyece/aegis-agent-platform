"""Anthropic Messages API adapter; SDK types remain inside this module."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from time import monotonic
from typing import Any

import httpx
from anthropic import AsyncAnthropic

from aegis_agent_platform.domain import (
    FinishReason,
    ImagePart,
    JsonValue,
    MessageRole,
    ModelErrorClass,
    ModelGatewayError,
    ModelIdentity,
    ModelRequest,
    ModelResponse,
    SafetyOutcome,
    SafetyResult,
    TextPart,
    TokenUsage,
    ToolCallPart,
    ToolCallProposal,
    ToolResultPart,
)
from aegis_agent_platform.providers._translation import (
    await_with_cancellation,
    bounded_text,
    classify_sdk_error,
    json_object,
    message_text,
    serialize_tool_result,
)
from aegis_agent_platform.providers.config import ProviderClientSettings
from aegis_agent_platform.providers.protocol import CancellationToken
from aegis_agent_platform.secrets_boundary import SecretProvider
from aegis_agent_platform.tenancy import TenantContext


class AnthropicAdapter:
    provider_name = "anthropic"

    def __init__(
        self,
        context: TenantContext,
        secrets: SecretProvider,
        settings: ProviderClientSettings,
        *,
        client_factory: Callable[..., Any] = AsyncAnthropic,
        max_response_chars: int = 1_000_000,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if str(context.tenant_id) != str(settings.api_key.tenant_id):
            raise ValueError("provider secret must belong to adapter tenant")
        if max_response_chars < 1:
            raise ValueError("response bound must be positive")
        self._context = context
        self._secrets = secrets
        self._settings = settings
        self._client_factory = client_factory
        self._max_response_chars = max_response_chars
        self._clock = clock
        self._client: Any | None = None
        self._http_client: httpx.AsyncClient | None = None

    async def reload_client(self) -> None:
        self._client = None
        http_client, self._http_client = self._http_client, None
        if http_client is not None:
            await http_client.aclose()

    async def complete(
        self,
        request: ModelRequest,
        model: ModelIdentity,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        if model.provider != self.provider_name:
            raise ValueError("Anthropic adapter received a non-Anthropic model")
        started = self._clock()
        try:
            client = await self._get_client()
            raw = await await_with_cancellation(
                client.messages.create(**self._request_kwargs(request, model)),
                timeout_seconds=request.timeout_seconds,
                cancellation=cancellation,
            )
            return self._response(raw, request, model, started)
        except TimeoutError:
            raise ModelGatewayError(
                ModelErrorClass.TIMEOUT,
                "provider_timeout",
                retryable=True,
                billing_ambiguous=True,
            ) from None
        except asyncio.CancelledError:
            raise ModelGatewayError(
                ModelErrorClass.CANCELLED,
                "provider_call_cancelled",
                retryable=False,
                billing_ambiguous=True,
            ) from None
        except ModelGatewayError:
            raise
        except Exception as error:
            raise classify_sdk_error(error) from None

    async def _get_client(self) -> Any:
        if self._client is None:
            key = self._secrets.resolve(
                self._context,
                self._settings.api_key,
            ).reveal()
            http_client = httpx.AsyncClient(
                proxy=self._settings.proxy_url,
                verify=self._settings.verify_tls,
                timeout=httpx.Timeout(
                    self._settings.read_timeout_seconds,
                    connect=self._settings.connect_timeout_seconds,
                ),
                limits=httpx.Limits(
                    max_connections=self._settings.max_connections,
                    max_keepalive_connections=(
                        self._settings.max_keepalive_connections
                    ),
                ),
                trust_env=False,
            )
            options: dict[str, object] = {
                "api_key": key.decode(),
                "http_client": http_client,
            }
            if self._settings.base_url is not None:
                options["base_url"] = self._settings.base_url
            try:
                self._client = self._client_factory(**options)
            except Exception:
                await http_client.aclose()
                raise
            self._http_client = http_client
        return self._client

    def _request_kwargs(
        self,
        request: ModelRequest,
        model: ModelIdentity,
    ) -> dict[str, object]:
        systems: list[str] = []
        messages: list[dict[str, object]] = []
        for message in request.messages:
            if message.role is MessageRole.SYSTEM:
                systems.append(message_text(message))
                continue
            content: list[dict[str, object]] = []
            for part in message.content:
                if isinstance(part, TextPart):
                    content.append({"type": "text", "text": part.text})
                elif isinstance(part, ImagePart):
                    content.append(
                        {
                            "type": "image",
                            "source": {"type": "url", "url": part.uri},
                        }
                    )
                elif isinstance(part, ToolCallPart):
                    content.append(
                        {
                            "type": "tool_use",
                            "id": part.proposal.call_id,
                            "name": part.proposal.tool_name,
                            "input": json_object(part.proposal.arguments),
                        }
                    )
                elif isinstance(part, ToolResultPart):
                    content.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": part.call_id,
                            "content": serialize_tool_result(part),
                            "is_error": part.is_error,
                        }
                    )
                else:
                    raise ModelGatewayError(
                        ModelErrorClass.INVALID_REQUEST,
                        "unsupported_content_part",
                        retryable=False,
                    )
            role = "assistant" if message.role is MessageRole.ASSISTANT else "user"
            messages.append({"role": role, "content": content})
        result: dict[str, object] = {
            "model": model.model,
            "messages": messages,
            "max_tokens": request.max_output_tokens,
            "temperature": float(request.temperature),
            "extra_headers": {"Idempotency-Key": request.idempotency_key},
        }
        if systems:
            result["system"] = "\n\n".join(systems)
        if request.tools:
            result["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": json_object(tool.input_schema.schema),
                }
                for tool in request.tools
            ]
        if request.response_schema is not None:
            result["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": json_object(request.response_schema.schema),
                }
            }
        return result

    def _response(
        self,
        raw: Any,
        request: ModelRequest,
        model: ModelIdentity,
        started: float,
    ) -> ModelResponse:
        content = getattr(raw, "content", None)
        usage = getattr(raw, "usage", None)
        if not isinstance(content, list) or usage is None:
            raise ModelGatewayError(
                ModelErrorClass.MALFORMED_RESPONSE,
                "malformed_anthropic_response",
                retryable=False,
                billing_ambiguous=True,
            )
        parts: list[TextPart | ToolCallPart] = []
        structured: Mapping[str, JsonValue] | None = None
        for item in content:
            item_type = getattr(item, "type", None)
            if item_type == "text":
                text = bounded_text(
                    getattr(item, "text", None),
                    self._max_response_chars,
                )
                parts.append(TextPart(text))
                if request.response_schema is not None:
                    structured = _json_object(text)
            elif item_type == "tool_use":
                value = getattr(item, "input", None)
                if not isinstance(value, Mapping):
                    raise ModelGatewayError(
                        ModelErrorClass.MALFORMED_RESPONSE,
                        "tool_arguments_not_object",
                        retryable=False,
                        billing_ambiguous=True,
                    )
                parts.append(
                    ToolCallPart(
                        ToolCallProposal(
                            call_id=str(getattr(item, "id", "")),
                            tool_name=str(getattr(item, "name", "")),
                            arguments=value,
                        )
                    )
                )
        raw_stop_reason = getattr(raw, "stop_reason", None)
        stop_reason = raw_stop_reason if isinstance(raw_stop_reason, str) else None
        finish_by_reason = {
            "end_turn": FinishReason.STOP,
            "stop_sequence": FinishReason.STOP,
            "max_tokens": FinishReason.LENGTH,
            "tool_use": FinishReason.TOOL_CALLS,
            "refusal": FinishReason.REFUSAL,
        }
        finish = (
            finish_by_reason.get(stop_reason, FinishReason.UNKNOWN)
            if stop_reason is not None
            else FinishReason.UNKNOWN
        )
        refusal = finish is FinishReason.REFUSAL
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0)
        return ModelResponse(
            request_id=request.request_id,
            model=model,
            content=tuple(parts),
            finish_reason=finish,
            safety=SafetyResult(
                SafetyOutcome.REFUSED if refusal else SafetyOutcome.ALLOWED,
                "provider_refusal" if refusal else None,
            ),
            usage=TokenUsage(
                input_tokens=_usage_int(getattr(usage, "input_tokens", None)),
                output_tokens=_usage_int(getattr(usage, "output_tokens", None)),
                cache_read_tokens=_usage_int(
                    getattr(usage, "cache_read_input_tokens", 0)
                ),
                cache_write_tokens=_usage_int(cache_creation),
            ),
            latency_ms=max(0, int((self._clock() - started) * 1000)),
            provider_request_id=_optional_text(
                getattr(raw, "_request_id", None) or getattr(raw, "id", None)
            ),
            structured_output=structured,
        )


def _json_object(value: str) -> Mapping[str, JsonValue]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "structured_output_not_json",
            retryable=False,
            billing_ambiguous=True,
        ) from error
    if not isinstance(parsed, dict):
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "structured_output_not_object",
            retryable=False,
            billing_ambiguous=True,
        )
    return parsed


def _usage_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "invalid_provider_usage",
            retryable=False,
            billing_ambiguous=True,
        )
    return value


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["AnthropicAdapter"]
