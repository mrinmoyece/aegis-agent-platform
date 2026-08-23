"""OpenAI Responses API adapter; SDK types remain inside this module."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from time import monotonic
from typing import Any

import httpx
from openai import AsyncOpenAI

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
    serialize_tool_result,
)
from aegis_agent_platform.providers.config import ProviderClientSettings
from aegis_agent_platform.providers.protocol import CancellationToken
from aegis_agent_platform.secrets_boundary import SecretProvider
from aegis_agent_platform.tenancy import TenantContext


class OpenAIAdapter:
    provider_name = "openai"

    def __init__(
        self,
        context: TenantContext,
        secrets: SecretProvider,
        settings: ProviderClientSettings,
        *,
        client_factory: Callable[..., Any] = AsyncOpenAI,
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
        """Close the client so the next request resolves the latest secret version."""
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
            raise ValueError("OpenAI adapter received a non-OpenAI model")
        started = self._clock()
        kwargs = self._request_kwargs(request, model)
        try:
            client = await self._get_client()
            raw = await await_with_cancellation(
                client.responses.create(**kwargs),
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
        inputs: list[dict[str, object]] = []
        for message in request.messages:
            role = (
                "developer"
                if message.role is MessageRole.SYSTEM
                else message.role.value
            )
            content: list[dict[str, object]] = []

            for part in message.content:
                if isinstance(part, TextPart):
                    content.append({"type": "input_text", "text": part.text})
                elif isinstance(part, ImagePart):
                    content.append({"type": "input_image", "image_url": part.uri})
                elif isinstance(part, ToolCallPart):
                    if content:
                        inputs.append({"role": role, "content": list(content)})
                        content.clear()
                    inputs.append(
                        {
                            "type": "function_call",
                            "call_id": part.proposal.call_id,
                            "name": part.proposal.tool_name,
                            "arguments": json.dumps(
                                json_object(part.proposal.arguments),
                                separators=(",", ":"),
                                sort_keys=True,
                            ),
                        }
                    )
                elif isinstance(part, ToolResultPart):
                    if content:
                        inputs.append({"role": role, "content": list(content)})
                        content.clear()
                    inputs.append(
                        {
                            "type": "function_call_output",
                            "call_id": part.call_id,
                            "output": serialize_tool_result(part),
                        }
                    )
                else:
                    raise ModelGatewayError(
                        ModelErrorClass.INVALID_REQUEST,
                        "unsupported_content_part",
                        retryable=False,
                    )
            if content:
                inputs.append({"role": role, "content": list(content)})
        result: dict[str, object] = {
            "model": model.model,
            "input": inputs,
            "max_output_tokens": request.max_output_tokens,
            "temperature": float(request.temperature),
            "extra_headers": {"Idempotency-Key": request.idempotency_key},
        }
        if request.tools:
            result["tools"] = [
                {
                    "type": "function",
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": json_object(tool.input_schema.schema),
                    "strict": tool.input_schema.strict,
                }
                for tool in request.tools
            ]
        if request.response_schema is not None:
            result["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": request.response_schema.name,
                    "schema": json_object(request.response_schema.schema),
                    "strict": request.response_schema.strict,
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
        output = getattr(raw, "output", None)
        usage = getattr(raw, "usage", None)
        if not isinstance(output, list) or usage is None:
            raise ModelGatewayError(
                ModelErrorClass.MALFORMED_RESPONSE,
                "malformed_openai_response",
                retryable=False,
                billing_ambiguous=True,
            )
        parts: list[TextPart | ToolCallPart] = []
        refusal: str | None = None
        structured: Mapping[str, JsonValue] | None = None
        for item in output:
            item_type = getattr(item, "type", None)
            if item_type == "function_call":
                arguments = _json_arguments(getattr(item, "arguments", None))
                parts.append(
                    ToolCallPart(
                        ToolCallProposal(
                            call_id=str(getattr(item, "call_id", "")),
                            tool_name=str(getattr(item, "name", "")),
                            arguments=arguments,
                        )
                    )
                )
            elif item_type == "message":
                for content in getattr(item, "content", ()):
                    content_type = getattr(content, "type", None)
                    if content_type == "output_text":
                        text = bounded_text(
                            getattr(content, "text", None),
                            self._max_response_chars,
                        )
                        parts.append(TextPart(text))
                        if request.response_schema is not None:
                            structured = _json_arguments(text)
                    elif content_type == "refusal":
                        refusal = bounded_text(
                            getattr(content, "refusal", None),
                            self._max_response_chars,
                        )
        input_details = getattr(usage, "input_tokens_details", None)
        output_details = getattr(usage, "output_tokens_details", None)
        total_input_tokens = _nonnegative_int(getattr(usage, "input_tokens", None))
        cache_read_tokens = _optional_nonnegative_int(
            getattr(input_details, "cached_tokens", 0)
        )
        if cache_read_tokens > total_input_tokens:
            raise ModelGatewayError(
                ModelErrorClass.MALFORMED_RESPONSE,
                "cached_tokens_exceed_input_tokens",
                retryable=False,
                billing_ambiguous=True,
            )
        total_output_tokens = _nonnegative_int(getattr(usage, "output_tokens", None))
        reasoning_tokens = _optional_nonnegative_int(
            getattr(output_details, "reasoning_tokens", 0)
        )
        if reasoning_tokens > total_output_tokens:
            raise ModelGatewayError(
                ModelErrorClass.MALFORMED_RESPONSE,
                "reasoning_tokens_exceed_output_tokens",
                retryable=False,
                billing_ambiguous=True,
            )
        token_usage = TokenUsage(
            input_tokens=total_input_tokens - cache_read_tokens,
            output_tokens=total_output_tokens - reasoning_tokens,
            cache_read_tokens=cache_read_tokens,
            reasoning_tokens=reasoning_tokens,
        )
        incomplete_details = getattr(raw, "incomplete_details", None)
        incomplete_reason = getattr(incomplete_details, "reason", None)
        if refusal is not None:
            finish = FinishReason.REFUSAL
        elif incomplete_reason == "max_output_tokens":
            finish = FinishReason.LENGTH
        elif incomplete_reason == "content_filter":
            finish = FinishReason.CONTENT_FILTER
        elif any(isinstance(part, ToolCallPart) for part in parts):
            finish = FinishReason.TOOL_CALLS
        else:
            finish = FinishReason.STOP
        return ModelResponse(
            request_id=request.request_id,
            model=model,
            content=tuple(parts),
            finish_reason=finish,
            safety=SafetyResult(
                SafetyOutcome.REFUSED
                if refusal is not None
                else SafetyOutcome.FILTERED
                if finish is FinishReason.CONTENT_FILTER
                else SafetyOutcome.ALLOWED,
                "provider_refusal"
                if refusal is not None
                else "provider_content_filter"
                if finish is FinishReason.CONTENT_FILTER
                else None,
            ),
            usage=token_usage,
            latency_ms=max(0, int((self._clock() - started) * 1000)),
            provider_request_id=_optional_text(
                getattr(raw, "_request_id", None) or getattr(raw, "id", None)
            ),
            structured_output=structured,
        )


def _json_arguments(value: object) -> Mapping[str, JsonValue]:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "tool_arguments_not_json",
            retryable=False,
            billing_ambiguous=True,
        )
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "tool_arguments_not_json",
            retryable=False,
            billing_ambiguous=True,
        ) from error
    if not isinstance(parsed, dict):
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "tool_arguments_not_object",
            retryable=False,
            billing_ambiguous=True,
        )
    return parsed


def _nonnegative_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ModelGatewayError(
            ModelErrorClass.MALFORMED_RESPONSE,
            "invalid_provider_usage",
            retryable=False,
            billing_ambiguous=True,
        )
    return value


def _optional_nonnegative_int(value: object) -> int:
    return 0 if value is None else _nonnegative_int(value)


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["OpenAIAdapter"]
