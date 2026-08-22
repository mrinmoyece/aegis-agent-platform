"""Mocked official-SDK transport integration tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import httpx
import pytest

from aegis_agent_platform.domain import (
    FinishReason,
    ImagePart,
    JsonSchema,
    MessageRole,
    ModelErrorClass,
    ModelGatewayError,
    ModelIdentity,
    ModelMessage,
    ModelRequest,
    SafetyOutcome,
    TextPart,
    ToolCallPart,
    ToolCallProposal,
    ToolDefinition,
    ToolResultPart,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.providers._translation import (
    all_parts,
    assert_supported_part,
    await_with_cancellation,
    bounded_text,
    classify_sdk_error,
    json_object,
    message_text,
    serialize_tool_result,
)
from aegis_agent_platform.providers.anthropic import AnthropicAdapter
from aegis_agent_platform.providers.config import ProviderClientSettings
from aegis_agent_platform.providers.openai import OpenAIAdapter
from aegis_agent_platform.secrets_boundary import (
    InMemorySecretProvider,
    SecretReference,
)
from aegis_agent_platform.tenancy import TenantContext

TENANT = TenantId("tenant-adapter")
SECRET = SecretReference(TENANT, "memory", "provider-key", "1")


def model_request(
    provider: str,
    *,
    timeout: float = 1,
    structured: bool = False,
    messages: tuple[ModelMessage, ...] | None = None,
) -> ModelRequest:
    schema = (
        JsonSchema(
            "answer",
            {
                "type": "object",
                "properties": {"answer": {"type": "string"}},
                "required": ["answer"],
            },
        )
        if structured
        else None
    )
    return ModelRequest(
        request_id=uuid4(),
        tenant_id=str(TENANT),
        run_id=uuid4(),
        messages=messages
        or (
            ModelMessage(MessageRole.SYSTEM, (TextPart("Be concise"),)),
            ModelMessage(MessageRole.USER, (TextPart("Hello"),)),
        ),
        max_output_tokens=50,
        prompt_token_estimate=10,
        requested_model=ModelIdentity(provider, "model-1"),
        tools=(
            (ToolDefinition("answer", "Answer", schema),) if schema is not None else ()
        ),
        response_schema=schema,
        timeout_seconds=timeout,
        idempotency_key="adapter-key",
    )


class AsyncCreate:
    def __init__(
        self,
        result: object | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.kwargs: dict[str, object] | None = None

    async def create(self, **kwargs: object) -> object | None:
        self.kwargs = kwargs
        if self.error is not None:
            raise self.error
        return self.result


class Client:
    def __init__(self, create: AsyncCreate, *, openai: bool) -> None:
        if openai:
            self.responses = create
        else:
            self.messages = create


def client_factory(
    create: AsyncCreate,
    *,
    openai: bool,
) -> tuple[Callable[..., Client], dict[str, object]]:
    captured: dict[str, object] = {}

    def factory(**kwargs: object) -> Client:
        captured.update(kwargs)
        return Client(create, openai=openai)

    return factory, captured


def secret_provider() -> InMemorySecretProvider:
    return InMemorySecretProvider({SECRET: b"local-test-key"})


def settings() -> ProviderClientSettings:
    return ProviderClientSettings(api_key=SECRET)


def test_openai_translation_usage_tool_call_and_request_id() -> None:
    raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="function_call",
                call_id="call-1",
                name="answer",
                arguments='{"answer":"yes"}',
            )
        ],
        usage=SimpleNamespace(
            input_tokens=10,
            output_tokens=4,
            input_tokens_details=SimpleNamespace(cached_tokens=2),
            output_tokens_details=SimpleNamespace(reasoning_tokens=1),
        ),
        _request_id="openai-request",
    )
    create = AsyncCreate(raw)
    factory, captured = client_factory(create, openai=True)
    request = model_request("openai", structured=True)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
        clock=lambda: 1,
    )

    response = asyncio.run(
        adapter.complete(request, ModelIdentity("openai", "model-1"))
    )

    assert response.finish_reason is FinishReason.TOOL_CALLS
    assert isinstance(response.content[0], ToolCallPart)
    assert response.usage.input_tokens == 8
    assert response.usage.output_tokens == 3
    assert response.usage.cache_read_tokens == 2
    assert response.usage.reasoning_tokens == 1
    assert response.provider_request_id == "openai-request"
    assert create.kwargs is not None
    assert create.kwargs["extra_headers"] == {"Idempotency-Key": "adapter-key"}
    assert "text" in create.kwargs
    assert captured["api_key"] == "local-test-key"
    assert "api_key" not in repr(response)


def test_openai_request_serializes_function_items_at_top_level() -> None:
    raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="output_text", text="ok")],
            )
        ],
        usage=SimpleNamespace(
            input_tokens=4,
            output_tokens=1,
            input_tokens_details=SimpleNamespace(cached_tokens=0),
            output_tokens_details=SimpleNamespace(reasoning_tokens=0),
        ),
        _request_id="openai-request",
    )
    create = AsyncCreate(raw)
    factory, _captured = client_factory(create, openai=True)
    request = model_request(
        "openai",
        messages=(
            ModelMessage(MessageRole.USER, (TextPart("Hello"),)),
            ModelMessage(
                MessageRole.ASSISTANT,
                (ToolCallPart(ToolCallProposal("call-1", "answer", {"ok": True})),),
            ),
            ModelMessage(
                MessageRole.TOOL,
                (ToolResultPart("call-1", {"done": True}),),
            ),
        ),
    )
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
        clock=lambda: 1,
    )

    asyncio.run(adapter.complete(request, ModelIdentity("openai", "model-1")))

    assert create.kwargs is not None
    assert create.kwargs["input"] == [
        {"role": "user", "content": [{"type": "input_text", "text": "Hello"}]},
        {
            "type": "function_call",
            "call_id": "call-1",
            "name": "answer",
            "arguments": '{"ok":true}',
        },
        {
            "type": "function_call_output",
            "call_id": "call-1",
            "output": '{"done":true}',
        },
    ]


def test_openai_request_serializes_frozen_nested_arguments() -> None:
    raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="output_text", text="ok")],
            )
        ],
        usage=SimpleNamespace(
            input_tokens=4,
            output_tokens=1,
            input_tokens_details=SimpleNamespace(cached_tokens=0),
            output_tokens_details=SimpleNamespace(reasoning_tokens=0),
        ),
        _request_id="openai-request",
    )
    create = AsyncCreate(raw)
    factory, _captured = client_factory(create, openai=True)
    request = model_request(
        "openai",
        messages=(
            ModelMessage(
                MessageRole.ASSISTANT,
                (
                    ToolCallPart(
                        ToolCallProposal(
                            "call-1",
                            "answer",
                            {"payload": {"nested": True}},
                        )
                    ),
                ),
            ),
        ),
    )
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
        clock=lambda: 1,
    )

    asyncio.run(adapter.complete(request, ModelIdentity("openai", "model-1")))

    assert create.kwargs is not None
    inputs = cast(list[dict[str, object]], create.kwargs["input"])
    assert inputs[0]["arguments"] == '{"payload":{"nested":true}}'


def test_anthropic_translation_structured_output_and_cache_usage() -> None:
    raw = SimpleNamespace(
        content=[SimpleNamespace(type="text", text='{"answer":"yes"}')],
        usage=SimpleNamespace(
            input_tokens=10,
            output_tokens=5,
            cache_read_input_tokens=3,
            cache_creation_input_tokens=2,
        ),
        stop_reason="end_turn",
        id="anthropic-message",
    )
    create = AsyncCreate(raw)
    factory, captured = client_factory(create, openai=False)
    request = model_request("anthropic", structured=True)
    adapter = AnthropicAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
        clock=lambda: 1,
    )

    response = asyncio.run(
        adapter.complete(request, ModelIdentity("anthropic", "model-1"))
    )

    assert response.structured_output == {"answer": "yes"}
    assert response.usage.cache_read_tokens == 3
    assert response.usage.cache_write_tokens == 2
    assert create.kwargs is not None
    assert create.kwargs["system"] == "Be concise"
    assert create.kwargs["extra_headers"] == {"Idempotency-Key": "adapter-key"}
    assert captured["api_key"] == "local-test-key"


class StatusError(Exception):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


@pytest.mark.parametrize(
    ("status", "classification", "retryable"),
    [
        (401, ModelErrorClass.AUTHENTICATION, False),
        (403, ModelErrorClass.AUTHORIZATION, False),
        (400, ModelErrorClass.INVALID_REQUEST, False),
        (429, ModelErrorClass.RATE_LIMIT, True),
        (503, ModelErrorClass.PROVIDER_UNAVAILABLE, True),
    ],
)
def test_sdk_errors_are_classified_and_never_escape(
    status: int,
    classification: ModelErrorClass,
    retryable: bool,
) -> None:
    create = AsyncCreate(error=StatusError(status))
    factory, _ = client_factory(create, openai=True)
    request = model_request("openai")
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )

    with pytest.raises(ModelGatewayError) as failure:
        asyncio.run(adapter.complete(request, ModelIdentity("openai", "model-1")))
    assert failure.value.error_class is classification
    assert failure.value.retryable is retryable


@pytest.mark.parametrize("adapter_type", [OpenAIAdapter, AnthropicAdapter])
def test_malformed_sdk_result_is_contained(
    adapter_type: type[OpenAIAdapter] | type[AnthropicAdapter],
) -> None:
    create = AsyncCreate(SimpleNamespace())
    is_openai = adapter_type is OpenAIAdapter
    factory, _ = client_factory(create, openai=is_openai)
    provider = "openai" if is_openai else "anthropic"
    request = model_request(provider)
    adapter = adapter_type(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )

    with pytest.raises(ModelGatewayError) as failure:
        asyncio.run(adapter.complete(request, ModelIdentity(provider, "model-1")))
    assert failure.value.error_class is ModelErrorClass.MALFORMED_RESPONSE
    assert failure.value.billing_ambiguous


def test_adapter_timeout_is_classified() -> None:
    class SlowCreate(AsyncCreate):
        async def create(self, **kwargs: object) -> None:
            del kwargs
            await asyncio.sleep(1)

    create = SlowCreate()
    factory, _ = client_factory(create, openai=True)
    request = model_request("openai", timeout=0.01)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )

    with pytest.raises(ModelGatewayError) as failure:
        asyncio.run(adapter.complete(request, ModelIdentity("openai", "model-1")))
    assert failure.value.error_class is ModelErrorClass.TIMEOUT
    assert failure.value.billing_ambiguous


def test_provider_client_settings_fail_closed() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        ProviderClientSettings(api_key=SECRET, base_url="http://provider.test")
    with pytest.raises(ValueError, match="TLS"):
        ProviderClientSettings(api_key=SECRET, verify_tls=False)
    with pytest.raises(ValueError, match="proxy"):
        ProviderClientSettings(api_key=SECRET, proxy_url="ftp://proxy.test")
    with pytest.raises(ValueError, match="timeouts"):
        ProviderClientSettings(api_key=SECRET, read_timeout_seconds=0)
    with pytest.raises(ValueError, match="pool"):
        ProviderClientSettings(
            api_key=SECRET,
            max_connections=1,
            max_keepalive_connections=2,
        )


def test_openai_text_refusal_and_structured_response_paths() -> None:
    text_raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="output_text", text='{"answer":"yes"}')],
            )
        ],
        usage=SimpleNamespace(
            input_tokens=2,
            output_tokens=3,
            input_tokens_details=None,
            output_tokens_details=None,
        ),
        id="response-id",
    )
    create = AsyncCreate(text_raw)
    factory, _ = client_factory(create, openai=True)
    request = model_request("openai", structured=True)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )
    result = asyncio.run(adapter.complete(request, ModelIdentity("openai", "model-1")))
    assert result.structured_output == {"answer": "yes"}
    assert result.finish_reason is FinishReason.STOP
    assert result.provider_request_id == "response-id"

    refusal_raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="refusal", refusal="policy")],
            )
        ],
        usage=SimpleNamespace(
            input_tokens=1,
            output_tokens=0,
            input_tokens_details=None,
            output_tokens_details=None,
        ),
        id="refusal-id",
    )
    refusal_create = AsyncCreate(refusal_raw)
    refusal_factory, _ = client_factory(refusal_create, openai=True)
    refused = asyncio.run(
        OpenAIAdapter(
            TenantContext(TENANT),
            secret_provider(),
            settings(),
            client_factory=refusal_factory,
        ).complete(model_request("openai"), ModelIdentity("openai", "model-1"))
    )
    assert refused.finish_reason is FinishReason.REFUSAL
    assert refused.safety.outcome is SafetyOutcome.REFUSED


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ("not-json", "tool_arguments_not_json"),
        ("[]", "tool_arguments_not_object"),
        (7, "tool_arguments_not_json"),
    ],
)
def test_openai_malformed_tool_arguments_are_contained(
    arguments: object,
    code: str,
) -> None:
    raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="function_call",
                call_id="call",
                name="tool",
                arguments=arguments,
            )
        ],
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
    )
    create = AsyncCreate(raw)
    factory, _ = client_factory(create, openai=True)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )
    with pytest.raises(ModelGatewayError, match=code):
        asyncio.run(
            adapter.complete(
                model_request("openai"),
                ModelIdentity("openai", "model-1"),
            )
        )


def test_openai_bounds_response_and_validates_usage() -> None:
    raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="output_text", text="too long")],
            )
        ],
        usage=SimpleNamespace(input_tokens=True, output_tokens=-1),
    )
    create = AsyncCreate(raw)
    factory, _ = client_factory(create, openai=True)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
        max_response_chars=3,
    )
    with pytest.raises(ModelGatewayError, match="too_large"):
        asyncio.run(
            adapter.complete(
                model_request("openai"),
                ModelIdentity("openai", "model-1"),
            )
        )

    raw.output[0].content[0].text = "ok"
    with pytest.raises(ModelGatewayError, match="invalid_provider_usage"):
        asyncio.run(
            adapter.complete(
                model_request("openai"),
                ModelIdentity("openai", "model-1"),
            )
        )


def test_anthropic_tool_refusal_and_malformed_structure_paths() -> None:
    tool_raw = SimpleNamespace(
        content=[
            SimpleNamespace(
                type="tool_use",
                id="call",
                name="answer",
                input={"answer": "yes"},
            )
        ],
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        stop_reason="tool_use",
    )
    create = AsyncCreate(tool_raw)
    factory, _ = client_factory(create, openai=False)
    result = asyncio.run(
        AnthropicAdapter(
            TenantContext(TENANT),
            secret_provider(),
            settings(),
            client_factory=factory,
        ).complete(
            model_request("anthropic"),
            ModelIdentity("anthropic", "model-1"),
        )
    )
    assert result.finish_reason is FinishReason.TOOL_CALLS
    assert isinstance(result.content[0], ToolCallPart)

    bad_raw = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="not-json")],
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        stop_reason="refusal",
    )
    bad_create = AsyncCreate(bad_raw)
    bad_factory, _ = client_factory(bad_create, openai=False)
    with pytest.raises(ModelGatewayError, match="structured_output_not_json"):
        asyncio.run(
            AnthropicAdapter(
                TenantContext(TENANT),
                secret_provider(),
                settings(),
                client_factory=bad_factory,
            ).complete(
                model_request("anthropic", structured=True),
                ModelIdentity("anthropic", "model-1"),
            )
        )


def test_cancellation_wrong_provider_reload_and_sdk_bug_paths() -> None:
    request = model_request("openai")
    create = AsyncCreate(SimpleNamespace())
    factory, captured = client_factory(create, openai=True)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )
    with pytest.raises(ValueError, match="non-OpenAI"):
        asyncio.run(adapter.complete(request, ModelIdentity("other", "model-1")))
    cancellation = asyncio.Event()
    cancellation.set()
    with pytest.raises(ModelGatewayError) as cancelled:
        asyncio.run(
            adapter.complete(
                request,
                ModelIdentity("openai", "model-1"),
                cancellation=cancellation,
            )
        )
    assert cancelled.value.error_class is ModelErrorClass.CANCELLED
    http_client = captured["http_client"]
    assert isinstance(http_client, httpx.AsyncClient)
    assert not http_client.is_closed
    asyncio.run(adapter.reload_client())
    assert bool(http_client.is_closed)
    assert captured["api_key"] == "local-test-key"

    bug_create = AsyncCreate(error=RuntimeError("sdk defect"))
    bug_factory, _ = client_factory(bug_create, openai=True)
    with pytest.raises(ModelGatewayError) as bug:
        asyncio.run(
            OpenAIAdapter(
                TenantContext(TENANT),
                secret_provider(),
                settings(),
                client_factory=bug_factory,
            ).complete(request, ModelIdentity("openai", "model-1"))
        )
    assert bug.value.error_class is ModelErrorClass.PROVIDER_BUG


def test_error_retry_after_and_json_translation_helpers() -> None:
    error = StatusError(429)
    error.response = SimpleNamespace(headers={"retry-after": "2.5"})  # type: ignore[attr-defined]
    classified = classify_sdk_error(error)
    assert classified.retry_after_seconds == 2.5
    assert json_object({"nested": {"values": [1, 2]}}) == {"nested": {"values": [1, 2]}}


def test_translation_helpers_cover_cancellation_and_invalid_values() -> None:
    message = ModelMessage(MessageRole.USER, (TextPart("a"), TextPart("b")))
    result = ToolResultPart("call", {"ok": True})
    assert message_text(message) == "a\nb"
    assert serialize_tool_result(result) == '{"ok":true}'
    assert all_parts((message,)) == message.content
    assert_supported_part(TextPart("supported"))
    with pytest.raises(ModelGatewayError, match="unsupported_content_part"):
        assert_supported_part(object())
    with pytest.raises(ModelGatewayError, match="not_string"):
        bounded_text(3, 10)

    class InvalidRetryError(StatusError):
        def __init__(self) -> None:
            super().__init__(429)
            self.response = SimpleNamespace(headers={"retry-after": "invalid"})

    assert classify_sdk_error(InvalidRetryError()).retry_after_seconds is None
    capped = StatusError(429)
    capped.response = SimpleNamespace(headers={"retry-after": "Infinity"})  # type: ignore[attr-defined]
    assert classify_sdk_error(capped).retry_after_seconds is None
    delayed = StatusError(429)
    delayed.response = SimpleNamespace(headers={"retry-after": "999"})  # type: ignore[attr-defined]
    assert classify_sdk_error(delayed).retry_after_seconds == 300.0
    assert classify_sdk_error(TimeoutError()).error_class is ModelErrorClass.TIMEOUT
    connection = classify_sdk_error(ConnectionError())
    assert connection.error_class is ModelErrorClass.PROVIDER_UNAVAILABLE
    assert connection.billing_ambiguous is True

    async def cancelled_during_wait() -> None:
        cancellation = asyncio.Event()

        async def operation() -> str:
            await asyncio.sleep(1)
            return "late"

        async def cancel() -> None:
            await asyncio.sleep(0)
            cancellation.set()

        cancel_task = asyncio.create_task(cancel())
        with pytest.raises(asyncio.CancelledError):
            await await_with_cancellation(
                operation(),
                timeout_seconds=1,
                cancellation=cancellation,
            )
        await cancel_task

    asyncio.run(cancelled_during_wait())

    async def timeout_cancels_operation() -> None:
        cancellation = asyncio.Event()
        operation_finished = asyncio.Event()

        async def operation() -> None:
            try:
                await asyncio.sleep(1)
            finally:
                operation_finished.set()

        with pytest.raises(TimeoutError):
            await await_with_cancellation(
                operation(),
                timeout_seconds=0.01,
                cancellation=cancellation,
            )
        assert operation_finished.is_set()

    asyncio.run(timeout_cancels_operation())


def test_anthropic_translates_all_neutral_content_parts() -> None:
    request = ModelRequest(
        request_id=uuid4(),
        tenant_id=str(TENANT),
        run_id=uuid4(),
        messages=(
            ModelMessage(
                MessageRole.USER,
                (
                    TextPart("inspect"),
                    ImagePart("image/png", "https://example.test/image.png"),
                ),
            ),
            ModelMessage(
                MessageRole.ASSISTANT,
                (ToolCallPart(ToolCallProposal("call", "answer", {"value": "x"})),),
            ),
            ModelMessage(
                MessageRole.TOOL,
                (ToolResultPart("call", {"value": "x"}),),
            ),
        ),
        max_output_tokens=10,
        prompt_token_estimate=10,
        timeout_seconds=1,
        idempotency_key="all-parts",
    )
    raw = SimpleNamespace(
        content=[],
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        stop_reason=None,
    )
    create = AsyncCreate(raw)
    factory, _ = client_factory(create, openai=False)
    adapter = AnthropicAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )
    result = asyncio.run(
        adapter.complete(request, ModelIdentity("anthropic", "model-1"))
    )
    assert result.finish_reason is FinishReason.UNKNOWN
    assert create.kwargs is not None
    messages = create.kwargs["messages"]
    assert isinstance(messages, list)
    assert messages[0]["content"][1]["type"] == "image"
    assert messages[1]["role"] == "assistant"
    assert messages[2]["content"][0]["type"] == "tool_result"


def test_anthropic_guards_constructor_provider_usage_and_reload() -> None:
    other_secret = SecretReference(
        TenantId("other"),
        "memory",
        "provider-key",
        "1",
    )
    with pytest.raises(ValueError, match="tenant"):
        AnthropicAdapter(
            TenantContext(TENANT),
            secret_provider(),
            ProviderClientSettings(api_key=other_secret),
        )
    with pytest.raises(ValueError, match="bound"):
        AnthropicAdapter(
            TenantContext(TENANT),
            secret_provider(),
            settings(),
            max_response_chars=0,
        )
    create = AsyncCreate(
        SimpleNamespace(
            content=[
                SimpleNamespace(
                    type="tool_use",
                    id="call",
                    name="tool",
                    input="not-object",
                )
            ],
            usage=SimpleNamespace(input_tokens=1, output_tokens=1),
            stop_reason="tool_use",
        )
    )
    factory, _ = client_factory(create, openai=False)
    adapter = AnthropicAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )
    with pytest.raises(ValueError, match="non-Anthropic"):
        asyncio.run(
            adapter.complete(
                model_request("anthropic"),
                ModelIdentity("other", "model"),
            )
        )
    with pytest.raises(ModelGatewayError, match="tool_arguments_not_object"):
        asyncio.run(
            adapter.complete(
                model_request("anthropic"),
                ModelIdentity("anthropic", "model"),
            )
        )
    asyncio.run(adapter.reload_client())


def test_openai_incomplete_response_and_invalid_cached_usage() -> None:
    raw = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="output_text", text="partial")],
            )
        ],
        usage=SimpleNamespace(input_tokens=2, output_tokens=4),
        incomplete_details=SimpleNamespace(reason="max_output_tokens"),
    )
    create = AsyncCreate(raw)
    factory, _ = client_factory(create, openai=True)
    adapter = OpenAIAdapter(
        TenantContext(TENANT),
        secret_provider(),
        settings(),
        client_factory=factory,
    )

    response = asyncio.run(
        adapter.complete(model_request("openai"), ModelIdentity("openai", "model-1"))
    )
    assert response.finish_reason is FinishReason.LENGTH

    raw.usage = SimpleNamespace(
        input_tokens=1,
        output_tokens=1,
        input_tokens_details=SimpleNamespace(cached_tokens=2),
    )
    with pytest.raises(ModelGatewayError, match="cached_tokens_exceed_input_tokens"):
        asyncio.run(
            adapter.complete(
                model_request("openai"),
                ModelIdentity("openai", "model-1"),
            )
        )

    raw.usage = SimpleNamespace(
        input_tokens=2,
        output_tokens=1,
        output_tokens_details=SimpleNamespace(reasoning_tokens=2),
    )
    with pytest.raises(
        ModelGatewayError, match="reasoning_tokens_exceed_output_tokens"
    ):
        asyncio.run(
            adapter.complete(
                model_request("openai"),
                ModelIdentity("openai", "model-1"),
            )
        )
