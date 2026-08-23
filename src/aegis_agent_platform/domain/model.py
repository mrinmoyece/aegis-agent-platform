"""Pure provider-neutral model gateway contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

from aegis_agent_platform.domain.events import (
    JsonValue,
    freeze_json,
    freeze_json_mapping,
)


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ContentKind(StrEnum):
    TEXT = "text"
    IMAGE = "image"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


class FinishReason(StrEnum):
    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    REFUSAL = "refusal"
    CONTENT_FILTER = "content_filter"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class SafetyOutcome(StrEnum):
    ALLOWED = "allowed"
    REFUSED = "refused"
    FILTERED = "filtered"


class ModelErrorClass(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INVALID_REQUEST = "invalid_request"
    CAPABILITY = "capability"
    SCHEMA = "schema"
    SAFETY = "safety"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    TRANSIENT = "transient"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    MALFORMED_RESPONSE = "malformed_response"
    PROVIDER_BUG = "provider_bug"


@dataclass(frozen=True, slots=True)
class TextPart:
    text: str
    kind: ContentKind = field(default=ContentKind.TEXT, init=False)

    def __post_init__(self) -> None:
        if not self.text:
            raise ValueError("text content cannot be empty")


@dataclass(frozen=True, slots=True)
class ImagePart:
    """Image reference; binary data remains outside the durable event payload."""

    media_type: str
    uri: str
    kind: ContentKind = field(default=ContentKind.IMAGE, init=False)

    def __post_init__(self) -> None:
        if self.media_type not in {
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
        }:
            raise ValueError("unsupported image media type")
        if not self.uri.startswith("https://"):
            raise ValueError("image uri must use an approved scheme")


@dataclass(frozen=True, slots=True)
class ToolCallProposal:
    call_id: str
    tool_name: str
    arguments: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if not self.call_id or not self.tool_name:
            raise ValueError("tool call id and name are required")
        object.__setattr__(self, "arguments", freeze_json_mapping(self.arguments))


@dataclass(frozen=True, slots=True)
class ToolCallPart:
    proposal: ToolCallProposal
    kind: ContentKind = field(default=ContentKind.TOOL_CALL, init=False)


@dataclass(frozen=True, slots=True)
class ToolResultPart:
    call_id: str
    content: JsonValue
    is_error: bool = False
    kind: ContentKind = field(default=ContentKind.TOOL_RESULT, init=False)

    def __post_init__(self) -> None:
        if not self.call_id:
            raise ValueError("tool result call id is required")
        object.__setattr__(self, "content", freeze_json(self.content))


type ContentPart = TextPart | ImagePart | ToolCallPart | ToolResultPart


@dataclass(frozen=True, slots=True)
class ModelMessage:
    role: MessageRole
    content: Sequence[ContentPart]
    name: str | None = None

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError("message content cannot be empty")
        if self.name is not None and not self.name:
            raise ValueError("message name cannot be empty")
        parts = tuple(self.content)
        if self.role is MessageRole.SYSTEM and any(
            not isinstance(part, TextPart) for part in parts
        ):
            raise ValueError("system messages may contain only text")
        if self.role is MessageRole.TOOL and any(
            not isinstance(part, ToolResultPart) for part in parts
        ):
            raise ValueError("tool messages require tool results")
        object.__setattr__(self, "content", parts)


@dataclass(frozen=True, slots=True)
class JsonSchema:
    name: str
    schema: Mapping[str, JsonValue]
    strict: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("schema name is required")
        if self.schema.get("type") != "object":
            raise ValueError("structured output schema root must be an object")
        object.__setattr__(self, "schema", freeze_json_mapping(self.schema))


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: JsonSchema

    def __post_init__(self) -> None:
        if not self.name or not self.description:
            raise ValueError("tool name and description are required")


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    max_context_tokens: int
    max_output_tokens: int
    supports_tools: bool
    supports_vision: bool
    supports_structured_output: bool
    supports_reasoning_tokens: bool = False
    supports_cache_tokens: bool = False

    def __post_init__(self) -> None:
        if self.max_context_tokens < 1 or self.max_output_tokens < 1:
            raise ValueError("model token limits must be positive")
        if self.max_output_tokens > self.max_context_tokens:
            raise ValueError("output limit cannot exceed context limit")


@dataclass(frozen=True, slots=True, order=True)
class ProviderIdentity:
    provider: str
    region: str

    def __post_init__(self) -> None:
        if not self.provider or not self.region:
            raise ValueError("provider and region are required")


@dataclass(frozen=True, slots=True, order=True)
class ModelIdentity:
    provider: str
    model: str

    def __post_init__(self) -> None:
        if not self.provider or not self.model:
            raise ValueError("provider and model are required")

    @property
    def catalog_key(self) -> str:
        return f"{self.provider}/{self.model}"


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0

    def __post_init__(self) -> None:
        if any(
            value < 0
            for value in (
                self.input_tokens,
                self.output_tokens,
                self.cache_read_tokens,
                self.cache_write_tokens,
                self.reasoning_tokens,
            )
        ):
            raise ValueError("token usage cannot be negative")

    @property
    def billable_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
            + self.reasoning_tokens
        )


@dataclass(frozen=True, slots=True)
class PricingVersion:
    version: str
    effective_at: datetime
    input_per_million_usd: Decimal
    output_per_million_usd: Decimal
    cache_read_per_million_usd: Decimal = Decimal("0")
    cache_write_per_million_usd: Decimal = Decimal("0")
    reasoning_per_million_usd: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        if not self.version or self.effective_at.tzinfo is None:
            raise ValueError(
                "pricing version and timezone-aware effective time required"
            )
        if any(
            value < 0
            for value in (
                self.input_per_million_usd,
                self.output_per_million_usd,
                self.cache_read_per_million_usd,
                self.cache_write_per_million_usd,
                self.reasoning_per_million_usd,
            )
        ):
            raise ValueError("prices cannot be negative")

    def cost(self, usage: TokenUsage) -> Decimal:
        million = Decimal(1_000_000)
        return (
            Decimal(usage.input_tokens) * self.input_per_million_usd
            + Decimal(usage.output_tokens) * self.output_per_million_usd
            + Decimal(usage.cache_read_tokens) * self.cache_read_per_million_usd
            + Decimal(usage.cache_write_tokens) * self.cache_write_per_million_usd
            + Decimal(usage.reasoning_tokens) * self.reasoning_per_million_usd
        ) / million


@dataclass(frozen=True, slots=True)
class SafetyResult:
    outcome: SafetyOutcome
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.outcome is SafetyOutcome.ALLOWED and self.reason_code is not None:
            raise ValueError("allowed result cannot have a refusal reason")
        if self.outcome is not SafetyOutcome.ALLOWED and not self.reason_code:
            raise ValueError("refusal or filtering requires a reason code")


@dataclass(frozen=True, slots=True)
class ModelRequest:
    request_id: UUID
    tenant_id: str
    run_id: UUID
    messages: Sequence[ModelMessage]
    max_output_tokens: int
    prompt_token_estimate: int
    requested_model: ModelIdentity | None = None
    tools: Sequence[ToolDefinition] = ()
    response_schema: JsonSchema | None = None
    temperature: Decimal = Decimal("0")
    timeout_seconds: float = 30.0
    idempotency_key: str = ""

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.messages or not self.idempotency_key:
            raise ValueError("tenant, messages, and idempotency key are required")
        if self.max_output_tokens < 1 or self.prompt_token_estimate < 1:
            raise ValueError("token estimates must be positive")
        if not 0 < self.timeout_seconds <= 600:
            raise ValueError("timeout must be between 0 and 600 seconds")
        if not Decimal("0") <= self.temperature <= Decimal("2"):
            raise ValueError("temperature must be between 0 and 2")
        object.__setattr__(self, "messages", tuple(self.messages))
        object.__setattr__(self, "tools", tuple(self.tools))


@dataclass(frozen=True, slots=True)
class ModelResponse:
    request_id: UUID
    model: ModelIdentity
    content: Sequence[ContentPart]
    finish_reason: FinishReason
    safety: SafetyResult
    usage: TokenUsage
    latency_ms: int
    provider_request_id: str | None = None
    structured_output: Mapping[str, JsonValue] | None = None
    cost_usd: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        if self.latency_ms < 0:
            raise ValueError("latency cannot be negative")
        if self.cost_usd < 0:
            raise ValueError("model response cost cannot be negative")
        if self.provider_request_id is not None and not self.provider_request_id:
            raise ValueError("provider request id cannot be empty")
        object.__setattr__(self, "content", tuple(self.content))
        if self.structured_output is not None:
            object.__setattr__(
                self,
                "structured_output",
                freeze_json_mapping(self.structured_output),
            )


class ModelGatewayError(RuntimeError):
    """Secret-safe classified model failure; vendor exceptions never escape."""

    def __init__(
        self,
        error_class: ModelErrorClass,
        code: str,
        *,
        retryable: bool,
        retry_after_seconds: float | None = None,
        billing_ambiguous: bool = False,
    ) -> None:
        super().__init__(code)
        if not code:
            raise ValueError("error code is required")
        if retry_after_seconds is not None and retry_after_seconds < 0:
            raise ValueError("retry delay cannot be negative")
        self.error_class = error_class
        self.code = code
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds
        self.billing_ambiguous = billing_ambiguous


__all__ = [
    "ContentKind",
    "ContentPart",
    "FinishReason",
    "ImagePart",
    "JsonSchema",
    "MessageRole",
    "ModelCapabilities",
    "ModelErrorClass",
    "ModelGatewayError",
    "ModelIdentity",
    "ModelMessage",
    "ModelRequest",
    "ModelResponse",
    "PricingVersion",
    "ProviderIdentity",
    "SafetyOutcome",
    "SafetyResult",
    "TextPart",
    "TokenUsage",
    "ToolCallPart",
    "ToolCallProposal",
    "ToolDefinition",
    "ToolResultPart",
]
