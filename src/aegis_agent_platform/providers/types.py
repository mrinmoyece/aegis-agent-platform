"""Compatibility exports for provider-neutral domain contracts."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum


class ResponseFormat(StrEnum):
    """Portable output formats retained for backward-compatible imports."""

    TEXT = "text"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class ModelMessage:
    """A provider-neutral conversation message."""

    role: str
    content: str


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """A normalized request to a model provider."""

    model: str
    messages: Sequence[ModelMessage]
    temperature: float | None = None
    max_output_tokens: int | None = None
    stop_sequences: tuple[str, ...] = ()
    response_format: ResponseFormat = ResponseFormat.TEXT

    def __post_init__(self) -> None:
        """Validate portable generation controls."""
        if self.temperature is not None and not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if self.max_output_tokens is not None and self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """A normalized provider result with metering fields."""

    content: str
    finish_reason: str
    input_tokens: int
    output_tokens: int
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        """Reject impossible usage values before cost accounting."""
        if self.input_tokens < 0 or self.output_tokens < 0:
            raise ValueError("token counts cannot be negative")


__all__ = ["ModelMessage", "ModelRequest", "ModelResponse", "ResponseFormat"]
