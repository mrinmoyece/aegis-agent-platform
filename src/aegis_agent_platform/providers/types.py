"""Types that prevent vendor SDK objects from crossing platform boundaries."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from aegis_agent_platform.domain import JsonValue


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
    parameters: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """A normalized provider result with metering fields."""

    content: str
    finish_reason: str
    input_tokens: int
    output_tokens: int
    provider_request_id: str | None = None
