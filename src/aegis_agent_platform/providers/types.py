"""Compatibility exports for provider-neutral domain contracts."""

from enum import StrEnum

from aegis_agent_platform.domain.model import ModelMessage, ModelRequest, ModelResponse


class ResponseFormat(StrEnum):
    """Portable output formats retained for backward-compatible imports."""

    TEXT = "text"
    JSON = "json"


__all__ = ["ModelMessage", "ModelRequest", "ModelResponse", "ResponseFormat"]
