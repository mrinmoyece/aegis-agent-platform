"""Provider-neutral model invocation contracts."""

from aegis_agent_platform.providers.config import ProviderClientSettings
from aegis_agent_platform.providers.fake import RecordedCall, ScriptedModelProvider
from aegis_agent_platform.providers.protocol import CancellationToken, ModelProvider
from aegis_agent_platform.providers.types import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
)

__all__ = [
    "CancellationToken",
    "ModelMessage",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderClientSettings",
    "RecordedCall",
    "ScriptedModelProvider",
]
