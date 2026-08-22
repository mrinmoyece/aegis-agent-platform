"""Provider-neutral model invocation contracts."""

from aegis_agent_platform.domain import ModelMessage, ModelRequest, ModelResponse
from aegis_agent_platform.providers.config import ProviderClientSettings
from aegis_agent_platform.providers.fake import RecordedCall, ScriptedModelProvider
from aegis_agent_platform.providers.protocol import CancellationToken, ModelProvider
from aegis_agent_platform.providers.types import (
    ModelMessage as LegacyModelMessage,
)
from aegis_agent_platform.providers.types import (
    ModelRequest as LegacyModelRequest,
)
from aegis_agent_platform.providers.types import (
    ModelResponse as LegacyModelResponse,
)
from aegis_agent_platform.providers.types import (
    ResponseFormat,
)

__all__ = [
    "CancellationToken",
    "LegacyModelMessage",
    "LegacyModelRequest",
    "LegacyModelResponse",
    "ModelMessage",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderClientSettings",
    "RecordedCall",
    "ResponseFormat",
    "ScriptedModelProvider",
]
