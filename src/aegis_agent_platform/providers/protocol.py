"""Infrastructure protocol implemented by every model provider adapter."""

from __future__ import annotations

from typing import Protocol

from aegis_agent_platform.domain import ModelIdentity, ModelRequest, ModelResponse


class CancellationToken(Protocol):
    def is_set(self) -> bool:
        """Return whether cancellation was requested."""
        ...

    async def wait(self) -> bool:
        """Wait until cancellation is requested."""
        ...


class ModelProvider(Protocol):
    """Provider-neutral async invocation boundary."""

    provider_name: str

    async def complete(
        self,
        request: ModelRequest,
        model: ModelIdentity,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        """Complete one request or raise a classified ModelGatewayError."""
        ...


__all__ = ["CancellationToken", "ModelProvider"]
