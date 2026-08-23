"""Deterministic scripted provider used by tests, evaluations, and diagnostics."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from aegis_agent_platform.domain import (
    ModelGatewayError,
    ModelIdentity,
    ModelRequest,
    ModelResponse,
)
from aegis_agent_platform.providers.protocol import CancellationToken

type ScriptedOutcome = ModelResponse | ModelGatewayError


@dataclass(frozen=True, slots=True)
class RecordedCall:
    request: ModelRequest
    model: ModelIdentity


class ScriptedModelProvider:
    """Returns an exact finite sequence and never performs network I/O."""

    def __init__(self, provider_name: str, outcomes: Iterable[ScriptedOutcome]) -> None:
        if not provider_name:
            raise ValueError("provider name is required")
        self.provider_name = provider_name
        self._outcomes = deque(outcomes)
        self.calls: list[RecordedCall] = []

    async def complete(
        self,
        request: ModelRequest,
        model: ModelIdentity,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        if model.provider != self.provider_name:
            raise ValueError("model does not belong to scripted provider")
        if cancellation is not None and cancellation.is_set():
            from aegis_agent_platform.domain import ModelErrorClass

            raise ModelGatewayError(
                ModelErrorClass.CANCELLED,
                "cancelled_before_attempt",
                retryable=False,
            )
        self.calls.append(RecordedCall(request, model))
        if not self._outcomes:
            raise RuntimeError("scripted provider has no remaining outcome")
        outcome = self._outcomes.popleft()
        if isinstance(outcome, ModelGatewayError):
            raise outcome
        return outcome


__all__ = ["RecordedCall", "ScriptedModelProvider", "ScriptedOutcome"]
