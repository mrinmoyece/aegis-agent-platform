"""Behavioral evaluation scenarios use only deterministic mock providers."""

from __future__ import annotations

from typing import cast

from aegis_agent_platform.gateway.__main__ import run_mock_diagnostic


def test_mock_diagnostic_eval_records_budget_and_usage_without_network() -> None:
    import asyncio

    result = asyncio.run(run_mock_diagnostic("Why reserve before calling?"))

    assert result["provider"] == "mock"
    assert result["finish_reason"] == "stop"
    event_types = cast(list[str], result["durable_event_types"])
    assert "model.call_requested.v1" in event_types
    assert "model.budget_reserved.v1" in event_types
    assert "model.usage_recorded.v1" in event_types
