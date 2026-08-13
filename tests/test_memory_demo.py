"""Executable deterministic Layer 10 demo coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest

from aegis_agent_platform.memory.__main__ import main
from aegis_agent_platform.memory.demo import run_demo


@pytest.mark.asyncio
async def test_memory_demo_covers_safety_and_recovery_scenarios() -> None:
    result: dict[str, Any] = await run_demo()

    assert result["normal_retrieval"]["hit_count"] > 0
    assert result["normal_retrieval"]["citation_ids"]
    assert result["contradiction"]["visible"]
    assert result["poisoning"]["status"] == "quarantined"
    assert result["tenant_isolation"]["tenant_b_excluded"]
    assert result["compaction"]["compacted"]
    assert result["purge"]["excluded_after_purge"]
    assert result["purge"]["immutable_ledger_retained"]


def test_memory_module_main_renders_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main()
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["normal_retrieval"]["hit_count"] > 0
