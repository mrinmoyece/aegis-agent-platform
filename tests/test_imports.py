"""Package boundary smoke tests."""

from __future__ import annotations

import importlib

import pytest

PACKAGES = [
    "aegis_agent_platform",
    "aegis_agent_platform.agents",
    "aegis_agent_platform.control_plane",
    "aegis_agent_platform.domain",
    "aegis_agent_platform.evals",
    "aegis_agent_platform.event_store",
    "aegis_agent_platform.identity",
    "aegis_agent_platform.integrations",
    "aegis_agent_platform.integrations.dynatrace",
    "aegis_agent_platform.integrations.github",
    "aegis_agent_platform.memory",
    "aegis_agent_platform.observability",
    "aegis_agent_platform.policy",
    "aegis_agent_platform.providers",
    "aegis_agent_platform.queueing",
    "aegis_agent_platform.runtime",
    "aegis_agent_platform.sandbox",
    "aegis_agent_platform.tenancy",
    "aegis_agent_platform.tools",
]


@pytest.mark.parametrize("package_name", PACKAGES)
def test_package_imports(package_name: str) -> None:
    assert importlib.import_module(package_name)
