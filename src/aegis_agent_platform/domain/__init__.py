"""Pure domain types and transitions.

This package must not import infrastructure, network clients, or framework code.
"""

from aegis_agent_platform.domain.events import EventEnvelope, JsonValue

__all__ = ["EventEnvelope", "JsonValue"]
