"""Pure domain types and transitions.

This package must not import infrastructure, network clients, or framework code.
"""

from aegis_agent_platform.domain.events import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EventEnvelope,
    JsonValue,
    TraceContext,
)

__all__ = [
    "ActorKind",
    "ActorReference",
    "DomainEventType",
    "EventEnvelope",
    "JsonValue",
    "TraceContext",
]
