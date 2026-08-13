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
from aegis_agent_platform.domain.work import (
    FailureClass,
    WorkLease,
    WorkRequest,
    WorkStatus,
    WorkTransition,
    next_status,
)

__all__ = [
    "ActorKind",
    "ActorReference",
    "DomainEventType",
    "EventEnvelope",
    "FailureClass",
    "JsonValue",
    "TraceContext",
    "WorkLease",
    "WorkRequest",
    "WorkStatus",
    "WorkTransition",
    "next_status",
]
