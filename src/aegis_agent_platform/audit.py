"""Immutable tenant-scoped security audit boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import JsonValue, require_aware_datetime
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.tenancy import TenantContext

REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = re.compile(
    r"(authorization|credential|password|prompt|secret|token)",
    re.IGNORECASE,
)
_BEARER_VALUE = re.compile(r"\bBearer\s+\S+", re.IGNORECASE)


class AuditEventType(StrEnum):
    """Additive security event names; existing names are never repurposed."""

    AUTHENTICATION_OUTCOME = "security.authentication_outcome.v1"
    AUTHORIZATION_DECISION = "security.authorization_decision.v1"
    POLICY_EVALUATION = "security.policy_evaluation.v1"
    APPROVAL_IDENTITY_RECORDED = "security.approval_identity_recorded.v1"
    ADMINISTRATIVE_CHANGE = "security.administrative_change.v1"


class AuditOutcome(StrEnum):
    """Security event outcome."""

    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


def redact_details(details: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    """Return an immutable copy with credentials and full prompts removed."""
    return MappingProxyType(
        {
            key: (REDACTED if _SENSITIVE_KEYS.search(key) else _redact_value(value))
            for key, value in details.items()
        }
    )


def _redact_value(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return _BEARER_VALUE.sub(REDACTED, value)
    if isinstance(value, Mapping):
        return redact_details(value)
    if isinstance(value, (list, tuple)):
        return tuple(_redact_value(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable event committed to the security event ledger."""

    event_id: UUID
    tenant_id: TenantId
    event_type: AuditEventType
    occurred_at: datetime
    outcome: AuditOutcome
    actor_id: str
    action: str
    resource: str
    correlation_id: UUID
    details: Mapping[str, JsonValue]
    schema_version: int = 1

    def __post_init__(self) -> None:
        require_aware_datetime(self.occurred_at, field_name="occurred_at")
        if self.schema_version != 1:
            raise ValueError("audit schema changes must use a new additive event type")
        if not self.actor_id or not self.action or not self.resource:
            raise ValueError("audit actor, action, and resource are required")
        object.__setattr__(self, "details", redact_details(self.details))


class AuditStore(Protocol):
    """Append-only, tenant-scoped audit persistence port."""

    def append(self, context: TenantContext, event: AuditEvent) -> None:
        """Append one event after validating tenant context."""
        ...

    def query(
        self, context: TenantContext, *, limit: int = 100
    ) -> tuple[AuditEvent, ...]:
        """Return only events owned by the supplied tenant."""
        ...


class InMemoryAuditStore:
    """Deterministic append-only store used by the vertical slice."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, context: TenantContext, event: AuditEvent) -> None:
        if context.tenant_id != event.tenant_id:
            raise ValueError("audit event tenant does not match trusted context")
        self._events.append(event)

    def query(
        self, context: TenantContext, *, limit: int = 100
    ) -> tuple[AuditEvent, ...]:
        if not 1 <= limit <= 1_000:
            raise ValueError("audit query limit must be between 1 and 1000")
        return tuple(
            event for event in self._events if event.tenant_id == context.tenant_id
        )[-limit:]
