"""Bounded provider-neutral contracts for derived operator views."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.identity import Principal
from aegis_agent_platform.tenancy import TenantContext

MAX_OPERATOR_ITEMS = 100
MAX_OPERATOR_STRING = 2_048


class DataAuthority(StrEnum):
    """How an operator-facing datum relates to durable truth."""

    EVENT_FACT = "event_fact"
    DERIVED_STATE = "derived_state"
    MODEL_CLAIM = "model_claim"
    OPERATOR_DECISION = "operator_decision"
    UNKNOWN = "unknown"


def _bounded_identifier(value: str, name: str) -> None:
    if (
        not value
        or value != value.strip()
        or len(value) > 128
        or not value.replace("-", "").replace("_", "").replace(".", "").isalnum()
    ):
        raise ValueError(f"{name} must be a bounded normalized identifier")


def _bounded_text(value: str, name: str) -> None:
    if not value or value != value.strip() or len(value) > MAX_OPERATOR_STRING:
        raise ValueError(f"{name} must be bounded normalized text")


@dataclass(frozen=True, slots=True)
class OperatorItem:
    """One bounded, classified operator datum."""

    item_id: str
    kind: str
    title: str
    summary: str
    status: str
    authority: DataAuthority
    occurred_at: datetime
    severity: str = "info"
    stale: bool = False
    citation: str | None = None
    metadata: Mapping[str, JsonValue] = MappingProxyType({})

    def __post_init__(self) -> None:
        _bounded_identifier(self.item_id, "item_id")
        _bounded_identifier(self.kind, "kind")
        _bounded_identifier(self.status, "status")
        _bounded_identifier(self.severity, "severity")
        _bounded_text(self.title, "title")
        _bounded_text(self.summary, "summary")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.citation is not None:
            _bounded_text(self.citation, "citation")
        if len(self.metadata) > 32:
            raise ValueError("operator item metadata is outside the bound")
        for meta_key, meta_val in self.metadata.items():
            if not isinstance(meta_key, str) or not meta_key or len(meta_key) > 128:
                raise ValueError("operator item metadata key exceeds length bound")
            # Only scalar JSON values (string, int/float, bool, None) are permitted.
            # Nested objects/arrays would be rejected by the OpenAPI JsonValue schema.
            if meta_val is not None and not isinstance(
                meta_val, (bool, int, float, str)
            ):
                raise ValueError(
                    "operator item metadata value must be a scalar"
                    " (string, number, bool, null)"
                )
            if isinstance(meta_val, str) and len(meta_val) > MAX_OPERATOR_STRING:
                raise ValueError("operator item metadata string value exceeds bound")
            if isinstance(meta_val, float) and not math.isfinite(meta_val):
                raise ValueError(
                    "operator item metadata must not contain non-finite float"
                )
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "id": self.item_id,
            "kind": self.kind,
            "title": self.title,
            "summary": self.summary,
            "status": self.status,
            "authority": self.authority.value,
            "occurred_at": self.occurred_at.isoformat(),
            "severity": self.severity,
            "stale": self.stale,
            "citation": self.citation,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatorSnapshot:
    """Tenant-scoped derived view; never an authoritative state store."""

    schema_version: int
    tenant_id: str
    generated_at: datetime
    source_cursor: str
    stale: bool
    demo: bool
    sections: Mapping[str, tuple[OperatorItem, ...]]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported operator snapshot schema")
        _bounded_identifier(self.tenant_id, "tenant_id")
        _bounded_text(self.source_cursor, "source_cursor")
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        if not 1 <= len(self.sections) <= 16:
            raise ValueError("operator snapshot sections are outside the bound")
        normalized: dict[str, tuple[OperatorItem, ...]] = {}
        for name, items in self.sections.items():
            _bounded_identifier(name, "section")
            if len(items) > MAX_OPERATOR_ITEMS:
                raise ValueError("operator snapshot section exceeds item bound")
            normalized[name] = tuple(items)
        object.__setattr__(self, "sections", MappingProxyType(normalized))

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at.isoformat(),
            "source_cursor": self.source_cursor,
            "stale": self.stale,
            "demo": self.demo,
            "sections": {
                name: [item.to_dict() for item in items]
                for name, items in self.sections.items()
            },
        }


@dataclass(frozen=True, slots=True)
class OperatorEventPage:
    """Cursor page used by bounded polling or stream adapters."""

    events: tuple[OperatorItem, ...]
    next_cursor: str | None
    server_time: datetime
    stale: bool = False

    def __post_init__(self) -> None:
        if len(self.events) > MAX_OPERATOR_ITEMS:
            raise ValueError("operator event page exceeds item bound")
        if self.server_time.tzinfo is None:
            raise ValueError("server_time must be timezone-aware")
        if self.next_cursor is not None:
            _bounded_text(self.next_cursor, "next_cursor")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "events": [event.to_dict() for event in self.events],
            "next_cursor": self.next_cursor,
            "server_time": self.server_time.isoformat(),
            "stale": self.stale,
        }


@dataclass(frozen=True, slots=True)
class ApprovalDecisionCommand:
    """Exact immutable approval scope supplied to an application service."""

    approval_id: str
    plan_digest: str
    policy_digest: str
    decision: str
    rationale_code: str
    comment: str
    expected_version: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.approval_id, "approval_id"),
            (self.rationale_code, "rationale_code"),
            (self.expected_version, "expected_version"),
            (self.idempotency_key, "idempotency_key"),
        ):
            _bounded_identifier(value, name)
        for digest, name in (
            (self.plan_digest, "plan_digest"),
            (self.policy_digest, "policy_digest"),
        ):
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if self.decision not in {"grant", "deny"}:
            raise ValueError("decision must be grant or deny")
        if len(self.comment) > 1_000:
            raise ValueError("approval comment exceeds the bound")


@dataclass(frozen=True, slots=True)
class ApprovalDecisionResult:
    """Durable-command acknowledgement, intentionally not effect success."""

    approval_id: str
    status: str
    verification: str
    version: str
    duplicate: bool
    server_time: datetime

    def __post_init__(self) -> None:
        _bounded_identifier(self.approval_id, "approval_id")
        _bounded_identifier(self.status, "status")
        _bounded_identifier(self.verification, "verification")
        _bounded_identifier(self.version, "version")
        if self.server_time.tzinfo is None:
            raise ValueError("server_time must be timezone-aware")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "approval_id": self.approval_id,
            "status": self.status,
            "verification": self.verification,
            "version": self.version,
            "duplicate": self.duplicate,
            "server_time": self.server_time.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class PeerTrustCommand:
    """Exact digest/version-bound peer trust decision."""

    peer_id: str
    peer_digest: str
    decision: str
    rationale_code: str
    expected_version: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.peer_id, "peer_id"),
            (self.rationale_code, "rationale_code"),
            (self.expected_version, "expected_version"),
            (self.idempotency_key, "idempotency_key"),
        ):
            _bounded_identifier(value, name)
        if len(self.peer_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.peer_digest
        ):
            raise ValueError("peer_digest must be a lowercase SHA-256 digest")
        if self.decision not in {"activate", "quarantine", "revoke"}:
            raise ValueError("peer trust decision is invalid")


@dataclass(frozen=True, slots=True)
class PeerTrustResult:
    """Trust acknowledgement; never implies remote protocol health."""

    peer_id: str
    status: str
    version: str
    duplicate: bool
    server_time: datetime

    def __post_init__(self) -> None:
        _bounded_identifier(self.peer_id, "peer_id")
        _bounded_identifier(self.status, "status")
        _bounded_identifier(self.version, "version")
        if self.server_time.tzinfo is None:
            raise ValueError("server_time must be timezone-aware")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "peer_id": self.peer_id,
            "status": self.status,
            "version": self.version,
            "duplicate": self.duplicate,
            "server_time": self.server_time.isoformat(),
        }


class OperatorViewService(Protocol):
    """Read only through tenant-scoped application/projection services."""

    async def snapshot(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
    ) -> OperatorSnapshot:
        """Return one bounded derived snapshot."""
        ...

    async def events(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        after_cursor: str | None,
        at: datetime,
    ) -> OperatorEventPage:
        """Return validated events in stable source order."""
        ...


class OperatorCommandService(Protocol):
    """Mutate only through governed application services."""

    async def decide_approval(
        self,
        principal: Principal,
        context: TenantContext,
        command: ApprovalDecisionCommand,
        *,
        at: datetime,
    ) -> ApprovalDecisionResult:
        """Record a decision without claiming effect completion."""
        ...

    async def change_peer_trust(
        self,
        principal: Principal,
        context: TenantContext,
        command: PeerTrustCommand,
        *,
        at: datetime,
    ) -> PeerTrustResult:
        """Record an exact peer trust decision without exposing credentials."""
        ...


__all__ = [
    "MAX_OPERATOR_ITEMS",
    "MAX_OPERATOR_STRING",
    "ApprovalDecisionCommand",
    "ApprovalDecisionResult",
    "DataAuthority",
    "OperatorCommandService",
    "OperatorEventPage",
    "OperatorItem",
    "OperatorSnapshot",
    "OperatorViewService",
    "PeerTrustCommand",
    "PeerTrustResult",
]
