"""Pure distributed-work contracts and deterministic transition rules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import ClassVar, Self
from uuid import UUID

from aegis_agent_platform.domain.events import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    TraceContext,
    freeze_json_mapping,
)


class _StringConstant(str):
    _values: ClassVar[dict[str, Self]]

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        cls._values = {}

    def __new__(cls, value: str) -> Self:
        try:
            return cls._values[value]
        except KeyError as error:
            raise ValueError(f"{value!r} is not a valid {cls.__name__}") from error

    @classmethod
    def _define(cls, value: str) -> Self:
        member: Self = str.__new__(cls, value)
        cls._values[value] = member
        return member

    @property
    def value(self) -> str:
        return str(self)


class WorkStatus(_StringConstant):
    """Authoritative lifecycle states reconstructed from work events."""

    REQUESTED: ClassVar[WorkStatus]
    PUBLISHED: ClassVar[WorkStatus]
    CLAIMED: ClassVar[WorkStatus]
    RUNNING: ClassVar[WorkStatus]
    RETRY_WAIT: ClassVar[WorkStatus]
    SUCCEEDED: ClassVar[WorkStatus]
    FAILED: ClassVar[WorkStatus]
    CANCELLED: ClassVar[WorkStatus]
    DEAD_LETTER: ClassVar[WorkStatus]


WorkStatus.REQUESTED = WorkStatus._define("requested")
WorkStatus.PUBLISHED = WorkStatus._define("published")
WorkStatus.CLAIMED = WorkStatus._define("claimed")
WorkStatus.RUNNING = WorkStatus._define("running")
WorkStatus.RETRY_WAIT = WorkStatus._define("retry_wait")
WorkStatus.SUCCEEDED = WorkStatus._define("succeeded")
WorkStatus.FAILED = WorkStatus._define("failed")
WorkStatus.CANCELLED = WorkStatus._define("cancelled")
WorkStatus.DEAD_LETTER = WorkStatus._define("dead_letter")


class FailureClass(_StringConstant):
    """Stable retry policy classification, independent of exception classes."""

    RETRYABLE: ClassVar[FailureClass]
    PERMANENT: ClassVar[FailureClass]
    CANCELLED: ClassVar[FailureClass]
    TIMEOUT: ClassVar[FailureClass]
    WORKER_BUG: ClassVar[FailureClass]


FailureClass.RETRYABLE = FailureClass._define("retryable")
FailureClass.PERMANENT = FailureClass._define("permanent")
FailureClass.CANCELLED = FailureClass._define("cancelled")
FailureClass.TIMEOUT = FailureClass._define("timeout")
FailureClass.WORKER_BUG = FailureClass._define("worker_bug")


TERMINAL_WORK_STATUSES = frozenset(
    {
        WorkStatus.SUCCEEDED,
        WorkStatus.FAILED,
        WorkStatus.CANCELLED,
        WorkStatus.DEAD_LETTER,
    }
)


@dataclass(frozen=True, slots=True)
class WorkRequest:
    """Immutable tenant-bound unit of provider-neutral work."""

    work_id: UUID
    tenant_id: str
    work_kind: str
    idempotency_key: str
    correlation_id: UUID
    requested_at: datetime
    payload: Mapping[str, JsonValue]
    causation_id: UUID | None = None
    trace_context: TraceContext | None = None
    max_attempts: int = 5
    timeout_seconds: int = 300
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.work_kind or not self.idempotency_key:
            raise ValueError("tenant, work kind, and idempotency key are required")
        if self.requested_at.tzinfo is None:
            raise ValueError("requested_at must be timezone-aware")
        if not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if not 1 <= self.timeout_seconds <= 86_400:
            raise ValueError("timeout_seconds must be between 1 and 86400")
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        object.__setattr__(self, "payload", freeze_json_mapping(self.payload))


@dataclass(frozen=True, slots=True)
class WorkLease:
    """Renewable PostgreSQL lease whose generation is a fencing token."""

    work_id: UUID
    tenant_id: str
    token: UUID
    generation: int
    owner: str
    attempt: int
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.owner:
            raise ValueError("lease tenant and owner are required")
        if self.generation < 1 or self.attempt < 1:
            raise ValueError("lease generation and attempt must be positive")
        timestamps = (self.acquired_at, self.heartbeat_at, self.expires_at)
        if any(value.tzinfo is None for value in timestamps):
            raise ValueError("lease timestamps must be timezone-aware")
        if self.expires_at <= self.heartbeat_at:
            raise ValueError("lease expiry must follow heartbeat")


@dataclass(frozen=True, slots=True)
class WorkTransition:
    """Data required to append one additive work lifecycle event."""

    event_type: DomainEventType
    occurred_at: datetime
    details: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )
    lease: WorkLease | None = None

    def __post_init__(self) -> None:
        if not str(self.event_type).startswith("work."):
            raise ValueError("work transition requires a work event type")
        if self.occurred_at.tzinfo is None:
            raise ValueError("transition time must be timezone-aware")
        object.__setattr__(self, "details", freeze_json_mapping(self.details))

    def to_event(
        self,
        request: WorkRequest,
        *,
        event_id: UUID,
        causation_id: UUID | None,
    ) -> EventEnvelope:
        """Create a replay-compatible immutable event without generating values."""
        payload: dict[str, JsonValue] = dict(self.details)
        payload.update(
            {
                "work_id": str(request.work_id),
                "work_kind": request.work_kind,
            }
        )
        if self.lease is not None:
            if (
                self.lease.work_id != request.work_id
                or self.lease.tenant_id != request.tenant_id
            ):
                raise ValueError("lease does not belong to work request")
            payload.update(
                {
                    "lease_token": str(self.lease.token),
                    "lease_generation": self.lease.generation,
                    "attempt": self.lease.attempt,
                }
            )
        return EventEnvelope(
            event_id=event_id,
            tenant_id=request.tenant_id,
            aggregate_id=str(request.work_id),
            event_type=self.event_type,
            schema_version=1,
            occurred_at=self.occurred_at,
            payload=payload,
            correlation_id=request.correlation_id,
            causation_id=causation_id or request.causation_id,
            idempotency_key=(
                f"{request.idempotency_key}:{self.event_type.value}:{event_id}"
            ),
            trace_context=request.trace_context,
        )


def next_status(current: WorkStatus | None, event_type: DomainEventType) -> WorkStatus:
    """Apply the deterministic work state machine or reject an invalid edge."""
    transitions: dict[
        tuple[WorkStatus | None, DomainEventType],
        WorkStatus,
    ] = {
        (None, DomainEventType.WORK_REQUESTED): WorkStatus.REQUESTED,
        (WorkStatus.REQUESTED, DomainEventType.WORK_PUBLISHED): WorkStatus.PUBLISHED,
        (WorkStatus.RETRY_WAIT, DomainEventType.WORK_PUBLISHED): WorkStatus.PUBLISHED,
        (WorkStatus.PUBLISHED, DomainEventType.WORK_CLAIMED): WorkStatus.CLAIMED,
        (WorkStatus.RETRY_WAIT, DomainEventType.WORK_CLAIMED): WorkStatus.CLAIMED,
        (WorkStatus.CLAIMED, DomainEventType.WORK_STARTED): WorkStatus.RUNNING,
        (WorkStatus.CLAIMED, DomainEventType.WORK_LEASE_EXPIRED): WorkStatus.RETRY_WAIT,
        (WorkStatus.RUNNING, DomainEventType.WORK_LEASE_EXPIRED): WorkStatus.RETRY_WAIT,
        (WorkStatus.RUNNING, DomainEventType.WORK_SUCCEEDED): WorkStatus.SUCCEEDED,
        (WorkStatus.RUNNING, DomainEventType.WORK_FAILED): WorkStatus.FAILED,
        (
            WorkStatus.FAILED,
            DomainEventType.WORK_RETRY_SCHEDULED,
        ): WorkStatus.RETRY_WAIT,
        (WorkStatus.FAILED, DomainEventType.WORK_DEAD_LETTERED): WorkStatus.DEAD_LETTER,
        (
            WorkStatus.RUNNING,
            DomainEventType.WORK_RETRY_SCHEDULED,
        ): WorkStatus.RETRY_WAIT,
        (
            WorkStatus.CLAIMED,
            DomainEventType.WORK_RETRY_SCHEDULED,
        ): WorkStatus.RETRY_WAIT,
        (
            WorkStatus.DEAD_LETTER,
            DomainEventType.WORK_RETRY_SCHEDULED,
        ): WorkStatus.RETRY_WAIT,
        (WorkStatus.REQUESTED, DomainEventType.WORK_CANCELLED): WorkStatus.CANCELLED,
        (WorkStatus.PUBLISHED, DomainEventType.WORK_CANCELLED): WorkStatus.CANCELLED,
        (WorkStatus.CLAIMED, DomainEventType.WORK_CANCELLED): WorkStatus.CANCELLED,
        (WorkStatus.RUNNING, DomainEventType.WORK_CANCELLED): WorkStatus.CANCELLED,
        (WorkStatus.RETRY_WAIT, DomainEventType.WORK_CANCELLED): WorkStatus.CANCELLED,
        (
            WorkStatus.RUNNING,
            DomainEventType.WORK_DEAD_LETTERED,
        ): WorkStatus.DEAD_LETTER,
        (
            WorkStatus.RETRY_WAIT,
            DomainEventType.WORK_DEAD_LETTERED,
        ): WorkStatus.DEAD_LETTER,
    }
    if event_type in {
        DomainEventType.WORK_HEARTBEAT,
        DomainEventType.WORK_CANCEL_REQUESTED,
        DomainEventType.WORK_RECONCILED,
    }:
        if current is None or current in TERMINAL_WORK_STATUSES:
            raise ValueError(f"{event_type} is invalid from {current}")
        return current
    try:
        return transitions[(current, event_type)]
    except KeyError as error:
        raise ValueError(f"{event_type} is invalid from {current}") from error


__all__ = [
    "TERMINAL_WORK_STATUSES",
    "FailureClass",
    "WorkLease",
    "WorkRequest",
    "WorkStatus",
    "WorkTransition",
    "next_status",
]
