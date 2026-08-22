"""Authorized tenant-scoped worker and queue operations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import JsonValue, WorkStatus
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
    Role,
)
from aegis_agent_platform.queueing import WorkQueue
from aegis_agent_platform.runtime import RuntimeTelemetry
from aegis_agent_platform.tenancy import TenantContext


class OperationDeniedError(PermissionError):
    """An authenticated principal lacks the required tenant permission."""


@dataclass(frozen=True, slots=True)
class RequeueApproval:
    """Explicit approval evidence required for a DLQ requeue."""

    approval_id: UUID
    approved_by: str
    approved_at: datetime
    scope: str

    def __post_init__(self) -> None:
        if not self.approved_by or self.approved_at.tzinfo is None:
            raise ValueError("approval actor and time are required")
        if self.scope != "dlq:requeue":
            raise ValueError("approval scope must be dlq:requeue")


class OperationsRepository(Protocol):
    """Payload-free operational persistence view."""

    async def status(
        self,
        context: TenantContext,
        *,
        status: WorkStatus | None = None,
        limit: int = 100,
        cursor: tuple[datetime, UUID] | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]: ...

    async def pending_status(
        self,
        context: TenantContext,
        *,
        limit: int = 100,
        cursor: tuple[datetime, UUID] | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]: ...

    async def cancel_by_id(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        at: datetime,
        actor_id: str,
    ) -> None: ...

    async def requeue_dead_letter(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        at: datetime,
        approval: RequeueApproval,
        actor_id: str,
    ) -> None: ...

    async def approve_dead_letter_requeue(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        approval: RequeueApproval,
        expires_at: datetime,
    ) -> None: ...

    async def reconcile_expired(
        self,
        context: TenantContext,
        *,
        now: datetime,
        limit: int = 100,
    ) -> tuple[UUID, ...]: ...


class WorkerOperations:
    """Authorization boundary for bounded queue and worker operations."""

    def __init__(
        self,
        repository: OperationsRepository,
        queue: WorkQueue,
        authorization: AuthorizationService | None = None,
        telemetry: RuntimeTelemetry | None = None,
    ) -> None:
        self._repository = repository
        self._queue = queue
        self._authorization = authorization or AuthorizationService()
        self._telemetry = telemetry or RuntimeTelemetry()

    async def work_status(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        status: WorkStatus | None = None,
        limit: int = 100,
        cursor: tuple[datetime, UUID] | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        self._require(principal, context, Permission.QUEUE_READ, at)
        return await self._repository.status(
            context,
            status=status,
            limit=limit,
            cursor=cursor,
        )

    async def pending(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        limit: int = 100,
        cursor: tuple[datetime, UUID] | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        self._require(principal, context, Permission.QUEUE_READ, at)
        return await self._repository.pending_status(
            context,
            limit=limit,
            cursor=cursor,
        )

    async def cancel(
        self,
        principal: Principal,
        context: TenantContext,
        work_id: UUID,
        *,
        at: datetime,
    ) -> None:
        self._require(principal, context, Permission.WORK_CANCEL, at)
        await self._repository.cancel_by_id(
            context,
            work_id,
            at=at,
            actor_id=principal.actor_id,
        )

    async def requeue_dead_letter(
        self,
        principal: Principal,
        context: TenantContext,
        work_id: UUID,
        approval: RequeueApproval,
        *,
        at: datetime,
    ) -> None:
        self._require(principal, context, Permission.DLQ_REQUEUE, at)
        if approval.approved_by == principal.actor_id:
            raise OperationDeniedError("requeue requires a different approving actor")
        await self._repository.requeue_dead_letter(
            context,
            work_id,
            at=at,
            approval=approval,
            actor_id=principal.actor_id,
        )

    async def approve_dead_letter_requeue(
        self,
        principal: Principal,
        context: TenantContext,
        work_id: UUID,
        approval_id: UUID,
        *,
        at: datetime,
        expires_at: datetime,
    ) -> RequeueApproval:
        self._require(principal, context, Permission.DLQ_REQUEUE, at)
        approval = RequeueApproval(
            approval_id=approval_id,
            approved_by=principal.actor_id,
            approved_at=at,
            scope="dlq:requeue",
        )
        await self._repository.approve_dead_letter_requeue(
            context,
            work_id,
            approval=approval,
            expires_at=expires_at,
        )
        return approval

    async def reconcile(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=Permission.WORK_RECONCILE,
            at=at,
        )
        if not decision.allowed or not {
            Role.TENANT_ADMIN,
            Role.PLATFORM_ADMIN,
        }.intersection(decision.active_roles):
            raise OperationDeniedError("operator or administrator permission required")
        try:
            result = await self._repository.reconcile_expired(
                context,
                now=at,
                limit=limit,
            )
        except Exception:
            self._telemetry.reconciliation("failure")
            raise
        self._telemetry.reconciliation("success")
        return result

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        permission: Permission,
        at: datetime,
    ) -> None:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=permission,
            at=at,
        )
        if not decision.allowed:
            raise OperationDeniedError(decision.reason)


__all__ = [
    "OperationDeniedError",
    "OperationsRepository",
    "RequeueApproval",
    "WorkerOperations",
]
