"""Authorized redacted investigation read operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from aegis_agent_platform.agents.repository import AgentRepository
from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
)
from aegis_agent_platform.tenancy import TenantContext


class InvestigationOperationDeniedError(PermissionError):
    """The authenticated principal lacks tenant investigation authority."""


class AgentOperations:
    """Deny-by-default API boundary over disposable read projections."""

    def __init__(
        self,
        repository: AgentRepository,
        authorization: AuthorizationService | None = None,
    ) -> None:
        self._repository = repository
        self._authorization = authorization or AuthorizationService()

    async def status(
        self,
        principal: Principal,
        context: TenantContext,
        run_id: UUID,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, at)
        return await self._repository.status(context, run_id)

    async def tasks(
        self,
        principal: Principal,
        context: TenantContext,
        run_id: UUID,
        *,
        at: datetime,
        after_ordinal: int = -1,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        self._require(principal, context, at)
        return await self._repository.task_page(
            context,
            run_id,
            after_ordinal=after_ordinal,
            limit=limit,
        )

    async def artifacts(
        self,
        principal: Principal,
        context: TenantContext,
        run_id: UUID,
        *,
        at: datetime,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        self._require(principal, context, at)
        return await self._repository.artifact_page(
            context,
            run_id,
            after_position=after_position,
            limit=limit,
        )

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        at: datetime,
    ) -> None:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=Permission.INVESTIGATION_READ,
            at=at,
        )
        if not decision.allowed:
            raise InvestigationOperationDeniedError(decision.reason)


__all__ = ["AgentOperations", "InvestigationOperationDeniedError"]
