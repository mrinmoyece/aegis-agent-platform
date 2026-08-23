"""Authenticated tenant-scoped redacted sandbox API operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import (
    JsonValue,
    SandboxApprovalBinding,
    SandboxRequest,
    replay_sandbox,
)
from aegis_agent_platform.identity import AuthorizationService, Permission, Principal
from aegis_agent_platform.sandbox.execution import (
    SandboxRequestDecision,
    SandboxRequestService,
)
from aegis_agent_platform.sandbox.policy import SandboxPolicy
from aegis_agent_platform.sandbox.repository import SandboxRepository
from aegis_agent_platform.tenancy import TenantContext


class SandboxPolicyRepository(Protocol):
    def get(self, context: TenantContext) -> SandboxPolicy | None: ...


class InMemorySandboxPolicyRepository:
    def __init__(self, policies: tuple[SandboxPolicy, ...]) -> None:
        self._policies = {policy.tenant_id: policy for policy in policies}

    def get(self, context: TenantContext) -> SandboxPolicy | None:
        return self._policies.get(str(context.tenant_id))


class SandboxOperations:
    """Deny-by-default request and bounded read façade."""

    def __init__(
        self,
        repository: SandboxRepository,
        requests: SandboxRequestService,
        policies: SandboxPolicyRepository,
        *,
        authorization: AuthorizationService | None = None,
    ) -> None:
        self._repository = repository
        self._requests = requests
        self._policies = policies
        self._authorization = authorization or AuthorizationService()

    async def request(
        self,
        principal: Principal,
        context: TenantContext,
        request: SandboxRequest,
        binding: SandboxApprovalBinding,
    ) -> SandboxRequestDecision:
        policy = self._policies.get(context)
        if policy is None:
            raise PermissionError("sandbox_policy_not_configured")
        return await self._requests.request(
            principal,
            context,
            request,
            policy,
            binding,
        )

    async def status(
        self,
        principal: Principal,
        context: TenantContext,
        sandbox_id: UUID,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue] | None:
        self._require(principal, context, at)
        events = await self._repository.load(context, sandbox_id)
        if not events:
            return None
        state = replay_sandbox(events)
        request = state.request
        return {
            "approval_id": str(request.linkage.approval_id),
            "approval_scope_digest": state.approval_scope_digest,
            "cleanup_attempts": state.cleanup_attempts,
            "image_digest": request.spec.image_digest,
            "policy_digest": state.policy_digest,
            "purpose": request.purpose.value,
            "quarantined": state.quarantine_reason is not None,
            "remediation_action_id": str(request.linkage.remediation_action_id),
            "remediation_plan_id": str(request.linkage.remediation_plan_id),
            "run_id": str(request.linkage.run_id),
            "sandbox_id": str(request.sandbox_id),
            "spec_digest": request.spec.digest,
            "status": state.status.value,
            "task_id": str(request.linkage.task_id),
            "version": state.version,
            "redacted": True,
        }

    async def page(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        self._require(principal, context, at)
        return await self._repository.page(
            context,
            after_sandbox_id=after_sandbox_id,
            limit=limit,
        )

    async def artifacts(
        self,
        principal: Principal,
        context: TenantContext,
        sandbox_id: UUID,
        *,
        at: datetime,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        self._require(principal, context, at)
        return await self._repository.artifact_page(
            context,
            sandbox_id,
            after_position=after_position,
            limit=limit,
        )

    async def cleanup_queue(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        self._require(principal, context, at)
        return await self._repository.cleanup_page(
            context,
            after_sandbox_id=after_sandbox_id,
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
            permission=Permission.SANDBOX_READ,
            at=at,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)


__all__ = [
    "InMemorySandboxPolicyRepository",
    "SandboxOperations",
    "SandboxPolicyRepository",
]
