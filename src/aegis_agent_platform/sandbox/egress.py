"""Brokered egress decision boundary; execution remains default-deny."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from aegis_agent_platform.domain import EgressRule, SandboxRequest
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class EgressDecision:
    allowed: bool
    reason: str
    rule: EgressRule
    policy_digest: str
    decided_at: datetime

    def __post_init__(self) -> None:
        if not self.reason or len(self.reason) > 128:
            raise ValueError("egress decision reason must be bounded")
        if len(self.policy_digest) != 64:
            raise ValueError("egress decision policy digest is invalid")
        if self.decided_at.tzinfo is None:
            raise ValueError("egress decision time must be timezone-aware")


class EgressBroker(Protocol):
    """External enforcement port; decisions alone do not provide isolation."""

    @property
    def enforcement_ready(self) -> bool: ...

    async def authorize(
        self,
        context: TenantContext,
        request: SandboxRequest,
        rule: EgressRule,
        *,
        policy_digest: str,
        at: datetime,
    ) -> EgressDecision: ...


class DenyAllEgressBroker:
    """Honest default when no verified proxy/network enforcement exists."""

    @property
    def enforcement_ready(self) -> bool:
        return True

    async def authorize(
        self,
        context: TenantContext,
        request: SandboxRequest,
        rule: EgressRule,
        *,
        policy_digest: str,
        at: datetime,
    ) -> EgressDecision:
        if request.linkage.tenant_id != str(context.tenant_id):
            raise PermissionError("cross_tenant_egress_request")
        return EgressDecision(
            allowed=False,
            reason="egress_default_deny",
            rule=rule,
            policy_digest=policy_digest,
            decided_at=at,
        )


__all__ = ["DenyAllEgressBroker", "EgressBroker", "EgressDecision"]
