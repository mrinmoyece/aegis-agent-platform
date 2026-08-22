"""Pure tenant policy and quota evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import IntEnum, StrEnum
from typing import Protocol

from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.tenancy import TenantContext


def _require_finite_non_negative_decimal(value: Decimal, name: str) -> None:
    if not value.is_finite():
        raise ValueError(f"{name} must be finite")
    if value < 0:
        raise ValueError(f"{name} cannot be negative")


class Decision(StrEnum):
    """Possible governance outcomes before a side effect is attempted."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class RiskLevel(IntEnum):
    """Ordered risk classification used by tenant policy."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class QuotaLimits:
    """Per-run and tenant-period limits enforced by policy evaluation."""

    max_run_tokens: int
    max_run_cost_usd: Decimal
    max_tenant_tokens_per_period: int
    max_tenant_cost_usd_per_period: Decimal
    max_concurrent_runs: int

    def __post_init__(self) -> None:
        numeric = (
            self.max_run_tokens,
            self.max_tenant_tokens_per_period,
            self.max_concurrent_runs,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("quota integer limits cannot be negative")
        _require_finite_non_negative_decimal(
            self.max_run_cost_usd,
            "max_run_cost_usd",
        )
        _require_finite_non_negative_decimal(
            self.max_tenant_cost_usd_per_period,
            "max_tenant_cost_usd_per_period",
        )


@dataclass(frozen=True, slots=True)
class TenantPolicy:
    """Versioned tenant governance policy with explicit allowlists."""

    tenant_id: TenantId
    version: str
    allowed_models: frozenset[str]
    allowed_tools: frozenset[str]
    allowed_connectors: frozenset[str]
    allowed_environments: frozenset[str]
    max_risk: RiskLevel
    approval_from_risk: RiskLevel
    tools_requiring_approval: frozenset[str]
    approver_roles: frozenset[Role]
    quotas: QuotaLimits

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("policy version is required")
        if not self.approver_roles:
            raise ValueError("at least one approver role is required")


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Provider-neutral proposed operation evaluated before durable intent."""

    tenant_id: TenantId
    model: str
    tool: str
    connector: str
    environment: str
    risk: RiskLevel
    estimated_tokens: int
    estimated_cost_usd: Decimal

    def __post_init__(self) -> None:
        names = (self.model, self.tool, self.connector, self.environment)
        if any(not value for value in names):
            raise ValueError("policy request selectors are required")
        if self.estimated_tokens < 0:
            raise ValueError("estimated tokens cannot be negative")
        _require_finite_non_negative_decimal(
            self.estimated_cost_usd,
            "estimated_cost_usd",
        )


@dataclass(frozen=True, slots=True)
class QuotaUsage:
    """Authoritative tenant-period usage supplied by a later runtime adapter."""

    tenant_id: TenantId
    tenant_tokens_used: int
    tenant_cost_usd: Decimal
    active_runs: int

    def __post_init__(self) -> None:
        if self.tenant_tokens_used < 0 or self.active_runs < 0:
            raise ValueError("quota usage cannot be negative")
        _require_finite_non_negative_decimal(
            self.tenant_cost_usd,
            "tenant_cost_usd",
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Auditable deterministic governance result."""

    decision: Decision
    reasons: tuple[str, ...]
    policy_version: str
    tenant_id: TenantId
    required_approver_roles: tuple[Role, ...] = ()


class PolicyEvaluator:
    """Evaluate allowlists, risk, approvals, and quotas without I/O."""

    def evaluate(
        self,
        context: TenantContext,
        policy: TenantPolicy,
        request: PolicyRequest,
        usage: QuotaUsage,
    ) -> PolicyDecision:
        # All mutable inputs are validated against the trusted context so a
        # caller cannot obtain a decision for a foreign tenant by supplying a
        # mutually-consistent but unauthorised triple.
        if (
            policy.tenant_id != context.tenant_id
            or request.tenant_id != context.tenant_id
            or usage.tenant_id != context.tenant_id
        ):
            return PolicyDecision(
                decision=Decision.DENY,
                reasons=("cross_tenant_policy",),
                policy_version=policy.version,
                tenant_id=policy.tenant_id,
            )
        reasons: list[str] = []
        selectors = (
            ("model_not_allowed", request.model, policy.allowed_models),
            ("tool_not_allowed", request.tool, policy.allowed_tools),
            ("connector_not_allowed", request.connector, policy.allowed_connectors),
            (
                "environment_not_allowed",
                request.environment,
                policy.allowed_environments,
            ),
        )
        reasons.extend(
            reason for reason, value, allowed in selectors if value not in allowed
        )
        if request.risk > policy.max_risk:
            reasons.append("risk_threshold_exceeded")
        quotas = policy.quotas
        if request.estimated_tokens > quotas.max_run_tokens:
            reasons.append("run_token_limit_exceeded")
        if request.estimated_cost_usd > quotas.max_run_cost_usd:
            reasons.append("run_cost_limit_exceeded")
        if (
            usage.tenant_tokens_used + request.estimated_tokens
            > quotas.max_tenant_tokens_per_period
        ):
            reasons.append("tenant_token_limit_exceeded")
        if (
            usage.tenant_cost_usd + request.estimated_cost_usd
            > quotas.max_tenant_cost_usd_per_period
        ):
            reasons.append("tenant_cost_limit_exceeded")
        if usage.active_runs >= quotas.max_concurrent_runs:
            reasons.append("tenant_concurrency_limit_exceeded")
        if reasons:
            return PolicyDecision(
                decision=Decision.DENY,
                reasons=tuple(reasons),
                policy_version=policy.version,
                tenant_id=policy.tenant_id,
            )
        requires_approval = (
            request.risk >= policy.approval_from_risk
            or request.tool in policy.tools_requiring_approval
        )
        return PolicyDecision(
            decision=(
                Decision.REQUIRE_APPROVAL if requires_approval else Decision.ALLOW
            ),
            reasons=(
                ("approval_required",) if requires_approval else ("policy_allowed",)
            ),
            policy_version=policy.version,
            tenant_id=policy.tenant_id,
            required_approver_roles=(
                tuple(sorted(policy.approver_roles, key=lambda role: role.value))
                if requires_approval
                else ()
            ),
        )


class PolicyRepository(Protocol):
    """Tenant-scoped policy persistence port."""

    def get(self, context: TenantContext) -> TenantPolicy | None:
        """Load the current policy for exactly one trusted tenant."""
        ...


class InMemoryPolicyRepository:
    """Deterministic policy store for tests and the local API slice."""

    def __init__(self, policies: tuple[TenantPolicy, ...]) -> None:
        self._policies: dict[TenantId, TenantPolicy] = {}
        for policy in policies:
            if policy.tenant_id in self._policies:
                raise ValueError("duplicate tenant policy is not allowed")
            self._policies[policy.tenant_id] = policy

    def get(self, context: TenantContext) -> TenantPolicy | None:
        return self._policies.get(context.tenant_id)


__all__ = [
    "Decision",
    "InMemoryPolicyRepository",
    "PolicyDecision",
    "PolicyEvaluator",
    "PolicyRepository",
    "PolicyRequest",
    "QuotaLimits",
    "QuotaUsage",
    "RiskLevel",
    "TenantPolicy",
]
