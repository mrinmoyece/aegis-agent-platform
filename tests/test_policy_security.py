"""Pure tenant governance and quota tests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal

import pytest

from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.policy import (
    Decision,
    InMemoryPolicyRepository,
    PolicyEvaluator,
    PolicyRequest,
    QuotaLimits,
    QuotaUsage,
    RiskLevel,
)
from aegis_agent_platform.tenancy import TenantContext
from security_helpers import TENANT_ID, tenant_policy

_CONTEXT = TenantContext(TENANT_ID)


def request() -> PolicyRequest:
    return PolicyRequest(
        tenant_id=TENANT_ID,
        model="model-safe",
        tool="search",
        connector="dynatrace",
        environment="production",
        risk=RiskLevel.LOW,
        estimated_tokens=100,
        estimated_cost_usd=Decimal("0.25"),
    )


def usage() -> QuotaUsage:
    return QuotaUsage(
        tenant_id=TENANT_ID,
        tenant_tokens_used=1_000,
        tenant_cost_usd=Decimal("2.00"),
        active_runs=1,
    )


def test_allowed_request_and_exact_quota_boundaries() -> None:
    policy = tenant_policy()
    exact = replace(
        request(),
        estimated_tokens=policy.quotas.max_run_tokens,
        estimated_cost_usd=policy.quotas.max_run_cost_usd,
    )
    exact_usage = QuotaUsage(
        tenant_id=TENANT_ID,
        tenant_tokens_used=(
            policy.quotas.max_tenant_tokens_per_period - exact.estimated_tokens
        ),
        tenant_cost_usd=(
            policy.quotas.max_tenant_cost_usd_per_period - exact.estimated_cost_usd
        ),
        active_runs=policy.quotas.max_concurrent_runs - 1,
    )

    decision = PolicyEvaluator().evaluate(_CONTEXT, policy, exact, exact_usage)

    assert decision.decision is Decision.ALLOW
    assert decision.reasons == ("policy_allowed",)


def test_high_risk_and_sensitive_tool_require_approval() -> None:
    policy = tenant_policy()

    risk = PolicyEvaluator().evaluate(
        _CONTEXT,
        policy,
        replace(request(), risk=RiskLevel.HIGH),
        usage(),
    )
    tool = PolicyEvaluator().evaluate(
        _CONTEXT,
        policy,
        replace(request(), tool="remediate"),
        usage(),
    )

    assert risk.decision is Decision.REQUIRE_APPROVAL
    assert tool.decision is Decision.REQUIRE_APPROVAL
    assert risk.required_approver_roles


@pytest.mark.parametrize(
    ("changed_request", "changed_usage", "reason"),
    [
        (
            replace(request(), tenant_id=TenantId("tenant-beta")),
            usage(),
            "cross_tenant_policy",
        ),
        (replace(request(), model="unknown"), usage(), "model_not_allowed"),
        (replace(request(), tool="unknown"), usage(), "tool_not_allowed"),
        (
            replace(request(), connector="unknown"),
            usage(),
            "connector_not_allowed",
        ),
        (
            replace(request(), environment="development"),
            usage(),
            "environment_not_allowed",
        ),
        (
            replace(request(), risk=RiskLevel.CRITICAL),
            usage(),
            "risk_threshold_exceeded",
        ),
        (
            replace(request(), estimated_tokens=1_001),
            usage(),
            "run_token_limit_exceeded",
        ),
        (
            replace(request(), estimated_cost_usd=Decimal("2.01")),
            usage(),
            "run_cost_limit_exceeded",
        ),
        (
            request(),
            replace(usage(), tenant_tokens_used=9_901),
            "tenant_token_limit_exceeded",
        ),
        (
            request(),
            replace(usage(), tenant_cost_usd=Decimal("19.76")),
            "tenant_cost_limit_exceeded",
        ),
        (
            request(),
            replace(usage(), active_runs=3),
            "tenant_concurrency_limit_exceeded",
        ),
    ],
)
def test_policy_and_quota_violations_deny_by_default(
    changed_request: PolicyRequest,
    changed_usage: QuotaUsage,
    reason: str,
) -> None:
    decision = PolicyEvaluator().evaluate(
        _CONTEXT,
        tenant_policy(),
        changed_request,
        changed_usage,
    )

    assert decision.decision is Decision.DENY
    assert reason in decision.reasons


def test_cross_tenant_usage_returns_only_the_cross_tenant_reason() -> None:
    decision = PolicyEvaluator().evaluate(
        _CONTEXT,
        tenant_policy(),
        replace(request(), model="unknown", tool="unknown"),
        replace(usage(), tenant_id=TenantId("tenant-beta")),
    )

    assert decision.decision is Decision.DENY
    assert decision.reasons == ("cross_tenant_policy",)


def test_duplicate_tenant_policies_are_rejected() -> None:
    policy = tenant_policy()

    with pytest.raises(ValueError, match="duplicate tenant policy"):
        InMemoryPolicyRepository((policy, policy))


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: QuotaUsage(TENANT_ID, -1, Decimal("0"), 0),
        lambda: PolicyRequest(
            TENANT_ID,
            "",
            "tool",
            "connector",
            "environment",
            RiskLevel.LOW,
            0,
            Decimal("0"),
        ),
        lambda: QuotaLimits(-1, Decimal("0"), 0, Decimal("0"), 0),
        lambda: QuotaLimits(0, Decimal("NaN"), 0, Decimal("0"), 0),
        lambda: PolicyRequest(
            TENANT_ID,
            "model",
            "tool",
            "connector",
            "environment",
            RiskLevel.LOW,
            0,
            Decimal("Infinity"),
        ),
        lambda: QuotaUsage(TENANT_ID, 0, Decimal("NaN"), 0),
    ],
)
def test_invalid_policy_inputs_are_rejected(
    constructor: Callable[[], object],
) -> None:
    with pytest.raises(ValueError, match=r"finite|negative|required"):
        constructor()
