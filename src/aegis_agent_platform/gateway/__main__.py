"""Safe deterministic mock completion diagnostic; never calls a live provider."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

from aegis_agent_platform.config import Environment
from aegis_agent_platform.domain import (
    FinishReason,
    MessageRole,
    ModelCapabilities,
    ModelIdentity,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PricingVersion,
    SafetyOutcome,
    SafetyResult,
    TextPart,
    TokenUsage,
    WorkLease,
)
from aegis_agent_platform.gateway.catalog import ModelCatalog, ModelCatalogEntry
from aegis_agent_platform.gateway.repository import InMemoryGatewayRepository
from aegis_agent_platform.gateway.resilience import ProviderControls, RetryPolicy
from aegis_agent_platform.gateway.service import ModelGateway
from aegis_agent_platform.gateway.telemetry import GatewayMetrics, GatewayTracer
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.policy import QuotaLimits, RiskLevel, TenantPolicy
from aegis_agent_platform.providers import ScriptedModelProvider
from aegis_agent_platform.runtime.backoff import ExponentialBackoff
from aegis_agent_platform.tenancy import TenantContext

_TENANT = TenantId("diagnostic-local")
_RUN_ID = UUID("00000000-0000-4000-8000-000000000001")
_REQUEST_ID = UUID("00000000-0000-4000-8000-000000000002")
_LEASE_TOKEN = UUID("00000000-0000-4000-8000-000000000003")
_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_MODEL = ModelIdentity("mock", "aegis-diagnostic-v1")


async def run_mock_diagnostic(prompt: str) -> dict[str, object]:
    if not prompt or len(prompt) > 1_000:
        raise ValueError("diagnostic prompt must contain 1 to 1000 characters")
    request = ModelRequest(
        request_id=_REQUEST_ID,
        tenant_id=str(_TENANT),
        run_id=_RUN_ID,
        messages=(ModelMessage(MessageRole.USER, (TextPart(prompt),)),),
        max_output_tokens=64,
        prompt_token_estimate=max(1, len(prompt) // 4),
        requested_model=_MODEL,
        timeout_seconds=5,
        idempotency_key="diagnostic-call-v1",
    )
    response = ModelResponse(
        request_id=request.request_id,
        model=_MODEL,
        content=(TextPart("Mock completion succeeded; no network was used."),),
        finish_reason=FinishReason.STOP,
        safety=SafetyResult(SafetyOutcome.ALLOWED),
        usage=TokenUsage(input_tokens=request.prompt_token_estimate, output_tokens=9),
        latency_ms=1,
        provider_request_id="mock-request-1",
    )
    pricing = PricingVersion(
        "mock-pricing-v1",
        _NOW,
        input_per_million_usd=Decimal("0.10"),
        output_per_million_usd=Decimal("0.20"),
    )
    entry = ModelCatalogEntry(
        identity=_MODEL,
        capabilities=ModelCapabilities(
            max_context_tokens=8_192,
            max_output_tokens=1_024,
            supports_tools=True,
            supports_vision=False,
            supports_structured_output=True,
        ),
        pricing=pricing,
        environments=frozenset({Environment.DEVELOPMENT, Environment.TEST}),
        data_residencies=frozenset({"local"}),
        provider_retains_data=False,
        cost_rank=0,
        latency_rank=0,
    )
    lease = WorkLease(
        work_id=_RUN_ID,
        tenant_id=str(_TENANT),
        token=_LEASE_TOKEN,
        generation=1,
        owner="diagnostic",
        attempt=1,
        acquired_at=_NOW,
        heartbeat_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )
    repository = InMemoryGatewayRepository(
        (lease,),
        uuid_factory=_diagnostic_uuid_factory(),
    )
    catalog = ModelCatalog((entry,))
    controls = ProviderControls(
        (_MODEL,),
        concurrency=1,
        requests_per_minute=10,
        tokens_per_minute=10_000,
        clock=lambda: 0,
    )
    gateway = ModelGateway(
        catalog=catalog,
        providers={"mock": ScriptedModelProvider("mock", (response,))},
        repository=repository,
        controls=controls,
        retry_policy=RetryPolicy(1, 0, ExponentialBackoff()),
        metrics=GatewayMetrics((_MODEL,)),
        tracer=GatewayTracer((_MODEL,)),
        clock=lambda: _NOW,
    )
    policy = TenantPolicy(
        tenant_id=_TENANT,
        version="diagnostic-policy-v1",
        allowed_models=frozenset({_MODEL.catalog_key}),
        allowed_tools=frozenset(),
        allowed_connectors=frozenset(),
        allowed_environments=frozenset({Environment.DEVELOPMENT.value}),
        max_risk=RiskLevel.LOW,
        approval_from_risk=RiskLevel.CRITICAL,
        tools_requiring_approval=frozenset(),
        approver_roles=frozenset({Role.APPROVER}),
        quotas=QuotaLimits(
            max_run_tokens=10_000,
            max_run_cost_usd=Decimal("1"),
            max_tenant_tokens_per_period=100_000,
            max_tenant_cost_usd_per_period=Decimal("10"),
            max_concurrent_runs=1,
        ),
        allowed_providers=frozenset({"mock"}),
        allowed_data_residencies=frozenset({"local"}),
    )
    result = await gateway.complete(
        TenantContext(_TENANT),
        request,
        lease,
        policy,
        environment=Environment.DEVELOPMENT,
    )
    return {
        "provider": result.model.provider,
        "model": result.model.model,
        "finish_reason": result.finish_reason.value,
        "text": "".join(
            part.text for part in result.content if isinstance(part, TextPart)
        ),
        "input_tokens": result.usage.input_tokens,
        "output_tokens": result.usage.output_tokens,
        "durable_event_types": [event.event_type for event in repository.events],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prompt",
        default="Explain why intent must precede model network effects.",
    )
    arguments = parser.parse_args()
    print(json.dumps(asyncio.run(run_mock_diagnostic(arguments.prompt)), indent=2))


def _diagnostic_uuid_factory() -> Callable[[], UUID]:
    values = iter(
        UUID(f"00000000-0000-4000-8000-{index:012d}") for index in range(4, 64)
    )
    return lambda: next(values)


if __name__ == "__main__":
    main()
