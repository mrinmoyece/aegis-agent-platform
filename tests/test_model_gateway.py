"""Deterministic model-gateway contracts, routing, budgets, and resilience."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from aegis_agent_platform.config import Environment
from aegis_agent_platform.domain import (
    DomainEventType,
    FinishReason,
    ImagePart,
    JsonSchema,
    JsonValue,
    MessageRole,
    ModelCapabilities,
    ModelErrorClass,
    ModelGatewayError,
    ModelIdentity,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PricingVersion,
    ProviderIdentity,
    SafetyOutcome,
    SafetyResult,
    TextPart,
    TokenUsage,
    ToolCallPart,
    ToolCallProposal,
    ToolDefinition,
    ToolResultPart,
    WorkLease,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.gateway import (
    BudgetDeniedError,
    BudgetReservation,
    CatalogError,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    GatewayMetrics,
    GatewayOperations,
    GatewayTracer,
    InMemoryGatewayRepository,
    ModelCatalog,
    ModelCatalogEntry,
    ModelGateway,
    ModelRouter,
    ProviderControls,
    RetryPolicy,
    RouteDeniedError,
    TokenBucket,
    estimate_cost,
    validate_object,
)
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.policy import QuotaLimits, RiskLevel, TenantPolicy
from aegis_agent_platform.providers import ScriptedModelProvider
from aegis_agent_platform.runtime.backoff import ExponentialBackoff
from aegis_agent_platform.tenancy import TenantContext

NOW = datetime(2026, 1, 1, tzinfo=UTC)
TENANT = TenantId("tenant-model")
RUN_ID = UUID("10000000-0000-4000-8000-000000000001")
MODEL_A = ModelIdentity("mock-a", "model-cheap")
MODEL_B = ModelIdentity("mock-b", "model-fast")


def pricing(version: str = "price-v1", multiplier: str = "1") -> PricingVersion:
    value = Decimal(multiplier)
    return PricingVersion(
        version,
        NOW,
        input_per_million_usd=value,
        output_per_million_usd=value * 2,
        cache_read_per_million_usd=value / 2,
        cache_write_per_million_usd=value,
        reasoning_per_million_usd=value * 3,
    )


def catalog_entry(
    identity: ModelIdentity = MODEL_A,
    *,
    cost_rank: int = 0,
    latency_rank: int = 1,
    tools: bool = True,
    vision: bool = True,
    structured: bool = True,
    retained: bool = False,
) -> ModelCatalogEntry:
    return ModelCatalogEntry(
        identity=identity,
        capabilities=ModelCapabilities(
            max_context_tokens=8_192,
            max_output_tokens=2_048,
            supports_tools=tools,
            supports_vision=vision,
            supports_structured_output=structured,
            supports_reasoning_tokens=True,
            supports_cache_tokens=True,
        ),
        pricing=pricing(
            f"{identity.provider}-price-v1",
            "1" if cost_rank == 0 else "2",
        ),
        environments=frozenset(
            {Environment.DEVELOPMENT, Environment.TEST, Environment.PRODUCTION}
        ),
        data_residencies=frozenset({"eu"}),
        provider_retains_data=retained,
        cost_rank=cost_rank,
        latency_rank=latency_rank,
    )


def policy(
    *,
    models: frozenset[str] | None = None,
    max_run_tokens: int = 10_000,
    max_tenant_tokens: int = 100_000,
) -> TenantPolicy:
    return TenantPolicy(
        tenant_id=TENANT,
        version="policy-model-v1",
        allowed_models=models or frozenset({MODEL_A.catalog_key, MODEL_B.catalog_key}),
        allowed_tools=frozenset(),
        allowed_connectors=frozenset(),
        allowed_environments=frozenset({"test", "development", "production"}),
        max_risk=RiskLevel.LOW,
        approval_from_risk=RiskLevel.CRITICAL,
        tools_requiring_approval=frozenset(),
        approver_roles=frozenset({Role.APPROVER}),
        quotas=QuotaLimits(
            max_run_tokens=max_run_tokens,
            max_run_cost_usd=Decimal("10"),
            max_tenant_tokens_per_period=max_tenant_tokens,
            max_tenant_cost_usd_per_period=Decimal("100"),
            max_concurrent_runs=10,
        ),
        allowed_providers=frozenset({"mock-a", "mock-b"}),
        allowed_data_residencies=frozenset({"eu"}),
    )


def request(
    *,
    request_id: UUID | None = None,
    run_id: UUID = RUN_ID,
    requested_model: ModelIdentity | None = None,
    messages: tuple[ModelMessage, ...] | None = None,
    tools: tuple[ToolDefinition, ...] = (),
    response_schema: JsonSchema | None = None,
    idempotency_key: str | None = None,
) -> ModelRequest:
    identifier = request_id or uuid4()
    return ModelRequest(
        request_id=identifier,
        tenant_id=str(TENANT),
        run_id=run_id,
        messages=messages or (ModelMessage(MessageRole.USER, (TextPart("hello"),)),),
        max_output_tokens=100,
        prompt_token_estimate=20,
        requested_model=requested_model,
        tools=tools,
        response_schema=response_schema,
        timeout_seconds=5,
        idempotency_key=idempotency_key or f"request-{identifier}",
    )


def response(
    value: ModelRequest,
    model: ModelIdentity = MODEL_A,
    *,
    content: tuple[TextPart | ToolCallPart, ...] | None = None,
    structured_output: dict[str, JsonValue] | None = None,
) -> ModelResponse:
    return ModelResponse(
        request_id=value.request_id,
        model=model,
        content=content or (TextPart("done"),),
        finish_reason=(
            FinishReason.TOOL_CALLS
            if content and isinstance(content[0], ToolCallPart)
            else FinishReason.STOP
        ),
        safety=SafetyResult(SafetyOutcome.ALLOWED),
        usage=TokenUsage(
            input_tokens=20,
            output_tokens=10,
            cache_read_tokens=2,
            cache_write_tokens=1,
            reasoning_tokens=3,
        ),
        latency_ms=12,
        provider_request_id="provider-request-1",
        structured_output=structured_output,
    )


def lease(run_id: UUID = RUN_ID, generation: int = 1) -> WorkLease:
    return WorkLease(
        work_id=run_id,
        tenant_id=str(TENANT),
        token=uuid4(),
        generation=generation,
        owner="worker-1",
        attempt=1,
        acquired_at=NOW,
        heartbeat_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def gateway(
    providers: dict[str, ScriptedModelProvider],
    repository: InMemoryGatewayRepository,
    entries: tuple[ModelCatalogEntry, ...],
    *,
    max_attempts: int = 2,
    max_failovers: int = 1,
    clock: list[float] | None = None,
    tokens_per_minute: int = 100_000,
) -> ModelGateway:
    monotonic = (lambda: clock[0]) if clock is not None else (lambda: 0)
    identities = tuple(entry.identity for entry in entries)
    return ModelGateway(
        catalog=ModelCatalog(entries),
        providers=providers,
        repository=repository,
        controls=ProviderControls(
            identities,
            concurrency=2,
            requests_per_minute=100,
            tokens_per_minute=tokens_per_minute,
            circuit_failure_threshold=2,
            clock=monotonic,
        ),
        retry_policy=RetryPolicy(
            max_attempts,
            max_failovers,
            ExponentialBackoff(jitter=lambda _attempt, seconds: seconds),
        ),
        metrics=GatewayMetrics(identities),
        tracer=GatewayTracer(identities),
        clock=lambda: NOW,
        sleep=lambda _delay: asyncio.sleep(0),
    )


def test_domain_is_deeply_immutable_and_prices_every_token_class() -> None:
    arguments: dict[str, JsonValue] = {"query": ["a", {"nested": True}]}
    proposal = ToolCallProposal("call-1", "search", arguments)
    arguments["query"] = []
    usage = TokenUsage(100, 50, 10, 5, 2)

    assert proposal.arguments["query"] == ("a", {"nested": True})
    with pytest.raises(TypeError):
        proposal.arguments["new"] = "value"  # type: ignore[index]
    assert pricing().cost(usage) == Decimal("0.000216")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ModelCapabilities(1, 2, False, False, False),
        lambda: ModelRequest(
            uuid4(),
            str(TENANT),
            RUN_ID,
            (),
            1,
            1,
            idempotency_key="key",
        ),
        lambda: ImagePart("image/svg+xml", "https://example.test/image"),
        lambda: SafetyResult(SafetyOutcome.REFUSED),
        lambda: TokenUsage(-1, 0),
    ],
)
def test_domain_rejects_invalid_contracts(factory: Callable[[], object]) -> None:
    with pytest.raises(ValueError, match=r".+"):
        factory()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: TextPart(""),
        lambda: ImagePart("image/png", "file:///tmp/image.png"),
        lambda: ImagePart("image/png", "aegis-object://artifact-1"),
        lambda: ToolCallProposal("", "tool", {}),
        lambda: ToolResultPart("", {}),
        lambda: ModelMessage(MessageRole.USER, (TextPart("x"),), name=""),
        lambda: ModelMessage(
            MessageRole.SYSTEM,
            (ToolCallPart(ToolCallProposal("id", "tool", {})),),
        ),
        lambda: ModelMessage(MessageRole.TOOL, (TextPart("not a result"),)),
        lambda: JsonSchema("", {"type": "object"}),
        lambda: JsonSchema("bad", {"type": "array"}),
        lambda: ToolDefinition("", "", JsonSchema("x", {"type": "object"})),
        lambda: ProviderIdentity("", "eu"),
        lambda: ModelIdentity("", "model"),
        lambda: PricingVersion("", NOW, Decimal("1"), Decimal("1")),
        lambda: PricingVersion("v", NOW, Decimal("-1"), Decimal("1")),
        lambda: SafetyResult(SafetyOutcome.ALLOWED, "unexpected"),
        lambda: ModelResponse(
            uuid4(),
            MODEL_A,
            (),
            FinishReason.STOP,
            SafetyResult(SafetyOutcome.ALLOWED),
            TokenUsage(0, 0),
            -1,
        ),
        lambda: ModelResponse(
            uuid4(),
            MODEL_A,
            (),
            FinishReason.STOP,
            SafetyResult(SafetyOutcome.ALLOWED),
            TokenUsage(0, 0),
            0,
            provider_request_id="",
        ),
        lambda: ModelGatewayError(
            ModelErrorClass.TRANSIENT,
            "",
            retryable=True,
        ),
        lambda: ModelGatewayError(
            ModelErrorClass.TRANSIENT,
            "bad-delay",
            retryable=True,
            retry_after_seconds=-1,
        ),
    ],
)
def test_model_contract_validation_edges(factory: Callable[[], object]) -> None:
    with pytest.raises(ValueError, match=r".+"):
        factory()


@pytest.mark.parametrize(
    ("timeout", "temperature", "tokens"),
    [
        (0, Decimal("0"), 1),
        (601, Decimal("0"), 1),
        (1, Decimal("-0.1"), 1),
        (1, Decimal("2.1"), 1),
        (1, Decimal("0"), 0),
    ],
)
def test_model_request_bounds(
    timeout: float,
    temperature: Decimal,
    tokens: int,
) -> None:
    with pytest.raises(ValueError, match=r".+"):
        ModelRequest(
            uuid4(),
            str(TENANT),
            RUN_ID,
            (ModelMessage(MessageRole.USER, (TextPart("x"),)),),
            tokens,
            1,
            temperature=temperature,
            timeout_seconds=timeout,
            idempotency_key="key",
        )


def test_router_is_deterministic_and_fails_closed() -> None:
    entries = (
        catalog_entry(MODEL_A, cost_rank=0, latency_rank=2),
        catalog_entry(MODEL_B, cost_rank=1, latency_rank=0),
    )
    catalog = ModelCatalog(entries)
    routed = ModelRouter().route(
        request(),
        catalog=catalog,
        policy=policy(),
        environment=Environment.TEST,
    )

    assert routed.selected.identity == MODEL_A
    with pytest.raises(CatalogError):
        catalog.get(ModelIdentity("unknown", "unknown"))
    with pytest.raises(RouteDeniedError, match="model_not_allowed"):
        ModelRouter().route(
            request(requested_model=MODEL_A),
            catalog=catalog,
            policy=policy(models=frozenset({"other/model"})),
            environment=Environment.TEST,
        )


def test_router_enforces_capabilities_retention_residency_and_limits() -> None:
    schema = JsonSchema(
        "answer",
        {"type": "object", "properties": {"answer": {"type": "string"}}},
    )
    tool = ToolDefinition("search", "Search", schema)
    visual = ModelMessage(
        MessageRole.USER,
        (TextPart("inspect"), ImagePart("image/png", "https://example.test/i.png")),
    )
    denied_policy = policy()
    object.__setattr__(denied_policy, "allowed_data_residencies", frozenset({"us"}))
    with pytest.raises(RouteDeniedError) as failure:
        ModelRouter().route(
            request(messages=(visual,), tools=(tool,), response_schema=schema),
            catalog=ModelCatalog(
                (
                    catalog_entry(
                        tools=False,
                        vision=False,
                        structured=False,
                        retained=True,
                    ),
                )
            ),
            policy=denied_policy,
            environment=Environment.TEST,
        )

    assert {
        "tools_unsupported",
        "vision_unsupported",
        "structured_output_unsupported",
        "retention_not_allowed",
        "residency_not_allowed",
    }.issubset(set(failure.value.reasons))


def test_circuit_and_rate_limits_are_deterministic() -> None:
    now = [0.0]
    circuit = CircuitBreaker(2, recovery_seconds=10, clock=lambda: now[0])
    circuit.acquire()
    circuit.fail()
    circuit.acquire()
    circuit.fail()
    assert circuit.state.value == CircuitState.OPEN.value
    with pytest.raises(CircuitOpenError):
        circuit.acquire()
    now[0] = 10
    assert circuit.state.value == CircuitState.HALF_OPEN.value
    circuit.acquire()
    with pytest.raises(CircuitOpenError):
        circuit.acquire()
    circuit.succeed()
    assert circuit.state is CircuitState.CLOSED

    bucket = TokenBucket(2, 1, clock=lambda: now[0])
    assert bucket.consume()
    assert bucket.consume()
    assert not bucket.consume()
    now[0] += 1
    assert bucket.consume()


def test_schema_validation_rejects_invalid_output() -> None:
    schema = JsonSchema(
        "answer",
        {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        },
    )
    assert validate_object({"answer": "ok"}, schema)["answer"] == "ok"
    with pytest.raises(ModelGatewayError) as failure:
        validate_object({"answer": 2}, schema)
    assert failure.value.error_class is ModelErrorClass.SCHEMA


def test_gateway_records_intent_before_attempt_and_reconciles_usage() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    result = asyncio.run(
        service.complete(
            TenantContext(TENANT),
            model_request,
            work_lease,
            policy(models=frozenset({MODEL_A.catalog_key})),
            environment=Environment.TEST,
        )
    )

    event_types = [event.event_type for event in repository.events]
    assert result.content == (TextPart("done"),)
    assert event_types[:4] == [
        DomainEventType.MODEL_ROUTE_DECIDED,
        DomainEventType.MODEL_CALL_REQUESTED,
        DomainEventType.MODEL_BUDGET_RESERVED,
        DomainEventType.MODEL_CALL_STARTED,
    ]
    assert event_types[-3:] == [
        DomainEventType.MODEL_USAGE_RECORDED,
        DomainEventType.MODEL_BUDGET_CHARGED,
        DomainEventType.MODEL_BUDGET_RELEASED,
    ]
    requested = repository.events[1]
    assert "hello" not in repr(requested.payload)
    assert requested.payload["persistence_policy"] == "metadata_and_digest_only"
    assert repository.usage_summary(TenantContext(TENANT))["tokens"] == 36


def test_estimate_cost_reserves_highest_priced_token_class() -> None:
    reserved = estimate_cost(pricing("price-v2", "1"), 20, 100)

    assert reserved == Decimal("0.000360")


def test_local_token_limit_releases_reservation_without_provider_call() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
        tokens_per_minute=100,
    )

    with pytest.raises(ModelGatewayError) as failure:
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )

    assert failure.value.error_class is ModelErrorClass.RATE_LIMIT
    assert provider.calls == []
    assert not next(iter(repository.reservations.values())).active


def test_gateway_retries_then_falls_back_in_order() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    retryable = ModelGatewayError(
        ModelErrorClass.PROVIDER_UNAVAILABLE,
        "outage",
        retryable=True,
    )
    first = ScriptedModelProvider("mock-a", (retryable, retryable))
    second = ScriptedModelProvider("mock-b", (response(model_request, MODEL_B),))
    service = gateway(
        {"mock-a": first, "mock-b": second},
        repository,
        (
            catalog_entry(MODEL_A, cost_rank=0),
            catalog_entry(MODEL_B, cost_rank=1),
        ),
    )

    result = asyncio.run(
        service.complete(
            TenantContext(TENANT),
            model_request,
            work_lease,
            policy(),
            environment=Environment.TEST,
        )
    )

    assert result.model == MODEL_B
    assert len(first.calls) == 2
    assert len(second.calls) == 1
    assert DomainEventType.MODEL_FALLBACK_SELECTED in {
        event.event_type for event in repository.events
    }


def test_retry_failures_are_durably_recorded_before_success() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    retryable = ModelGatewayError(
        ModelErrorClass.TIMEOUT,
        "provider_timeout",
        retryable=True,
        billing_ambiguous=True,
    )
    provider = ScriptedModelProvider("mock-a", (retryable, response(model_request)))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=2,
        max_failovers=0,
    )

    result = asyncio.run(
        service.complete(
            TenantContext(TENANT),
            model_request,
            work_lease,
            policy(models=frozenset({MODEL_A.catalog_key})),
            environment=Environment.TEST,
        )
    )

    assert result.model == MODEL_A
    failures = [
        event
        for event in repository.events
        if event.event_type == DomainEventType.MODEL_CALL_TIMED_OUT
    ]
    assert len(failures) == 1
    assert failures[0].payload["billing_ambiguous"] is True
    assert failures[0].payload["attempt"] == 1


@pytest.mark.parametrize(
    "error_class",
    [
        ModelErrorClass.AUTHENTICATION,
        ModelErrorClass.AUTHORIZATION,
        ModelErrorClass.INVALID_REQUEST,
        ModelErrorClass.SAFETY,
        ModelErrorClass.SCHEMA,
    ],
)
def test_gateway_never_retries_permanent_failures(
    error_class: ModelErrorClass,
) -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider(
        "mock-a",
        (
            ModelGatewayError(error_class, "permanent", retryable=False),
            response(model_request),
        ),
    )
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
    )

    with pytest.raises(ModelGatewayError):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )
    assert len(provider.calls) == 1
    assert repository.reservations
    assert not next(iter(repository.reservations.values())).active


def test_stale_worker_cannot_call_charge_or_emit_response() -> None:
    model_request = request()
    stale = lease()
    current = lease(generation=2)
    repository = InMemoryGatewayRepository((stale,))
    repository.replace_lease(current)
    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    with pytest.raises(FencingError):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                stale,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )
    assert provider.calls == []
    assert repository.events == ()


def test_budget_reservation_race_allows_only_one_call() -> None:
    first_run = RUN_ID
    second_run = UUID("10000000-0000-4000-8000-000000000002")
    first_request = request(run_id=first_run)
    second_request = request(run_id=second_run)
    first_lease = lease(first_run)
    second_lease = lease(second_run)
    repository = InMemoryGatewayRepository((first_lease, second_lease))
    catalog = ModelCatalog((catalog_entry(),))
    route_one = ModelRouter().route(
        first_request,
        catalog=catalog,
        policy=policy(models=frozenset({MODEL_A.catalog_key})),
        environment=Environment.TEST,
    )
    route_two = ModelRouter().route(
        second_request,
        catalog=catalog,
        policy=policy(models=frozenset({MODEL_A.catalog_key})),
        environment=Environment.TEST,
    )
    constrained = policy(
        models=frozenset({MODEL_A.catalog_key}),
        max_tenant_tokens=120,
    )

    async def race() -> tuple[object, object]:
        outcomes = await asyncio.gather(
            repository.reserve(
                TenantContext(TENANT),
                first_request,
                first_lease,
                route_one,
                quotas=constrained.quotas,
                token_limit=120,
                cost_limit_usd=Decimal("0.001"),
                price_version="mock-a-price-v1",
                at=NOW,
            ),
            repository.reserve(
                TenantContext(TENANT),
                second_request,
                second_lease,
                route_two,
                quotas=constrained.quotas,
                token_limit=120,
                cost_limit_usd=Decimal("0.001"),
                price_version="mock-a-price-v1",
                at=NOW,
            ),
            return_exceptions=True,
        )
        return outcomes[0], outcomes[1]

    outcomes = asyncio.run(race())
    assert sum(isinstance(item, BudgetReservation) for item in outcomes) == 1
    assert sum(isinstance(item, BudgetDeniedError) for item in outcomes) == 1


def test_duplicate_request_returns_same_response_without_second_charge() -> None:
    model_request = request(idempotency_key="stable-key")
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    async def twice() -> tuple[ModelResponse, ModelResponse]:
        first = await service.complete(
            TenantContext(TENANT),
            model_request,
            work_lease,
            policy(models=frozenset({MODEL_A.catalog_key})),
            environment=Environment.TEST,
        )
        second = await service.complete(
            TenantContext(TENANT),
            model_request,
            work_lease,
            policy(models=frozenset({MODEL_A.catalog_key})),
            environment=Environment.TEST,
        )
        return first, second

    first, second = asyncio.run(twice())
    assert first is second
    assert len(provider.calls) == 1
    assert repository.usage_summary(TenantContext(TENANT))["calls"] == 1


def test_zero_token_success_counts_as_completed_call() -> None:
    model_request = request(idempotency_key="zero-token")
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    zero_usage = ModelResponse(
        request_id=model_request.request_id,
        model=MODEL_A,
        content=(TextPart("done"),),
        finish_reason=FinishReason.STOP,
        safety=SafetyResult(SafetyOutcome.ALLOWED),
        usage=TokenUsage(0, 0),
        latency_ms=1,
    )
    service = gateway(
        {"mock-a": ScriptedModelProvider("mock-a", (zero_usage,))},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    asyncio.run(
        service.complete(
            TenantContext(TENANT),
            model_request,
            work_lease,
            policy(models=frozenset({MODEL_A.catalog_key})),
            environment=Environment.TEST,
        )
    )

    assert repository.usage_summary(TenantContext(TENANT))["calls"] == 1


def test_sequential_calls_include_charged_usage_in_budget_checks() -> None:
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    first_request = request(
        idempotency_key="budget-first",
        request_id=UUID("10000000-0000-4000-8000-000000000010"),
    )
    second_request = request(
        idempotency_key="budget-second",
        request_id=UUID("10000000-0000-4000-8000-000000000011"),
    )
    provider = ScriptedModelProvider(
        "mock-a",
        (
            response(first_request),
            response(second_request),
        ),
    )
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )
    constrained = policy(
        models=frozenset({MODEL_A.catalog_key}),
        max_run_tokens=150,
    )

    asyncio.run(
        service.complete(
            TenantContext(TENANT),
            first_request,
            work_lease,
            constrained,
            environment=Environment.TEST,
        )
    )

    with pytest.raises(BudgetDeniedError, match="run_token_budget_exceeded"):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                second_request,
                work_lease,
                constrained,
                environment=Environment.TEST,
            )
        )


def test_estimate_reservation_cost_uses_local_route_candidates() -> None:
    repository = InMemoryGatewayRepository(())
    service = gateway(
        {
            "mock-a": ScriptedModelProvider("mock-a", ()),
            "mock-b": ScriptedModelProvider("mock-b", ()),
        },
        repository,
        (
            catalog_entry(MODEL_A, cost_rank=0, latency_rank=1),
            catalog_entry(MODEL_B, cost_rank=1, latency_rank=0),
        ),
    )
    estimated = service.estimate_reservation_cost(
        request(),
        policy(),
        environment=Environment.TEST,
    )
    assert estimated == Decimal("0.00072")


def test_open_circuit_returns_provider_unavailable_without_calling_provider() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    entry = catalog_entry()
    service = gateway(
        {"mock-a": provider},
        repository,
        (entry,),
        max_attempts=1,
        max_failovers=0,
    )
    circuit = service._controls.circuit(MODEL_A)
    for _ in range(circuit.failure_threshold):
        circuit.fail()
    outcome, error = asyncio.run(
        service._try_model(
            TenantContext(TENANT),
            model_request,
            work_lease,
            BudgetReservation(
                uuid4(),
                str(TENANT),
                model_request.run_id,
                model_request.request_id,
                120,
                Decimal("1"),
                "price-v1",
            ),
            entry,
            fallback_index=0,
            cancellation=None,
        )
    )
    assert outcome is None
    assert error is not None
    assert error.error_class is ModelErrorClass.PROVIDER_UNAVAILABLE
    assert provider.calls == []


def test_tool_arguments_and_structured_output_are_strictly_validated() -> None:
    schema = JsonSchema(
        "answer",
        {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        },
    )
    tool = ToolDefinition("answer", "Return answer", schema)
    model_request = request(tools=(tool,), response_schema=schema)
    work_lease = lease()
    invalid = response(
        model_request,
        content=(
            ToolCallPart(
                ToolCallProposal("call-1", "answer", {"answer": 7}),
            ),
        ),
        structured_output={"answer": "valid top level"},
    )
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (invalid,))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    with pytest.raises(ModelGatewayError) as failure:
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )
    assert failure.value.error_class is ModelErrorClass.SCHEMA
    assert not next(iter(repository.reservations.values())).active
    assert repository.usage_summary(TenantContext(TENANT))["tokens"] == 36


def test_service_constructor_and_budget_guards_fail_closed() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    entry = catalog_entry()
    with pytest.raises(ValueError, match="catalog provider"):
        gateway({}, repository, (entry,))

    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    service = gateway(
        {"mock-a": provider},
        repository,
        (entry,),
        max_attempts=1,
        max_failovers=0,
    )
    with pytest.raises(BudgetDeniedError):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(
                    models=frozenset({MODEL_A.catalog_key}),
                    max_run_tokens=10,
                ),
                environment=Environment.TEST,
            )
        )
    assert provider.calls == []


def test_invalid_request_schema_fails_before_provider_or_reservation() -> None:
    invalid_schema = JsonSchema(
        "answer",
        {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "$defs": {"broken": {"type": "not-a-real-type"}},
        },
    )
    model_request = request(
        tools=(ToolDefinition("answer", "Answer", invalid_schema),),
        response_schema=invalid_schema,
    )
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (response(model_request),))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    with pytest.raises(ModelGatewayError, match="invalid_json_schema"):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )

    assert provider.calls == []
    assert repository.events == ()


@pytest.mark.parametrize("wrong_request_id", [True, False])
def test_malformed_or_missing_structured_response_is_billed_before_failure(
    wrong_request_id: bool,
) -> None:
    schema = JsonSchema(
        "answer",
        {"type": "object", "properties": {"answer": {"type": "string"}}},
    )
    model_request = request(response_schema=schema)
    work_lease = lease()
    bad_response = ModelResponse(
        request_id=uuid4() if wrong_request_id else model_request.request_id,
        model=MODEL_A,
        content=(TextPart("missing structure"),),
        finish_reason=FinishReason.STOP,
        safety=SafetyResult(SafetyOutcome.ALLOWED),
        usage=TokenUsage(1, 1),
        latency_ms=1,
    )
    repository = InMemoryGatewayRepository((work_lease,))
    provider = ScriptedModelProvider("mock-a", (bad_response,))
    service = gateway(
        {"mock-a": provider},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    with pytest.raises(ModelGatewayError):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )
    assert not next(iter(repository.reservations.values())).active
    assert repository.usage_summary(TenantContext(TENANT))["calls"] == 1


def test_unknown_tool_call_is_rejected() -> None:
    schema = JsonSchema("tool", {"type": "object", "properties": {}})
    model_request = request(tools=(ToolDefinition("known", "Known", schema),))
    result = response(
        model_request,
        content=(ToolCallPart(ToolCallProposal("call", "unknown", {})),),
    )
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    service = gateway(
        {"mock-a": ScriptedModelProvider("mock-a", (result,))},
        repository,
        (catalog_entry(),),
        max_attempts=1,
        max_failovers=0,
    )

    with pytest.raises(ModelGatewayError, match="unknown_tool_call"):
        asyncio.run(
            service.complete(
                TenantContext(TENANT),
                model_request,
                work_lease,
                policy(models=frozenset({MODEL_A.catalog_key})),
                environment=Environment.TEST,
            )
        )


def test_repository_rejects_cross_tenant_and_usage_overage() -> None:
    model_request = request()
    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    route = ModelRouter().route(
        model_request,
        catalog=ModelCatalog((catalog_entry(),)),
        policy=policy(models=frozenset({MODEL_A.catalog_key})),
        environment=Environment.TEST,
    )
    with pytest.raises(ValueError, match="tenant"):
        asyncio.run(
            repository.reserve(
                TenantContext(TenantId("other")),
                model_request,
                work_lease,
                route,
                quotas=policy().quotas,
                token_limit=120,
                cost_limit_usd=Decimal("1"),
                price_version="v1",
                at=NOW,
            )
        )
    reservation = asyncio.run(
        repository.reserve(
            TenantContext(TENANT),
            model_request,
            work_lease,
            route,
            quotas=policy().quotas,
            token_limit=120,
            cost_limit_usd=Decimal("1"),
            price_version="v1",
            at=NOW,
        )
    )
    too_large = ModelResponse(
        request_id=model_request.request_id,
        model=MODEL_A,
        content=(TextPart("large"),),
        finish_reason=FinishReason.STOP,
        safety=SafetyResult(SafetyOutcome.ALLOWED),
        usage=TokenUsage(121, 1),
        latency_ms=1,
    )
    with pytest.raises(ModelGatewayError, match="token_reservation"):
        asyncio.run(
            repository.succeed(
                TenantContext(TENANT),
                model_request,
                work_lease,
                reservation,
                too_large,
                pricing(),
                at=NOW,
            )
        )


def test_metrics_and_gateway_operations_are_bounded_and_authorized() -> None:
    from security_helpers import binding, principal

    work_lease = lease()
    repository = InMemoryGatewayRepository((work_lease,))
    entries = (catalog_entry(),)
    controls = ProviderControls(
        (MODEL_A,),
        concurrency=1,
        requests_per_minute=10,
        tokens_per_minute=1_000,
        clock=lambda: 0,
    )
    metrics = GatewayMetrics((MODEL_A,))
    metrics.usage(MODEL_A, TokenUsage(1, 2, 3, 4, 5))
    with pytest.raises(ValueError, match="bounded"):
        metrics.add("unknown", MODEL_A)
    with pytest.raises(ValueError, match="bounded"):
        metrics.add("attempts", MODEL_B)
    with pytest.raises(ValueError, match="negative"):
        metrics.add("attempts", MODEL_A, -1)

    operations = GatewayOperations(
        ModelCatalog(entries),
        controls,
        repository,
    )
    tenant_principal = principal(
        (binding(tenant_id=TENANT, assigned_at=NOW - timedelta(hours=1)),),
        tenant_id=TENANT,
    )
    tenant_policy = policy(models=frozenset({MODEL_A.catalog_key}))
    catalog_view = operations.catalog(
        tenant_principal,
        TenantContext(TENANT),
        tenant_policy,
        at=NOW,
    )
    assert catalog_view[0]["pricing_version"] == "mock-a-price-v1"
    assert (
        operations.usage(
            tenant_principal,
            TenantContext(TENANT),
            at=NOW,
        )["tokens"]
        == 0
    )
    assert (
        operations.health(
            tenant_principal,
            TenantContext(TENANT),
            tenant_policy,
            at=NOW,
        )[0]["circuit_state"]
        == "closed"
    )
    with pytest.raises(PermissionError, match="cross_tenant"):
        operations.catalog(
            tenant_principal,
            TenantContext(TenantId("other")),
            tenant_policy,
            at=NOW,
        )
