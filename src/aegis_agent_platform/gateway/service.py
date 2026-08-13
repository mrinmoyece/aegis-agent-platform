"""Fenced, budgeted, policy-routed model gateway execution."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

from aegis_agent_platform.config import Environment
from aegis_agent_platform.domain import (
    ModelErrorClass,
    ModelGatewayError,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    WorkLease,
)
from aegis_agent_platform.gateway.catalog import (
    ModelCatalog,
    ModelCatalogEntry,
    ModelRouter,
    RouteDecision,
    RoutePreference,
)
from aegis_agent_platform.gateway.repository import (
    BudgetDeniedError,
    BudgetReservation,
    GatewayRepository,
    estimate_cost,
)
from aegis_agent_platform.gateway.resilience import (
    CircuitOpenError,
    ProviderControls,
    RetryPolicy,
)
from aegis_agent_platform.gateway.structured import validate_object, validate_schema
from aegis_agent_platform.gateway.telemetry import GatewayMetrics, GatewayTracer
from aegis_agent_platform.policy import TenantPolicy
from aegis_agent_platform.providers import CancellationToken, ModelProvider
from aegis_agent_platform.tenancy import TenantContext


class ModelGateway:
    """Coordinates durable intent, reservation, invocation, and reconciliation."""

    def __init__(
        self,
        *,
        catalog: ModelCatalog,
        providers: Mapping[str, ModelProvider],
        repository: GatewayRepository,
        controls: ProviderControls,
        retry_policy: RetryPolicy,
        metrics: GatewayMetrics,
        tracer: GatewayTracer,
        router: ModelRouter | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        catalog_providers = {entry.identity.provider for entry in catalog.entries()}
        if set(providers) != catalog_providers:
            raise ValueError("every catalog provider requires exactly one adapter")
        self._catalog = catalog
        self._providers = dict(providers)
        self._repository = repository
        self._controls = controls
        self._retry_policy = retry_policy
        self._metrics = metrics
        self._tracer = tracer
        self._router = router or ModelRouter()
        self._clock = clock
        self._sleep = sleep
        self._fault_hook = fault_hook or _no_fault

    async def complete(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        policy: TenantPolicy,
        *,
        environment: Environment,
        preference: RoutePreference = RoutePreference.COST,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        self._validate_request(request)
        cached = await self._repository.completed(context, request)
        if cached is not None:
            return cached
        route = self._route(
            request,
            policy=policy,
            environment=environment,
            preference=preference,
        )
        candidates = route.candidates[: self._retry_policy.max_failovers + 1]
        token_limit = request.prompt_token_estimate + request.max_output_tokens
        reservation_cost = self._reservation_cost(request, candidates)
        try:
            self._fault_hook("before_intent_append")
            reservation = await self._repository.reserve(
                context,
                request,
                lease,
                route,
                quotas=policy.quotas,
                token_limit=token_limit,
                cost_limit_usd=reservation_cost,
                price_version=route.selected.pricing.version,
                at=self._clock(),
            )
            self._fault_hook("after_intent_append")
        except BudgetDeniedError:
            self._metrics.add("budget_denials", route.selected.identity)
            raise
        self._metrics.add("route_decisions", route.selected.identity)
        last_error: ModelGatewayError | None = None
        for fallback_index, candidate in enumerate(candidates):
            if fallback_index > 0:
                self._metrics.add("fallbacks", candidate.identity)
            response, last_error = await self._try_model(
                context,
                request,
                lease,
                reservation,
                candidate,
                fallback_index=fallback_index,
                cancellation=cancellation,
            )
            if response is not None:
                try:
                    self._validate_response(request, response)
                    cost = candidate.pricing.cost(response.usage)
                    response = replace(response, cost_usd=cost)
                    self._fault_hook("before_result_append")
                    await self._repository.succeed(
                        context,
                        request,
                        lease,
                        reservation,
                        response,
                        candidate.pricing,
                        at=self._clock(),
                    )
                    self._fault_hook("after_result_append")
                except ModelGatewayError as error:
                    self._fault_hook("before_result_append")
                    await self._repository.fail(
                        context,
                        request,
                        lease,
                        reservation,
                        response,
                        candidate.pricing,
                        error,
                        at=self._clock(),
                    )
                    self._fault_hook("after_result_append")
                    raise
                self._metrics.usage(candidate.identity, response.usage)
                self._metrics.add("latency_ms", candidate.identity, response.latency_ms)
                self._metrics.add("cost_usd", candidate.identity, float(cost))
                self._metrics.add(
                    "reservation_drift_tokens",
                    candidate.identity,
                    token_limit - response.usage.billable_tokens,
                )
                self._metrics.add(
                    "reservation_drift_cost_usd",
                    candidate.identity,
                    float(reservation_cost - cost),
                )
                return response
            if last_error is not None and not last_error.retryable:
                break
        if last_error is None:
            last_error = ModelGatewayError(
                ModelErrorClass.PROVIDER_UNAVAILABLE,
                "no_provider_attempt_succeeded",
                retryable=True,
            )
        self._fault_hook("before_result_append")
        await self._repository.fail(
            context,
            request,
            lease,
            reservation,
            last_error,
            at=self._clock(),
        )
        self._fault_hook("after_result_append")
        raise last_error

    def estimate_reservation_cost(
        self,
        request: ModelRequest,
        policy: TenantPolicy,
        *,
        environment: Environment,
        preference: RoutePreference = RoutePreference.COST,
    ) -> Decimal:
        route = self._route(
            request,
            policy=policy,
            environment=environment,
            preference=preference,
        )
        return self._reservation_cost(
            request,
            route.candidates[: self._retry_policy.max_failovers + 1],
        )

    def _route(
        self,
        request: ModelRequest,
        *,
        policy: TenantPolicy,
        environment: Environment,
        preference: RoutePreference,
    ) -> RouteDecision:
        unavailable = frozenset(
            entry.identity
            for entry in self._catalog.entries()
            if self._controls.circuit(entry.identity).state.value == "open"
        )
        return self._router.route(
            request,
            catalog=self._catalog,
            policy=policy,
            environment=environment,
            unavailable=unavailable,
            preference=preference,
        )

    @staticmethod
    def _reservation_cost(
        request: ModelRequest,
        candidates: tuple[ModelCatalogEntry, ...],
    ) -> Decimal:
        return max(
            estimate_cost(
                candidate.pricing,
                request.prompt_token_estimate,
                request.max_output_tokens,
            )
            for candidate in candidates
        )

    async def _try_model(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        candidate: ModelCatalogEntry,
        *,
        fallback_index: int,
        cancellation: CancellationToken | None,
    ) -> tuple[ModelResponse | None, ModelGatewayError | None]:
        model = candidate.identity
        circuit = self._controls.circuit(model)
        try:
            circuit.acquire()
        except CircuitOpenError:
            self._metrics.add("circuit_open", model)
            return None, ModelGatewayError(
                ModelErrorClass.PROVIDER_UNAVAILABLE,
                "provider_circuit_open",
                retryable=True,
            )
        provider = self._providers[model.provider]
        last_error: ModelGatewayError | None = None
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            if not self._controls.admit(
                model,
                request.prompt_token_estimate + request.max_output_tokens,
            ):
                last_error = ModelGatewayError(
                    ModelErrorClass.RATE_LIMIT,
                    "local_rate_limit",
                    retryable=True,
                )
                self._metrics.add("rate_limits", model)
                break
            await self._repository.record_attempt(
                context,
                request,
                lease,
                reservation,
                provider=model.provider,
                model=model.model,
                attempt=attempt,
                fallback_index=fallback_index,
                at=self._clock(),
            )
            self._metrics.add("attempts", model)
            try:
                async with self._controls.semaphore(model):
                    with self._tracer.attempt(model):
                        self._fault_hook("before_side_effect")
                        response = await provider.complete(
                            request,
                            model,
                            cancellation=cancellation,
                        )
                        self._fault_hook("after_side_effect")
            except ModelGatewayError as error:
                last_error = error
                if error.error_class is ModelErrorClass.MALFORMED_RESPONSE:
                    self._metrics.add("malformed_responses", model)
                if error.error_class is ModelErrorClass.RATE_LIMIT:
                    self._metrics.add("rate_limits", model)
                    break
                try:
                    async with self._controls.semaphore(model):
                        await self._repository.record_attempt(
                            context,
                            request,
                            lease,
                            reservation,
                            provider=model.provider,
                            model=model.model,
                            attempt=attempt,
                            fallback_index=fallback_index,
                            at=self._clock(),
                        )
                        self._metrics.add("attempts", model)
                        with self._tracer.attempt(model):
                            response = await provider.complete(
                                request,
                                model,
                                cancellation=cancellation,
                            )
                except ModelGatewayError as error:
                    last_error = error
                    if error.error_class is ModelErrorClass.MALFORMED_RESPONSE:
                        self._metrics.add("malformed_responses", model)
                    if error.error_class is ModelErrorClass.RATE_LIMIT:
                        self._metrics.add("rate_limits", model)
                    if not self._retry_policy.may_retry(error, attempt):
                        break
                    await self._repository.record_attempt_failure(
                        context,
                        request,
                        lease,
                        reservation,
                        error,
                        provider=model.provider,
                        model=model.model,
                        attempt=attempt,
                        fallback_index=fallback_index,
                        at=self._clock(),
                    )
                    self._metrics.add("retries", model)
                    delay = (
                        error.retry_after_seconds
                        if error.retry_after_seconds is not None
                        else self._retry_policy.backoff.delay(attempt).total_seconds()
                    )
                    await self._sleep(delay)
                    continue
                circuit.succeed()
                return response, None
        except BaseException:
            circuit.fail()
            raise
        if last_error is not None:
            circuit.fail()
        return None, last_error

    @staticmethod
    def _validate_request(request: ModelRequest) -> None:
        if request.response_schema is not None:
            validate_schema(request.response_schema)
        for tool in request.tools:
            validate_schema(tool.input_schema)

    @staticmethod
    def _validate_response(request: ModelRequest, response: ModelResponse) -> None:
        if response.request_id != request.request_id:
            raise ModelGatewayError(
                ModelErrorClass.MALFORMED_RESPONSE,
                "response_request_id_mismatch",
                retryable=False,
                billing_ambiguous=True,
            )
        if request.response_schema is not None:
            if response.structured_output is None:
                raise ModelGatewayError(
                    ModelErrorClass.SCHEMA,
                    "structured_output_missing",
                    retryable=False,
                    billing_ambiguous=True,
                )
            validate_object(response.structured_output, request.response_schema)
        tool_schemas = {tool.name: tool.input_schema for tool in request.tools}
        for part in response.content:
            if isinstance(part, ToolCallPart):
                try:
                    schema = tool_schemas[part.proposal.tool_name]
                except KeyError as error:
                    raise ModelGatewayError(
                        ModelErrorClass.SCHEMA,
                        "unknown_tool_call",
                        retryable=False,
                        billing_ambiguous=True,
                    ) from error
                validate_object(part.proposal.arguments, schema)


def _no_fault(_cut_point: str) -> None:
    return None


__all__ = ["ModelGateway"]
