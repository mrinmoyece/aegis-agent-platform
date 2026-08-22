"""Layer 5 fenced, budgeted, policy-routed model gateway execution."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime

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
    """Coordinates durable Layer 5 reservation, invocation, and reconciliation."""

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
        at = self._clock()
        cached = await self._repository.completed(context, request, lease, at=at)
        if cached is not None:
            return cached
        unavailable = frozenset(
            entry.identity
            for entry in self._catalog.entries()
            if self._controls.circuit(entry.identity).state.value == "open"
        )
        deadline = asyncio.get_running_loop().time() + request.timeout_seconds
        route = self._router.route(
            request,
            catalog=self._catalog,
            policy=policy,
            environment=environment,
            unavailable=unavailable,
            preference=preference,
        )
        candidates = route.candidates[: self._retry_policy.max_failovers + 1]
        token_limit = request.prompt_token_estimate + request.max_output_tokens
        reservation_cost = max(
            estimate_cost(
                candidate.pricing,
                request.prompt_token_estimate,
                request.max_output_tokens,
            )
            for candidate in candidates
        )
        try:
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
                deadline=deadline,
                cancellation=cancellation,
            )
            if response is not None:
                try:
                    self._validate_response(request, response)
                    await self._repository.succeed(
                        context,
                        request,
                        lease,
                        reservation,
                        response,
                        candidate.pricing,
                        at=self._clock(),
                    )
                except ModelGatewayError as error:
                    await self._repository.record_usage_failure(
                        context,
                        request,
                        lease,
                        reservation,
                        response,
                        candidate.pricing,
                        error,
                        at=self._clock(),
                    )
                    raise
                self._metrics.usage(candidate.identity, response.usage)
                self._metrics.add("latency_ms", candidate.identity, response.latency_ms)
                cost = candidate.pricing.cost(response.usage)
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
        await self._repository.fail(
            context,
            request,
            lease,
            reservation,
            last_error,
            at=self._clock(),
        )
        raise last_error

    async def _try_model(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        candidate: ModelCatalogEntry,
        *,
        fallback_index: int,
        deadline: float,
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
        try:
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
                try:
                    semaphore = self._controls.semaphore(model)
                    acquired = False
                    try:
                        await self._acquire_semaphore(
                            semaphore,
                            deadline=deadline,
                            cancellation=cancellation,
                        )
                        acquired = True
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
                    finally:
                        if acquired:
                            semaphore.release()
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
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError):
                circuit.fail()
            raise
        if last_error is not None and _provider_health_failure(last_error):
            circuit.fail()
        return None, last_error

    async def _acquire_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        *,
        deadline: float,
        cancellation: CancellationToken | None,
    ) -> None:
        if cancellation is not None and cancellation.is_set():
            raise ModelGatewayError(
                ModelErrorClass.CANCELLED,
                "gateway_concurrency_cancelled",
                retryable=False,
            )
        remaining_seconds = deadline - asyncio.get_running_loop().time()
        if remaining_seconds <= 0:
            raise ModelGatewayError(
                ModelErrorClass.TIMEOUT,
                "gateway_concurrency_timeout",
                retryable=True,
            )
        acquire_task = asyncio.create_task(
            asyncio.wait_for(semaphore.acquire(), timeout=remaining_seconds)
        )
        cancellation_task: asyncio.Task[bool] | None = None
        try:
            if cancellation is None:
                await acquire_task
                return
            cancellation_task = asyncio.create_task(cancellation.wait())
            done, _ = await asyncio.wait(
                (acquire_task, cancellation_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancellation_task in done:
                if (
                    acquire_task in done
                    and not acquire_task.cancelled()
                    and acquire_task.exception() is None
                ):
                    semaphore.release()
                else:
                    acquire_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await acquire_task
                raise ModelGatewayError(
                    ModelErrorClass.CANCELLED,
                    "gateway_concurrency_cancelled",
                    retryable=False,
                )
            await acquire_task
        except TimeoutError as error:
            raise ModelGatewayError(
                ModelErrorClass.TIMEOUT,
                "gateway_concurrency_timeout",
                retryable=True,
            ) from error
        finally:
            if cancellation_task is not None and not cancellation_task.done():
                cancellation_task.cancel()
            await asyncio.gather(acquire_task, return_exceptions=True)

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


__all__ = ["ModelGateway"]


def _provider_health_failure(error: ModelGatewayError) -> bool:
    if error.error_class is ModelErrorClass.RATE_LIMIT:
        return error.code != "local_rate_limit"
    if error.error_class is ModelErrorClass.TIMEOUT:
        return error.code != "gateway_concurrency_timeout"
    return error.error_class in {
        ModelErrorClass.TRANSIENT,
        ModelErrorClass.PROVIDER_UNAVAILABLE,
        ModelErrorClass.MALFORMED_RESPONSE,
        ModelErrorClass.PROVIDER_BUG,
    }
