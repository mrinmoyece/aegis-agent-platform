"""PostgreSQL budget reservations reconciled atomically with fenced ledger events."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import psycopg

from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    ModelErrorClass,
    ModelGatewayError,
    ModelRequest,
    ModelResponse,
    PricingVersion,
    TokenUsage,
    WorkLease,
)
from aegis_agent_platform.event_store import ConcurrencyError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.gateway.catalog import RouteDecision
from aegis_agent_platform.gateway.repository import (
    BudgetDeniedError,
    BudgetReservation,
    GatewayRepository,
    request_content_digest,
)
from aegis_agent_platform.policy import QuotaLimits
from aegis_agent_platform.tenancy import TenantContext


class PostgresGatewayRepository(GatewayRepository):
    """Keep lease checks, events, and budget rows in one transaction."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
        *,
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._connection = connection
        self._events = event_store
        self._uuid_factory = uuid_factory

    async def completed(
        self,
        context: TenantContext,
        request: ModelRequest,
    ) -> ModelResponse | None:
        del context, request
        # Raw responses are intentionally not persisted without an encrypted artifact
        # store. Durable workers deduplicate before invocation via reservation keys.
        return None

    async def reserve(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        route: RouteDecision,
        *,
        quotas: QuotaLimits,
        token_limit: int,
        cost_limit_usd: Decimal,
        price_version: str,
        at: datetime,
    ) -> BudgetReservation:
        _validate(context, request, lease, at)
        reservation = BudgetReservation(
            reservation_id=self._uuid_factory(),
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            request_id=request.request_id,
            token_limit=token_limit,
            cost_limit_usd=cost_limit_usd,
            price_version=price_version,
        )
        common = _common(request, lease, reservation)
        events = _events(
            request,
            lease,
            at,
            (
                (
                    DomainEventType.MODEL_ROUTE_DECIDED,
                    {
                        **common,
                        "provider": route.selected.identity.provider,
                        "model": route.selected.identity.model,
                        "candidate_count": len(route.candidates),
                        "rationale": route.rationale,
                    },
                ),
                (
                    DomainEventType.MODEL_CALL_REQUESTED,
                    {
                        **common,
                        "provider": route.selected.identity.provider,
                        "model": route.selected.identity.model,
                        "message_count": len(request.messages),
                        "content_digest": request_content_digest(request),
                        "max_output_tokens": request.max_output_tokens,
                        "prompt_token_estimate": request.prompt_token_estimate,
                        "has_tools": bool(request.tools),
                        "has_structured_output": request.response_schema is not None,
                        "persistence_policy": "metadata_and_digest_only",
                    },
                ),
                (
                    DomainEventType.MODEL_BUDGET_RESERVED,
                    {
                        **common,
                        "token_limit": token_limit,
                        "cost_limit_usd": str(cost_limit_usd),
                        "price_version": price_version,
                    },
                ),
            ),
        )

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _lock_budget(connection, request.tenant_id)
            configured = await _quota_limits(connection, request.tenant_id)
            if configured != quotas:
                raise BudgetDeniedError("policy_quota_projection_mismatch")
            cursor = await connection.execute(
                """
                SELECT
                    COALESCE(sum(token_limit), 0),
                    COALESCE(sum(cost_limit_usd), 0)
                FROM model_budget_reservations
                WHERE tenant_id = %s AND status = 'active'
                """,
                (request.tenant_id,),
            )
            tenant_active = await cursor.fetchone()
            usage_cursor = await connection.execute(
                """
                SELECT
                    COALESCE(sum(total_tokens), 0),
                    COALESCE(sum(cost_usd), 0)
                FROM model_usage_projection
                WHERE tenant_id = %s
                  AND recorded_at >= date_trunc('month', %s::timestamptz)
                """,
                (request.tenant_id, at),
            )
            tenant_used = await usage_cursor.fetchone()
            run_cursor = await connection.execute(
                """
                SELECT
                    COALESCE(sum(token_limit), 0),
                    COALESCE(sum(cost_limit_usd), 0)
                FROM model_budget_reservations
                WHERE tenant_id = %s AND run_id = %s AND status = 'active'
                """,
                (request.tenant_id, request.run_id),
            )
            run_active = await run_cursor.fetchone()
            run_usage_cursor = await connection.execute(
                """
                SELECT
                    COALESCE(sum(total_tokens), 0),
                    COALESCE(sum(cost_usd), 0)
                FROM model_usage_projection
                WHERE tenant_id = %s AND run_id = %s
                """,
                (request.tenant_id, request.run_id),
            )
            run_used = await run_usage_cursor.fetchone()
            if any(
                row is None
                for row in (tenant_active, tenant_used, run_active, run_used)
            ):
                raise RuntimeError("aggregate budget query returned no row")
            assert tenant_active is not None
            assert tenant_used is not None
            assert run_active is not None
            assert run_used is not None
            tenant_tokens = int(tenant_active[0]) + int(tenant_used[0])
            tenant_cost = Decimal(tenant_active[1]) + Decimal(tenant_used[1])
            run_tokens = int(run_active[0]) + int(run_used[0])
            run_cost = Decimal(run_active[1]) + Decimal(run_used[1])
            _check_budget(
                quotas,
                tenant_tokens=tenant_tokens,
                tenant_cost=tenant_cost,
                run_tokens=run_tokens,
                run_cost=run_cost,
                token_limit=token_limit,
                cost_limit=cost_limit_usd,
            )
            await connection.execute(
                """
                INSERT INTO model_budget_reservations (
                    tenant_id, reservation_id, run_id, work_id, request_id,
                    idempotency_key, token_limit, cost_limit_usd, price_version,
                    status, lease_token, lease_generation, created_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s
                )
                """,
                (
                    request.tenant_id,
                    reservation.reservation_id,
                    request.run_id,
                    lease.work_id,
                    request.request_id,
                    request.idempotency_key,
                    token_limit,
                    cost_limit_usd,
                    price_version,
                    lease.token,
                    lease.generation,
                    at,
                ),
            )

        await self._append_fenced(context, lease, events, at=at, mutation=mutation)
        return reservation

    async def record_attempt(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        *,
        provider: str,
        model: str,
        attempt: int,
        fallback_index: int,
        at: datetime,
    ) -> None:
        _validate(context, request, lease, at)
        values: list[tuple[DomainEventType, Mapping[str, JsonValue]]] = []
        if fallback_index > 0 and attempt == 1:
            values.append(
                (
                    DomainEventType.MODEL_FALLBACK_SELECTED,
                    {
                        **_common(request, lease, reservation),
                        "provider": provider,
                        "model": model,
                        "fallback_index": fallback_index,
                    },
                )
            )
        values.append(
            (
                (
                    DomainEventType.MODEL_CALL_STARTED
                    if fallback_index == 0 and attempt == 1
                    else DomainEventType.MODEL_CALL_ATTEMPTED
                ),
                {
                    **_common(request, lease, reservation),
                    "provider": provider,
                    "model": model,
                    "attempt": attempt,
                    "fallback_index": fallback_index,
                },
            )
        )
        await self._append_fenced(
            context,
            lease,
            _events(request, lease, at, tuple(values)),
            at=at,
        )

    async def succeed(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        response: ModelResponse,
        pricing: PricingVersion,
        *,
        at: datetime,
    ) -> None:
        _validate(context, request, lease, at)
        tokens, cost = _actual_usage(pricing, response, reservation)
        common = {
            **_common(request, lease, reservation),
            "provider": response.model.provider,
            "model": response.model.model,
            "price_version": pricing.version,
        }
        usage = response.usage
        events = _events(
            request,
            lease,
            at,
            (
                (
                    DomainEventType.MODEL_CALL_SUCCEEDED,
                    {
                        **common,
                        "finish_reason": response.finish_reason.value,
                        "safety_outcome": response.safety.outcome.value,
                        "latency_ms": response.latency_ms,
                        "provider_request_id": response.provider_request_id,
                    },
                ),
                (
                    DomainEventType.MODEL_USAGE_RECORDED,
                    {
                        **common,
                        **_usage(usage),
                        "cost_usd": str(cost),
                    },
                ),
                (
                    DomainEventType.MODEL_BUDGET_CHARGED,
                    {**common, "tokens": tokens, "cost_usd": str(cost)},
                ),
                (
                    DomainEventType.MODEL_BUDGET_RELEASED,
                    {
                        **common,
                        "tokens_released": reservation.token_limit - tokens,
                        "cost_released_usd": str(reservation.cost_limit_usd - cost),
                    },
                ),
            ),
        )

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            updated = await connection.execute(
                """
                UPDATE model_budget_reservations
                SET status = 'charged', charged_tokens = %s,
                    charged_cost_usd = %s, reconciled_at = %s
                WHERE tenant_id = %s AND reservation_id = %s
                  AND status = 'active' AND lease_token = %s
                  AND lease_generation = %s
                """,
                (
                    tokens,
                    cost,
                    at,
                    request.tenant_id,
                    reservation.reservation_id,
                    lease.token,
                    lease.generation,
                ),
            )
            if updated.rowcount != 1:
                raise ConcurrencyError(1, 0)
            await connection.execute(
                """
                INSERT INTO model_usage_projection (
                    tenant_id, request_id, run_id, provider, model, price_version,
                    input_tokens, output_tokens, cache_read_tokens,
                    cache_write_tokens, reasoning_tokens, total_tokens, cost_usd,
                    recorded_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    request.tenant_id,
                    request.request_id,
                    request.run_id,
                    response.model.provider,
                    response.model.model,
                    pricing.version,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.cache_read_tokens,
                    usage.cache_write_tokens,
                    usage.reasoning_tokens,
                    tokens,
                    cost,
                    at,
                ),
            )

        await self._append_fenced(context, lease, events, at=at, mutation=mutation)

    async def record_usage_failure(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        response: ModelResponse,
        pricing: PricingVersion,
        error: ModelGatewayError,
        *,
        at: datetime,
    ) -> None:
        _validate(context, request, lease, at)
        tokens, cost = _actual_usage(pricing, response, reservation)
        common = {
            **_common(request, lease, reservation),
            "provider": response.model.provider,
            "model": response.model.model,
            "price_version": pricing.version,
        }
        usage = response.usage
        details = {
            **common,
            "error_class": error.error_class.value,
            "error_code": error.code,
            "retryable": error.retryable,
            "billing_ambiguous": error.billing_ambiguous,
        }
        events = _events(
            request,
            lease,
            at,
            (
                (_failure_event_type(error), details),
                (
                    DomainEventType.MODEL_USAGE_RECORDED,
                    {**common, **_usage(usage), "cost_usd": str(cost)},
                ),
                (
                    DomainEventType.MODEL_BUDGET_CHARGED,
                    {**common, "tokens": tokens, "cost_usd": str(cost)},
                ),
                (
                    DomainEventType.MODEL_BUDGET_RELEASED,
                    {
                        **common,
                        "tokens_released": reservation.token_limit - tokens,
                        "cost_released_usd": str(reservation.cost_limit_usd - cost),
                        "reason": "validation_failed_after_provider_response",
                    },
                ),
            ),
        )

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            updated = await connection.execute(
                """
                UPDATE model_budget_reservations
                SET status = 'charged', charged_tokens = %s,
                    charged_cost_usd = %s, reconciled_at = %s
                WHERE tenant_id = %s AND reservation_id = %s
                  AND status = 'active' AND lease_token = %s
                  AND lease_generation = %s
                """,
                (
                    tokens,
                    cost,
                    at,
                    request.tenant_id,
                    reservation.reservation_id,
                    lease.token,
                    lease.generation,
                ),
            )
            if updated.rowcount != 1:
                raise ConcurrencyError(1, 0)
            await connection.execute(
                """
                INSERT INTO model_usage_projection (
                    tenant_id, request_id, run_id, provider, model, price_version,
                    input_tokens, output_tokens, cache_read_tokens,
                    cache_write_tokens, reasoning_tokens, total_tokens, cost_usd,
                    recorded_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    request.tenant_id,
                    request.request_id,
                    request.run_id,
                    response.model.provider,
                    response.model.model,
                    pricing.version,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.cache_read_tokens,
                    usage.cache_write_tokens,
                    usage.reasoning_tokens,
                    tokens,
                    cost,
                    at,
                ),
            )

        await self._append_fenced(context, lease, events, at=at, mutation=mutation)

    async def record_attempt_failure(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        error: ModelGatewayError,
        *,
        provider: str,
        model: str,
        attempt: int,
        fallback_index: int,
        at: datetime,
    ) -> None:
        _validate(context, request, lease, at)
        details = {
            **_common(request, lease, reservation),
            "provider": provider,
            "model": model,
            "attempt": attempt,
            "fallback_index": fallback_index,
            "error_class": error.error_class.value,
            "error_code": error.code,
            "retryable": error.retryable,
            "billing_ambiguous": error.billing_ambiguous,
        }
        await self._append_fenced(
            context,
            lease,
            _events(request, lease, at, ((_failure_event_type(error), details),)),
            at=at,
        )

    async def fail(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        error: ModelGatewayError,
        *,
        at: datetime,
    ) -> None:
        _validate(context, request, lease, at)
        common = _common(request, lease, reservation)
        details = {
            **common,
            "error_class": error.error_class.value,
            "error_code": error.code,
            "retryable": error.retryable,
            "billing_ambiguous": error.billing_ambiguous,
        }
        events = _events(
            request,
            lease,
            at,
            (
                (_failure_event_type(error), details),
                (
                    DomainEventType.MODEL_BUDGET_RELEASED,
                    {
                        **details,
                        "tokens_released": reservation.token_limit,
                        "cost_released_usd": str(reservation.cost_limit_usd),
                        "reason": "model_call_failed",
                    },
                ),
            ),
        )

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            updated = await connection.execute(
                """
                UPDATE model_budget_reservations
                SET status = 'released', reconciled_at = %s
                WHERE tenant_id = %s AND reservation_id = %s
                  AND status = 'active' AND lease_token = %s
                  AND lease_generation = %s
                """,
                (
                    at,
                    request.tenant_id,
                    reservation.reservation_id,
                    lease.token,
                    lease.generation,
                ),
            )
            if updated.rowcount != 1:
                raise ConcurrencyError(1, 0)

        await self._append_fenced(context, lease, events, at=at, mutation=mutation)

    async def _append_fenced(
        self,
        context: TenantContext,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        at: datetime,
        mutation: (Callable[[psycopg.AsyncConnection[Any]], object] | None) = None,
    ) -> None:
        from collections.abc import Awaitable
        from typing import cast

        expected = await self._events.current_version(context, str(lease.work_id))
        typed_mutation = cast(
            Callable[[psycopg.AsyncConnection[Any]], Awaitable[None]] | None,
            mutation,
        )
        await self._events.append_fenced(
            context,
            events,
            expected_version=expected,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=at,
            mutation=typed_mutation,
        )


async def _lock_budget(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
) -> None:
    await connection.execute(
        """
        INSERT INTO tenant_model_budget_locks (tenant_id)
        VALUES (%s) ON CONFLICT (tenant_id) DO NOTHING
        """,
        (tenant_id,),
    )
    await connection.execute(
        """
        SELECT tenant_id FROM tenant_model_budget_locks
        WHERE tenant_id = %s FOR UPDATE
        """,
        (tenant_id,),
    )


async def _quota_limits(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
) -> QuotaLimits:
    cursor = await connection.execute(
        """
        SELECT max_run_tokens, max_run_cost_usd,
            max_tenant_tokens_per_period, max_tenant_cost_usd_per_period,
            max_concurrent_runs
        FROM tenant_quotas WHERE tenant_id = %s FOR SHARE
        """,
        (tenant_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise BudgetDeniedError("tenant_quota_not_configured")
    return QuotaLimits(
        max_run_tokens=int(row[0]),
        max_run_cost_usd=Decimal(row[1]),
        max_tenant_tokens_per_period=int(row[2]),
        max_tenant_cost_usd_per_period=Decimal(row[3]),
        max_concurrent_runs=int(row[4]),
    )


def _check_budget(
    quotas: QuotaLimits,
    *,
    tenant_tokens: int,
    tenant_cost: Decimal,
    run_tokens: int,
    run_cost: Decimal,
    token_limit: int,
    cost_limit: Decimal,
) -> None:
    checks = (
        (run_tokens + token_limit > quotas.max_run_tokens, "run_token_budget_exceeded"),
        (run_cost + cost_limit > quotas.max_run_cost_usd, "run_cost_budget_exceeded"),
        (
            tenant_tokens + token_limit > quotas.max_tenant_tokens_per_period,
            "tenant_token_budget_exceeded",
        ),
        (
            tenant_cost + cost_limit > quotas.max_tenant_cost_usd_per_period,
            "tenant_cost_budget_exceeded",
        ),
    )
    for denied, code in checks:
        if denied:
            raise BudgetDeniedError(code)


def _validate(
    context: TenantContext,
    request: ModelRequest,
    lease: WorkLease,
    at: datetime,
) -> None:
    if (
        str(context.tenant_id) != request.tenant_id
        or request.tenant_id != lease.tenant_id
        or request.run_id != lease.work_id
    ):
        raise ValueError("tenant, request, run, and fence must match")
    if at.tzinfo is None:
        raise ValueError("gateway event time must be timezone-aware")


def _common(
    request: ModelRequest,
    lease: WorkLease,
    reservation: BudgetReservation,
) -> dict[str, JsonValue]:
    return {
        "work_id": str(lease.work_id),
        "lease_token": str(lease.token),
        "lease_generation": lease.generation,
        "request_id": str(request.request_id),
        "reservation_id": str(reservation.reservation_id),
    }


def _events(
    request: ModelRequest,
    lease: WorkLease,
    at: datetime,
    values: Sequence[tuple[DomainEventType, Mapping[str, JsonValue]]],
) -> tuple[EventEnvelope, ...]:
    result: list[EventEnvelope] = []
    causation: UUID | None = None
    for index, (event_type, payload) in enumerate(values, start=1):
        event_id = uuid4()
        result.append(
            EventEnvelope(
                event_id=event_id,
                tenant_id=request.tenant_id,
                aggregate_id=str(lease.work_id),
                event_type=event_type,
                schema_version=1,
                occurred_at=at,
                payload=payload,
                correlation_id=request.run_id,
                causation_id=causation,
                idempotency_key=_event_idempotency_key(
                    request,
                    event_type,
                    payload,
                    index=index,
                ),
            )
        )
        causation = event_id
    return tuple(result)


def _usage(value: TokenUsage) -> dict[str, JsonValue]:
    return {
        "input_tokens": value.input_tokens,
        "output_tokens": value.output_tokens,
        "cache_read_tokens": value.cache_read_tokens,
        "cache_write_tokens": value.cache_write_tokens,
        "reasoning_tokens": value.reasoning_tokens,
    }


def _failure_event_type(error: ModelGatewayError) -> DomainEventType:
    return {
        ModelErrorClass.TIMEOUT: DomainEventType.MODEL_CALL_TIMED_OUT,
        ModelErrorClass.RATE_LIMIT: DomainEventType.MODEL_CALL_RATE_LIMITED,
        ModelErrorClass.CANCELLED: DomainEventType.MODEL_CALL_CANCELLED,
    }.get(error.error_class, DomainEventType.MODEL_CALL_FAILED)


def _actual_usage(
    pricing: PricingVersion,
    response: ModelResponse,
    reservation: BudgetReservation,
) -> tuple[int, Decimal]:
    cost = pricing.cost(response.usage)
    tokens = response.usage.billable_tokens
    if tokens > reservation.token_limit or cost > reservation.cost_limit_usd:
        raise ModelGatewayError(
            ModelErrorClass.PROVIDER_BUG,
            "usage_exceeded_reservation",
            retryable=False,
            billing_ambiguous=True,
        )
    return tokens, cost


def _event_idempotency_key(
    request: ModelRequest,
    event_type: DomainEventType,
    payload: Mapping[str, JsonValue],
    *,
    index: int,
) -> str:
    parts = [
        request.idempotency_key,
        event_type.value,
        str(payload.get("fallback_index", 0)),
        str(payload.get("attempt", 0)),
        str(payload.get("reservation_id", "")),
        str(index),
    ]
    provider = payload.get("provider")
    model = payload.get("model")
    if isinstance(provider, str) and provider:
        parts.append(provider)
    if isinstance(model, str) and model:
        parts.append(model)
    return ":".join(parts)


__all__ = ["PostgresGatewayRepository"]
