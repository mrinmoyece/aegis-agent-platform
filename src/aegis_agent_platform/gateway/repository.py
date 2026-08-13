"""Durable gateway ledger port and deterministic in-memory implementation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

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
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.gateway.catalog import RouteDecision
from aegis_agent_platform.policy import QuotaLimits
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: UUID
    tenant_id: str
    run_id: UUID
    request_id: UUID
    token_limit: int
    cost_limit_usd: Decimal
    price_version: str
    active: bool = True
    charged_tokens: int = 0
    charged_cost_usd: Decimal = Decimal("0")


class BudgetDeniedError(PermissionError):
    pass


class DuplicateCallInProgressError(RuntimeError):
    pass


class GatewayRepository(Protocol):
    """Protocol-shaped base used to keep service dependencies explicit."""

    async def completed(
        self,
        context: TenantContext,
        idempotency_key: str,
    ) -> ModelResponse | None: ...

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
    ) -> BudgetReservation: ...

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
    ) -> None: ...

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
    ) -> None: ...

    async def fail(
        self,
        context: TenantContext,
        request: ModelRequest,
        lease: WorkLease,
        reservation: BudgetReservation,
        error: ModelGatewayError,
        *,
        at: datetime,
    ) -> None: ...


class InMemoryGatewayRepository(GatewayRepository):
    """Race-safe event truth plus rebuildable budget projection for tests/local use."""

    def __init__(
        self,
        active_leases: Sequence[WorkLease],
        *,
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._active_leases = {
            (lease.tenant_id, lease.work_id): lease for lease in active_leases
        }
        self._uuid_factory = uuid_factory
        self._lock = asyncio.Lock()
        self._events: list[EventEnvelope] = []
        self._reservations: dict[UUID, BudgetReservation] = {}
        self._inflight: dict[tuple[str, str], UUID] = {}
        self._completed: dict[tuple[str, str], ModelResponse] = {}

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(self._events)

    @property
    def reservations(self) -> Mapping[UUID, BudgetReservation]:
        return MappingProxyType(dict(self._reservations))

    def replace_lease(self, lease: WorkLease) -> None:
        self._active_leases[(lease.tenant_id, lease.work_id)] = lease

    async def completed(
        self,
        context: TenantContext,
        idempotency_key: str,
    ) -> ModelResponse | None:
        return self._completed.get((str(context.tenant_id), idempotency_key))

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
        _validate_request_context(context, request, lease)
        if token_limit < 1 or cost_limit_usd < 0 or not price_version:
            raise ValueError("reservation values and price version are required")
        async with self._lock:
            self._require_fence(lease, at)
            duplicate_key = (request.tenant_id, request.idempotency_key)
            if duplicate_key in self._completed:
                raise ValueError("completed duplicate must be read before reservation")
            if duplicate_key in self._inflight:
                raise DuplicateCallInProgressError("model call is already in progress")
            active = tuple(
                item
                for item in self._reservations.values()
                if item.tenant_id == request.tenant_id and item.active
            )
            tenant_tokens = sum(item.token_limit for item in active)
            tenant_cost = sum(
                (item.cost_limit_usd for item in active),
                start=Decimal("0"),
            )
            run_tokens = sum(
                item.token_limit for item in active if item.run_id == request.run_id
            )
            run_cost = sum(
                (
                    item.cost_limit_usd
                    for item in active
                    if item.run_id == request.run_id
                ),
                start=Decimal("0"),
            )
            if run_tokens + token_limit > quotas.max_run_tokens:
                raise BudgetDeniedError("run_token_budget_exceeded")
            if run_cost + cost_limit_usd > quotas.max_run_cost_usd:
                raise BudgetDeniedError("run_cost_budget_exceeded")
            if tenant_tokens + token_limit > quotas.max_tenant_tokens_per_period:
                raise BudgetDeniedError("tenant_token_budget_exceeded")
            if tenant_cost + cost_limit_usd > quotas.max_tenant_cost_usd_per_period:
                raise BudgetDeniedError("tenant_cost_budget_exceeded")
            reservation = BudgetReservation(
                reservation_id=self._uuid_factory(),
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                request_id=request.request_id,
                token_limit=token_limit,
                cost_limit_usd=cost_limit_usd,
                price_version=price_version,
            )
            self._reservations[reservation.reservation_id] = reservation
            self._inflight[duplicate_key] = reservation.reservation_id
            rationale = route.rationale
            base: dict[str, JsonValue] = {
                "work_id": str(lease.work_id),
                "lease_token": str(lease.token),
                "lease_generation": lease.generation,
                "request_id": str(request.request_id),
            }
            self._append(
                request,
                lease,
                at,
                (
                    (
                        DomainEventType.MODEL_ROUTE_DECIDED,
                        {
                            **base,
                            "provider": route.selected.identity.provider,
                            "model": route.selected.identity.model,
                            "candidate_count": len(route.candidates),
                            "rationale": rationale,
                        },
                    ),
                    (
                        DomainEventType.MODEL_CALL_REQUESTED,
                        {
                            **base,
                            "provider": route.selected.identity.provider,
                            "model": route.selected.identity.model,
                            "message_count": len(request.messages),
                            "content_digest": request_content_digest(request),
                            "max_output_tokens": request.max_output_tokens,
                            "prompt_token_estimate": request.prompt_token_estimate,
                            "has_tools": bool(request.tools),
                            "has_structured_output": (
                                request.response_schema is not None
                            ),
                            "persistence_policy": "metadata_and_digest_only",
                        },
                    ),
                    (
                        DomainEventType.MODEL_BUDGET_RESERVED,
                        {
                            **base,
                            "reservation_id": str(reservation.reservation_id),
                            "token_limit": token_limit,
                            "cost_limit_usd": str(cost_limit_usd),
                            "price_version": price_version,
                        },
                    ),
                ),
            )
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
        _validate_request_context(context, request, lease)
        if attempt < 1 or fallback_index < 0:
            raise ValueError("attempt and fallback index are invalid")
        async with self._lock:
            self._require_active(reservation)
            self._require_fence(lease, at)
            event_type = (
                DomainEventType.MODEL_CALL_STARTED
                if attempt == 1 and fallback_index == 0
                else DomainEventType.MODEL_CALL_ATTEMPTED
            )
            events: list[tuple[DomainEventType, Mapping[str, JsonValue]]] = []
            if fallback_index > 0 and attempt == 1:
                events.append(
                    (
                        DomainEventType.MODEL_FALLBACK_SELECTED,
                        {
                            "provider": provider,
                            "model": model,
                            "fallback_index": fallback_index,
                        },
                    )
                )
            events.append(
                (
                    event_type,
                    {
                        "provider": provider,
                        "model": model,
                        "attempt": attempt,
                        "fallback_index": fallback_index,
                        "reservation_id": str(reservation.reservation_id),
                    },
                )
            )
            self._append(request, lease, at, tuple(events))

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
        _validate_request_context(context, request, lease)
        actual_cost = pricing.cost(response.usage)
        actual_tokens = response.usage.billable_tokens
        if actual_tokens > reservation.token_limit:
            raise ModelGatewayError(
                ModelErrorClass.PROVIDER_BUG,
                "usage_exceeded_token_reservation",
                retryable=False,
                billing_ambiguous=True,
            )
        if actual_cost > reservation.cost_limit_usd:
            raise ModelGatewayError(
                ModelErrorClass.PROVIDER_BUG,
                "usage_exceeded_cost_reservation",
                retryable=False,
                billing_ambiguous=True,
            )
        async with self._lock:
            self._require_active(reservation)
            self._require_fence(lease, at)
            charged = BudgetReservation(
                reservation_id=reservation.reservation_id,
                tenant_id=reservation.tenant_id,
                run_id=reservation.run_id,
                request_id=reservation.request_id,
                token_limit=reservation.token_limit,
                cost_limit_usd=reservation.cost_limit_usd,
                price_version=reservation.price_version,
                active=False,
                charged_tokens=actual_tokens,
                charged_cost_usd=actual_cost,
            )
            self._reservations[reservation.reservation_id] = charged
            self._completed[(request.tenant_id, request.idempotency_key)] = response
            self._inflight.pop((request.tenant_id, request.idempotency_key), None)
            usage = response.usage
            details = {
                "reservation_id": str(reservation.reservation_id),
                "request_id": str(request.request_id),
                "provider": response.model.provider,
                "model": response.model.model,
                "price_version": pricing.version,
            }
            self._append(
                request,
                lease,
                at,
                (
                    (
                        DomainEventType.MODEL_CALL_SUCCEEDED,
                        {
                            **details,
                            "finish_reason": response.finish_reason.value,
                            "safety_outcome": response.safety.outcome.value,
                            "latency_ms": response.latency_ms,
                            "provider_request_id": response.provider_request_id,
                        },
                    ),
                    (
                        DomainEventType.MODEL_USAGE_RECORDED,
                        {
                            **details,
                            **_usage_payload(usage),
                            "cost_usd": str(actual_cost),
                        },
                    ),
                    (
                        DomainEventType.MODEL_BUDGET_CHARGED,
                        {
                            **details,
                            "tokens": actual_tokens,
                            "cost_usd": str(actual_cost),
                        },
                    ),
                    (
                        DomainEventType.MODEL_BUDGET_RELEASED,
                        {
                            **details,
                            "tokens_released": reservation.token_limit - actual_tokens,
                            "cost_released_usd": str(
                                reservation.cost_limit_usd - actual_cost
                            ),
                        },
                    ),
                ),
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
        _validate_request_context(context, request, lease)
        async with self._lock:
            self._require_active(reservation)
            self._require_fence(lease, at)
            released = BudgetReservation(
                reservation_id=reservation.reservation_id,
                tenant_id=reservation.tenant_id,
                run_id=reservation.run_id,
                request_id=reservation.request_id,
                token_limit=reservation.token_limit,
                cost_limit_usd=reservation.cost_limit_usd,
                price_version=reservation.price_version,
                active=False,
            )
            self._reservations[reservation.reservation_id] = released
            self._inflight.pop((request.tenant_id, request.idempotency_key), None)
            event_type = {
                ModelErrorClass.TIMEOUT: DomainEventType.MODEL_CALL_TIMED_OUT,
                ModelErrorClass.RATE_LIMIT: DomainEventType.MODEL_CALL_RATE_LIMITED,
                ModelErrorClass.CANCELLED: DomainEventType.MODEL_CALL_CANCELLED,
            }.get(error.error_class, DomainEventType.MODEL_CALL_FAILED)
            details = {
                "reservation_id": str(reservation.reservation_id),
                "request_id": str(request.request_id),
                "error_class": error.error_class.value,
                "error_code": error.code,
                "retryable": error.retryable,
                "billing_ambiguous": error.billing_ambiguous,
            }
            self._append(
                request,
                lease,
                at,
                (
                    (event_type, details),
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

    def usage_summary(self, tenant_id: str) -> Mapping[str, JsonValue]:
        charged = tuple(
            item
            for item in self._reservations.values()
            if item.tenant_id == tenant_id and not item.active
        )
        return {
            "tokens": sum(item.charged_tokens for item in charged),
            "cost_usd": str(
                sum(
                    (item.charged_cost_usd for item in charged),
                    start=Decimal("0"),
                )
            ),
            "calls": sum(1 for item in charged if item.charged_tokens > 0),
        }

    def _require_fence(self, lease: WorkLease, at: datetime) -> None:
        current = self._active_leases.get((lease.tenant_id, lease.work_id))
        if (
            current is None
            or current.token != lease.token
            or current.generation != lease.generation
            or current.expires_at <= at
        ):
            raise FencingError(lease.generation, current.generation if current else 0)

    def _require_active(self, reservation: BudgetReservation) -> None:
        current = self._reservations.get(reservation.reservation_id)
        if current is None or not current.active:
            raise ValueError("budget reservation is not active")

    def _append(
        self,
        request: ModelRequest,
        lease: WorkLease,
        at: datetime,
        events: Sequence[tuple[DomainEventType, Mapping[str, JsonValue]]],
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("event time must be timezone-aware")
        sequence = sum(
            event.aggregate_id == str(lease.work_id) for event in self._events
        )
        causation: UUID | None = None
        for event_type, details in events:
            sequence += 1
            event_id = self._uuid_factory()
            payload = dict(details)
            payload.update(
                {
                    "work_id": str(lease.work_id),
                    "lease_token": str(lease.token),
                    "lease_generation": lease.generation,
                }
            )
            self._events.append(
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
                    aggregate_sequence=sequence,
                    idempotency_key=(
                        f"{request.idempotency_key}:{event_type.value}:{sequence}"
                    ),
                )
            )
            causation = event_id


def estimate_cost(
    pricing: PricingVersion,
    prompt_tokens: int,
    max_output_tokens: int,
) -> Decimal:
    return pricing.cost(
        TokenUsage(
            input_tokens=prompt_tokens,
            output_tokens=max_output_tokens,
        )
    )


def _validate_request_context(
    context: TenantContext,
    request: ModelRequest,
    lease: WorkLease,
) -> None:
    tenant = str(context.tenant_id)
    if tenant != request.tenant_id or tenant != lease.tenant_id:
        raise ValueError("gateway tenant context, request, and lease must match")
    if request.run_id != lease.work_id:
        raise ValueError("model run must be the fenced work aggregate")


def request_content_digest(request: ModelRequest) -> str:
    digest = sha256()
    for message in request.messages:
        digest.update(message.role.value.encode())
        for part in message.content:
            digest.update(repr(part).encode())
    return digest.hexdigest()


def _usage_payload(usage: TokenUsage) -> dict[str, JsonValue]:
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_read_tokens": usage.cache_read_tokens,
        "cache_write_tokens": usage.cache_write_tokens,
        "reasoning_tokens": usage.reasoning_tokens,
    }


def utc_now() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "BudgetDeniedError",
    "BudgetReservation",
    "DuplicateCallInProgressError",
    "GatewayRepository",
    "InMemoryGatewayRepository",
    "estimate_cost",
    "request_content_digest",
]
