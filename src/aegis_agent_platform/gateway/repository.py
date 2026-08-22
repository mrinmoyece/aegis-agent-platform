"""Durable gateway ledger port and deterministic in-memory implementation."""

from __future__ import annotations

import asyncio
import json
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
    ImagePart,
    JsonValue,
    ModelErrorClass,
    ModelGatewayError,
    ModelIdentity,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PricingVersion,
    TextPart,
    TokenUsage,
    ToolCallPart,
    ToolResultPart,
    WorkLease,
)
from aegis_agent_platform.domain.events import thaw_json
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
    status: str = "active"
    charged_tokens: int = 0
    charged_cost_usd: Decimal = Decimal("0")
    created_at: datetime | None = None
    reconciled_at: datetime | None = None


class BudgetDeniedError(PermissionError):
    pass


class DuplicateCallInProgressError(RuntimeError):
    pass


class GatewayRepository(Protocol):
    """Protocol-shaped base used to keep service dependencies explicit."""

    async def completed(
        self,
        context: TenantContext,
        request: ModelRequest,
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
    ) -> None: ...

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
        self._inflight: dict[tuple[str, str], tuple[UUID, str]] = {}
        self._completed: dict[tuple[str, str], tuple[str, ModelResponse]] = {}

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
        request: ModelRequest,
    ) -> ModelResponse | None:
        stored = self._completed.get((str(context.tenant_id), request.idempotency_key))
        if stored is None:
            return None
        digest, response = stored
        return response if digest == request_content_digest(request) else None

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
            request_digest = request_content_digest(request)
            completed = self._completed.get(duplicate_key)
            if completed is not None:
                if completed[0] != request_digest:
                    raise ValueError(
                        "idempotency key already belongs to another request"
                    )
                raise ValueError("completed duplicate must be read before reservation")
            inflight = self._inflight.get(duplicate_key)
            if inflight is not None:
                raise DuplicateCallInProgressError("model call is already in progress")
            active = tuple(
                item
                for item in self._reservations.values()
                if item.tenant_id == request.tenant_id and item.active
            )
            period_start = _billing_period_start(at)
            charged = tuple(
                item
                for item in self._reservations.values()
                if (
                    item.tenant_id == request.tenant_id
                    and item.status == "charged"
                    and item.reconciled_at is not None
                    and item.reconciled_at >= period_start
                )
            )
            tenant_tokens = sum(item.token_limit for item in active) + sum(
                item.charged_tokens for item in charged
            )
            tenant_cost = sum(
                (item.cost_limit_usd for item in active),
                start=Decimal("0"),
            ) + sum(
                (item.charged_cost_usd for item in charged),
                start=Decimal("0"),
            )
            run_charged = tuple(
                item
                for item in self._reservations.values()
                if item.run_id == request.run_id and item.status == "charged"
            )
            run_tokens = sum(
                item.token_limit for item in active if item.run_id == request.run_id
            ) + sum(item.charged_tokens for item in run_charged)
            run_cost = sum(
                (
                    item.cost_limit_usd
                    for item in active
                    if item.run_id == request.run_id
                ),
                start=Decimal("0"),
            ) + sum(
                (item.charged_cost_usd for item in run_charged),
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
                created_at=at,
            )
            self._reservations[reservation.reservation_id] = reservation
            self._inflight[duplicate_key] = (reservation.reservation_id, request_digest)
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
        actual_tokens, actual_cost = _actual_usage(pricing, response, reservation)
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
                status="charged",
                charged_tokens=actual_tokens,
                charged_cost_usd=actual_cost,
                created_at=reservation.created_at,
                reconciled_at=at,
            )
            self._reservations[reservation.reservation_id] = charged
            self._completed[(request.tenant_id, request.idempotency_key)] = (
                request_content_digest(request),
                response,
            )
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
        _validate_request_context(context, request, lease)
        actual_tokens, actual_cost = _usage_totals(pricing, response)
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
                status="charged",
                charged_tokens=actual_tokens,
                charged_cost_usd=actual_cost,
                created_at=reservation.created_at,
                reconciled_at=at,
            )
            self._reservations[reservation.reservation_id] = charged
            self._inflight.pop((request.tenant_id, request.idempotency_key), None)
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
                        _failure_event_type(error),
                        {
                            **details,
                            "error_class": error.error_class.value,
                            "error_code": error.code,
                            "retryable": error.retryable,
                            "billing_ambiguous": error.billing_ambiguous,
                        },
                    ),
                    (
                        DomainEventType.MODEL_USAGE_RECORDED,
                        {
                            **details,
                            **_usage_payload(response.usage),
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
                            "tokens_released": max(
                                reservation.token_limit - actual_tokens,
                                0,
                            ),
                            "cost_released_usd": str(
                                max(
                                    reservation.cost_limit_usd - actual_cost,
                                    Decimal("0"),
                                )
                            ),
                            "reason": "validation_failed_after_provider_response",
                        },
                    ),
                ),
            )

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
        _validate_request_context(context, request, lease)
        async with self._lock:
            self._require_active(reservation)
            self._require_fence(lease, at)
            self._append(
                request,
                lease,
                at,
                (
                    (
                        _failure_event_type(error),
                        {
                            "reservation_id": str(reservation.reservation_id),
                            "request_id": str(request.request_id),
                            "provider": provider,
                            "model": model,
                            "attempt": attempt,
                            "fallback_index": fallback_index,
                            "error_class": error.error_class.value,
                            "error_code": error.code,
                            "retryable": error.retryable,
                            "billing_ambiguous": error.billing_ambiguous,
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
                status="released",
                created_at=reservation.created_at,
                reconciled_at=at,
            )
            self._reservations[reservation.reservation_id] = released
            self._inflight.pop((request.tenant_id, request.idempotency_key), None)
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

    def usage_summary(self, context: TenantContext) -> Mapping[str, JsonValue]:
        tenant_id = str(context.tenant_id)
        charged = tuple(
            item
            for item in self._reservations.values()
            if item.tenant_id == tenant_id and item.status == "charged"
        )
        return {
            "tokens": sum(item.charged_tokens for item in charged),
            "cost_usd": str(
                sum(
                    (item.charged_cost_usd for item in charged),
                    start=Decimal("0"),
                )
            ),
            "calls": sum(1 for item in charged),
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
    highest_rate = max(
        pricing.input_per_million_usd,
        pricing.output_per_million_usd,
        pricing.cache_read_per_million_usd,
        pricing.cache_write_per_million_usd,
        pricing.reasoning_per_million_usd,
    )
    return (Decimal(prompt_tokens + max_output_tokens) * highest_rate) / Decimal(
        1_000_000
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
    payload = {
        "messages": [_message_payload(message) for message in request.messages],
        "requested_model": (
            None
            if request.requested_model is None
            else _model_identity_payload(request.requested_model)
        ),
        "max_output_tokens": request.max_output_tokens,
        "prompt_token_estimate": request.prompt_token_estimate,
        "temperature": str(request.temperature),
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "strict": tool.input_schema.strict,
                "schema": thaw_json(tool.input_schema.schema),
            }
            for tool in request.tools
        ],
        "response_schema": (
            None
            if request.response_schema is None
            else {
                "name": request.response_schema.name,
                "strict": request.response_schema.strict,
                "schema": thaw_json(request.response_schema.schema),
            }
        ),
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _billing_period_start(at: datetime) -> datetime:
    return at.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _failure_event_type(error: ModelGatewayError) -> DomainEventType:
    if error.error_class is ModelErrorClass.TIMEOUT:
        return DomainEventType.MODEL_CALL_TIMED_OUT
    if error.error_class is ModelErrorClass.RATE_LIMIT:
        return DomainEventType.MODEL_CALL_RATE_LIMITED
    if error.error_class is ModelErrorClass.CANCELLED:
        return DomainEventType.MODEL_CALL_CANCELLED
    return DomainEventType.MODEL_CALL_FAILED


def _actual_usage(
    pricing: PricingVersion,
    response: ModelResponse,
    reservation: BudgetReservation,
) -> tuple[int, Decimal]:
    actual_tokens, actual_cost = _usage_totals(pricing, response)
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
    return actual_tokens, actual_cost


def _usage_totals(
    pricing: PricingVersion,
    response: ModelResponse,
) -> tuple[int, Decimal]:
    return response.usage.billable_tokens, pricing.cost(response.usage)


def _message_payload(message: ModelMessage) -> dict[str, object]:
    return {
        "role": message.role.value,
        "name": message.name,
        "content": [_content_part_payload(part) for part in message.content],
    }


def _content_part_payload(part: object) -> dict[str, object]:
    if isinstance(part, TextPart):
        return {"kind": part.kind.value, "text": part.text}
    if isinstance(part, ImagePart):
        return {
            "kind": part.kind.value,
            "media_type": part.media_type,
            "uri": part.uri,
        }
    if isinstance(part, ToolCallPart):
        return {
            "kind": part.kind.value,
            "call_id": part.proposal.call_id,
            "tool_name": part.proposal.tool_name,
            "arguments": thaw_json(part.proposal.arguments),
        }
    if isinstance(part, ToolResultPart):
        return {
            "kind": part.kind.value,
            "call_id": part.call_id,
            "content": thaw_json(part.content),
            "is_error": part.is_error,
        }
    raise TypeError(f"unsupported content part: {type(part)!r}")


def _model_identity_payload(identity: ModelIdentity) -> dict[str, str]:
    return {"provider": identity.provider, "model": identity.model}


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
