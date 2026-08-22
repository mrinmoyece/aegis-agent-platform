"""Crash-safe Layer 3 outbox publisher for at-least-once Redis delivery."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from aegis_agent_platform.event_store import ClaimedOutboxMessage
from aegis_agent_platform.observability.runtime import (
    RuntimeMetrics,
    RuntimeTracer,
    shared_runtime_metrics,
)
from aegis_agent_platform.queueing import (
    MessageEnvelope,
    OutboxRepository,
    PermanentQueueError,
    RetryableQueueError,
    WorkQueue,
)
from aegis_agent_platform.tenancy import TenantContext


class PublisherTelemetry:
    """Bounded-cardinality publisher metrics interface."""

    def __init__(self, metrics: RuntimeMetrics | None = None) -> None:
        self._metrics = metrics or shared_runtime_metrics()

    def outbox_lag(self, seconds: float) -> None:
        self._metrics.set_gauge("outbox_lag", seconds)

    def published(self) -> None:
        pass

    def failed(self, *, retryable: bool) -> None:
        del retryable
        self._metrics.add("publish_failures")


@dataclass(frozen=True, slots=True)
class PublishBatchResult:
    """Observable bounded publisher outcome."""

    claimed: int
    published: int
    failed: int


class OutboxPublisher:
    """Claims PostgreSQL rows, XADDs, then acknowledges the database lease.

    A crash after XADD and before acknowledgement republishes the same deterministic
    message_id. Consumers commit that identity to the PostgreSQL inbox before XACK.
    """

    def __init__(
        self,
        repository: OutboxRepository,
        queue: WorkQueue,
        *,
        publisher_id: str,
        batch_size: int = 50,
        lease_duration: timedelta = timedelta(seconds=30),
        retry_delay: Callable[[int], timedelta] | None = None,
        telemetry: PublisherTelemetry | None = None,
        logger: logging.Logger | None = None,
        tracer: RuntimeTracer | None = None,
    ) -> None:
        if not publisher_id:
            raise ValueError("publisher_id is required")
        if not 1 <= batch_size <= 100:
            raise ValueError("batch_size must be between 1 and 100")
        if lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be positive")
        self._repository = repository
        self._queue = queue
        self._publisher_id = publisher_id
        self._batch_size = batch_size
        self._lease_duration = lease_duration
        self._retry_delay = retry_delay or _default_retry_delay
        self._telemetry = telemetry or PublisherTelemetry()
        self._logger = logger or logging.getLogger(__name__)
        self._tracer = tracer or RuntimeTracer()

    async def publish_batch(
        self,
        context: TenantContext,
        *,
        now: datetime,
        cancelled: asyncio.Event | None = None,
    ) -> PublishBatchResult:
        """Publish at most one bounded tenant batch, respecting shutdown."""
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        claims = await self._repository.claim_outbox(
            context,
            lease_owner=self._publisher_id,
            lease_expires_at=now + self._lease_duration,
            now=now,
            limit=self._batch_size,
        )
        published = failed = 0
        for raw_claim in claims:
            if cancelled is not None and cancelled.is_set():
                break
            if not isinstance(raw_claim, ClaimedOutboxMessage):
                raise TypeError("outbox repository returned an invalid claim")
            claim = raw_claim
            self._telemetry.outbox_lag(
                max(0.0, (now - claim.message.available_at).total_seconds())
            )
            try:
                envelope = _envelope(context, claim, now)
                with self._tracer.span("outbox.publish"):
                    await self._queue.publish(envelope)
                    await self._repository.mark_outbox_published(
                        context,
                        claim.message.message_id,
                        lease_owner=claim.lease_owner,
                        published_at=now,
                    )
            except RetryableQueueError:
                failed += 1
                self._telemetry.failed(retryable=True)
                await self._mark_failed(context, claim, now, "redis_unavailable")
            except PermanentQueueError:
                failed += 1
                self._telemetry.failed(retryable=False)
                await self._mark_failed(context, claim, now, "invalid_envelope")
            else:
                published += 1
                self._telemetry.published()
        if failed:
            self._logger.warning(
                "outbox_publish_batch_failed",
                extra={
                    "claimed_count": len(claims),
                    "published_count": published,
                    "failed_count": failed,
                },
            )
        return PublishBatchResult(len(claims), published, failed)

    async def _mark_failed(
        self,
        context: TenantContext,
        claim: ClaimedOutboxMessage,
        now: datetime,
        error_code: str,
    ) -> None:
        await self._repository.mark_outbox_failed(
            context,
            claim.message.message_id,
            lease_owner=claim.lease_owner,
            retry_at=now + self._retry_delay(claim.attempt_count),
            error_code=error_code,
        )


def _envelope(
    context: TenantContext,
    claim: ClaimedOutboxMessage,
    now: datetime,
) -> MessageEnvelope:
    payload = claim.message.payload
    try:
        work_id = UUID(str(payload["work_id"]))
        correlation_id = UUID(str(payload["correlation_id"]))
    except (KeyError, ValueError) as error:
        raise PermanentQueueError(
            "outbox payload lacks work routing metadata"
        ) from error
    tenant_header = claim.message.headers.get("tenant_id")
    if tenant_header is not None and str(tenant_header) != str(context.tenant_id):
        raise PermanentQueueError("outbox tenant header mismatch")
    causation_value = payload.get("causation_id")
    return MessageEnvelope(
        message_id=claim.message.message_id,
        tenant_id=str(context.tenant_id),
        work_id=work_id,
        event_id=claim.message.event_id,
        destination=claim.message.destination,
        correlation_id=correlation_id,
        causation_id=(
            UUID(str(causation_value)) if causation_value is not None else None
        ),
        occurred_at=now,
        payload=payload,
        headers=claim.message.headers,
    )


def _default_retry_delay(attempt: int) -> timedelta:
    return timedelta(seconds=min(300, 2 ** min(attempt, 8)))


__all__ = ["OutboxPublisher", "PublishBatchResult", "PublisherTelemetry"]
