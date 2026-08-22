"""Bounded, tenant-fair worker supervisor with durable failure containment."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, TypeVar, cast
from uuid import UUID

from aegis_agent_platform.domain import FailureClass, JsonValue, WorkLease
from aegis_agent_platform.event_store import ConcurrencyError, FencingError
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.observability.runtime import (
    RuntimeMetrics,
    RuntimeTracer,
    shared_runtime_metrics,
)
from aegis_agent_platform.queueing import QueueDelivery, WorkQueue
from aegis_agent_platform.runtime.backoff import ExponentialBackoff
from aegis_agent_platform.tenancy import TenantContext

_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class WorkResult:
    """Provider-neutral handler result; payloads remain in durable artifacts."""

    result_reference: str

    def __post_init__(self) -> None:
        if not self.result_reference:
            raise ValueError("result_reference is required")


@dataclass(frozen=True, slots=True)
class WorkExecution:
    """Execution context exposed to a fixed-capability handler."""

    tenant: TenantContext
    delivery: QueueDelivery
    lease: WorkLease
    cancellation: asyncio.Event

    @property
    def payload(self) -> Mapping[str, JsonValue]:
        value = self.delivery.envelope.payload.get("request_payload", {})
        return value if isinstance(value, Mapping) else {}


class WorkerExecutionError(Exception):
    """Secret-safe classified failure deliberately raised by a handler."""

    def __init__(self, failure_class: FailureClass, error_code: str) -> None:
        if not error_code or len(error_code) > 128:
            raise ValueError("bounded error_code is required")
        super().__init__(error_code)
        self.failure_class = failure_class
        self.error_code = error_code


class WorkerStateStore(Protocol):
    """Durable state transitions required by the supervisor."""

    async def mark_published(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        *,
        at: datetime,
    ) -> None: ...

    async def claim(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        *,
        owner: str,
        now: datetime,
        expires_at: datetime,
        tenant_concurrency_limit: int,
    ) -> WorkLease | None: ...

    async def start(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None: ...

    async def heartbeat(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
        expires_at: datetime,
    ) -> WorkLease: ...

    async def cancellation_requested(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> bool: ...

    async def delivery_complete(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> bool: ...

    async def succeed(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
        result_reference: str,
    ) -> None: ...

    async def cancel(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None: ...

    async def fail(
        self,
        context: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        *,
        at: datetime,
        failure_class: FailureClass,
        error_code: str,
        retry_at: datetime | None,
    ) -> bool: ...


class RuntimeTelemetry:
    """Bounded-cardinality runtime metrics sink backed by a shared registry."""

    def __init__(self, metrics: RuntimeMetrics | None = None) -> None:
        self._metrics = metrics or shared_runtime_metrics()

    def claim_conflict(self) -> None:
        self._metrics.add("claim_conflicts")

    def active_leases(self, value: int) -> None:
        self._metrics.set_gauge("active_leases", float(value))

    def heartbeat_failure(self) -> None:
        self._metrics.add("heartbeat_failures")

    def retry(self) -> None:
        self._metrics.add("retries")

    def dead_letter(self) -> None:
        self._metrics.add("dead_letters")

    def completed(self, latency_seconds: float) -> None:
        self._metrics.add("work_latency", latency_seconds)

    def cancelled(self) -> None:
        self._metrics.add("cancellations")

    def reconciliation(self, outcome: str) -> None:
        if outcome == "failure":
            self._metrics.add("reconciliation_failure")
            return
        self._metrics.add("reconciliation_success")


class FairTenantScheduler:
    """FIFO within a tenant and round-robin across non-empty tenants."""

    def __init__(self) -> None:
        self._queues: dict[str, deque[QueueDelivery]] = {}
        self._round_robin: deque[str] = deque()

    def add(self, deliveries: tuple[QueueDelivery, ...]) -> None:
        for delivery in deliveries:
            tenant_id = delivery.envelope.tenant_id
            queue = self._queues.setdefault(tenant_id, deque())
            if not queue:
                self._round_robin.append(tenant_id)
            queue.append(delivery)

    def pop(self) -> QueueDelivery | None:
        if not self._round_robin:
            return None
        tenant_id = self._round_robin.popleft()
        queue = self._queues[tenant_id]
        delivery = queue.popleft()
        if queue:
            self._round_robin.append(tenant_id)
        else:
            del self._queues[tenant_id]
        return delivery

    def __bool__(self) -> bool:
        return bool(self._round_robin)


class WorkerSupervisor:
    """Contains handler bugs and commits every outcome before Redis XACK."""

    def __init__(
        self,
        queue: WorkQueue,
        state: WorkerStateStore,
        handler: Callable[[WorkExecution], Awaitable[WorkResult]],
        quota: Callable[[TenantContext], int],
        *,
        worker_id: str,
        clock: Callable[[], datetime],
        max_concurrency: int = 16,
        lease_duration: timedelta = timedelta(seconds=30),
        heartbeat_interval: timedelta = timedelta(seconds=10),
        backoff: ExponentialBackoff | None = None,
        telemetry: RuntimeTelemetry | None = None,
        tracer: RuntimeTracer | None = None,
    ) -> None:
        if not worker_id:
            raise ValueError("worker_id is required")
        if not 1 <= max_concurrency <= 1_000:
            raise ValueError("max_concurrency must be between 1 and 1000")
        if heartbeat_interval <= timedelta(0) or lease_duration <= heartbeat_interval:
            raise ValueError("lease must exceed a positive heartbeat interval")
        self._queue = queue
        self._state = state
        self._handler = handler
        self._quota = quota
        self._worker_id = worker_id
        self._clock = clock
        self._max_concurrency = max_concurrency
        self._lease_duration = lease_duration
        self._heartbeat_interval = heartbeat_interval
        self._backoff = backoff or ExponentialBackoff()
        self._telemetry = telemetry or RuntimeTelemetry()
        self._tracer = tracer or RuntimeTracer()
        self._active: set[asyncio.Task[None]] = set()
        self._draining = False

    async def run_batch(
        self,
        deliveries: tuple[QueueDelivery, ...],
    ) -> None:
        """Run a bounded fair batch and wait for all durable outcomes."""
        scheduler = FairTenantScheduler()
        scheduler.add(deliveries)
        while scheduler:
            while len(self._active) >= self._max_concurrency:
                await self._wait_one()
            if self._draining:  # drain() may have fired while blocked above
                break
            delivery = scheduler.pop()
            if delivery is None:
                break
            task = asyncio.create_task(self._process(delivery))
            self._active.add(task)
            self._telemetry.active_leases(len(self._active))
        while self._active:
            await self._wait_one()

    async def poll_once(
        self,
        *,
        count: int = 100,
        block_milliseconds: int = 1_000,
    ) -> int:
        """Read and execute one bounded transport batch unless draining."""
        if self._draining:
            return 0
        deliveries = await self._queue.read(
            consumer=self._worker_id,
            count=min(count, self._max_concurrency * 4),
            block_milliseconds=block_milliseconds,
        )
        if self._drain_requested():
            return 0
        await self.run_batch(deliveries)
        return len(deliveries)

    async def recover_once(
        self,
        *,
        minimum_idle_milliseconds: int,
        count: int = 100,
    ) -> int:
        """Reclaim one bounded pending page and run normal PostgreSQL claims."""
        if self._draining:
            return 0
        deliveries = await self._queue.reclaim(
            consumer=self._worker_id,
            minimum_idle_milliseconds=minimum_idle_milliseconds,
            count=min(count, self._max_concurrency * 4),
        )
        if self._drain_requested():
            return 0
        await self.run_batch(deliveries)
        return len(deliveries)

    async def drain(self, *, timeout: timedelta) -> bool:
        """Stop new claims and cooperatively wait for active work."""
        if timeout <= timedelta(0):
            raise ValueError("drain timeout must be positive")
        self._draining = True
        if not self._active:
            return True
        _, pending = await asyncio.wait(
            tuple(self._active),
            timeout=timeout.total_seconds(),
        )
        return not pending

    async def _wait_one(self) -> None:
        done, _ = await asyncio.wait(
            self._active,
            return_when=asyncio.FIRST_COMPLETED,
        )
        self._active.difference_update(done)
        self._telemetry.active_leases(len(self._active))
        for task in done:
            task.result()

    def _drain_requested(self) -> bool:
        return self._draining

    async def _process(self, delivery: QueueDelivery) -> None:
        try:
            tenant = TenantContext(TenantId(delivery.envelope.tenant_id))
        except ValueError:
            await self._queue.quarantine(
                delivery,
                reason_code="invalid_tenant_envelope",
            )
            return
        started_at = self._clock()
        if await self._state.delivery_complete(tenant, delivery.envelope.work_id):
            await self._queue.acknowledge(delivery)
            return
        try:
            with self._tracer.span("work.claim"):
                await self._state.mark_published(tenant, delivery, at=started_at)
                quota = self._quota(tenant)
                lease = await self._state.claim(
                    tenant,
                    delivery,
                    owner=self._worker_id,
                    now=started_at,
                    expires_at=started_at + self._lease_duration,
                    tenant_concurrency_limit=quota,
                )
        except ValueError:
            await self._queue.quarantine(
                delivery,
                reason_code="authoritative_delivery_rejected",
            )
            return
        except ConcurrencyError:
            if await self._state.delivery_complete(
                tenant,
                delivery.envelope.work_id,
            ):
                await self._queue.acknowledge(delivery)
            return
        if lease is None:
            self._telemetry.claim_conflict()
            if await self._state.delivery_complete(
                tenant,
                delivery.envelope.work_id,
            ):
                await self._queue.acknowledge(delivery)
            return
        cancellation = asyncio.Event()
        try:
            await self._state.start(tenant, delivery, lease, at=self._clock())
            with self._tracer.span("work.execute"):
                result = await self._execute_handler(
                    tenant,
                    delivery,
                    lease,
                    cancellation,
                )
            if await self._state.cancellation_requested(tenant, lease.work_id):
                cancellation.set()
                await self._state.cancel(
                    tenant,
                    delivery,
                    lease,
                    at=self._clock(),
                )
                self._telemetry.cancelled()
            else:
                await self._state.succeed(
                    tenant,
                    delivery,
                    lease,
                    at=self._clock(),
                    result_reference=result.result_reference,
                )
                self._telemetry.completed(
                    max(0.0, (self._clock() - started_at).total_seconds())
                )
        except TimeoutError:
            await self._record_failure(
                tenant,
                delivery,
                lease,
                FailureClass.TIMEOUT,
                "task_timeout",
            )
        except WorkerExecutionError as error:
            if error.failure_class is FailureClass.CANCELLED:
                if not await self._state.cancellation_requested(tenant, lease.work_id):
                    return
                await self._state.cancel(
                    tenant,
                    delivery,
                    lease,
                    at=self._clock(),
                )
                self._telemetry.cancelled()
            else:
                await self._record_failure(
                    tenant,
                    delivery,
                    lease,
                    error.failure_class,
                    error.error_code,
                )
        except FencingError:
            if not await self._state.cancellation_requested(tenant, lease.work_id):
                return
            try:
                await self._state.cancel(
                    tenant,
                    delivery,
                    lease,
                    at=self._clock(),
                )
                self._telemetry.cancelled()
            except FencingError:
                # Lease was reclaimed between the fenced start() and cancel();
                # the new holder is responsible for the durable outcome.
                return
        except asyncio.CancelledError:
            # Preserve the pending entry and live lease for expiry-based recovery.
            raise
        except Exception:
            await self._record_failure(
                tenant,
                delivery,
                lease,
                FailureClass.WORKER_BUG,
                "unhandled_worker_exception",
            )
        await self._queue.acknowledge(delivery)

    async def _execute_handler(
        self,
        tenant: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        cancellation: asyncio.Event,
    ) -> WorkResult:
        finished = asyncio.Event()

        async def heartbeat() -> None:
            current = lease
            while not finished.is_set():
                try:
                    await asyncio.wait_for(
                        finished.wait(),
                        self._heartbeat_interval.total_seconds(),
                    )
                    return
                except TimeoutError:
                    at = self._clock()
                    if await self._state.cancellation_requested(
                        tenant,
                        lease.work_id,
                    ):
                        cancellation.set()
                    try:
                        current = await self._state.heartbeat(
                            tenant,
                            delivery,
                            current,
                            at=at,
                            expires_at=at + self._lease_duration,
                        )
                    except Exception as error:
                        self._telemetry.heartbeat_failure()
                        raise WorkerExecutionError(
                            FailureClass.RETRYABLE,
                            "heartbeat_failed",
                        ) from error

        handler_task: asyncio.Future[WorkResult] = asyncio.ensure_future(
            self._handler(
                WorkExecution(tenant, delivery, lease, cancellation),
            )
        )
        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            waiters = {
                cast(asyncio.Future[object], handler_task),
                cast(asyncio.Future[object], heartbeat_task),
            }
            done, _ = await asyncio.wait(
                waiters,
                timeout=_timeout_seconds(delivery),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise TimeoutError
            if heartbeat_task in done:
                heartbeat_task.result()
            if handler_task not in done:
                raise WorkerExecutionError(
                    FailureClass.RETRYABLE,
                    "heartbeat_stopped",
                )
            result = handler_task.result()
        finally:
            finished.set()
            for task in (handler_task, heartbeat_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(
                handler_task,
                heartbeat_task,
                return_exceptions=True,
            )
        return result

    async def _record_failure(
        self,
        tenant: TenantContext,
        delivery: QueueDelivery,
        lease: WorkLease,
        failure_class: FailureClass,
        error_code: str,
    ) -> None:
        retryable = failure_class in {
            FailureClass.RETRYABLE,
            FailureClass.TIMEOUT,
        }
        retry_at = (
            self._clock() + self._backoff.delay(lease.attempt) if retryable else None
        )
        terminal = await self._state.fail(
            tenant,
            delivery,
            lease,
            at=self._clock(),
            failure_class=failure_class,
            error_code=error_code,
            retry_at=retry_at,
        )
        if terminal:
            self._telemetry.dead_letter()
        else:
            self._telemetry.retry()


def _timeout_seconds(delivery: QueueDelivery) -> float:
    value = delivery.envelope.payload.get("timeout_seconds", 300)
    valid = (
        isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 86_400
    )
    if not valid:
        raise WorkerExecutionError(
            FailureClass.PERMANENT,
            "invalid_task_timeout",
        )
    assert isinstance(value, int)
    return float(value)


__all__ = [
    "FairTenantScheduler",
    "RuntimeTelemetry",
    "WorkExecution",
    "WorkResult",
    "WorkerExecutionError",
    "WorkerStateStore",
    "WorkerSupervisor",
]
