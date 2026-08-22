"""Deterministic tests for distributed delivery and worker reliability."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from aegis_agent_platform.config import Settings
from aegis_agent_platform.domain import (
    DomainEventType,
    FailureClass,
    JsonValue,
    WorkLease,
    WorkRequest,
    WorkStatus,
    WorkTransition,
    next_status,
)
from aegis_agent_platform.event_store import (
    ClaimedOutboxMessage,
    ConcurrencyError,
    FencingError,
    OutboxMessage,
)
from aegis_agent_platform.identity import (
    PLATFORM_TENANT_ID,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    TenantId,
    UserId,
)
from aegis_agent_platform.observability.runtime import RuntimeMetrics, RuntimeTracer
from aegis_agent_platform.queueing import (
    MessageEnvelope,
    PendingEntry,
    PermanentQueueError,
    QueueDelivery,
    RetryableQueueError,
)
from aegis_agent_platform.queueing.publisher import OutboxPublisher, PublisherTelemetry
from aegis_agent_platform.runtime import (
    FairTenantScheduler,
    RuntimeTelemetry,
    WorkerExecutionError,
    WorkerSupervisor,
    WorkExecution,
    WorkResult,
)
from aegis_agent_platform.runtime.backoff import ExponentialBackoff
from aegis_agent_platform.runtime.operations import (
    OperationDeniedError,
    RequeueApproval,
    WorkerOperations,
)
from aegis_agent_platform.tenancy import TenantContext

NOW = datetime(2025, 1, 1, tzinfo=UTC)
TENANT_A = TenantContext(TenantId("tenant-a"))
TENANT_B = TenantContext(TenantId("tenant-b"))


def uid(value: int) -> UUID:
    return UUID(int=value)


def request(*, payload: Mapping[str, JsonValue] | None = None) -> WorkRequest:
    return WorkRequest(
        work_id=uid(1),
        tenant_id="tenant-a",
        work_kind="fixture",
        idempotency_key="work-one",
        correlation_id=uid(2),
        causation_id=uid(3),
        requested_at=NOW,
        payload=payload or {"nested": {"safe": True}},
        max_attempts=3,
        timeout_seconds=30,
    )


def delivery(
    tenant_id: str = "tenant-a",
    *,
    message_id: int = 10,
    work_id: int = 1,
) -> QueueDelivery:
    return QueueDelivery(
        stream_entry_id=f"{message_id}-0",
        delivery_count=1,
        idle_milliseconds=0,
        envelope=MessageEnvelope(
            message_id=uid(message_id),
            tenant_id=tenant_id,
            work_id=uid(work_id),
            event_id=uid(4),
            destination="aegis.work",
            correlation_id=uid(2),
            causation_id=uid(3),
            occurred_at=NOW,
            payload={
                "work_id": str(uid(work_id)),
                "work_kind": "fixture",
                "idempotency_key": f"work-{work_id}",
                "correlation_id": str(uid(2)),
                "causation_id": str(uid(3)),
                "requested_at": NOW.isoformat(),
                "max_attempts": 3,
                "timeout_seconds": 30,
                "request_payload": {"safe": True},
            },
            headers={"tenant_id": tenant_id},
        ),
    )


def lease(*, attempt: int = 1) -> WorkLease:
    return WorkLease(
        work_id=uid(1),
        tenant_id="tenant-a",
        token=uid(20),
        generation=1,
        owner="worker-a",
        attempt=attempt,
        acquired_at=NOW,
        heartbeat_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def test_work_contract_is_deeply_immutable_and_tenant_bound() -> None:
    mutable: dict[str, JsonValue] = {"nested": {"safe": True}}
    item = request(payload=mutable)
    mutable["nested"] = {"safe": False}

    assert item.payload["nested"] == {"safe": True}
    with pytest.raises(TypeError):
        item.payload["new"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="timezone-aware"):
        WorkRequest(
            work_id=uid(1),
            tenant_id="tenant-a",
            work_kind="fixture",
            idempotency_key="key",
            correlation_id=uid(2),
            requested_at=datetime(2025, 1, 1),
            payload={},
        )


def test_work_event_has_correlation_causation_idempotency_and_fence() -> None:
    transition = WorkTransition(
        DomainEventType.WORK_STARTED,
        NOW,
        {"phase": "execute"},
        lease(),
    )
    event = transition.to_event(request(), event_id=uid(30), causation_id=uid(31))

    assert event.tenant_id == "tenant-a"
    assert event.correlation_id == uid(2)
    assert event.causation_id == uid(31)
    assert event.payload["lease_generation"] == 1
    assert event.idempotency_key is not None
    assert str(uid(30)) in event.idempotency_key


def test_work_state_machine_rejects_invalid_edges() -> None:
    status = next_status(None, DomainEventType.WORK_REQUESTED)
    status = next_status(status, DomainEventType.WORK_PUBLISHED)
    status = next_status(status, DomainEventType.WORK_CLAIMED)
    status = next_status(status, DomainEventType.WORK_STARTED)
    status = next_status(status, DomainEventType.WORK_FAILED)
    status = next_status(status, DomainEventType.WORK_RETRY_SCHEDULED)

    assert status is WorkStatus.RETRY_WAIT
    with pytest.raises(ValueError, match="invalid"):
        next_status(WorkStatus.SUCCEEDED, DomainEventType.WORK_HEARTBEAT)

    retry = next_status(WorkStatus.RETRY_WAIT, DomainEventType.WORK_PUBLISHED)
    assert next_status(retry, DomainEventType.WORK_CLAIMED) is WorkStatus.CLAIMED
    assert (
        next_status(
            WorkStatus.DEAD_LETTER,
            DomainEventType.WORK_RETRY_SCHEDULED,
        )
        is WorkStatus.RETRY_WAIT
    )
    with pytest.raises(ValueError, match="invalid"):
        next_status(WorkStatus.REQUESTED, DomainEventType.WORK_HEARTBEAT)
    with pytest.raises(ValueError, match="invalid"):
        next_status(WorkStatus.RETRY_WAIT, DomainEventType.WORK_HEARTBEAT)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: WorkTransition(DomainEventType.RUN_STARTED, NOW),
        lambda: WorkTransition(DomainEventType.WORK_STARTED, datetime(2025, 1, 1)),
        lambda: WorkLease(
            uid(1),
            "tenant-a",
            uid(2),
            0,
            "worker",
            1,
            NOW,
            NOW,
            NOW + timedelta(seconds=1),
        ),
        lambda: WorkLease(
            uid(1),
            "tenant-a",
            uid(2),
            1,
            "worker",
            1,
            NOW,
            NOW,
            NOW,
        ),
        lambda: MessageEnvelope(
            uid(1),
            "",
            uid(2),
            None,
            "work",
            uid(3),
            None,
            NOW,
            {},
        ),
        lambda: QueueDelivery("", delivery().envelope, 1, 0),
        lambda: QueueDelivery("1-0", delivery().envelope, 0, 0),
    ],
)
def test_work_and_queue_contract_guards(factory: object) -> None:
    with pytest.raises(ValueError, match=r".+"):
        factory()  # type: ignore[operator]


def test_backoff_is_bounded_and_jitter_is_injectable() -> None:
    backoff = ExponentialBackoff(
        base=timedelta(seconds=2),
        maximum=timedelta(seconds=10),
        jitter=lambda attempt, seconds: seconds - attempt,
    )

    assert backoff.delay(1) == timedelta(seconds=1)
    assert backoff.delay(4) == timedelta(seconds=6)
    with pytest.raises(ValueError, match="attempt"):
        backoff.delay(0)


def test_scheduler_is_fifo_per_tenant_and_round_robin_across_tenants() -> None:
    scheduler = FairTenantScheduler()
    scheduler.add(
        (
            delivery("tenant-a", message_id=10, work_id=1),
            delivery("tenant-a", message_id=11, work_id=2),
            delivery("tenant-b", message_id=12, work_id=3),
            delivery("tenant-a", message_id=13, work_id=4),
            delivery("tenant-b", message_id=14, work_id=5),
        )
    )

    order = [scheduler.pop() for _ in range(5)]

    assert [item.envelope.tenant_id for item in order if item] == [
        "tenant-a",
        "tenant-b",
        "tenant-a",
        "tenant-b",
        "tenant-a",
    ]
    assert [item.envelope.message_id for item in order if item] == [
        uid(10),
        uid(12),
        uid(11),
        uid(14),
        uid(13),
    ]


class FakeQueue:
    def __init__(self) -> None:
        self.published: list[MessageEnvelope] = []
        self.acknowledged: list[QueueDelivery] = []
        self.quarantined: list[tuple[QueueDelivery, str]] = []
        self.publish_error: Exception | None = None
        self.pending_entries: tuple[PendingEntry, ...] = ()
        self.read_deliveries: tuple[QueueDelivery, ...] = ()
        self.reclaim_deliveries: tuple[QueueDelivery, ...] = ()

    async def publish(self, envelope: MessageEnvelope) -> str:
        if self.publish_error:
            raise self.publish_error
        self.published.append(envelope)
        return f"{len(self.published)}-0"

    async def read(
        self,
        *,
        consumer: str,
        count: int,
        block_milliseconds: int,
    ) -> tuple[QueueDelivery, ...]:
        del consumer, block_milliseconds
        return self.read_deliveries[:count]

    async def acknowledge(self, item: QueueDelivery) -> None:
        self.acknowledged.append(item)

    async def quarantine(
        self,
        item: QueueDelivery,
        *,
        reason_code: str,
    ) -> None:
        self.quarantined.append((item, reason_code))

    async def pending(
        self,
        *,
        count: int,
        minimum_idle_milliseconds: int = 0,
    ) -> tuple[PendingEntry, ...]:
        del minimum_idle_milliseconds
        return self.pending_entries[:count]

    async def reclaim(
        self,
        *,
        consumer: str,
        minimum_idle_milliseconds: int,
        count: int,
    ) -> tuple[QueueDelivery, ...]:
        del consumer, minimum_idle_milliseconds
        return self.reclaim_deliveries[:count]

    async def health(self) -> bool:
        return True


class FakeOutbox:
    def __init__(self, claims: Sequence[ClaimedOutboxMessage]) -> None:
        self.claims = tuple(claims)
        self.published: list[UUID] = []
        self.failed: list[tuple[UUID, str]] = []
        self.publish_conflicts: set[UUID] = set()

    async def claim_outbox(self, *args: object, **kwargs: object) -> Sequence[object]:
        del args, kwargs
        return self.claims

    async def mark_outbox_published(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        published_at: datetime,
    ) -> None:
        del context, lease_owner, lease_expires_at, published_at
        if message_id in self.publish_conflicts:
            raise ConcurrencyError(1, 2)
        self.published.append(message_id)

    async def mark_outbox_failed(
        self,
        context: TenantContext,
        message_id: UUID,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        retry_at: datetime,
        error_code: str,
    ) -> None:
        del context, lease_owner, lease_expires_at, retry_at
        self.failed.append((message_id, error_code))


def outbox_claim() -> ClaimedOutboxMessage:
    return ClaimedOutboxMessage(
        message=OutboxMessage(
            message_id=uid(10),
            event_id=uid(4),
            destination="aegis.work",
            available_at=NOW,
            max_attempts=3,
            payload={
                "work_id": str(uid(1)),
                "correlation_id": str(uid(2)),
            },
            headers={"tenant_id": "tenant-a"},
        ),
        attempt_count=1,
        lease_owner="publisher-a",
        lease_expires_at=NOW + timedelta(seconds=30),
    )


@pytest.mark.parametrize(
    ("error", "error_code"),
    [
        (RetryableQueueError("offline"), "redis_unavailable"),
        (PermanentQueueError("poison"), "invalid_envelope"),
    ],
)
def test_outbox_publisher_classifies_failures(
    error: Exception,
    error_code: str,
) -> None:
    repository = FakeOutbox((outbox_claim(),))
    queue = FakeQueue()
    queue.publish_error = error
    publisher = OutboxPublisher(
        repository,
        queue,
        publisher_id="publisher-a",
        retry_delay=lambda _: timedelta(seconds=1),
    )

    result = asyncio.run(publisher.publish_batch(TENANT_A, now=NOW))

    assert result.failed == 1
    assert repository.failed == [(uid(10), error_code)]
    assert repository.published == []


def test_outbox_publisher_uses_deterministic_identity_then_acknowledges_db() -> None:
    repository = FakeOutbox((outbox_claim(),))
    queue = FakeQueue()
    publisher = OutboxPublisher(repository, queue, publisher_id="publisher-a")

    result = asyncio.run(publisher.publish_batch(TENANT_A, now=NOW))

    assert result.published == 1
    assert queue.published[0].message_id == uid(10)
    assert repository.published == [uid(10)]


def test_outbox_publisher_skips_reclaimed_rows_and_continues_batch() -> None:
    first = outbox_claim()
    second = replace(
        outbox_claim(),
        message=replace(outbox_claim().message, message_id=uid(11)),
    )
    repository = FakeOutbox((first, second))
    repository.publish_conflicts.add(uid(10))
    queue = FakeQueue()

    result = asyncio.run(
        OutboxPublisher(repository, queue, publisher_id="publisher-a").publish_batch(
            TENANT_A,
            now=NOW,
        )
    )

    assert result.published == 1
    assert result.failed == 0
    assert [item.message_id for item in queue.published] == [uid(10), uid(11)]
    assert repository.published == [uid(11)]


def test_outbox_publisher_marks_invalid_causation_uuid_as_invalid_envelope() -> None:
    repository = FakeOutbox(
        (
            replace(
                outbox_claim(),
                message=replace(
                    outbox_claim().message,
                    payload={
                        "work_id": str(uid(1)),
                        "correlation_id": str(uid(2)),
                        "causation_id": "not-a-uuid",
                    },
                ),
            ),
        )
    )
    queue = FakeQueue()

    result = asyncio.run(
        OutboxPublisher(
            repository,
            queue,
            publisher_id="publisher-a",
            retry_delay=lambda _: timedelta(seconds=1),
        ).publish_batch(TENANT_A, now=NOW)
    )

    assert result.failed == 1
    assert repository.failed == [(uid(10), "invalid_envelope")]
    assert queue.published == []


def test_publisher_telemetry_records_runtime_metrics() -> None:
    repository = FakeOutbox((outbox_claim(),))
    queue = FakeQueue()
    metrics = RuntimeMetrics()
    publisher = OutboxPublisher(
        repository,
        queue,
        publisher_id="publisher-a",
        telemetry=PublisherTelemetry(metrics),
    )

    queue.publish_error = RetryableQueueError("offline")
    asyncio.run(publisher.publish_batch(TENANT_A, now=NOW))

    assert metrics.snapshot() == {"outbox_lag": 0.0, "publish_failures": 1.0}


def test_publisher_shutdown_and_constructor_guards_are_bounded() -> None:
    repository = FakeOutbox((outbox_claim(),))
    queue = FakeQueue()
    cancelled = asyncio.Event()
    cancelled.set()

    result = asyncio.run(
        OutboxPublisher(
            repository,
            queue,
            publisher_id="publisher-a",
        ).publish_batch(TENANT_A, now=NOW, cancelled=cancelled)
    )

    assert result.claimed == 1
    assert result.published == result.failed == 0
    with pytest.raises(ValueError, match="publisher_id"):
        OutboxPublisher(repository, queue, publisher_id="")
    with pytest.raises(ValueError, match="batch_size"):
        OutboxPublisher(repository, queue, publisher_id="a", batch_size=0)
    with pytest.raises(ValueError, match="lease_duration"):
        OutboxPublisher(
            repository,
            queue,
            publisher_id="a",
            lease_duration=timedelta(0),
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        asyncio.run(
            OutboxPublisher(
                repository,
                queue,
                publisher_id="a",
            ).publish_batch(TENANT_A, now=datetime(2025, 1, 1))
        )


class FakeState:
    def __init__(
        self,
        *,
        cancel_requested: bool = False,
        attempt: int = 1,
        claim_enabled: bool = True,
        complete: bool = False,
    ) -> None:
        self.cancel_requested_value = cancel_requested
        self.claim_enabled = claim_enabled
        self.complete = complete
        self.lease = lease(attempt=attempt)
        self.transitions: list[str] = []
        self.failures: list[FailureClass] = []
        self.heartbeat_event = asyncio.Event()

    async def mark_published(
        self,
        context: TenantContext,
        item: QueueDelivery,
        *,
        at: datetime,
    ) -> None:
        del context, item, at
        self.transitions.append("published")

    async def claim(
        self,
        context: TenantContext,
        item: QueueDelivery,
        *,
        owner: str,
        now: datetime,
        expires_at: datetime,
        tenant_concurrency_limit: int,
    ) -> WorkLease | None:
        del context, item, owner, now, expires_at
        if tenant_concurrency_limit < 1 or not self.claim_enabled:
            return None
        self.transitions.append("claimed")
        return self.lease

    async def start(
        self,
        context: TenantContext,
        item: QueueDelivery,
        active_lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        del context, item, active_lease, at
        self.transitions.append("started")

    async def heartbeat(
        self,
        context: TenantContext,
        item: QueueDelivery,
        active_lease: WorkLease,
        *,
        at: datetime,
        expires_at: datetime,
    ) -> WorkLease:
        del context, item, at, expires_at
        self.transitions.append("heartbeat")
        self.heartbeat_event.set()
        return active_lease

    async def cancellation_requested(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> bool:
        del context, work_id
        return self.cancel_requested_value

    async def delivery_complete(
        self,
        context: TenantContext,
        work_id: UUID,
    ) -> bool:
        del context, work_id
        return self.complete

    async def succeed(
        self,
        context: TenantContext,
        item: QueueDelivery,
        active_lease: WorkLease,
        *,
        at: datetime,
        result_reference: str,
    ) -> None:
        del context, item, active_lease, at, result_reference
        self.transitions.append("succeeded")

    async def cancel(
        self,
        context: TenantContext,
        item: QueueDelivery,
        active_lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        del context, item, active_lease, at
        self.transitions.append("cancelled")

    async def fail(
        self,
        context: TenantContext,
        item: QueueDelivery,
        active_lease: WorkLease,
        *,
        at: datetime,
        failure_class: FailureClass,
        error_code: str,
        retry_at: datetime | None,
    ) -> bool:
        del context, item, active_lease, at, error_code
        self.transitions.append("failed")
        self.failures.append(failure_class)
        return retry_at is None


def supervisor(
    queue: FakeQueue,
    state: FakeState,
    handler: object,
    *,
    quota: int = 2,
) -> WorkerSupervisor:
    return WorkerSupervisor(
        queue,
        state,
        handler,  # type: ignore[arg-type]
        lambda _: quota,
        worker_id="worker-a",
        clock=lambda: NOW,
        max_concurrency=2,
        backoff=ExponentialBackoff(jitter=lambda _attempt, seconds: seconds),
    )


def test_supervisor_from_settings_uses_worker_environment_values() -> None:
    runtime = WorkerSupervisor.from_settings(
        Settings(
            worker_max_concurrency=7,
            worker_lease_seconds=45,
            worker_heartbeat_seconds=9,
        ),
        FakeQueue(),
        FakeState(),
        lambda _: asyncio.sleep(0, result=WorkResult("artifact:settings")),
        lambda _: 2,
        worker_id="worker-settings",
        clock=lambda: NOW,
    )

    assert runtime._max_concurrency == 7
    assert runtime._lease_duration == timedelta(seconds=45)
    assert runtime._heartbeat_interval == timedelta(seconds=9)


def test_supervisor_commits_success_before_ack() -> None:
    queue = FakeQueue()
    state = FakeState()

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("artifact:one")

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.transitions == ["published", "claimed", "started", "succeeded"]
    assert len(queue.acknowledged) == 1


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (
            WorkerExecutionError(FailureClass.RETRYABLE, "dependency_offline"),
            FailureClass.RETRYABLE,
        ),
        (RuntimeError("secret must not escape"), FailureClass.WORKER_BUG),
    ],
)
def test_supervisor_contains_and_durably_classifies_handler_failures(
    raised: Exception,
    expected: FailureClass,
) -> None:
    queue = FakeQueue()
    state = FakeState()

    async def handler(_: WorkExecution) -> WorkResult:
        raise raised

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.failures == [expected]
    assert len(queue.acknowledged) == 1


def test_supervisor_cancellation_race_prefers_durable_cancel_over_success() -> None:
    queue = FakeQueue()
    state = FakeState(cancel_requested=True)

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("artifact:late")

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.transitions[-1] == "cancelled"
    assert "succeeded" not in state.transitions


def test_supervisor_maps_cooperative_cancellation_to_cancelled() -> None:
    queue = FakeQueue()
    state = FakeState(cancel_requested=True)

    async def handler(_: WorkExecution) -> WorkResult:
        raise WorkerExecutionError(FailureClass.CANCELLED, "cancelled_by_handler")

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.transitions[-1] == "cancelled"
    assert state.failures == []
    assert queue.acknowledged == [delivery()]


def test_supervisor_preserves_pending_delivery_for_undurable_cancellation() -> None:
    queue = FakeQueue()
    state = FakeState(cancel_requested=False)

    async def handler(_: WorkExecution) -> WorkResult:
        raise WorkerExecutionError(FailureClass.CANCELLED, "cancelled_by_handler")

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.transitions == ["published", "claimed", "started"]
    assert queue.acknowledged == []


def test_supervisor_preserves_pending_delivery_when_start_is_fenced() -> None:
    queue = FakeQueue()

    class FencedStartState(FakeState):
        async def start(
            self,
            context: TenantContext,
            item: QueueDelivery,
            active_lease: WorkLease,
            *,
            at: datetime,
        ) -> None:
            del context, item, active_lease, at
            self.transitions.append("started")
            raise FencingError(1, 0)

    state = FencedStartState()

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("must-not-run")

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.transitions == ["published", "claimed", "started"]
    assert queue.acknowledged == []


def test_supervisor_preserves_pending_delivery_when_failure_record_is_fenced() -> None:
    queue = FakeQueue()

    class FencedFailureState(FakeState):
        async def fail(
            self,
            context: TenantContext,
            item: QueueDelivery,
            active_lease: WorkLease,
            *,
            at: datetime,
            failure_class: FailureClass,
            error_code: str,
            retry_at: datetime | None,
        ) -> bool:
            del context, item, active_lease, at, failure_class, error_code, retry_at
            self.transitions.append("failed")
            raise FencingError(1, 0)

    state = FencedFailureState()

    async def handler(_: WorkExecution) -> WorkResult:
        raise WorkerExecutionError(FailureClass.PERMANENT, "dependency_rejected")

    asyncio.run(supervisor(queue, state, handler).run_batch((delivery(),)))

    assert state.transitions == ["published", "claimed", "started", "failed"]
    assert queue.acknowledged == []


def test_drain_timeout_does_not_cancel_active_work() -> None:
    async def scenario() -> None:
        queue = FakeQueue()
        state = FakeState()
        started = asyncio.Event()
        release = asyncio.Event()

        async def handler(_: WorkExecution) -> WorkResult:
            started.set()
            await release.wait()
            return WorkResult("artifact:drained")

        runtime = supervisor(queue, state, handler)
        batch = asyncio.create_task(runtime.run_batch((delivery(),)))
        await started.wait()
        assert not await runtime.drain(timeout=timedelta(milliseconds=1))
        assert not batch.done()
        release.set()
        await batch
        assert state.transitions[-1] == "succeeded"

    asyncio.run(scenario())


def test_supervisor_poll_claim_conflict_and_graceful_empty_drain() -> None:
    queue = FakeQueue()
    queue.read_deliveries = (delivery(),)
    state = FakeState()

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("must-not-run")

    runtime = supervisor(queue, state, handler, quota=0)
    assert asyncio.run(runtime.poll_once(block_milliseconds=0)) == 1
    assert state.transitions == ["published"]
    assert queue.acknowledged == []
    assert asyncio.run(runtime.drain(timeout=timedelta(seconds=1)))
    assert asyncio.run(runtime.poll_once(block_milliseconds=0)) == 0


def test_supervisor_quarantines_invalid_tenant_and_authority() -> None:
    queue = FakeQueue()
    state = FakeState()

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("must-not-run")

    invalid_tenant = replace(
        delivery(),
        envelope=replace(delivery().envelope, tenant_id=" invalid "),
    )
    asyncio.run(supervisor(queue, state, handler).run_batch((invalid_tenant,)))
    assert queue.quarantined[-1] == (invalid_tenant, "invalid_tenant_envelope")

    class RejectingState(FakeState):
        async def mark_published(
            self,
            context: TenantContext,
            item: QueueDelivery,
            *,
            at: datetime,
        ) -> None:
            del context, item, at
            raise ValueError("authoritative mismatch")

    rejected = delivery()
    asyncio.run(supervisor(queue, RejectingState(), handler).run_batch((rejected,)))
    assert queue.quarantined[-1] == (
        rejected,
        "authoritative_delivery_rejected",
    )

    class TerminalRaceState(FakeState):
        def __init__(self) -> None:
            super().__init__()
            self.complete_checks = 0

        async def delivery_complete(
            self,
            context: TenantContext,
            work_id: UUID,
        ) -> bool:
            del context, work_id
            self.complete_checks += 1
            return self.complete_checks > 1

        async def mark_published(
            self,
            context: TenantContext,
            item: QueueDelivery,
            *,
            at: datetime,
        ) -> None:
            del context, item, at
            raise ConcurrencyError(1, 2)

    raced = delivery()
    asyncio.run(supervisor(queue, TerminalRaceState(), handler).run_batch((raced,)))
    assert queue.acknowledged[-1] == raced


def test_supervisor_reclaims_pending_and_acks_terminal_duplicates() -> None:
    queue = FakeQueue()
    queue.reclaim_deliveries = (delivery(),)
    state = FakeState(claim_enabled=False, complete=True)

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("must-not-run")

    runtime = supervisor(queue, state, handler)

    assert (
        asyncio.run(
            runtime.recover_once(
                minimum_idle_milliseconds=1_000,
                count=10,
            )
        )
        == 1
    )
    assert queue.acknowledged == [delivery()]


def test_supervisor_stops_scheduling_reads_after_drain_starts() -> None:
    async def scenario() -> None:
        queue = FakeQueue()
        queue.read_deliveries = (delivery(),)
        state = FakeState()

        async def handler(_: WorkExecution) -> WorkResult:
            return WorkResult("should-not-run")

        runtime = supervisor(queue, state, handler)

        async def blocking_read(
            *,
            consumer: str,
            count: int,
            block_milliseconds: int,
        ) -> tuple[QueueDelivery, ...]:
            del consumer, count, block_milliseconds
            await asyncio.sleep(0)
            return queue.read_deliveries

        queue.read = blocking_read  # type: ignore[method-assign]
        poll = asyncio.create_task(runtime.poll_once(block_milliseconds=0))
        await asyncio.sleep(0)
        assert await runtime.drain(timeout=timedelta(seconds=1))
        assert await poll == 0
        assert state.transitions == []
        assert queue.acknowledged == []

    asyncio.run(scenario())


def test_supervisor_stops_scheduling_reclaimed_entries_after_drain_starts() -> None:
    async def scenario() -> None:
        queue = FakeQueue()
        queue.reclaim_deliveries = (delivery(),)
        state = FakeState()

        async def handler(_: WorkExecution) -> WorkResult:
            return WorkResult("should-not-run")

        runtime = supervisor(queue, state, handler)

        async def blocking_reclaim(
            *,
            consumer: str,
            minimum_idle_milliseconds: int,
            count: int,
        ) -> tuple[QueueDelivery, ...]:
            del consumer, minimum_idle_milliseconds, count
            await asyncio.sleep(0)
            return queue.reclaim_deliveries

        queue.reclaim = blocking_reclaim  # type: ignore[method-assign]
        recover = asyncio.create_task(
            runtime.recover_once(
                minimum_idle_milliseconds=1_000,
                count=10,
            )
        )
        await asyncio.sleep(0)
        assert await runtime.drain(timeout=timedelta(seconds=1))
        assert await recover == 0
        assert state.transitions == []
        assert queue.acknowledged == []

    asyncio.run(scenario())


def test_supervisor_renews_lease_while_handler_is_active() -> None:
    queue = FakeQueue()
    state = FakeState()

    async def handler(_: WorkExecution) -> WorkResult:
        await state.heartbeat_event.wait()
        return WorkResult("artifact:heartbeat")

    runtime = WorkerSupervisor(
        queue,
        state,
        handler,
        lambda _: 1,
        worker_id="worker-a",
        clock=lambda: NOW,
        lease_duration=timedelta(seconds=1),
        heartbeat_interval=timedelta(milliseconds=1),
    )

    asyncio.run(runtime.run_batch((delivery(),)))

    assert "heartbeat" in state.transitions
    assert state.transitions[-1] == "succeeded"


def test_supervisor_and_result_validation_guards() -> None:
    queue = FakeQueue()
    state = FakeState()

    async def handler(_: WorkExecution) -> WorkResult:
        return WorkResult("ok")

    with pytest.raises(ValueError, match="result_reference"):
        WorkResult("")
    with pytest.raises(ValueError, match="error_code"):
        WorkerExecutionError(FailureClass.PERMANENT, "")
    with pytest.raises(ValueError, match="worker_id"):
        WorkerSupervisor(
            queue,
            state,
            handler,
            lambda _: 1,
            worker_id="",
            clock=lambda: NOW,
        )
    with pytest.raises(ValueError, match="max_concurrency"):
        WorkerSupervisor(
            queue,
            state,
            handler,
            lambda _: 1,
            worker_id="worker",
            clock=lambda: NOW,
            max_concurrency=0,
        )
    with pytest.raises(ValueError, match="heartbeat"):
        WorkerSupervisor(
            queue,
            state,
            handler,
            lambda _: 1,
            worker_id="worker",
            clock=lambda: NOW,
            lease_duration=timedelta(seconds=5),
            heartbeat_interval=timedelta(seconds=5),
        )


class FakeOperationsRepository:
    def __init__(self) -> None:
        self.cancelled: list[UUID] = []
        self.requeued: list[UUID] = []

    async def status(
        self,
        context: TenantContext,
        *,
        status: WorkStatus | None = None,
        limit: int = 100,
        cursor: tuple[datetime, UUID] | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        del context, status, limit, cursor
        return ({"status": "running"},)

    async def pending_status(
        self,
        context: TenantContext,
        *,
        limit: int = 100,
        cursor: tuple[datetime, UUID] | datetime | None = None,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        del context, limit, cursor
        return ({"status": "claimed"},)

    async def cancel_by_id(self, *args: object, **kwargs: object) -> None:
        del kwargs
        self.cancelled.append(args[1])  # type: ignore[arg-type]

    async def requeue_dead_letter(self, *args: object, **kwargs: object) -> None:
        del kwargs
        self.requeued.append(args[1])  # type: ignore[arg-type]

    async def approve_dead_letter_requeue(
        self,
        context: TenantContext,
        work_id: UUID,
        *,
        approval: RequeueApproval,
        expires_at: datetime,
    ) -> None:
        del context, work_id, approval, expires_at

    async def reconcile_expired(
        self,
        context: TenantContext,
        *,
        now: datetime,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        del context, now, limit
        return (uid(1),)


def principal(role: Role) -> Principal:
    tenant_id = (
        PLATFORM_TENANT_ID if role is Role.PLATFORM_ADMIN else TenantId("tenant-a")
    )
    return Principal(
        subject="subject",
        issuer="https://issuer.test",
        tenant_id=tenant_id,
        kind=PrincipalKind.USER,
        user_id=UserId("user-a"),
        role_bindings=(
            RoleBinding(
                tenant_id=tenant_id,
                role=role,
                assigned_by=UserId("admin"),
                assigned_at=NOW - timedelta(days=1),
            ),
        ),
    )


def test_operations_are_tenant_authorized_bounded_and_approval_scoped() -> None:
    queue = FakeQueue()
    repository = FakeOperationsRepository()
    metrics = RuntimeMetrics()
    operations = WorkerOperations(
        repository,
        queue,
        telemetry=RuntimeTelemetry(metrics),
    )
    approval = RequeueApproval(
        approval_id=uid(50),
        approved_by="admin",
        approved_at=NOW,
        scope="dlq:requeue",
    )

    rows = asyncio.run(
        operations.work_status(
            principal(Role.OPERATOR),
            TENANT_A,
            at=NOW,
            limit=10,
        )
    )
    asyncio.run(
        operations.requeue_dead_letter(
            principal(Role.TENANT_ADMIN),
            TENANT_A,
            uid(1),
            approval,
            at=NOW,
        )
    )
    asyncio.run(
        operations.cancel(
            principal(Role.OPERATOR),
            TENANT_A,
            uid(2),
            at=NOW,
        )
    )
    assert asyncio.run(
        operations.reconcile(
            principal(Role.TENANT_ADMIN),
            TENANT_A,
            at=NOW,
            limit=10,
        )
    ) == (uid(1),)
    assert (
        len(
            asyncio.run(
                operations.pending(
                    principal(Role.OPERATOR),
                    TENANT_A,
                    at=NOW,
                    limit=10,
                )
            )
        )
        == 1
    )
    with pytest.raises(OperationDeniedError):
        asyncio.run(
            operations.reconcile(
                principal(Role.PLATFORM_ADMIN),
                TENANT_A,
                at=NOW,
                limit=1,
            )
        )
    with pytest.raises(
        OperationDeniedError,
        match="tenant admin or platform admin required",
    ):
        asyncio.run(
            operations.reconcile(
                principal(Role.OPERATOR),
                TENANT_A,
                at=NOW,
                limit=1,
            )
        )

    assert rows[0]["status"] == "running"
    assert repository.cancelled == [uid(2)]
    assert repository.requeued == [uid(1)]
    assert metrics.snapshot()["reconciliation_success"] == 1.0
    with pytest.raises(OperationDeniedError):
        asyncio.run(
            operations.work_status(
                principal(Role.VIEWER),
                TENANT_B,
                at=NOW,
            )
        )
    with pytest.raises(ValueError, match="scope"):
        RequeueApproval(uid(50), "admin", NOW, "work:cancel")


def test_metrics_and_spans_have_fixed_names_without_identifier_labels() -> None:
    metrics = RuntimeMetrics()
    metrics.add("retries")
    metrics.set_gauge("active_leases", 2)

    assert metrics.snapshot() == {"retries": 1, "active_leases": 2}
    with pytest.raises(ValueError, match="unrecognized"):
        metrics.add("tenant-a")
    with pytest.raises(ValueError, match="negative"):
        metrics.add("retries", -1)
    with pytest.raises(ValueError, match="negative"):
        metrics.set_gauge("active_leases", -1)
    telemetry = RuntimeTelemetry(metrics)
    telemetry.claim_conflict()
    telemetry.active_leases(1)
    telemetry.heartbeat_failure()
    telemetry.retry()
    telemetry.dead_letter()
    telemetry.completed(1)
    telemetry.cancelled()
    telemetry.reconciliation("recovered")
    assert metrics.snapshot() == {
        "retries": 2.0,
        "active_leases": 1.0,
        "claim_conflicts": 1.0,
        "heartbeat_failures": 1.0,
        "dead_letters": 1.0,
        "work_latency": 1.0,
        "cancellations": 1.0,
        "reconciliation_success": 1.0,
    }
    with RuntimeTracer().span("work.execute"):
        pass
    with (
        pytest.raises(ValueError, match="unrecognized"),
        RuntimeTracer().span("work.execute.tenant-a"),
    ):
        pass
