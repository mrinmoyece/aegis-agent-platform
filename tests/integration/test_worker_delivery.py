"""Live PostgreSQL plus Redis evidence for delivery, leases, and fencing."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
import redis.asyncio as redis

from aegis_agent_platform.domain import (
    DomainEventType,
    FailureClass,
    WorkRequest,
    WorkStatus,
    next_status,
)
from aegis_agent_platform.event_store import ConcurrencyError, FencingError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.queueing.publisher import OutboxPublisher
from aegis_agent_platform.queueing.redis_streams import RedisStreamQueue
from aegis_agent_platform.runtime.operations import RequeueApproval
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext

DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("AEGIS_TEST_REDIS_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.redis_integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="AEGIS_TEST_DATABASE_URL and AEGIS_TEST_REDIS_URL are required",
    ),
]
TENANT_A = TenantContext(TenantId("tenant-a"))
TENANT_B = TenantContext(TenantId("tenant-b"))
NOW = datetime.now(UTC)


async def app_connection() -> psycopg.AsyncConnection[tuple[object, ...]]:
    assert DATABASE_URL is not None
    connection = await psycopg.AsyncConnection.connect(
        DATABASE_URL,
        autocommit=True,
    )
    await connection.execute("SET ROLE aegis_app")
    return connection


def test_live_publish_claim_fence_duplicate_ack_and_poison() -> None:
    async def scenario() -> None:
        assert REDIS_URL is not None
        stream = f"aegis:test:{uuid4()}"
        group = f"group:{uuid4()}"
        client = redis.from_url(  # type: ignore[no-untyped-call]
            REDIS_URL,
            decode_responses=False,
        )
        queue = RedisStreamQueue(client, stream=stream, group=group)
        first_connection = await app_connection()
        second_connection = await app_connection()
        first_events = PostgresEventStore(first_connection)
        second_events = PostgresEventStore(second_connection)
        first = PostgresWorkRepository(first_connection, first_events)
        second = PostgresWorkRepository(second_connection, second_events)
        work_id = uuid4()
        work = WorkRequest(
            work_id=work_id,
            tenant_id="tenant-a",
            work_kind="integration-fixture",
            idempotency_key=f"integration-{work_id}",
            correlation_id=uuid4(),
            requested_at=NOW,
            payload={"fixture_reference": "safe"},
            max_attempts=3,
            timeout_seconds=30,
        )
        try:
            await first.register(
                TENANT_A,
                work,
                requested_event_id=uuid4(),
                outbox_message_id=uuid4(),
            )
            result = await OutboxPublisher(
                first_events,
                queue,
                publisher_id="publisher-a",
            ).publish_batch(TENANT_A, now=NOW)
            assert result.published == 1

            deliveries = await queue.read(
                consumer="worker-a",
                count=1,
                block_milliseconds=100,
            )
            assert len(deliveries) == 1
            item = deliveries[0]
            await first.mark_published(TENANT_A, item, at=NOW)
            expiry = NOW + timedelta(seconds=30)

            claims = await asyncio.gather(
                first.claim(
                    TENANT_A,
                    item,
                    owner="worker-a",
                    now=NOW,
                    expires_at=expiry,
                    tenant_concurrency_limit=2,
                ),
                second.claim(
                    TENANT_A,
                    item,
                    owner="worker-b",
                    now=NOW,
                    expires_at=expiry,
                    tenant_concurrency_limit=2,
                ),
            )
            active = [claim for claim in claims if claim is not None]
            assert len(active) == 1
            old_lease = active[0]
            owner = first if old_lease.owner == "worker-a" else second
            await owner.start(TENANT_A, item, old_lease, at=NOW)
            renewed = await owner.heartbeat(
                TENANT_A,
                item,
                old_lease,
                at=NOW + timedelta(seconds=5),
                expires_at=NOW + timedelta(seconds=35),
            )
            assert (
                timedelta(seconds=29)
                < (renewed.expires_at - renewed.heartbeat_at)
                <= timedelta(seconds=30, milliseconds=10)
            )

            reclaim_at = NOW + timedelta(seconds=6)
            await owner.release(
                TENANT_A,
                renewed,
                at=reclaim_at,
                reason="controlled_reclaim",
                retry_at=NOW,
            )
            claim_at = datetime.now(UTC)
            new_lease = await second.claim(
                TENANT_A,
                item,
                owner="worker-c",
                now=claim_at,
                expires_at=claim_at + timedelta(seconds=30),
                tenant_concurrency_limit=2,
            )
            assert new_lease is not None
            assert new_lease.generation == old_lease.generation + 1
            with pytest.raises(FencingError):
                await owner.start(
                    TENANT_A,
                    item,
                    old_lease,
                    at=reclaim_at,
                )

            await second.start(TENANT_A, item, new_lease, at=reclaim_at)
            await second.succeed(
                TENANT_A,
                item,
                new_lease,
                at=reclaim_at,
                result_reference="artifact:integration",
            )
            replayed_status: WorkStatus | None = None
            async for stored_event in second_events.read_stream(
                TENANT_A,
                str(work_id),
            ):
                replayed_status = next_status(
                    replayed_status,
                    DomainEventType(stored_event.event_type),
                )
            assert replayed_status is WorkStatus.SUCCEEDED
            await queue.acknowledge(item)
            assert await queue.pending(count=10) == ()

            await queue.publish(item.envelope)
            duplicate = (
                await queue.read(
                    consumer="worker-b",
                    count=1,
                    block_milliseconds=100,
                )
            )[0]
            await second.mark_published(TENANT_A, duplicate, at=reclaim_at)
            assert (
                await second.claim(
                    TENANT_A,
                    duplicate,
                    owner="must-not-run",
                    now=reclaim_at,
                    expires_at=reclaim_at + timedelta(seconds=30),
                    tenant_concurrency_limit=2,
                )
                is None
            )
            tenant_b_rows = await second.status(TENANT_B, limit=10)
            assert tenant_b_rows == ()
            await queue.acknowledge(duplicate)

            forged = replace(
                duplicate,
                envelope=replace(
                    duplicate.envelope,
                    payload={
                        **duplicate.envelope.payload,
                        "request_payload": {"fixture_reference": "forged"},
                    },
                ),
            )
            with pytest.raises(ValueError, match="authoritative"):
                await second.mark_published(TENANT_A, forged, at=reclaim_at)

            await client.xadd(stream, {b"envelope": b"{not-json"})
            assert (
                await queue.read(
                    consumer="worker-poison",
                    count=1,
                    block_milliseconds=100,
                )
                == ()
            )
            assert await queue.pending(count=10) == ()
            assert await client.xlen(f"{stream}:poison") == 1

            cancelled_id = uuid4()
            cancelled_work = WorkRequest(
                work_id=cancelled_id,
                tenant_id="tenant-a",
                work_kind="cancel-fixture",
                idempotency_key=f"cancel-{cancelled_id}",
                correlation_id=uuid4(),
                requested_at=NOW,
                payload={"fixture_reference": "cancel"},
            )
            await first.register(
                TENANT_A,
                cancelled_work,
                requested_event_id=uuid4(),
                outbox_message_id=uuid4(),
            )
            assert (
                await OutboxPublisher(
                    first_events,
                    queue,
                    publisher_id="publisher-cancel",
                ).publish_batch(TENANT_A, now=datetime.now(UTC))
            ).published == 1
            cancelled_delivery = (
                await queue.read(
                    consumer="worker-cancel",
                    count=1,
                    block_milliseconds=100,
                )
            )[0]
            await first.cancel_by_id(
                TENANT_A,
                cancelled_id,
                at=datetime.now(UTC),
                actor_id="operator-a",
            )
            with pytest.raises(ConcurrencyError):
                await first.mark_published(
                    TENANT_A,
                    cancelled_delivery,
                    at=datetime.now(UTC),
                )
            cancelled_status: WorkStatus | None = None
            async for stored_event in first_events.read_stream(
                TENANT_A,
                str(cancelled_id),
            ):
                cancelled_status = next_status(
                    cancelled_status,
                    DomainEventType(stored_event.event_type),
                )
            assert cancelled_status is WorkStatus.CANCELLED
            await queue.acknowledge(cancelled_delivery)

            running_cancel_id = uuid4()
            running_cancel = WorkRequest(
                work_id=running_cancel_id,
                tenant_id="tenant-a",
                work_kind="running-cancel-fixture",
                idempotency_key=f"running-cancel-{running_cancel_id}",
                correlation_id=uuid4(),
                requested_at=NOW,
                payload={},
            )
            await first.register(
                TENANT_A,
                running_cancel,
                requested_event_id=uuid4(),
                outbox_message_id=uuid4(),
            )
            assert (
                await OutboxPublisher(
                    first_events,
                    queue,
                    publisher_id="publisher-running-cancel",
                ).publish_batch(TENANT_A, now=datetime.now(UTC))
            ).published == 1
            running_cancel_delivery = (
                await queue.read(
                    consumer="worker-running-cancel",
                    count=1,
                    block_milliseconds=100,
                )
            )[0]
            await first.mark_published(
                TENANT_A,
                running_cancel_delivery,
                at=datetime.now(UTC),
            )
            running_claim_at = datetime.now(UTC)
            running_cancel_lease = await first.claim(
                TENANT_A,
                running_cancel_delivery,
                owner="worker-running-cancel",
                now=running_claim_at,
                expires_at=running_claim_at + timedelta(seconds=30),
                tenant_concurrency_limit=2,
            )
            assert running_cancel_lease is not None
            await first.start(
                TENANT_A,
                running_cancel_delivery,
                running_cancel_lease,
                at=datetime.now(UTC),
            )
            await first.request_cancel(
                TENANT_A,
                running_cancel,
                at=datetime.now(UTC),
                actor_id="operator-a",
            )
            await first.cancel(
                TENANT_A,
                running_cancel_delivery,
                running_cancel_lease,
                at=datetime.now(UTC),
            )
            assert await first.delivery_complete(TENANT_A, running_cancel_id)
            await queue.acknowledge(running_cancel_delivery)

            dead_id = uuid4()
            dead_work = WorkRequest(
                work_id=dead_id,
                tenant_id="tenant-a",
                work_kind="dlq-fixture",
                idempotency_key=f"dlq-{dead_id}",
                correlation_id=uuid4(),
                requested_at=NOW,
                payload={"fixture_reference": "preserved"},
                max_attempts=1,
            )
            await first.register(
                TENANT_A,
                dead_work,
                requested_event_id=uuid4(),
                outbox_message_id=uuid4(),
            )
            assert (
                await OutboxPublisher(
                    first_events,
                    queue,
                    publisher_id="publisher-dlq",
                ).publish_batch(TENANT_A, now=datetime.now(UTC))
            ).published == 1
            dead_delivery = (
                await queue.read(
                    consumer="worker-dlq",
                    count=1,
                    block_milliseconds=100,
                )
            )[0]
            await first.mark_published(
                TENANT_A,
                dead_delivery,
                at=datetime.now(UTC),
            )
            dead_claim_at = datetime.now(UTC)
            dead_lease = await first.claim(
                TENANT_A,
                dead_delivery,
                owner="worker-dlq",
                now=dead_claim_at,
                expires_at=dead_claim_at + timedelta(seconds=30),
                tenant_concurrency_limit=2,
            )
            assert dead_lease is not None
            await first.start(
                TENANT_A,
                dead_delivery,
                dead_lease,
                at=datetime.now(UTC),
            )
            assert await first.fail(
                TENANT_A,
                dead_delivery,
                dead_lease,
                at=datetime.now(UTC),
                failure_class=FailureClass.PERMANENT,
                error_code="permanent_fixture",
                retry_at=None,
            )
            await queue.acknowledge(dead_delivery)
            approval_time = datetime.now(UTC)
            approval = RequeueApproval(
                approval_id=uuid4(),
                approved_by="approver-a",
                approved_at=approval_time,
                scope="dlq:requeue",
            )
            await first.approve_dead_letter_requeue(
                TENANT_A,
                dead_id,
                approval=approval,
                expires_at=approval_time + timedelta(minutes=5),
            )
            await first.requeue_dead_letter(
                TENANT_A,
                dead_id,
                at=datetime.now(UTC),
                approval=approval,
                actor_id="operator-b",
            )
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
                )
                payload_row = await (
                    await first_connection.execute(
                        """
                        SELECT payload->'request_payload'
                        FROM outbox_messages
                        WHERE tenant_id = 'tenant-a'
                          AND payload->>'work_id' = %s
                          AND status = 'pending'
                        """,
                        (str(dead_id),),
                    )
                ).fetchone()
            assert payload_row == ({"fixture_reference": "preserved"},)
            assert (
                await OutboxPublisher(
                    first_events,
                    queue,
                    publisher_id="publisher-dlq-requeue",
                ).publish_batch(TENANT_A, now=datetime.now(UTC))
            ).published == 1
            requeued_delivery = (
                await queue.read(
                    consumer="worker-dlq-requeue",
                    count=1,
                    block_milliseconds=100,
                )
            )[0]
            await first.mark_published(
                TENANT_A,
                requeued_delivery,
                at=datetime.now(UTC),
            )
            await first.cancel_by_id(
                TENANT_A,
                dead_id,
                at=datetime.now(UTC),
                actor_id="operator-b",
            )
            await queue.acknowledge(requeued_delivery)

            redrive_id = uuid4()
            redrive = WorkRequest(
                work_id=redrive_id,
                tenant_id="tenant-a",
                work_kind="redrive-fixture",
                idempotency_key=f"redrive-{redrive_id}",
                correlation_id=uuid4(),
                requested_at=NOW,
                payload={"fixture_reference": "redrive"},
            )
            redrive_message_id = uuid4()
            await first.register(
                TENANT_A,
                redrive,
                requested_event_id=uuid4(),
                outbox_message_id=redrive_message_id,
            )
            assert (
                await OutboxPublisher(
                    first_events,
                    queue,
                    publisher_id="publisher-redrive",
                ).publish_batch(TENANT_A, now=NOW)
            ).published == 1
            lost_delivery = (
                await queue.read(
                    consumer="worker-redrive",
                    count=1,
                    block_milliseconds=100,
                )
            )[0]
            await first.mark_published(
                TENANT_A,
                lost_delivery,
                at=datetime.now(UTC),
            )
            await queue.acknowledge(lost_delivery)
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
                )
                await first_connection.execute(
                    """
                    UPDATE outbox_messages
                    SET published_at = clock_timestamp() - interval '6 minutes'
                    WHERE tenant_id = 'tenant-a' AND message_id = %s
                    """,
                    (redrive_message_id,),
                )
            assert redrive_id in await first.reconcile_expired(
                TENANT_A,
                now=datetime.now(UTC),
                limit=10,
            )
            assert (
                await OutboxPublisher(
                    first_events,
                    queue,
                    publisher_id="publisher-redrive",
                ).publish_batch(TENANT_A, now=datetime.now(UTC))
            ).published == 1
        finally:
            await client.delete(stream)
            await client.delete(f"{stream}:poison")
            await client.aclose()
            await first_connection.close()
            await second_connection.close()

    asyncio.run(scenario())
