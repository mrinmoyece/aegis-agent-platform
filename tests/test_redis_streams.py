"""Unit tests for Redis stream adapter edge cases."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
import redis.asyncio as redis
from redis.exceptions import ResponseError

from aegis_agent_platform.queueing import (
    MessageEnvelope,
    PermanentQueueError,
    PoisonMessageError,
    RetryableQueueError,
)
from aegis_agent_platform.queueing.redis_streams import (
    RedisStreamQueue,
    _decode_fields,
    validate_transport_size,
)


def _envelope_bytes(message_id: str = "00000000-0000-0000-0000-000000000001") -> bytes:
    return (
        b'{"causation_id":null,"correlation_id":"00000000-0000-0000-0000-000000000002",'
        b'"destination":"aegis.work","event_id":null,'
        + f'"message_id":"{message_id}",'.encode()
        + b'"headers":{},"occurred_at":"2025-01-01T00:00:00+00:00","payload":{},'
        b'"schema_version":1,"tenant_id":"tenant-a","work_id":"00000000-0000-0000-0000-000000000003"}'
    )


class FakeRedisClient:
    def __init__(self) -> None:
        self.xreadgroup_calls: list[dict[str, object]] = []
        self.xgroup_create_calls = 0
        self.read_error: ResponseError | None = None
        self.xautoclaim_calls: list[str] = []
        self.xautoclaim_results: list[
            tuple[bytes, list[tuple[bytes, dict[bytes, bytes]]]]
        ] = []
        self.pending_rows: list[dict[str, object]] = []

    async def xgroup_create(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.xgroup_create_calls += 1

    async def xreadgroup(
        self,
        group: str,
        consumer: str,
        streams: dict[str, str],
        **kwargs: object,
    ) -> list[tuple[bytes, list[tuple[bytes, dict[bytes, bytes]]]]]:
        self.xreadgroup_calls.append(
            {
                "group": group,
                "consumer": consumer,
                "streams": streams,
                **kwargs,
            }
        )
        if self.read_error is not None:
            raise self.read_error
        return []

    async def xautoclaim(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_time: int,
        start_id: str,
        count: int,
    ) -> tuple[bytes, list[tuple[bytes, dict[bytes, bytes]]]]:
        del stream, group, consumer, min_idle_time, count
        self.xautoclaim_calls.append(start_id)
        return self.xautoclaim_results.pop(0)

    async def xpending_range(
        self,
        stream: str,
        group: str,
        *,
        count: int,
        idle: int | None = None,
        **kwargs: object,
    ) -> list[dict[str, object]]:
        del stream, group, count, idle, kwargs
        return self.pending_rows


def test_decode_fields_treats_invalid_utf8_as_poison() -> None:
    with pytest.raises(PoisonMessageError, match="invalid message envelope"):
        _decode_fields({b"envelope": b"\x80"})


def test_read_omits_block_parameter_for_non_blocking_reads() -> None:
    client = FakeRedisClient()
    queue = RedisStreamQueue(
        cast(redis.Redis, client),
        stream="aegis:test",
        group="workers",
    )

    deliveries = asyncio.run(
        queue.read(
            consumer="worker-a",
            count=1,
            block_milliseconds=0,
        )
    )

    assert deliveries == ()
    assert client.xreadgroup_calls == [
        {
            "group": "workers",
            "consumer": "worker-a",
            "streams": {"aegis:test": ">"},
            "count": 1,
        }
    ]


def test_reclaim_advances_cursor_and_wraps_after_full_scan() -> None:
    client = FakeRedisClient()
    client.xautoclaim_results = [
        (
            b"7-0",
            [(b"1-0", {b"envelope": _envelope_bytes()})],
        ),
        (b"0-0", []),
        (b"9-0", []),
    ]
    client.pending_rows = [
        {
            "message_id": b"1-0",
            "consumer": b"worker-a",
            "time_since_delivered": 1_500,
            "times_delivered": 3,
        }
    ]
    queue = RedisStreamQueue(
        cast(redis.Redis, client),
        stream="aegis:test",
        group="workers",
    )

    first = asyncio.run(
        queue.reclaim(
            consumer="worker-a",
            minimum_idle_milliseconds=1_000,
            count=1,
        )
    )
    second = asyncio.run(
        queue.reclaim(
            consumer="worker-a",
            minimum_idle_milliseconds=1_000,
            count=1,
        )
    )
    third = asyncio.run(
        queue.reclaim(
            consumer="worker-a",
            minimum_idle_milliseconds=1_000,
            count=1,
        )
    )

    assert len(first) == 1
    assert first[0].delivery_count == 3
    assert second == ()
    assert third == ()
    assert client.xautoclaim_calls == ["0-0", "7-0", "0-0"]


def test_read_invalidates_cached_group_when_redis_reports_nogroup() -> None:
    client = FakeRedisClient()
    client.read_error = ResponseError("NOGROUP No such key 'aegis:test'")
    queue = RedisStreamQueue(
        cast(redis.Redis, client),
        stream="aegis:test",
        group="workers",
    )

    with pytest.raises(RetryableQueueError, match="consumer group missing"):
        asyncio.run(
            queue.read(
                consumer="worker-a",
                count=1,
                block_milliseconds=0,
            )
        )

    assert queue._group_ready is False
    client.read_error = None
    asyncio.run(
        queue.read(
            consumer="worker-a",
            count=1,
            block_milliseconds=0,
        )
    )

    assert client.xgroup_create_calls == 2


def test_validate_transport_size_rejects_oversized_envelopes() -> None:
    with pytest.raises(PermanentQueueError, match="256 KiB"):
        validate_transport_size(
            MessageEnvelope(
                message_id=UUID(int=1),
                tenant_id="tenant-a",
                work_id=UUID(int=2),
                event_id=None,
                destination="aegis.work",
                correlation_id=UUID(int=3),
                causation_id=None,
                occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
                payload={"request_payload": {"blob": "x" * (300 * 1024)}},
                headers={},
            )
        )
