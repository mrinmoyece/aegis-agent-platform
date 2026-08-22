"""Unit tests for Redis stream adapter edge cases."""

from __future__ import annotations

import asyncio
from typing import cast

import pytest
import redis.asyncio as redis

from aegis_agent_platform.queueing import PoisonMessageError
from aegis_agent_platform.queueing.redis_streams import RedisStreamQueue, _decode_fields


class FakeRedisClient:
    def __init__(self) -> None:
        self.xreadgroup_calls: list[dict[str, object]] = []

    async def xgroup_create(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

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
        return []


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
