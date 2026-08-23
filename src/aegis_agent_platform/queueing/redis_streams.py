"""Redis Streams transport adapter; Redis is never authoritative state."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import cast
from uuid import UUID

import redis.asyncio as redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError

from aegis_agent_platform.config import Settings
from aegis_agent_platform.domain.events import JsonValue, thaw_json
from aegis_agent_platform.queueing import (
    MessageEnvelope,
    PendingEntry,
    PermanentQueueError,
    PoisonMessageError,
    QueueDelivery,
    RetryableQueueError,
)

_ENVELOPE_FIELD = b"envelope"
_MAX_ENVELOPE_BYTES = 256 * 1024


class RedisStreamQueue:
    """One shared stream with tenant-bound envelopes and consumer groups.

    Shared cardinality keeps stream/group operations bounded. It provides global
    stream order, not tenant fairness; the runtime schedules decoded deliveries
    round-robin and enforces per-tenant concurrency quotas.
    """

    def __init__(
        self,
        client: redis.Redis,
        *,
        stream: str = "aegis:work:v1",
        group: str = "aegis-workers-v1",
    ) -> None:
        if not stream or not group:
            raise ValueError("stream and group are required")
        self._client = client
        self._stream = stream
        self._group = group
        self._poison_stream = f"{stream}:poison"
        self._group_ready = False

    async def ensure_group(self) -> None:
        """Idempotently create the consumer group at the beginning of the stream."""
        if self._group_ready:
            return
        try:
            await self._client.xgroup_create(
                self._stream,
                self._group,
                id="0-0",
                mkstream=True,
            )
        except RedisError as error:
            if "BUSYGROUP" not in str(error):
                raise _classify_redis_error(error) from error
        self._group_ready = True

    async def publish(self, envelope: MessageEnvelope) -> str:
        """XADD a deterministic identity; duplicates remain safe and visible."""
        await self.ensure_group()
        encoded = _encode_envelope(envelope)
        try:
            result = await self._client.xadd(
                self._stream,
                {_ENVELOPE_FIELD: encoded},
            )
        except RedisError as error:
            raise _classify_redis_error(error) from error
        return _text(result)

    async def read(
        self,
        *,
        consumer: str,
        count: int,
        block_milliseconds: int,
    ) -> tuple[QueueDelivery, ...]:
        await self.ensure_group()
        _validate_consumer_read(consumer, count, block_milliseconds)
        try:
            kwargs: dict[str, object] = {
                "count": count,
            }
            if block_milliseconds > 0:
                kwargs["block"] = block_milliseconds
            rows = await self._client.xreadgroup(
                self._group,
                consumer,
                {self._stream: ">"},
                **kwargs,
            )
        except RedisError as error:
            raise _classify_redis_error(error) from error
        entries = _stream_entries(rows)
        return await self._decode_entries(
            entries,
            delivery_count=1,
            idle_milliseconds=0,
        )

    async def acknowledge(self, delivery: QueueDelivery) -> None:
        await self.ensure_group()
        try:
            async with self._client.pipeline(transaction=True) as pipeline:
                pipeline.xack(
                    self._stream,
                    self._group,
                    delivery.stream_entry_id,
                )
                pipeline.xdel(self._stream, delivery.stream_entry_id)
                result = await pipeline.execute()
        except RedisError as error:
            raise _classify_redis_error(error) from error
        acknowledged = result[0]
        if int(acknowledged) not in {0, 1}:
            raise PermanentQueueError("unexpected acknowledgement count")

    async def quarantine(
        self,
        delivery: QueueDelivery,
        *,
        reason_code: str,
    ) -> None:
        if not reason_code or len(reason_code) > 128:
            raise ValueError("bounded reason_code is required")
        await self._quarantine_poison(
            delivery.stream_entry_id,
            reason_code=reason_code,
        )

    async def pending(
        self,
        *,
        count: int,
        minimum_idle_milliseconds: int = 0,
    ) -> tuple[PendingEntry, ...]:
        await self.ensure_group()
        if not 1 <= count <= 1_000 or minimum_idle_milliseconds < 0:
            raise ValueError("invalid bounded pending query")
        try:
            rows = await self._client.xpending_range(
                self._stream,
                self._group,
                min="-",
                max="+",
                count=count,
                idle=minimum_idle_milliseconds or None,
            )
        except RedisError as error:
            raise _classify_redis_error(error) from error
        return tuple(
            PendingEntry(
                stream_entry_id=_text(row["message_id"]),
                consumer=_text(row["consumer"]),
                idle_milliseconds=int(str(row["time_since_delivered"])),
                delivery_count=int(str(row["times_delivered"])),
            )
            for row in cast(list[dict[str, object]], rows)
        )

    async def reclaim(
        self,
        *,
        consumer: str,
        minimum_idle_milliseconds: int,
        count: int,
    ) -> tuple[QueueDelivery, ...]:
        await self.ensure_group()
        if not consumer or minimum_idle_milliseconds < 1 or not 1 <= count <= 100:
            raise ValueError("invalid bounded reclaim request")
        try:
            result = await self._client.xautoclaim(
                self._stream,
                self._group,
                consumer,
                min_idle_time=minimum_idle_milliseconds,
                start_id="0-0",
                count=count,
            )
        except RedisError as error:
            raise _classify_redis_error(error) from error
        entries = cast(list[tuple[object, Mapping[object, object]]], result[1])
        deliveries: list[QueueDelivery] = []
        metadata = {
            entry.stream_entry_id: entry for entry in await self.pending(count=count)
        }
        for entry_id, fields in entries:
            text_id = _text(entry_id)
            pending = metadata.get(text_id)
            decoded = await self._decode_entries(
                ((entry_id, fields),),
                delivery_count=pending.delivery_count if pending else 2,
                idle_milliseconds=(
                    pending.idle_milliseconds if pending else minimum_idle_milliseconds
                ),
            )
            deliveries.extend(decoded)
        return tuple(deliveries)

    async def _decode_entries(
        self,
        entries: tuple[tuple[object, Mapping[object, object]], ...],
        *,
        delivery_count: int,
        idle_milliseconds: int,
    ) -> tuple[QueueDelivery, ...]:
        deliveries: list[QueueDelivery] = []
        for entry_id, fields in entries:
            text_id = _text(entry_id)
            try:
                envelope = _decode_fields(fields)
            except PoisonMessageError:
                await self._quarantine_poison(
                    text_id,
                    reason_code="invalid_envelope",
                )
                continue
            deliveries.append(
                QueueDelivery(
                    stream_entry_id=text_id,
                    envelope=envelope,
                    delivery_count=delivery_count,
                    idle_milliseconds=idle_milliseconds,
                )
            )
        return tuple(deliveries)

    async def _quarantine_poison(
        self,
        stream_entry_id: str,
        *,
        reason_code: str,
    ) -> None:
        """Atomically record payload-free poison evidence and clear the PEL entry."""
        try:
            async with self._client.pipeline(transaction=True) as pipeline:
                pipeline.xadd(
                    self._poison_stream,
                    {
                        b"source_entry_id": stream_entry_id.encode(),
                        b"reason_code": reason_code.encode(),
                    },
                    maxlen=10_000,
                    approximate=True,
                )
                pipeline.xack(self._stream, self._group, stream_entry_id)
                pipeline.xdel(self._stream, stream_entry_id)
                await pipeline.execute()
        except RedisError as error:
            raise _classify_redis_error(error) from error

    async def health(self) -> bool:
        try:
            return bool(await self._client.ping())
        except RedisError:
            return False


def _encode_envelope(envelope: MessageEnvelope) -> bytes:
    body = {
        "schema_version": envelope.schema_version,
        "message_id": str(envelope.message_id),
        "tenant_id": envelope.tenant_id,
        "work_id": str(envelope.work_id),
        "event_id": str(envelope.event_id) if envelope.event_id else None,
        "destination": envelope.destination,
        "correlation_id": str(envelope.correlation_id),
        "causation_id": (str(envelope.causation_id) if envelope.causation_id else None),
        "occurred_at": envelope.occurred_at.isoformat(),
        "payload": thaw_json(envelope.payload),
        "headers": thaw_json(envelope.headers),
    }
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) > _MAX_ENVELOPE_BYTES:
        raise PermanentQueueError("message envelope exceeds 256 KiB")
    return encoded


def _stream_entries(
    rows: object,
) -> tuple[tuple[object, Mapping[object, object]], ...]:
    decoded: list[tuple[object, Mapping[object, object]]] = []
    for _, entries in cast(
        list[tuple[object, list[tuple[object, Mapping[object, object]]]]],
        rows,
    ):
        decoded.extend(entries)
    return tuple(decoded)


def _decode_fields(fields: Mapping[object, object]) -> MessageEnvelope:
    encoded = fields.get(_ENVELOPE_FIELD, fields.get("envelope"))
    if not isinstance(encoded, (bytes, str)):
        raise PoisonMessageError("stream entry has no envelope")
    raw = encoded if isinstance(encoded, bytes) else encoded.encode()
    if len(raw) > _MAX_ENVELOPE_BYTES:
        raise PoisonMessageError("message envelope exceeds 256 KiB")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise TypeError
        payload = value["payload"]
        headers = value["headers"]
        if not isinstance(payload, dict) or not isinstance(headers, dict):
            raise TypeError
        return MessageEnvelope(
            message_id=UUID(str(value["message_id"])),
            tenant_id=str(value["tenant_id"]),
            work_id=UUID(str(value["work_id"])),
            event_id=(
                UUID(str(value["event_id"]))
                if value.get("event_id") is not None
                else None
            ),
            destination=str(value["destination"]),
            correlation_id=UUID(str(value["correlation_id"])),
            causation_id=(
                UUID(str(value["causation_id"]))
                if value.get("causation_id") is not None
                else None
            ),
            occurred_at=datetime.fromisoformat(str(value["occurred_at"])),
            payload=cast(Mapping[str, JsonValue], payload),
            headers=cast(Mapping[str, JsonValue], headers),
            schema_version=int(value["schema_version"]),
        )
    except (
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise PoisonMessageError("invalid message envelope") from error


def _validate_consumer_read(
    consumer: str,
    count: int,
    block_milliseconds: int,
) -> None:
    if not consumer:
        raise ValueError("consumer is required")
    if not 1 <= count <= 100:
        raise ValueError("read count must be between 1 and 100")
    if not 0 <= block_milliseconds <= 60_000:
        raise ValueError("block_milliseconds must be between 0 and 60000")


def _text(value: object) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def _classify_redis_error(
    error: RedisError,
) -> RetryableQueueError | PermanentQueueError:
    if isinstance(error, (RedisConnectionError, RedisTimeoutError)):
        return RetryableQueueError("redis transport unavailable")
    return PermanentQueueError("redis operation rejected")


def create_redis_client(settings: Settings) -> redis.Redis:
    """Create a bounded Redis client from validated process settings."""
    if not settings.redis_url:
        raise ValueError("AEGIS_REDIS_URL is required")
    return cast(
        redis.Redis,
        redis.from_url(  # type: ignore[no-untyped-call]
            settings.redis_url,
            max_connections=settings.redis_max_connections,
            socket_connect_timeout=settings.redis_connect_timeout_seconds,
            socket_timeout=settings.redis_socket_timeout_seconds,
            health_check_interval=30,
            decode_responses=False,
        ),
    )


__all__ = ["RedisStreamQueue", "create_redis_client"]
