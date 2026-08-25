#!/usr/bin/env python3
"""Exercise durable PostgreSQL outbox redrive into an empty Redis transport."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import redis.asyncio as redis

from aegis_agent_platform.event_store.fencing import TenantWriterFenceResolver
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.operations import WriterFence
from aegis_agent_platform.queueing.publisher import OutboxPublisher
from aegis_agent_platform.queueing.redis_streams import RedisStreamQueue
from aegis_agent_platform.tenancy import TenantContext


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


async def _run(database_url: str, redis_url: str, output: Path) -> None:
    context = TenantContext(TenantId("restore-tenant"))
    connection = await psycopg.AsyncConnection.connect(database_url)
    client = redis.from_url(redis_url, decode_responses=False)  # type: ignore[no-untyped-call]
    try:
        repository = PostgresEventStore(
            connection,
            writer_fence_resolver=TenantWriterFenceResolver(
                {
                    context.tenant_id: WriterFence(
                        home_region="restore-region",
                        generation=1,
                    )
                }
            ),
        )
        queue = RedisStreamQueue(client)
        publisher = OutboxPublisher(
            repository,
            queue,
            publisher_id="restore-drill-redrive",
            batch_size=10,
            destination="aegis:work:v1",
        )
        result = await publisher.publish_batch(
            context,
            now=datetime(2026, 8, 14, 0, 1, tzinfo=UTC),
        )
        deliveries = await queue.read(
            consumer="restore-drill-verifier",
            count=10,
            block_milliseconds=1,
        )
        if (
            result.claimed != 1
            or result.published != 1
            or result.failed != 0
            or len(deliveries) != 1
            or str(deliveries[0].envelope.tenant_id) != str(context.tenant_id)
        ):
            raise RuntimeError(
                "restored outbox did not redrive exactly one tenant item"
            )
        output.write_text(
            json.dumps(
                {
                    "claimed": result.claimed,
                    "delivered": len(deliveries),
                    "failed": result.failed,
                    "message_id": str(deliveries[0].envelope.message_id),
                    "published": result.published,
                    "tenant_id": str(context.tenant_id),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    finally:
        await client.aclose()
        await connection.close()


def main() -> int:
    """Run the bounded redrive and emit secret-free evidence."""
    args = _arguments()
    asyncio.run(_run(args.database_url, args.redis_url, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
