"""Live PostgreSQL evidence for durable storage and tenant controls."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
)
from aegis_agent_platform.config import Environment
from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    FinishReason,
    JsonValue,
    MessageRole,
    ModelCapabilities,
    ModelIdentity,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PricingVersion,
    SafetyOutcome,
    SafetyResult,
    TextPart,
    TokenUsage,
    WorkLease,
    thaw_json,
)
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    FencingError,
    OutboxMessage,
    PermanentStorageError,
)
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    PostgresProjectionRepository,
)
from aegis_agent_platform.gateway.catalog import ModelCatalogEntry, RouteDecision
from aegis_agent_platform.gateway.postgres import PostgresGatewayRepository
from aegis_agent_platform.gateway.repository import BudgetDeniedError
from aegis_agent_platform.identity import (
    AuthenticationError,
    PrincipalKind,
    TenantId,
    VerifiedClaims,
)
from aegis_agent_platform.persistence import (
    PostgresAuditStore,
    PostgresIdentityDirectory,
    PostgresPolicyRepository,
    PostgresTenantRepository,
)
from aegis_agent_platform.policy import QuotaLimits
from aegis_agent_platform.projections import ProjectionEngine
from aegis_agent_platform.tenancy import TenantContext

DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None,
        reason="AEGIS_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]
TENANT_A = TenantContext(TenantId("tenant-a"))
TENANT_B = TenantContext(TenantId("tenant-b"))
TENANT_GATEWAY = TENANT_B  # avoids interfering with tenant-a concurrent tests


async def app_connection() -> psycopg.AsyncConnection[tuple[object, ...]]:
    assert DATABASE_URL is not None
    connection = await psycopg.AsyncConnection.connect(
        DATABASE_URL,
        autocommit=True,
    )
    await connection.execute("SET ROLE aegis_app")
    return connection


def sync_app_connection() -> psycopg.Connection[tuple[object, ...]]:
    assert DATABASE_URL is not None
    connection = psycopg.connect(DATABASE_URL, autocommit=True)
    connection.execute("SET ROLE aegis_app")
    return connection


def admin_connection() -> psycopg.Connection[tuple[object, ...]]:
    assert DATABASE_URL is not None
    return psycopg.connect(DATABASE_URL, autocommit=True)


def gateway_pricing() -> PricingVersion:
    return PricingVersion(
        "gateway-price-v1",
        datetime(2026, 1, 1, tzinfo=UTC),
        Decimal("1"),
        Decimal("2"),
        cache_read_per_million_usd=Decimal("0.5"),
        cache_write_per_million_usd=Decimal("1"),
        reasoning_per_million_usd=Decimal("3"),
    )


def gateway_route(run_id: UUID) -> tuple[ModelRequest, WorkLease, RouteDecision]:
    model = ModelIdentity("mock", "safe-model")
    pricing = gateway_pricing()
    request = ModelRequest(
        request_id=UUID(f"00000000-0000-4000-8000-{run_id.int % 10**12:012d}"),
        tenant_id=str(TENANT_GATEWAY.tenant_id),
        run_id=run_id,
        messages=(ModelMessage(MessageRole.USER, (TextPart("hello"),)),),
        max_output_tokens=32,
        prompt_token_estimate=12,
        requested_model=model,
        timeout_seconds=5,
        idempotency_key=f"gateway-{run_id}",
    )
    lease = WorkLease(
        work_id=run_id,
        tenant_id=str(TENANT_GATEWAY.tenant_id),
        token=UUID(f"10000000-0000-4000-8000-{run_id.int % 10**12:012d}"),
        generation=1,
        owner="integration-worker",
        attempt=1,
        acquired_at=datetime.now(UTC),
        heartbeat_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    entry = ModelCatalogEntry(
        identity=model,
        capabilities=ModelCapabilities(8_192, 1_024, True, False, True),
        pricing=pricing,
        environments=frozenset({Environment.TEST}),
        data_residencies=frozenset({"eu"}),
        provider_retains_data=False,
        cost_rank=0,
        latency_rank=0,
    )
    route = RouteDecision(entry, (entry,), ("integration",))
    return request, lease, route


def event(
    aggregate_id: str,
    event_type: DomainEventType = DomainEventType.RUN_STARTED,
    *,
    payload: dict[str, JsonValue] | None = None,
    idempotency_key: str | None = None,
    tenant_id: str = "tenant-a",
) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid4(),
        tenant_id=tenant_id,
        aggregate_id=aggregate_id,
        event_type=event_type,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        payload=payload or {},
        idempotency_key=idempotency_key,
    )


def seed_gateway_work(lease: WorkLease) -> None:
    request_event = event(str(lease.work_id), tenant_id=str(TENANT_GATEWAY.tenant_id))
    with admin_connection() as connection:
        connection.execute(
            """
            INSERT INTO event_stream_heads (tenant_id, aggregate_id, current_version)
            VALUES (%s, %s, 1)
            ON CONFLICT (tenant_id, aggregate_id) DO NOTHING
            """,
            (request_event.tenant_id, request_event.aggregate_id),
        )
        connection.execute(
            """
            INSERT INTO events (
                event_id, tenant_id, aggregate_id, aggregate_sequence, event_type,
                schema_version, occurred_at, payload, correlation_id, causation_id,
                idempotency_key, metadata
            ) VALUES (
                %s, %s, %s, 1, %s, %s, %s, %s, %s, NULL, %s, '{}'::jsonb
            )
            ON CONFLICT (tenant_id, aggregate_id, aggregate_sequence) DO NOTHING
            """,
            (
                request_event.event_id,
                request_event.tenant_id,
                request_event.aggregate_id,
                request_event.event_type,
                request_event.schema_version,
                request_event.occurred_at,
                Jsonb(thaw_json(request_event.payload)),
                request_event.correlation_id,
                request_event.idempotency_key or f"seed-{lease.work_id}",
            ),
        )
        connection.execute(
            """
            INSERT INTO tenant_quotas (
                tenant_id, max_run_tokens, max_run_cost_usd,
                max_tenant_tokens_per_period, max_tenant_cost_usd_per_period,
                max_concurrent_runs, updated_at
            ) VALUES ('tenant-b', 100, 1, 100, 1, 10, transaction_timestamp())
            ON CONFLICT (tenant_id) DO UPDATE
            SET max_run_tokens = EXCLUDED.max_run_tokens,
                max_run_cost_usd = EXCLUDED.max_run_cost_usd,
                max_tenant_tokens_per_period =
                    EXCLUDED.max_tenant_tokens_per_period,
                max_tenant_cost_usd_per_period =
                    EXCLUDED.max_tenant_cost_usd_per_period,
                max_concurrent_runs = EXCLUDED.max_concurrent_runs,
                updated_at = EXCLUDED.updated_at
            """
        )
        connection.execute(
            """
            INSERT INTO work_items (
                tenant_id, work_id, work_kind, idempotency_key, status,
                requested_at, available_at, max_attempts, timeout_seconds,
                request_event_id, correlation_id, request_payload
            ) VALUES (
                %s, %s, 'model-call', %s, 'running',
                %s, %s, 1, 60, %s, %s, '{}'::jsonb
            )
            ON CONFLICT (tenant_id, work_id) DO NOTHING
            """,
            (
                str(TENANT_GATEWAY.tenant_id),
                lease.work_id,
                f"work-{lease.work_id}",
                lease.acquired_at,
                lease.acquired_at,
                request_event.event_id,
                lease.work_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO work_leases (
                tenant_id, work_id, lease_token, generation, owner,
                acquired_at, heartbeat_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, work_id) DO UPDATE
            SET lease_token = EXCLUDED.lease_token,
                generation = EXCLUDED.generation,
                owner = EXCLUDED.owner,
                acquired_at = EXCLUDED.acquired_at,
                heartbeat_at = EXCLUDED.heartbeat_at,
                expires_at = EXCLUDED.expires_at,
                released_at = NULL,
                release_reason = NULL
            """,
            (
                str(TENANT_GATEWAY.tenant_id),
                lease.work_id,
                lease.token,
                lease.generation,
                lease.owner,
                lease.acquired_at,
                lease.heartbeat_at,
                lease.expires_at,
            ),
        )


async def collect(
    events: AsyncIterator[EventEnvelope],
) -> tuple[EventEnvelope, ...]:
    return tuple([item async for item in events])


def test_append_replay_stale_version_and_transaction_rollback() -> None:
    async def scenario() -> None:
        connection = await app_connection()
        try:
            store = PostgresEventStore(connection)
            aggregate_id = f"run-{uuid4()}"
            first = event(aggregate_id)
            assert await store.append(TENANT_A, (first,), expected_version=0) == 1
            with pytest.raises(ConcurrencyError):
                await store.append(
                    TENANT_A,
                    (event(aggregate_id),),
                    expected_version=0,
                )
            replay = await collect(store.read_stream(TENANT_A, aggregate_id))
            assert [item.aggregate_sequence for item in replay] == [1]
            assert replay[0].global_position is not None

            rollback_id = f"rollback-{uuid4()}"
            duplicate_key = f"duplicate-{uuid4()}"
            with pytest.raises(PermanentStorageError):
                await store.append(
                    TENANT_A,
                    (
                        event(rollback_id, idempotency_key=duplicate_key),
                        event(rollback_id, idempotency_key=duplicate_key),
                    ),
                    expected_version=0,
                )
            assert await collect(store.read_stream(TENANT_A, rollback_id)) == ()
        finally:
            await connection.close()

    asyncio.run(scenario())


def test_concurrent_append_has_one_winner_and_gapless_sequence() -> None:
    async def scenario() -> None:
        first_connection = await app_connection()
        second_connection = await app_connection()
        aggregate_id = f"race-{uuid4()}"
        ready = asyncio.Event()
        arrivals = 0
        lock = asyncio.Lock()

        async def contender(
            connection: psycopg.AsyncConnection[tuple[object, ...]],
        ) -> str:
            nonlocal arrivals
            async with lock:
                arrivals += 1
                if arrivals == 2:
                    ready.set()
            await ready.wait()
            try:
                await PostgresEventStore(connection).append(
                    TENANT_A,
                    (event(aggregate_id),),
                    expected_version=0,
                )
            except ConcurrencyError:
                return "conflict"
            return "committed"

        try:
            outcomes = await asyncio.gather(
                contender(first_connection),
                contender(second_connection),
            )
            assert sorted(outcomes) == ["committed", "conflict"]
            replay = await collect(
                PostgresEventStore(first_connection).read_stream(TENANT_A, aggregate_id)
            )
            assert [item.aggregate_sequence for item in replay] == [1]

            shared_store = PostgresEventStore(first_connection)
            tenant_a_aggregate = f"shared-a-{uuid4()}"
            tenant_b_aggregate = f"shared-b-{uuid4()}"
            versions = await asyncio.gather(
                shared_store.append(
                    TENANT_A,
                    (event(tenant_a_aggregate),),
                    expected_version=0,
                ),
                shared_store.append(
                    TENANT_B,
                    (event(tenant_b_aggregate, tenant_id="tenant-b"),),
                    expected_version=0,
                ),
            )
            assert list(versions) == [1, 1]
            tenant_a_events, tenant_b_events = await asyncio.gather(
                collect(shared_store.read_stream(TENANT_A, tenant_a_aggregate)),
                collect(shared_store.read_stream(TENANT_B, tenant_b_aggregate)),
            )
            assert tenant_a_events[0].tenant_id == "tenant-a"
            assert tenant_b_events[0].tenant_id == "tenant-b"
        finally:
            await first_connection.close()
            await second_connection.close()

    asyncio.run(scenario())


def test_inbox_deduplication_and_outbox_claim_race() -> None:
    async def scenario() -> None:
        first_connection = await app_connection()
        second_connection = await app_connection()
        aggregate_id = f"inbox-{uuid4()}"
        message = OutboxMessage(
            message_id=uuid4(),
            destination="later-worker",
            payload={"run_id": aggregate_id},
            headers={},
            available_at=datetime(2025, 1, 1, tzinfo=UTC),
            max_attempts=2,
        )
        inbox_message_id = f"message-{uuid4()}"
        try:
            first_store = PostgresEventStore(first_connection)
            first = await first_store.append_from_inbox(
                TENANT_A,
                source="test-source",
                message_id=inbox_message_id,
                events=(event(aggregate_id),),
                expected_version=0,
                outbox=(message,),
            )
            duplicate = await first_store.append_from_inbox(
                TENANT_A,
                source="test-source",
                message_id=inbox_message_id,
                events=(event(aggregate_id),),
                expected_version=0,
            )
            assert first.aggregate_version == duplicate.aggregate_version == 1
            assert duplicate.duplicate

            now = datetime(2025, 1, 2, tzinfo=UTC)
            expiry = now + timedelta(minutes=1)
            claims = await asyncio.gather(
                first_store.claim_outbox(
                    TENANT_A,
                    lease_owner="publisher-a",
                    lease_expires_at=expiry,
                    now=now,
                    limit=1,
                ),
                PostgresEventStore(second_connection).claim_outbox(
                    TENANT_A,
                    lease_owner="publisher-b",
                    lease_expires_at=expiry,
                    now=now,
                    limit=1,
                ),
            )
            assert sum(len(claim) for claim in claims) == 1
            winning_claim = next(claim[0] for claim in claims if claim)
            winning_store = (
                first_store
                if winning_claim.lease_owner == "publisher-a"
                else PostgresEventStore(second_connection)
            )
            await winning_store.mark_outbox_failed(
                TENANT_A,
                message.message_id,
                lease_owner=winning_claim.lease_owner,
                lease_expires_at=winning_claim.lease_expires_at,
                retry_at=now,
                error_code="temporary_delivery_failure",
            )
            retry = await first_store.claim_outbox(
                TENANT_A,
                lease_owner="publisher-retry",
                lease_expires_at=expiry,
                now=now,
                limit=1,
            )
            assert len(retry) == 1
            await first_store.mark_outbox_failed(
                TENANT_A,
                message.message_id,
                lease_owner="publisher-retry",
                lease_expires_at=retry[0].lease_expires_at,
                retry_at=now,
                error_code="poison_message",
            )
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
                )
                row = await (
                    await first_connection.execute(
                        """
                        SELECT status, attempt_count, last_error_code
                        FROM outbox_messages
                        WHERE tenant_id = 'tenant-a' AND message_id = %s
                        """,
                        (message.message_id,),
                    )
                ).fetchone()
            assert row == ("dead_letter", 2, "poison_message")

            crash_message = OutboxMessage(
                message_id=uuid4(),
                destination="crash-worker",
                payload={},
                headers={},
                available_at=now,
                max_attempts=1,
            )
            crash_aggregate = f"crash-{uuid4()}"
            await first_store.append(
                TENANT_A,
                (event(crash_aggregate),),
                expected_version=0,
                outbox=(crash_message,),
            )
            claimed_once = await first_store.claim_outbox(
                TENANT_A,
                lease_owner="crashing-publisher",
                lease_expires_at=expiry,
                now=now,
                limit=1,
            )
            assert claimed_once[0].message.message_id == crash_message.message_id
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
                )
                await first_connection.execute(
                    """
                    UPDATE outbox_messages
                    SET lease_expires_at = clock_timestamp() - interval '1 second'
                    WHERE tenant_id = 'tenant-a' AND message_id = %s
                    """,
                    (crash_message.message_id,),
                )
            reclaimed = await first_store.claim_outbox(
                TENANT_A,
                lease_owner="reconciling-publisher",
                lease_expires_at=expiry + timedelta(minutes=2),
                now=expiry + timedelta(minutes=1),
                limit=1,
            )
            assert reclaimed[0].message.message_id == crash_message.message_id
            await first_store.mark_outbox_published(
                TENANT_A,
                crash_message.message_id,
                lease_owner="reconciling-publisher",
                lease_expires_at=reclaimed[0].lease_expires_at,
                published_at=expiry + timedelta(minutes=1),
            )
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
                )
                crash_row = await (
                    await first_connection.execute(
                        """
                        SELECT status, attempt_count, last_error_code
                        FROM outbox_messages
                        WHERE tenant_id = 'tenant-a' AND message_id = %s
                        """,
                        (crash_message.message_id,),
                    )
                ).fetchone()
            assert crash_row == ("published", 2, None)
        finally:
            await first_connection.close()
            await second_connection.close()

    asyncio.run(scenario())


def test_forced_rls_denies_cross_tenant_and_event_mutation() -> None:
    assert DATABASE_URL is not None
    with sync_app_connection() as connection:
        with connection.transaction():
            connection.execute("SELECT set_config('aegis.tenant_id', 'tenant-a', true)")
            assert (
                connection.execute(
                    "SELECT tenant_id FROM tenants WHERE tenant_id = 'tenant-b'"
                ).fetchone()
                is None
            )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cross_tenant_insert(connection)

    aggregate_id = f"immutable-{uuid4()}"

    async def append() -> UUID:
        connection = await app_connection()
        try:
            item = event(aggregate_id)
            await PostgresEventStore(connection).append(
                TENANT_A, (item,), expected_version=0
            )
            return item.event_id
        finally:
            await connection.close()

    event_id = asyncio.run(append())
    with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            admin.execute(
                "UPDATE events SET payload = '{}' WHERE event_id = %s",
                (event_id,),
            )
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            admin.execute("DELETE FROM events WHERE event_id = %s", (event_id,))


def test_projection_idempotence_and_rebuild() -> None:
    async def scenario() -> None:
        connection = await app_connection()
        aggregate_id = f"projection-{uuid4()}"
        try:
            store = PostgresEventStore(connection)
            await store.append(
                TENANT_A,
                (
                    event(aggregate_id),
                    event(
                        aggregate_id,
                        DomainEventType.RUN_STATUS_CHANGED,
                        payload={"status": "awaiting_approval"},
                    ),
                ),
                expected_version=0,
            )
            repository = PostgresProjectionRepository(connection)
            engine = ProjectionEngine(store, repository, page_size=1)
            first = await engine.catch_up(TENANT_A, "run-status")
            second = await engine.catch_up(TENANT_A, "run-status")
            rebuilt = await engine.rebuild(TENANT_A, "run-status")
            assert first == second == rebuilt
            rows = await repository.run_status(TENANT_A)
            row = next(item for item in rows if item["run_id"] == aggregate_id)
            assert row["status"] == "awaiting_approval"
        finally:
            await connection.close()

    asyncio.run(scenario())


def test_postgres_gateway_repository_reservation_race_and_fence_rejection() -> None:
    async def scenario() -> None:
        first_connection = await app_connection()
        second_connection = await app_connection()
        try:
            first_request, first_lease, first_route = gateway_route(
                UUID("20000000-0000-4000-8000-000000000001")
            )
            second_request, second_lease, second_route = gateway_route(
                UUID("20000000-0000-4000-8000-000000000002")
            )
            seed_gateway_work(first_lease)
            seed_gateway_work(second_lease)
            quotas = QuotaLimits(100, Decimal("1"), 100, Decimal("1"), 10)
            ready = asyncio.Event()
            arrivals = 0
            gate = asyncio.Lock()

            async def contender(
                connection: psycopg.AsyncConnection[tuple[object, ...]],
                request: ModelRequest,
                lease: WorkLease,
                route: RouteDecision,
            ) -> object:
                nonlocal arrivals
                async with gate:
                    arrivals += 1
                    if arrivals == 2:
                        ready.set()
                await ready.wait()
                try:
                    return await PostgresGatewayRepository(
                        connection,
                        PostgresEventStore(connection),
                    ).reserve(
                        TENANT_GATEWAY,
                        request,
                        lease,
                        route,
                        quotas=quotas,
                        token_limit=60,
                        cost_limit_usd=Decimal("0.001"),
                        price_version="gateway-price-v1",
                        at=lease.acquired_at,
                    )
                except Exception as error:  # pragma: no cover - assertion target
                    return error

            outcomes = await asyncio.gather(
                contender(
                    first_connection,
                    first_request,
                    first_lease,
                    first_route,
                ),
                contender(
                    second_connection,
                    second_request,
                    second_lease,
                    second_route,
                ),
            )
            assert sum(type(item) is BudgetDeniedError for item in outcomes) == 1
            assert (
                sum(type(item).__name__ == "BudgetReservation" for item in outcomes)
                == 1
            )

            stale_lease = WorkLease(
                work_id=first_lease.work_id,
                tenant_id=first_lease.tenant_id,
                token=uuid4(),
                generation=99,
                owner=first_lease.owner,
                attempt=first_lease.attempt,
                acquired_at=first_lease.acquired_at,
                heartbeat_at=first_lease.heartbeat_at,
                expires_at=first_lease.expires_at,
            )
            with pytest.raises(FencingError):
                await PostgresGatewayRepository(
                    first_connection,
                    PostgresEventStore(first_connection),
                ).reserve(
                    TENANT_GATEWAY,
                    first_request,
                    stale_lease,
                    first_route,
                    quotas=quotas,
                    token_limit=10,
                    cost_limit_usd=Decimal("0.001"),
                    price_version="gateway-price-v1",
                    at=first_lease.acquired_at,
                )
        finally:
            await first_connection.close()
            await second_connection.close()

    asyncio.run(scenario())


def test_postgres_gateway_repository_rolls_back_failed_projection_mutation() -> None:
    async def scenario() -> None:
        connection = await app_connection()
        try:
            request, lease, route = gateway_route(
                UUID("20000000-0000-4000-8000-000000000003")
            )
            seed_gateway_work(lease)
            repository = PostgresGatewayRepository(
                connection,
                PostgresEventStore(connection),
            )
            reservation = await repository.reserve(
                TENANT_GATEWAY,
                request,
                lease,
                route,
                quotas=QuotaLimits(100, Decimal("1"), 100, Decimal("1"), 10),
                token_limit=60,
                cost_limit_usd=Decimal("0.001"),
                price_version="gateway-price-v1",
                at=lease.acquired_at,
            )
            with admin_connection() as admin:
                admin.execute(
                    """
                    INSERT INTO model_usage_projection (
                        tenant_id, request_id, run_id, provider, model, price_version,
                        input_tokens, output_tokens, cache_read_tokens,
                        cache_write_tokens, reasoning_tokens, total_tokens, cost_usd,
                        recorded_at
                    ) VALUES (
                        'tenant-a', %s, %s, 'mock', 'safe-model', 'existing',
                        1, 1, 0, 0, 0, 2, 0.000002, transaction_timestamp()
                    )
                    """,
                    (request.request_id, request.run_id),
                )
            reply = ModelResponse(
                request_id=request.request_id,
                model=route.selected.identity,
                content=(TextPart("done"),),
                finish_reason=FinishReason.STOP,
                safety=SafetyResult(SafetyOutcome.ALLOWED),
                usage=TokenUsage(12, 4),
                latency_ms=1,
            )
            with pytest.raises(PermanentStorageError):
                await repository.succeed(
                    TENANT_GATEWAY,
                    request,
                    lease,
                    reservation,
                    reply,
                    gateway_pricing(),
                    at=lease.acquired_at + timedelta(seconds=1),
                )
            stream = await collect(
                PostgresEventStore(connection).read_stream(
                    TENANT_GATEWAY, str(lease.work_id)
                )
            )
            assert [item.event_type for item in stream] == [
                DomainEventType.MODEL_ROUTE_DECIDED,
                DomainEventType.MODEL_CALL_REQUESTED,
                DomainEventType.MODEL_BUDGET_RESERVED,
            ]
        finally:
            await connection.close()

    asyncio.run(scenario())


def test_postgres_gateway_repository_rebuilds_model_usage_projection_under_rls() -> (
    None
):
    async def scenario() -> None:
        connection = await app_connection()
        try:
            request, lease, route = gateway_route(
                UUID("20000000-0000-4000-8000-000000000004")
            )
            seed_gateway_work(lease)
            repository = PostgresGatewayRepository(
                connection,
                PostgresEventStore(connection),
            )
            reservation = await repository.reserve(
                TENANT_GATEWAY,
                request,
                lease,
                route,
                quotas=QuotaLimits(100, Decimal("1"), 100, Decimal("1"), 10),
                token_limit=60,
                cost_limit_usd=Decimal("0.001"),
                price_version="gateway-price-v1",
                at=lease.acquired_at,
            )
            await repository.succeed(
                TENANT_GATEWAY,
                request,
                lease,
                reservation,
                ModelResponse(
                    request_id=request.request_id,
                    model=route.selected.identity,
                    content=(TextPart("done"),),
                    finish_reason=FinishReason.STOP,
                    safety=SafetyResult(SafetyOutcome.ALLOWED),
                    usage=TokenUsage(12, 4),
                    latency_ms=1,
                ),
                gateway_pricing(),
                at=lease.acquired_at + timedelta(seconds=1),
            )
            projection = PostgresProjectionRepository(connection)
            engine = ProjectionEngine(PostgresEventStore(connection), projection)
            await projection.reset(TENANT_GATEWAY, "model-usage")
            checkpoint = await engine.rebuild(TENANT_GATEWAY, "model-usage")
            assert checkpoint.last_global_position > 0
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-a', true)"
                )
                visible = await (
                    await connection.execute(
                        """
                        SELECT count(*)
                        FROM model_usage_projection
                        WHERE tenant_id = 'tenant-a' AND request_id = %s
                        """,
                        (request.request_id,),
                    )
                ).fetchone()
            assert visible == (1,)
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', 'tenant-b', true)"
                )
                hidden = await (
                    await connection.execute(
                        """
                        SELECT count(*)
                        FROM model_usage_projection
                        WHERE tenant_id = 'tenant-a' AND request_id = %s
                        """,
                        (request.request_id,),
                    )
                ).fetchone()
            assert hidden == (0,)
        finally:
            await connection.close()

    asyncio.run(scenario())


def cross_tenant_insert(
    connection: psycopg.Connection[tuple[object, ...]],
) -> None:
    """Attempt one confused-deputy write in its own rollback-safe transaction."""
    with connection.transaction():
        connection.execute("SELECT set_config('aegis.tenant_id', 'tenant-a', true)")
        connection.execute(
            """
            INSERT INTO event_stream_heads (
                tenant_id, aggregate_id, current_version
            ) VALUES ('tenant-b', 'confused-deputy', 0)
            """
        )


def test_durable_repositories_are_tenant_scoped_and_audit_is_redacted() -> None:
    assert DATABASE_URL is not None
    subject = f"subject-{uuid4()}"
    identity_id = uuid4()
    with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
        admin.execute(
            """
            INSERT INTO identities (
                identity_id, tenant_id, issuer, subject, identity_kind,
                user_id, enabled, created_at
            ) VALUES (%s, 'tenant-a', 'https://issuer.test', %s, 'user',
                'user-a', true, transaction_timestamp())
            """,
            (identity_id, subject),
        )
        admin.execute(
            """
            INSERT INTO role_bindings (
                role_binding_id, tenant_id, identity_id, role, assigned_by,
                assigned_at
            ) VALUES (%s, 'tenant-a', %s, 'viewer', 'admin-a',
                transaction_timestamp())
            """,
            (uuid4(), identity_id),
        )
        admin.execute(
            """
            INSERT INTO tenant_policies (
                tenant_id, policy_version, policy_document, updated_by,
                updated_at
            ) VALUES ('tenant-a', 'v1', %s, 'admin-a', transaction_timestamp())
            ON CONFLICT (tenant_id) DO UPDATE
            SET policy_version = EXCLUDED.policy_version,
                policy_document = EXCLUDED.policy_document,
                updated_by = EXCLUDED.updated_by,
                updated_at = EXCLUDED.updated_at
            """,
            (
                Jsonb(
                    {
                        "allowed_models": ["safe-model"],
                        "allowed_tools": ["read"],
                        "allowed_connectors": ["fixture"],
                        "allowed_environments": ["test"],
                        "allowed_providers": ["mock"],
                        "allowed_data_residencies": ["eu"],
                        "allow_provider_retention": False,
                        "max_risk": 2,
                        "approval_from_risk": 2,
                        "tools_requiring_approval": [],
                        "approver_roles": ["approver"],
                    }
                ),
            ),
        )
        admin.execute(
            """
            INSERT INTO tenant_quotas (
                tenant_id, max_run_tokens, max_run_cost_usd,
                max_tenant_tokens_per_period,
                max_tenant_cost_usd_per_period, max_concurrent_runs,
                updated_at
            ) VALUES ('tenant-a', 100, 1, 1000, 10, 2,
                transaction_timestamp())
            ON CONFLICT (tenant_id) DO NOTHING
            """
        )
    with sync_app_connection() as connection:
        tenants = PostgresTenantRepository(connection)
        assert tenants.get(TENANT_A).display_name == "Tenant A"  # type: ignore[union-attr]
        assert tenants.get(TENANT_B).display_name == "Tenant B"  # type: ignore[union-attr]
        claims = VerifiedClaims(
            issuer="https://issuer.test",
            subject=subject,
            audiences=("aegis",),
            expires_at=datetime(2025, 1, 2, tzinfo=UTC),
            issued_at=datetime(2025, 1, 1, tzinfo=UTC),
            asserted_tenant_id=TENANT_A.tenant_id,
            authorized_party=None,
        )
        principal = PostgresIdentityDirectory(connection).resolve(claims)
        assert principal.kind is PrincipalKind.USER
        assert principal.actor_id == "user-a"
        with pytest.raises(AuthenticationError):
            PostgresIdentityDirectory(connection).resolve(
                VerifiedClaims(
                    issuer=claims.issuer,
                    subject=claims.subject,
                    audiences=claims.audiences,
                    expires_at=claims.expires_at,
                    issued_at=claims.issued_at,
                    asserted_tenant_id=TENANT_B.tenant_id,
                    authorized_party=None,
                )
            )
        policy = PostgresPolicyRepository(connection).get(TENANT_A)
        assert policy is not None
        assert policy.allowed_models == frozenset({"safe-model"})

        audit = PostgresAuditStore(connection)
        audit_event = AuditEvent(
            event_id=uuid4(),
            tenant_id=TENANT_A.tenant_id,
            event_type=AuditEventType.ADMINISTRATIVE_CHANGE,
            occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
            outcome=AuditOutcome.SUCCESS,
            actor_id="admin-a",
            action="inspect",
            resource="ledger",
            correlation_id=uuid4(),
            details={"authorization": "secret", "note": "Bearer hidden"},
        )
        audit.append(TENANT_A, audit_event)
        stored = audit.query(TENANT_A)
        assert stored[-1].details == {
            "authorization": "[REDACTED]",
            "note": "[REDACTED]",
        }
        assert audit.query(TENANT_B) == ()
