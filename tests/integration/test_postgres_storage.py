"""Live PostgreSQL evidence for durable storage and tenant controls."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
)
from aegis_agent_platform.domain import DomainEventType, EventEnvelope, JsonValue
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    OutboxMessage,
    PermanentStorageError,
)
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    PostgresProjectionRepository,
)
from aegis_agent_platform.identity import (
    AuthenticationError,
    PrincipalKind,
    TenantId,
    VerifiedClaims,
)
from aegis_agent_platform.operations import PostgresSchemaVersionProbe
from aegis_agent_platform.persistence import (
    PostgresAuditStore,
    PostgresIdentityDirectory,
    PostgresPolicyRepository,
    PostgresTenantRepository,
)
from aegis_agent_platform.projections import ProjectionEngine
from aegis_agent_platform.tenancy import TenantContext
from integration_helpers import integration_writer_fences

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


async def collect(
    events: AsyncIterator[EventEnvelope],
) -> tuple[EventEnvelope, ...]:
    return tuple([item async for item in events])


def test_append_replay_stale_version_and_transaction_rollback() -> None:
    async def scenario() -> None:
        connection = await app_connection()
        try:
            store = PostgresEventStore(
                connection,
                writer_fence_resolver=integration_writer_fences("local-test", 1),
            )
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
                await PostgresEventStore(
                    connection,
                    writer_fence_resolver=integration_writer_fences("local-test", 1),
                ).append(
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
                PostgresEventStore(
                    first_connection,
                    writer_fence_resolver=integration_writer_fences("local-test", 1),
                ).read_stream(TENANT_A, aggregate_id)
            )
            assert [item.aggregate_sequence for item in replay] == [1]

            shared_store = PostgresEventStore(
                first_connection,
                writer_fence_resolver=integration_writer_fences("local-test", 1),
            )
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
            first_store = PostgresEventStore(
                first_connection,
                writer_fence_resolver=integration_writer_fences("local-test", 1),
            )
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
                    destination="later-worker",
                ),
                PostgresEventStore(
                    second_connection,
                    writer_fence_resolver=integration_writer_fences("local-test", 1),
                ).claim_outbox(
                    TENANT_A,
                    lease_owner="publisher-b",
                    lease_expires_at=expiry,
                    now=now,
                    limit=1,
                    destination="later-worker",
                ),
            )
            assert sum(len(claim) for claim in claims) == 1
            winning_claim = next(claim[0] for claim in claims if claim)
            winning_store = (
                first_store
                if winning_claim.lease_owner == "publisher-a"
                else PostgresEventStore(
                    second_connection,
                    writer_fence_resolver=integration_writer_fences("local-test", 1),
                )
            )
            await winning_store.mark_outbox_failed(
                TENANT_A,
                message.message_id,
                lease_owner=winning_claim.lease_owner,
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
            await PostgresEventStore(
                connection,
                writer_fence_resolver=integration_writer_fences("local-test", 1),
            ).append(TENANT_A, (item,), expected_version=0)
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


def test_stale_region_writer_cannot_append() -> None:
    async def scenario() -> None:
        for region, generation in (("stale-region", 1), ("local-test", 2)):
            connection = await app_connection()
            try:
                store = PostgresEventStore(
                    connection,
                    writer_fence_resolver=integration_writer_fences(region, generation),
                )
                with pytest.raises(PermanentStorageError):
                    await store.append(
                        TENANT_A,
                        (event(f"stale-writer-{region}-{generation}-{uuid4()}"),),
                        expected_version=0,
                    )
            finally:
                await connection.close()

    asyncio.run(scenario())


def test_writer_fence_activation_preserves_expand_phase_overlap() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
        admin.execute(
            """
            INSERT INTO tenants (tenant_id, display_name, enabled, created_at)
            VALUES (
                'tenant-expand-overlap',
                'Tenant Expand Overlap',
                true,
                transaction_timestamp()
            )
            """
        )
        admin.execute(
            """
            UPDATE tenant_writer_fences
            SET home_region = 'local-test',
                state = 'active',
                approved_change_reference = 'change-ref://integration-expand',
                updated_at = transaction_timestamp()
            WHERE tenant_id = 'tenant-expand-overlap'
            """
        )
        admin.execute(
            "SELECT aegis_assert_writer_fence('tenant-expand-overlap', NULL, NULL)"
        )
        admin.execute(
            """
            UPDATE tenant_writer_fences
            SET enforcement_enabled = true,
                updated_at = transaction_timestamp()
            WHERE tenant_id = 'tenant-expand-overlap'
            """
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            admin.execute(
                "SELECT aegis_assert_writer_fence('tenant-expand-overlap', NULL, NULL)"
            )
        admin.execute(
            "DELETE FROM tenant_writer_fences WHERE tenant_id = 'tenant-expand-overlap'"
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="missing"):
            admin.execute(
                "SELECT aegis_assert_writer_fence("
                "'tenant-expand-overlap', 'local-test', 1)"
            )


def test_writer_fence_transitions_are_monotonic_and_irreversible() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            admin.execute(
                """
                UPDATE tenant_writer_fences
                SET generation = 3,
                    state = 'failover_pending',
                    updated_at = transaction_timestamp()
                WHERE tenant_id = 'tenant-a'
                """
            )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            admin.execute(
                """
                UPDATE tenant_writer_fences
                SET enforcement_enabled = false,
                    updated_at = transaction_timestamp()
                WHERE tenant_id = 'tenant-a'
                """
            )


def test_schema_probe_reads_contiguous_migration_history() -> None:
    async def scenario() -> None:
        connection = await app_connection()
        try:
            assert await PostgresSchemaVersionProbe(connection)() == 11
        finally:
            await connection.close()

    asyncio.run(scenario())


def test_projection_idempotence_and_rebuild() -> None:
    async def scenario() -> None:
        connection = await app_connection()
        aggregate_id = f"projection-{uuid4()}"
        try:
            store = PostgresEventStore(
                connection,
                writer_fence_resolver=integration_writer_fences("local-test", 1),
            )
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
