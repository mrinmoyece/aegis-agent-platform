"""Live PostgreSQL evidence for Layer 7 fencing, RLS, and rebuildability."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from aegis_agent_platform.agents import (
    CanonicalCheckoutEngine,
    DurableCoordinator,
    InvestigationStatus,
    canonical_checkout_citations,
    canonical_checkout_plan,
)
from aegis_agent_platform.agents.postgres import PostgresAgentRepository
from aegis_agent_platform.domain import DomainEventType, EventEnvelope, WorkLease
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext

DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None,
        reason="AEGIS_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]
CONTEXT = TenantContext(TenantId("tenant-a"))
OTHER_CONTEXT = TenantContext(TenantId("tenant-b"))


def test_specialist_projection_fencing_rls_and_rebuild() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await connection.execute("SET ROLE aegis_app")
        now = datetime.now(UTC)
        run_id = uuid4()
        event_store = PostgresEventStore(connection)
        work = PostgresWorkRepository(connection, event_store)
        repository = PostgresAgentRepository(connection, event_store, work)
        coordinator = DurableCoordinator(
            repository,
            CanonicalCheckoutEngine(clock=lambda: now),
            clock=lambda: now,
        )
        plan = canonical_checkout_plan(
            tenant_id="tenant-a",
            incident_id="checkout-postgres",
            run_id=run_id,
            created_at=now,
        )
        token = uuid4()
        active_lease = WorkLease(
            run_id,
            "tenant-a",
            token,
            1,
            "agent-integration-worker",
            1,
            now,
            now,
            now + timedelta(minutes=5),
        )
        try:
            requested = await coordinator.request(
                CONTEXT,
                plan,
                actor_id="integration",
                idempotency_key=f"agent-integration:{run_id}",
            )
            assert requested.created
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-a",),
                )
                await connection.execute(
                    """
                    INSERT INTO work_leases (
                        tenant_id, work_id, lease_token, generation, owner,
                        acquired_at, heartbeat_at, expires_at
                    ) VALUES (%s, %s, %s, 1, %s, %s, %s, %s)
                    """,
                    (
                        "tenant-a",
                        run_id,
                        token,
                        active_lease.owner,
                        now,
                        now,
                        active_lease.expires_at,
                    ),
                )
            state = await coordinator.execute(
                CONTEXT,
                run_id,
                active_lease,
                canonical_checkout_citations(),
            )
            assert state.status is InvestigationStatus.SUCCEEDED
            assert await repository.status(OTHER_CONTEXT, run_id) is None
            tasks, task_cursor = await repository.task_page(
                CONTEXT,
                run_id,
                limit=3,
            )
            artifacts, artifact_cursor = await repository.artifact_page(
                CONTEXT,
                run_id,
                limit=3,
            )
            assert len(tasks) == len(artifacts) == 3
            assert task_cursor == 2
            assert artifact_cursor is not None

            stale_lease = replace(active_lease, token=uuid4())
            with pytest.raises(FencingError):
                await repository.append_fenced(
                    CONTEXT,
                    run_id,
                    stale_lease,
                    (
                        EventEnvelope(
                            event_id=uuid4(),
                            tenant_id="tenant-a",
                            aggregate_id=str(run_id),
                            event_type=DomainEventType.RUN_FAILED,
                            schema_version=1,
                            occurred_at=now,
                            payload={
                                "reason": "stale",
                                "work_id": str(run_id),
                                "lease_token": str(stale_lease.token),
                                "lease_generation": stale_lease.generation,
                            },
                            correlation_id=run_id,
                            idempotency_key=f"agent-integration:{run_id}:stale",
                        ),
                    ),
                )
        finally:
            await connection.close()

        maintenance = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await maintenance.execute("SET ROLE aegis_maintenance")
        maintenance_events = PostgresEventStore(maintenance)
        maintenance_repository = PostgresAgentRepository(
            maintenance,
            maintenance_events,
            PostgresWorkRepository(maintenance, maintenance_events),
        )
        try:
            await maintenance_repository.rebuild_projection(CONTEXT, run_id)
            rebuilt = await maintenance_repository.status(CONTEXT, run_id)
            assert rebuilt is not None
            assert rebuilt["status"] == "succeeded"
            rebuilt_artifacts, _cursor = await maintenance_repository.artifact_page(
                CONTEXT,
                run_id,
            )
            assert len(rebuilt_artifacts) == len(state.artifacts)
        finally:
            await maintenance.close()

    asyncio.run(scenario())
