"""Live PostgreSQL evidence for Layer 8 RLS, races, fencing, and rebuilds."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from dataclasses import replace
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from aegis_agent_platform.domain import (
    ActionLifecycleStatus,
    ActionSpecification,
    ApprovalStatus,
    DomainEventType,
    EventEnvelope,
    RemediationPlan,
    WorkLease,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.remediation import (
    ActionAdapterResult,
    ActionQuotaUsage,
    ApprovalDecision,
    ControlledActionExecutor,
    FakeControlledActionAdapter,
    RemediationApprovalService,
    StaticApprovalAuthority,
)
from aegis_agent_platform.remediation.postgres import PostgresRemediationRepository
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext
from remediation_helpers import Clock, action, lease, plan, policy, principal

DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None,
        reason="AEGIS_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]
CONTEXT = TenantContext(TenantId("tenant-remediation"))
OTHER_CONTEXT = TenantContext(TenantId("tenant-b"))


class BarrierRemediationRepository(PostgresRemediationRepository):
    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
        work_repository: PostgresWorkRepository,
        barrier: asyncio.Barrier,
    ) -> None:
        super().__init__(connection, event_store, work_repository)
        self._barrier = barrier

    async def append_fenced(
        self,
        context: TenantContext,
        plan_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if any(
            event.event_type is DomainEventType.ACTION_EXECUTION_REQUESTED
            for event in events
        ):
            await asyncio.wait_for(self._barrier.wait(), timeout=3)
        return await super().append_fenced(
            context,
            plan_id,
            lease,
            events,
            expected_version=expected_version,
        )


class BlockingActionAdapter(FakeControlledActionAdapter):
    def __init__(self) -> None:
        super().__init__(clock=Clock())
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(
        self,
        context: TenantContext,
        action_spec: ActionSpecification,
    ) -> ActionAdapterResult:
        self.started.set()
        await self.release.wait()
        return await super().execute(context, action_spec)


def test_remediation_approval_execution_rls_race_and_rebuild() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await connection.execute("SET ROLE aegis_app")
        events = PostgresEventStore(connection)
        repository = PostgresRemediationRepository(
            connection,
            events,
            PostgresWorkRepository(connection, events),
        )
        service = RemediationApprovalService(repository, clock=Clock())
        selected_action = action(
            idempotency_key="tenant-remediation:checkout:restart:integration"
        )
        selected = plan(
            selected_action,
            policy(
                selected_action.target,
                tenant_id=TenantId("tenant-remediation"),
            ),
            requested_by="operator",
            tenant_id=TenantId("tenant-remediation"),
        )
        try:
            proposal = await service.propose(
                principal(
                    "operator",
                    Role.OPERATOR,
                    tenant_id=TenantId("tenant-remediation"),
                ),
                CONTEXT,
                selected,
                selected.approval_policy,
                ActionQuotaUsage(0, 0),
                idempotency_key=f"remediation-integration:{selected.plan_id}",
            )
            approval_id = next(iter(proposal.state.approvals))

            grants = await asyncio.gather(
                *(
                    service.decide(
                        principal(
                            actor_id,
                            Role.APPROVER,
                            tenant_id=TenantId("tenant-remediation"),
                        ),
                        CONTEXT,
                        selected.plan_id,
                        approval_id,
                        ApprovalDecision.GRANT,
                        decision_id=uuid4(),
                        current_policy=selected.approval_policy,
                        rationale_code="reviewed",
                        comment="integration approval",
                    )
                    for actor_id in ("approver-one", "approver-two")
                )
            )
            assert any(grant.status is ApprovalStatus.GRANTED for grant in grants)
            assert await repository.load(OTHER_CONTEXT, selected.plan_id) == ()

            active_lease = lease(
                selected.plan_id,
                tenant_id=TenantId("tenant-remediation"),
                expires_at=Clock().value + timedelta(days=3_650),
            )
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-remediation",),
                )
                await connection.execute(
                    """
                    INSERT INTO work_leases (
                        tenant_id, work_id, lease_token, generation, owner,
                        acquired_at, heartbeat_at, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        "tenant-remediation",
                        selected.plan_id,
                        active_lease.token,
                        active_lease.generation,
                        active_lease.owner,
                        active_lease.acquired_at,
                        active_lease.heartbeat_at,
                        active_lease.expires_at,
                    ),
                )
            adapter = FakeControlledActionAdapter(clock=Clock())
            executor = ControlledActionExecutor(
                repository,
                adapter,
                StaticApprovalAuthority(
                    {
                        "approver-one": frozenset({Role.APPROVER.value}),
                        "approver-two": frozenset({Role.APPROVER.value}),
                    }
                ),
                clock=Clock(),
            )
            completed = await executor.execute(
                principal(
                    "operator",
                    Role.OPERATOR,
                    tenant_id=TenantId("tenant-remediation"),
                ),
                CONTEXT,
                selected.plan_id,
                selected.actions[0].action_id,
                active_lease,
                selected.approval_policy,
            )
            assert (
                completed.action_statuses[selected.actions[0].action_id]
                is ActionLifecycleStatus.VERIFIED
            )
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-remediation",),
                )
                cursor = await connection.execute(
                    """
                    SELECT status FROM remediation_effect_claims
                    WHERE tenant_id = %s AND idempotency_key = %s
                    """,
                    (
                        "tenant-remediation",
                        selected.actions[0].idempotency_key,
                    ),
                )
                row = await cursor.fetchone()
                assert row is not None
                assert row[0] == "succeeded"

            stale = replace(active_lease, token=uuid4())
            with pytest.raises(FencingError):
                await executor.rollback(
                    principal(
                        "operator",
                        Role.OPERATOR,
                        tenant_id=TenantId("tenant-remediation"),
                    ),
                    CONTEXT,
                    selected.plan_id,
                    selected.actions[0].action_id,
                    stale,
                    selected.approval_policy,
                )
            replacement_action = action(
                idempotency_key=(
                    "tenant-remediation:checkout:restart:integration-revision"
                )
            )
            replacement_policy = policy(
                replacement_action.target,
                tenant_id=TenantId("tenant-remediation"),
            )
            revised = replace(
                selected,
                revision=2,
                rationale="Replace the exact action scope after renewed review.",
                actions=(replacement_action,),
                approval_policy=replacement_policy,
            )
            revised_state = await service.revise(
                principal(
                    "operator",
                    Role.OPERATOR,
                    tenant_id=TenantId("tenant-remediation"),
                ),
                CONTEXT,
                revised,
                replacement_policy,
                await repository.quota_usage(CONTEXT, at=Clock().value),
                idempotency_key=f"remediation-revision:{selected.plan_id}:2",
            )
            assert revised_state.plan.actions == (replacement_action,)
        finally:
            await connection.close()

        maintenance = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await maintenance.execute("SET ROLE aegis_maintenance")
        maintenance_events = PostgresEventStore(maintenance)
        maintenance_repository = PostgresRemediationRepository(
            maintenance,
            maintenance_events,
            PostgresWorkRepository(maintenance, maintenance_events),
        )
        try:
            async with maintenance.transaction():
                await maintenance.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-remediation",),
                )
                await maintenance.execute(
                    "DELETE FROM remediation_approval_projection WHERE plan_id = %s",
                    (selected.plan_id,),
                )
                await maintenance.execute(
                    "DELETE FROM remediation_action_projection WHERE plan_id = %s",
                    (selected.plan_id,),
                )
                await maintenance.execute(
                    "DELETE FROM remediation_plan_projection WHERE plan_id = %s",
                    (selected.plan_id,),
                )
            await maintenance_repository.rebuild_projection(
                CONTEXT,
                selected.plan_id,
            )
            page, _cursor = await maintenance_repository.page(CONTEXT)
            assert any(row["plan_id"] == str(selected.plan_id) for row in page)
            current_actions = await maintenance.execute(
                """
                SELECT action_id FROM remediation_action_projection
                WHERE tenant_id = %s AND plan_id = %s
                """,
                ("tenant-remediation", selected.plan_id),
            )
            action_rows = await current_actions.fetchall()
            assert action_rows == [(replacement_action.action_id,)]
            current_approvals = await maintenance.execute(
                """
                SELECT approval_id FROM remediation_approval_projection
                WHERE tenant_id = %s AND plan_id = %s
                """,
                ("tenant-remediation", selected.plan_id),
            )
            approval_rows = await current_approvals.fetchall()
            assert all(row[0] != approval_id for row in approval_rows)
            rebuilt_claim = await maintenance.execute(
                """
                SELECT action_id, status FROM remediation_effect_claims
                WHERE tenant_id = %s AND plan_id = %s
                """,
                ("tenant-remediation", selected.plan_id),
            )
            claim_row = await rebuilt_claim.fetchone()
            assert claim_row == (selected.actions[0].action_id, "succeeded")
            immutable = await maintenance.execute(
                """
                SELECT decision_event_id FROM remediation_approval_decisions
                WHERE tenant_id = %s AND approval_id = %s LIMIT 1
                """,
                ("tenant-remediation", approval_id),
            )
            decision_row = await immutable.fetchone()
            assert decision_row is not None
            with pytest.raises(psycopg.Error):
                await maintenance.execute(
                    """
                    UPDATE remediation_approval_decisions
                    SET rationale_code = 'tampered'
                    WHERE tenant_id = %s AND decision_event_id = %s
                    """,
                    ("tenant-remediation", decision_row[0]),
                )
        finally:
            await maintenance.close()

    asyncio.run(scenario())


def test_postgres_effect_quota_race_and_long_stream_rebuild() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        first_connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        second_connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await first_connection.execute("SET ROLE aegis_app")
        await second_connection.execute("SET ROLE aegis_app")
        barrier = asyncio.Barrier(2)
        first_events = PostgresEventStore(first_connection)
        second_events = PostgresEventStore(second_connection)
        first_repository = BarrierRemediationRepository(
            first_connection,
            first_events,
            PostgresWorkRepository(first_connection, first_events),
            barrier,
        )
        second_repository = BarrierRemediationRepository(
            second_connection,
            second_events,
            PostgresWorkRepository(second_connection, second_events),
            barrier,
        )
        service = RemediationApprovalService(first_repository, clock=Clock())
        first_adapter = BlockingActionAdapter()
        second_adapter = BlockingActionAdapter()

        async def approve(
            suffix: str,
        ) -> tuple[RemediationPlan, WorkLease]:
            selected_action = action(
                idempotency_key=f"tenant-remediation:quota-race:{suffix}"
            )
            selected_policy = replace(
                policy(
                    selected_action.target,
                    tenant_id=TenantId("tenant-remediation"),
                ),
                max_actions_per_period=100,
                max_concurrent_actions=1,
            )
            selected_plan = plan(
                selected_action,
                selected_policy,
                requested_by="operator",
                tenant_id=TenantId("tenant-remediation"),
            )
            proposal = await service.propose(
                principal(
                    "operator",
                    Role.OPERATOR,
                    tenant_id=TenantId("tenant-remediation"),
                ),
                CONTEXT,
                selected_plan,
                selected_policy,
                await first_repository.quota_usage(CONTEXT, at=Clock().value),
                idempotency_key=f"quota-race:{suffix}:{selected_plan.plan_id}",
            )
            approval_id = next(iter(proposal.state.approvals))
            for actor_id in ("approver-one", "approver-two"):
                await service.decide(
                    principal(
                        actor_id,
                        Role.APPROVER,
                        tenant_id=TenantId("tenant-remediation"),
                    ),
                    CONTEXT,
                    selected_plan.plan_id,
                    approval_id,
                    ApprovalDecision.GRANT,
                    decision_id=uuid4(),
                    current_policy=selected_policy,
                    rationale_code="reviewed",
                    comment="quota race approval",
                )
            active_lease = lease(
                selected_plan.plan_id,
                tenant_id=TenantId("tenant-remediation"),
                expires_at=Clock().value + timedelta(days=3_650),
            )
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-remediation",),
                )
                await first_connection.execute(
                    """
                    INSERT INTO work_leases (
                        tenant_id, work_id, lease_token, generation, owner,
                        acquired_at, heartbeat_at, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        "tenant-remediation",
                        selected_plan.plan_id,
                        active_lease.token,
                        active_lease.generation,
                        active_lease.owner,
                        active_lease.acquired_at,
                        active_lease.heartbeat_at,
                        active_lease.expires_at,
                    ),
                )
            return selected_plan, active_lease

        try:
            first_plan, first_lease = await approve("one")
            second_plan, second_lease = await approve("two")
            authority = StaticApprovalAuthority(
                {
                    "approver-one": frozenset({Role.APPROVER.value}),
                    "approver-two": frozenset({Role.APPROVER.value}),
                }
            )
            first_executor = ControlledActionExecutor(
                first_repository,
                first_adapter,
                authority,
                clock=Clock(),
            )
            second_executor = ControlledActionExecutor(
                second_repository,
                second_adapter,
                authority,
                clock=Clock(),
            )
            first_task = asyncio.create_task(
                first_executor.execute(
                    principal(
                        "operator",
                        Role.OPERATOR,
                        tenant_id=TenantId("tenant-remediation"),
                    ),
                    CONTEXT,
                    first_plan.plan_id,
                    first_plan.actions[0].action_id,
                    first_lease,
                    first_plan.approval_policy,
                )
            )
            second_task = asyncio.create_task(
                second_executor.execute(
                    principal(
                        "operator",
                        Role.OPERATOR,
                        tenant_id=TenantId("tenant-remediation"),
                    ),
                    CONTEXT,
                    second_plan.plan_id,
                    second_plan.actions[0].action_id,
                    second_lease,
                    second_plan.approval_policy,
                )
            )
            done, pending = await asyncio.wait(
                {first_task, second_task},
                timeout=5,
                return_when=asyncio.FIRST_COMPLETED,
            )
            assert len(done) == 1
            denied_task = next(iter(done))
            assert isinstance(denied_task.exception(), PermissionError)
            assert len(pending) == 1
            first_adapter.release.set()
            second_adapter.release.set()
            successful_task = next(iter(pending))
            completed = await successful_task
            successful_plan = (
                first_plan if successful_task is first_task else second_plan
            )
            successful_repository = (
                first_repository if successful_task is first_task else second_repository
            )
            successful_events = (
                first_events if successful_task is first_task else second_events
            )
            assert (
                completed.action_statuses[successful_plan.actions[0].action_id]
                is ActionLifecycleStatus.VERIFIED
            )

            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-remediation",),
                )
                claim_cursor = await first_connection.execute(
                    """
                    SELECT COUNT(*) FROM remediation_effect_claims
                    WHERE tenant_id = %s AND plan_id IN (%s, %s)
                    """,
                    (
                        "tenant-remediation",
                        first_plan.plan_id,
                        second_plan.plan_id,
                    ),
                )
                claim_row = await claim_cursor.fetchone()
                assert claim_row is not None
                assert claim_row[0] == 1

            before = await successful_repository.load(
                CONTEXT,
                successful_plan.plan_id,
            )
            heartbeats = tuple(
                EventEnvelope(
                    event_id=uuid4(),
                    tenant_id="tenant-remediation",
                    aggregate_id=str(successful_plan.plan_id),
                    event_type=DomainEventType.WORK_HEARTBEAT,
                    schema_version=1,
                    occurred_at=Clock().value,
                    payload={"heartbeat_index": index},
                    idempotency_key=(f"long-stream:{successful_plan.plan_id}:{index}"),
                )
                for index in range(1_001)
            )
            await successful_events.append(
                CONTEXT,
                heartbeats,
                expected_version=len(before),
            )
            loaded = await successful_repository.load(
                CONTEXT,
                successful_plan.plan_id,
            )
            assert len(loaded) == len(before) + 1_001
            assert loaded[-1].aggregate_sequence == len(loaded)

            await successful_repository.rebuild_projection(
                CONTEXT,
                successful_plan.plan_id,
            )
            async with first_connection.transaction():
                await first_connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-remediation",),
                )
                projection_cursor = await first_connection.execute(
                    """
                    SELECT aggregate_version FROM remediation_plan_projection
                    WHERE tenant_id = %s AND plan_id = %s
                    """,
                    ("tenant-remediation", successful_plan.plan_id),
                )
                projection_row = await projection_cursor.fetchone()
                assert projection_row is not None
                assert projection_row[0] == len(loaded)
                quota_cursor = await first_connection.execute(
                    """
                    SELECT
                        (SELECT COUNT(*) FROM remediation_effect_claims
                         WHERE tenant_id = %s),
                        COALESCE(SUM(actions_started), 0),
                        COALESCE(SUM(active_actions), 0)
                    FROM remediation_quota_projection
                    WHERE tenant_id = %s
                    """,
                    ("tenant-remediation", "tenant-remediation"),
                )
                quota_row = await quota_cursor.fetchone()
                assert quota_row is not None
                assert quota_row[0] == quota_row[1]
                assert quota_row[2] == 0
        finally:
            first_adapter.release.set()
            second_adapter.release.set()
            await first_connection.close()
            await second_connection.close()

    asyncio.run(scenario())


def test_postgres_projection_allows_shared_action_digest_across_plans() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await connection.execute("SET ROLE aegis_app")
        events = PostgresEventStore(connection)
        repository = PostgresRemediationRepository(
            connection,
            events,
            PostgresWorkRepository(connection, events),
        )
        service = RemediationApprovalService(repository, clock=Clock())
        shared_action = action(
            idempotency_key="tenant-remediation:shared-projection-action"
        )
        shared_policy = policy(
            shared_action.target,
            tenant_id=TenantId("tenant-remediation"),
        )
        first_plan = plan(
            shared_action,
            shared_policy,
            requested_by="operator",
            tenant_id=TenantId("tenant-remediation"),
        )
        second_plan = plan(
            shared_action,
            shared_policy,
            requested_by="operator",
            tenant_id=TenantId("tenant-remediation"),
        )
        try:
            for selected_plan in (first_plan, second_plan):
                await service.propose(
                    principal(
                        "operator",
                        Role.OPERATOR,
                        tenant_id=TenantId("tenant-remediation"),
                    ),
                    CONTEXT,
                    selected_plan,
                    shared_policy,
                    ActionQuotaUsage(0, 0),
                    idempotency_key=f"shared-action:{selected_plan.plan_id}",
                )
        finally:
            await connection.close()

        maintenance = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        try:
            await maintenance.execute("SET ROLE aegis_maintenance")
            cursor = await maintenance.execute(
                """
                SELECT plan_id, action_digest
                FROM remediation_action_projection
                WHERE tenant_id = %s AND action_digest = %s
                ORDER BY plan_id
                """,
                ("tenant-remediation", shared_action.digest),
            )
            rows = await cursor.fetchall()
            assert set(rows) == {
                (first_plan.plan_id, shared_action.digest),
                (second_plan.plan_id, shared_action.digest),
            }
        finally:
            await maintenance.close()

    asyncio.run(scenario())
