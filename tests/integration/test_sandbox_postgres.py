"""Live Layer 7/8/9 PostgreSQL linkage, RLS, fencing, and rebuild evidence."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
import pytest

from aegis_agent_platform.agents import (
    AgentRole,
    CanonicalCheckoutEngine,
    DurableCoordinator,
    canonical_checkout_citations,
    canonical_checkout_plan,
)
from aegis_agent_platform.agents.postgres import PostgresAgentRepository
from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    ActionTarget,
    BlastRadius,
    Condition,
    ConditionOperator,
    ContentReference,
    EgressRule,
    NetworkMode,
    ReconciliationPolicy,
    RetryPolicy,
    RiskTier,
    SandboxApprovalBinding,
    SandboxExecutionOutcome,
    SandboxLinkage,
    SandboxPurpose,
    SandboxRequest,
    SandboxRisk,
    SandboxStatus,
    WorkLease,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.remediation import (
    ActionQuotaUsage,
    ApprovalDecision,
    RemediationApprovalService,
)
from aegis_agent_platform.remediation.postgres import PostgresRemediationRepository
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.sandbox import (
    DenyAllEgressBroker,
    EgressDecision,
    FakeSandboxBackend,
    PostgresSandboxApprovalAuthority,
    PostgresSandboxRepository,
    SandboxIdempotencyConflictError,
    SandboxOrchestrator,
    SandboxRequestService,
    StaticInputSnapshotVerifier,
)
from aegis_agent_platform.tenancy import TenantContext
from integration_helpers import integration_writer_fences
from remediation_helpers import Clock, plan, policy, principal
from sandbox_helpers import UUIDs, result, spec
from sandbox_helpers import policy as sandbox_policy
from sandbox_helpers import principal as sandbox_principal

DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None,
        reason="AEGIS_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]
TENANT_ID = TenantId("tenant-remediation")
CONTEXT = TenantContext(TENANT_ID)
OTHER_CONTEXT = TenantContext(TenantId("tenant-b"))


class _AllowEgressBroker:
    @property
    def enforcement_ready(self) -> bool:
        return True

    async def authorize(
        self,
        context: TenantContext,
        request: SandboxRequest,
        rule: EgressRule,
        *,
        policy_digest: str,
        at: datetime,
    ) -> EgressDecision:
        assert request.linkage.tenant_id == str(context.tenant_id)
        return EgressDecision(True, "reviewed_test_egress", rule, policy_digest, at)


async def _insert_lease(
    connection: psycopg.AsyncConnection[Any],
    lease: WorkLease,
) -> None:
    async with connection.transaction():
        await connection.execute(
            "SELECT set_config('aegis.tenant_id', %s, true)",
            (lease.tenant_id,),
        )
        await connection.execute(
            """
            INSERT INTO work_leases (
                tenant_id, work_id, lease_token, generation, owner,
                acquired_at, heartbeat_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                lease.tenant_id,
                lease.work_id,
                lease.token,
                lease.generation,
                lease.owner,
                lease.acquired_at,
                lease.heartbeat_at,
                lease.expires_at,
            ),
        )


async def _insert_approver_identities(
    connection: psycopg.AsyncConnection[Any],
    *,
    at: datetime,
) -> None:
    for actor_id in ("approver-one", "approver-two"):
        identity_id = uuid4()
        await connection.execute(
            """
            INSERT INTO identities (
                identity_id, tenant_id, issuer, subject, identity_kind,
                user_id, enabled, created_at
            ) VALUES (%s, %s, %s, %s, 'user', %s, true, %s)
            """,
            (
                identity_id,
                str(TENANT_ID),
                "https://identity.integration.invalid",
                f"sandbox-{actor_id}",
                actor_id,
                at - timedelta(minutes=1),
            ),
        )
        await connection.execute(
            """
            INSERT INTO role_bindings (
                role_binding_id, tenant_id, identity_id, role, assigned_by,
                assigned_at
            ) VALUES (%s, %s, %s, 'approver', 'integration', %s)
            """,
            (
                uuid4(),
                str(TENANT_ID),
                identity_id,
                at - timedelta(minutes=1),
            ),
        )


def test_canonical_specialist_approval_sandbox_rls_fencing_and_rebuild() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        clock = Clock()
        await _insert_approver_identities(connection, at=clock.value)
        await connection.execute("SET ROLE aegis_app")
        database_clock = await connection.execute("SELECT clock_timestamp()")
        database_now_row = await database_clock.fetchone()
        assert database_now_row is not None
        database_now = database_now_row[0]
        event_store = PostgresEventStore(
            connection,
            writer_fence_resolver=integration_writer_fences("local-test", 1),
        )
        work = PostgresWorkRepository(connection, event_store)
        run_id = uuid4()
        agent_repository = PostgresAgentRepository(connection, event_store, work)
        coordinator = DurableCoordinator(
            agent_repository,
            CanonicalCheckoutEngine(clock=clock),
            clock=clock,
        )
        investigation = canonical_checkout_plan(
            tenant_id=str(TENANT_ID),
            incident_id="sandbox-integration",
            run_id=run_id,
            created_at=clock.value,
        )
        run_lease = WorkLease(
            run_id,
            str(TENANT_ID),
            uuid4(),
            1,
            "sandbox-integration-coordinator",
            1,
            database_now,
            database_now,
            database_now + timedelta(minutes=5),
        )
        try:
            await coordinator.request(
                CONTEXT,
                investigation,
                actor_id="integration",
                idempotency_key=f"sandbox-agent:{run_id}",
            )
            await _insert_lease(connection, run_lease)
            await coordinator.execute(
                CONTEXT,
                run_id,
                run_lease,
                canonical_checkout_citations(),
            )
            task_id = next(
                assignment.assignment_id
                for assignment in investigation.assignments
                if assignment.role is AgentRole.REMEDIATION_PLANNER
            )

            remediation_repository = PostgresRemediationRepository(
                connection,
                event_store,
                work,
            )
            remediation_service = RemediationApprovalService(
                remediation_repository,
                clock=clock,
            )
            uuids = UUIDs("postgres")
            selected_spec = spec(
                input_snapshot=ContentReference(
                    f"aegis-input://{TENANT_ID}/snapshot",
                    "b" * 64,
                    1_024,
                    "application/vnd.aegis.snapshot",
                ),
                network_mode=NetworkMode.BROKERED,
                egress_rules=(EgressRule("https", "packages.example.com", 443),),
            )
            plan_id = uuid4()
            action_id = uuid4()
            provisional_request = SandboxRequest(
                sandbox_id=uuids(),
                linkage=SandboxLinkage(
                    tenant_id=str(TENANT_ID),
                    run_id=run_id,
                    task_id=task_id,
                    remediation_plan_id=plan_id,
                    remediation_action_id=action_id,
                    approval_id=uuid4(),
                ),
                purpose=SandboxPurpose.CODE_ANALYSIS,
                risk=SandboxRisk.MEDIUM,
                spec=selected_spec,
                requested_by="operator",
                requested_at=clock.value,
                idempotency_key=f"sandbox-scope:{run_id}",
            )
            reviewed_sandbox_policy = sandbox_policy(provisional_request)
            sandbox_target = ActionTarget(
                "aegis",
                "analysis",
                "sandbox",
                str(action_id),
                "tenant",
            )
            selected_action = ActionSpecification(
                action_id=action_id,
                kind=ActionKind.SANDBOX_CHANGE_PREPARATION,
                target=sandbox_target,
                risk=RiskTier.MEDIUM,
                blast_radius=BlastRadius.SINGLE_RESOURCE,
                preconditions=(
                    Condition(
                        "sandbox.scope_reviewed",
                        ConditionOperator.EQUALS,
                        True,
                        "evidence-checkout",
                    ),
                ),
                postconditions=(
                    Condition(
                        "sandbox.outputs_scanned",
                        ConditionOperator.EQUALS,
                        True,
                    ),
                ),
                evidence_ids=("evidence-checkout",),
                idempotency_key=f"sandbox-remediation:{run_id}",
                timeout_seconds=30,
                retry_policy=RetryPolicy(2, 0, 0),
                reconciliation_policy=ReconciliationPolicy(interval_seconds=0),
                dry_run_supported=True,
                parameters={
                    "sandbox_policy_digest": reviewed_sandbox_policy.digest,
                    "sandbox_purpose": provisional_request.purpose.value,
                    "sandbox_risk": int(provisional_request.risk),
                    "sandbox_spec_digest": selected_spec.digest,
                },
            )
            selected_approval_policy = replace(
                policy(selected_action.target),
                allowed_action_kinds=frozenset({ActionKind.SANDBOX_CHANGE_PREPARATION}),
            )
            selected_plan = replace(
                plan(
                    selected_action,
                    selected_approval_policy,
                    plan_id=plan_id,
                    requested_by="operator",
                ),
                investigation_run_id=run_id,
            )
            proposal = await remediation_service.propose(
                principal("operator", Role.OPERATOR),
                CONTEXT,
                selected_plan,
                selected_plan.approval_policy,
                ActionQuotaUsage(0, 0),
                idempotency_key=f"sandbox-plan:{selected_plan.plan_id}",
            )
            approval_id = next(iter(proposal.state.approvals))
            for approver_id in ("approver-one", "approver-two"):
                await remediation_service.decide(
                    principal(approver_id, Role.APPROVER),
                    CONTEXT,
                    selected_plan.plan_id,
                    approval_id,
                    ApprovalDecision.GRANT,
                    decision_id=uuid4(),
                    current_policy=selected_plan.approval_policy,
                    rationale_code="sandbox_scope_reviewed",
                    comment="reviewed exact analysis scope",
                )

            sandbox_request = SandboxRequest(
                sandbox_id=uuids(),
                linkage=SandboxLinkage(
                    tenant_id=str(TENANT_ID),
                    run_id=run_id,
                    task_id=task_id,
                    remediation_plan_id=selected_plan.plan_id,
                    remediation_action_id=selected_action.action_id,
                    approval_id=approval_id,
                ),
                purpose=SandboxPurpose.CODE_ANALYSIS,
                risk=SandboxRisk.MEDIUM,
                spec=selected_spec,
                requested_by="operator",
                requested_at=clock.value,
                idempotency_key=f"sandbox-execution:{run_id}",
            )
            selected_policy = sandbox_policy(sandbox_request)
            assert selected_policy.digest == reviewed_sandbox_policy.digest
            approval = SandboxApprovalBinding(
                approval_id=approval_id,
                plan_id=selected_plan.plan_id,
                action_id=selected_action.action_id,
                plan_digest=selected_plan.digest,
                action_digest=selected_action.digest,
                policy_digest=selected_policy.digest,
                spec_digest=selected_spec.digest,
                purpose=sandbox_request.purpose,
                risk=sandbox_request.risk,
                approver_ids=("approver-one", "approver-two"),
                issued_at=clock.value,
                expires_at=clock.value + timedelta(minutes=5),
            )
            sandbox_repository = PostgresSandboxRepository(
                connection,
                event_store,
                work,
            )
            approval_authority = PostgresSandboxApprovalAuthority(connection)
            request_service = SandboxRequestService(
                sandbox_repository,
                approval_authority,
                clock=clock,
                uuid_factory=uuids,
            )
            operator = sandbox_principal(
                role=Role.OPERATOR,
                tenant_id=TENANT_ID,
                issued_at=clock.value - timedelta(minutes=1),
            )
            requested = await request_service.request(
                operator,
                CONTEXT,
                sandbox_request,
                selected_policy,
                approval,
            )
            with pytest.raises(
                SandboxIdempotencyConflictError,
                match="sandbox_idempotency_key_reused",
            ):
                await request_service.request(
                    operator,
                    CONTEXT,
                    replace(sandbox_request, sandbox_id=uuids()),
                    selected_policy,
                    approval,
                )
            assert requested.state.status is SandboxStatus.APPROVED
            assert (
                await sandbox_repository.load(
                    OTHER_CONTEXT,
                    sandbox_request.sandbox_id,
                )
                == ()
            )

            sandbox_lease = WorkLease(
                sandbox_request.sandbox_id,
                str(TENANT_ID),
                uuids(),
                1,
                "sandbox-integration-worker",
                1,
                database_now,
                database_now,
                database_now + timedelta(minutes=5),
            )
            await _insert_lease(connection, sandbox_lease)
            final = await SandboxOrchestrator(
                sandbox_repository,
                FakeSandboxBackend(
                    result=result(
                        uuids,
                        outcome=SandboxExecutionOutcome.SUCCEEDED,
                    ),
                    clock=clock,
                ),
                approval_authority,
                StaticInputSnapshotVerifier(),
                egress_broker=_AllowEgressBroker(),
                clock=clock,
                uuid_factory=uuids,
            ).execute(
                sandbox_principal(
                    role=Role.OPERATOR,
                    tenant_id=TENANT_ID,
                    issued_at=clock.value - timedelta(minutes=1),
                ),
                CONTEXT,
                sandbox_request.sandbox_id,
                sandbox_lease,
                selected_policy,
                approval,
            )
            assert final.status is SandboxStatus.CLEANED
            assert final.attestation is not None
            total_usage = await sandbox_repository.quota_usage(
                CONTEXT,
                at=clock.value,
            )
            retry_usage = await sandbox_repository.quota_usage(
                CONTEXT,
                at=clock.value,
                exclude_idempotency_key=sandbox_request.idempotency_key,
            )
            assert total_usage.runs_in_period == 1
            assert total_usage.cpu_millis_seconds == (
                selected_spec.resources.cpu_millis
                * selected_spec.resources.timeout_seconds
            )
            assert total_usage.artifact_bytes == sum(
                output.max_bytes for output in selected_spec.expected_outputs
            )
            assert retry_usage == type(retry_usage)(0, 0, 0, 0)

            denied_request = replace(
                sandbox_request,
                sandbox_id=uuids(),
                idempotency_key=f"sandbox-egress-denied:{run_id}",
            )
            denied_requested = await SandboxRequestService(
                sandbox_repository,
                approval_authority,
                clock=clock,
                uuid_factory=uuids,
            ).request(
                sandbox_principal(
                    role=Role.OPERATOR,
                    tenant_id=TENANT_ID,
                    issued_at=clock.value - timedelta(minutes=1),
                ),
                CONTEXT,
                denied_request,
                selected_policy,
                approval,
            )
            assert denied_requested.state.status is SandboxStatus.APPROVED
            denied_lease = WorkLease(
                denied_request.sandbox_id,
                str(TENANT_ID),
                uuids(),
                1,
                "sandbox-egress-denial-worker",
                1,
                database_now,
                database_now,
                database_now + timedelta(minutes=5),
            )
            await _insert_lease(connection, denied_lease)
            denied = await SandboxOrchestrator(
                sandbox_repository,
                FakeSandboxBackend(
                    result=result(
                        uuids,
                        outcome=SandboxExecutionOutcome.SUCCEEDED,
                    ),
                    clock=clock,
                ),
                approval_authority,
                StaticInputSnapshotVerifier(),
                egress_broker=DenyAllEgressBroker(),
                clock=clock,
                uuid_factory=uuids,
            ).execute(
                sandbox_principal(
                    role=Role.OPERATOR,
                    tenant_id=TENANT_ID,
                    issued_at=clock.value - timedelta(minutes=1),
                ),
                CONTEXT,
                denied_request.sandbox_id,
                denied_lease,
                selected_policy,
                approval,
            )
            assert denied.status is SandboxStatus.POLICY_VIOLATION
            assert (
                await sandbox_repository.load(
                    CONTEXT,
                    denied_request.sandbox_id,
                )
            )[-1].event_type == "sandbox.policy_violation.v1"
            with pytest.raises(FencingError):
                await sandbox_repository.assert_fence(
                    CONTEXT,
                    sandbox_request.sandbox_id,
                    replace(sandbox_lease, token=uuid4()),
                    at=clock.value,
                )
            await remediation_repository.rebuild_projection(
                CONTEXT,
                selected_plan.plan_id,
            )
            assert await approval_authority.current(
                CONTEXT,
                approval,
                at=clock.value,
            )
            await connection.execute("SET ROLE aegis_maintenance")
            await connection.execute(
                """
                UPDATE role_bindings
                SET revoked_at = %s
                WHERE tenant_id = %s
                  AND identity_id = (
                      SELECT identity_id
                      FROM identities
                      WHERE tenant_id = %s AND user_id = 'approver-one'
                  )
                """,
                (clock.value, str(TENANT_ID), str(TENANT_ID)),
            )
            await connection.execute("SET ROLE aegis_app")
            assert not await approval_authority.current(
                CONTEXT,
                approval,
                at=clock.value,
            )
            await connection.execute("SET ROLE aegis_maintenance")
            await connection.execute(
                """
                UPDATE role_bindings
                SET revoked_at = NULL
                WHERE tenant_id = %s
                  AND identity_id = (
                      SELECT identity_id
                      FROM identities
                      WHERE tenant_id = %s AND user_id = 'approver-one'
                  )
                """,
                (str(TENANT_ID), str(TENANT_ID)),
            )
            await connection.execute("SET ROLE aegis_app")
        finally:
            await connection.close()

        maintenance = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await maintenance.execute("SET ROLE aegis_maintenance")
        maintenance_events = PostgresEventStore(
            maintenance,
            writer_fence_resolver=integration_writer_fences("local-test", 1),
        )
        maintenance_repository = PostgresSandboxRepository(
            maintenance,
            maintenance_events,
            PostgresWorkRepository(maintenance, maintenance_events),
        )
        try:
            await maintenance.execute(
                """
                UPDATE sandbox_projection
                SET run_id = %s, risk = 4, spec_digest = %s
                WHERE tenant_id = %s AND sandbox_id = %s
                """,
                (uuid4(), "d" * 64, str(TENANT_ID), sandbox_request.sandbox_id),
            )
            await maintenance.execute(
                """
                UPDATE sandbox_quota_projection
                SET runs_started = 99, active_runs = 7,
                    cpu_millis_seconds = 1, artifact_bytes = 1
                WHERE tenant_id = %s AND usage_period = %s
                """,
                (str(TENANT_ID), sandbox_request.requested_at.date().isoformat()),
            )
            await maintenance_repository.rebuild_projection(
                CONTEXT,
                sandbox_request.sandbox_id,
            )
            rows, _cursor = await maintenance_repository.page(CONTEXT)
            rebuilt = next(
                row
                for row in rows
                if row["sandbox_id"] == str(sandbox_request.sandbox_id)
            )
            assert rebuilt["status"] == SandboxStatus.CLEANED.value
            rebuilt_cursor = await maintenance.execute(
                """
                SELECT run_id, risk, spec_digest
                FROM sandbox_projection
                WHERE tenant_id = %s AND sandbox_id = %s
                """,
                (str(TENANT_ID), sandbox_request.sandbox_id),
            )
            rebuilt_scope = await rebuilt_cursor.fetchone()
            assert rebuilt_scope is not None
            assert rebuilt_scope == (
                sandbox_request.linkage.run_id,
                int(sandbox_request.risk),
                sandbox_request.spec.digest,
            )
            quota_cursor = await maintenance.execute(
                """
                SELECT runs_started, active_runs, cpu_millis_seconds,
                       artifact_bytes
                FROM sandbox_quota_projection
                WHERE tenant_id = %s AND usage_period = %s
                """,
                (str(TENANT_ID), sandbox_request.requested_at.date().isoformat()),
            )
            quota = await quota_cursor.fetchone()
            assert quota is not None
            assert quota == (
                1,
                0,
                sandbox_request.spec.resources.cpu_millis
                * sandbox_request.spec.resources.timeout_seconds,
                sum(
                    output.max_bytes for output in sandbox_request.spec.expected_outputs
                ),
            )
        finally:
            await maintenance.close()

    asyncio.run(scenario())
