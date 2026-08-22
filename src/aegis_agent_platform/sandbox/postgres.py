"""PostgreSQL ledger adapter for sandbox projections, claims, and cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg

from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    SandboxApprovalBinding,
    SandboxState,
    WorkLease,
    WorkRequest,
    WorkTransition,
    replay_sandbox,
)
from aegis_agent_platform.event_store import (
    ConcurrencyError,
    FencingError,
    PermanentStorageError,
)
from aegis_agent_platform.event_store.postgres import (
    PostgresEventStore,
    classify_storage_error,
    postgres_connection_lock,
)
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.sandbox.policy import SandboxQuotaUsage
from aegis_agent_platform.sandbox.repository import (
    SandboxIdempotencyConflictError,
    SandboxRepository,
    SandboxRequestResult,
)
from aegis_agent_platform.tenancy import TenantContext


class PostgresSandboxApprovalAuthority:
    """Recheck the exact granted Layer 8 approval under forced tenant RLS."""

    def __init__(self, connection: psycopg.AsyncConnection[Any]) -> None:
        self._connection = connection
        self._lock = postgres_connection_lock(connection)

    async def current(
        self,
        context: TenantContext,
        binding: SandboxApprovalBinding,
        *,
        at: datetime,
    ) -> bool:
        if at.tzinfo is None:
            raise ValueError("sandbox authority time must be timezone-aware")
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT plan.plan_digest, action.action_digest,
                           approval.status, approval.approver_ids,
                           approval.expires_at, action.action_kind,
                           action.sandbox_spec_digest,
                           action.sandbox_policy_digest,
                           action.sandbox_purpose,
                           action.sandbox_risk
                    FROM remediation_approval_projection AS approval
                    JOIN remediation_plan_projection AS plan
                      ON plan.tenant_id = approval.tenant_id
                     AND plan.plan_id = approval.plan_id
                    JOIN remediation_action_projection AS action
                      ON action.tenant_id = approval.tenant_id
                     AND action.plan_id = approval.plan_id
                     AND action.action_id = approval.action_id
                    WHERE approval.tenant_id = %s
                      AND approval.approval_id = %s
                      AND approval.plan_id = %s
                      AND approval.action_id = %s
                      AND NOT EXISTS (
                          SELECT 1
                          FROM unnest(approval.approver_ids)
                              AS approved(approver_id)
                          WHERE NOT EXISTS (
                              SELECT 1
                              FROM identities AS identity
                              JOIN role_bindings AS binding
                                ON binding.tenant_id = identity.tenant_id
                               AND binding.identity_id = identity.identity_id
                              WHERE identity.tenant_id = approval.tenant_id
                                AND identity.user_id = approved.approver_id
                                AND identity.enabled
                                AND binding.role IN ('approver', 'tenant_admin')
                                AND binding.assigned_at <= %s
                                AND (
                                    binding.expires_at IS NULL
                                    OR binding.expires_at > %s
                                )
                                AND (
                                    binding.revoked_at IS NULL
                                    OR binding.revoked_at > %s
                                )
                          )
                      )
                    """,
                    (
                        str(context.tenant_id),
                        binding.approval_id,
                        binding.plan_id,
                        binding.action_id,
                        at,
                        at,
                        at,
                    ),
                )
                row = await cursor.fetchone()
                return bool(
                    row is not None
                    and str(row[0]) == binding.plan_digest
                    and str(row[1]) == binding.action_digest
                    and str(row[2]) == "granted"
                    and set(row[3]) == set(binding.approver_ids)
                    and row[4] > at
                    and str(row[5]) == "sandbox.change_preparation.v1"
                    and str(row[6]) == binding.spec_digest
                    and str(row[7]) == binding.policy_digest
                    and str(row[8]) == binding.purpose.value
                    and int(row[9]) == int(binding.risk)
                )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error


class PostgresSandboxRepository(SandboxRepository):
    """Fenced PostgreSQL authority with rebuildable tenant projections."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        event_store: PostgresEventStore,
        work_repository: PostgresWorkRepository,
    ) -> None:
        self._connection = connection
        self._events = event_store
        self._work = work_repository
        self._lock = postgres_connection_lock(connection)

    async def request(
        self,
        context: TenantContext,
        request: WorkRequest,
        sandbox_events: Sequence[EventEnvelope],
        *,
        requested_event_id: UUID,
        outbox_message_id: UUID,
    ) -> SandboxRequestResult:
        existing = await self._work.work_id_for_idempotency(
            context,
            request.idempotency_key,
            work_kind=request.work_kind,
            request_payload=request.payload,
        )
        if existing is not None:
            if existing != request.work_id:
                raise SandboxIdempotencyConflictError("sandbox_idempotency_key_reused")
            return SandboxRequestResult(False, existing)
        if await self._work.idempotency_key_in_use(
            context,
            request.idempotency_key,
        ):
            raise SandboxIdempotencyConflictError("sandbox_idempotency_key_reused")
        work_event = WorkTransition(
            DomainEventType.WORK_REQUESTED,
            request.requested_at,
            {
                "idempotency_key": request.idempotency_key,
                "max_attempts": request.max_attempts,
                "request_payload": request.payload,
                "timeout_seconds": request.timeout_seconds,
            },
        ).to_event(
            request,
            event_id=requested_event_id,
            causation_id=request.causation_id,
        )
        candidate = [replace(work_event, aggregate_sequence=1)]
        candidate.extend(
            replace(event, aggregate_sequence=index)
            for index, event in enumerate(sandbox_events, start=2)
        )
        state = replay_sandbox(candidate)

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _replace_projection(connection, state, candidate[-1])

        try:
            await self._work.register(
                context,
                request,
                requested_event_id=requested_event_id,
                outbox_message_id=outbox_message_id,
                additional_events=sandbox_events,
                additional_mutation=mutation,
            )
        except (ConcurrencyError, PermanentStorageError):
            existing = await self._work.work_id_for_idempotency(
                context,
                request.idempotency_key,
                work_kind=request.work_kind,
                request_payload=request.payload,
            )
            if existing is not None:
                if existing != request.work_id:
                    raise SandboxIdempotencyConflictError(
                        "sandbox_idempotency_key_reused"
                    ) from None
                return SandboxRequestResult(False, existing)
            if await self._work.idempotency_key_in_use(
                context,
                request.idempotency_key,
            ):
                raise SandboxIdempotencyConflictError(
                    "sandbox_idempotency_key_reused"
                ) from None
            raise
        return SandboxRequestResult(True, request.work_id)

    async def load(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> tuple[EventEnvelope, ...]:
        loaded: list[EventEnvelope] = []
        while True:
            page = [
                event
                async for event in self._events.read_stream(
                    context,
                    str(sandbox_id),
                    after_version=len(loaded),
                    limit=1_000,
                )
            ]
            loaded.extend(page)
            if len(page) < 1_000:
                return tuple(loaded)

    async def append(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        if any(_requires_fence(event) for event in events):
            raise FencingError(0, 0)
        state, prepared = await self._candidate(
            context,
            sandbox_id,
            events,
            expected_version,
        )

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _replace_projection(connection, state, prepared[-1])
            await _apply_side_tables(connection, state, prepared)

        return await self._events.append_atomic(
            context,
            events,
            expected_version=expected_version,
            mutation=mutation,
        )

    async def append_fenced(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        expected_version: int,
    ) -> int:
        state, prepared = await self._candidate(
            context,
            sandbox_id,
            events,
            expected_version,
        )

        async def mutation(connection: psycopg.AsyncConnection[Any]) -> None:
            await _replace_projection(connection, state, prepared[-1])
            await _apply_side_tables(connection, state, prepared)

        return await self._events.append_fenced(
            context,
            events,
            expected_version=expected_version,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=events[0].occurred_at,
            mutation=mutation,
        )

    async def assert_fence(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        lease: WorkLease,
        *,
        at: datetime,
    ) -> None:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT lease_token, generation, expires_at, released_at
                    FROM work_leases
                    WHERE tenant_id = %s AND work_id = %s
                    FOR UPDATE
                    """,
                    (str(context.tenant_id), sandbox_id),
                )
                row = await cursor.fetchone()
                if (
                    row is None
                    or lease.tenant_id != str(context.tenant_id)
                    or lease.work_id != sandbox_id
                    or row[0] != lease.token
                    or int(row[1]) != lease.generation
                    or row[2] <= at
                    or row[3] is not None
                ):
                    raise FencingError(
                        lease.generation,
                        int(row[1]) if row is not None else 0,
                    )
        except FencingError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def quota_usage(
        self,
        context: TenantContext,
        *,
        at: datetime,
        exclude_idempotency_key: str | None = None,
    ) -> SandboxQuotaUsage:
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT runs_started, active_runs, cpu_millis_seconds,
                           artifact_bytes
                    FROM sandbox_quota_projection
                    WHERE tenant_id = %s AND usage_period = %s
                    """,
                    (str(context.tenant_id), at.date().isoformat()),
                )
                row = await cursor.fetchone()
                values = [int(value) for value in row] if row is not None else [0] * 4
                if exclude_idempotency_key is not None:
                    claim = await self._connection.execute(
                        """
                        SELECT status, started_at, sandbox_id,
                               reserved_cpu_millis_seconds,
                               reserved_artifact_bytes, quota_reserved
                        FROM sandbox_execution_claims
                        WHERE tenant_id = %s AND idempotency_key = %s
                        """,
                        (str(context.tenant_id), exclude_idempotency_key),
                    )
                    existing = await claim.fetchone()
                    if (
                        existing is not None
                        and existing[1].date() == at.date()
                        and bool(existing[5])
                    ):
                        values[0] = max(0, values[0] - 1)
                        values[2] = max(0, values[2] - int(existing[3]))
                        values[3] = max(0, values[3] - int(existing[4]))
                        if existing[0] in {
                            "intent_recorded",
                            "running",
                            "ambiguous",
                            "cleanup_pending",
                        }:
                            values[1] = max(0, values[1] - 1)
                return SandboxQuotaUsage(*values)
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    async def page(
        self,
        context: TenantContext,
        *,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        _page_limit(limit)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT sandbox_id, run_id, task_id, remediation_plan_id,
                           remediation_action_id, approval_id, purpose, risk,
                           spec_digest, image_digest, policy_digest,
                           approval_scope_digest, status, cleanup_attempts,
                           aggregate_version, requested_at, updated_at
                    FROM sandbox_projection
                    WHERE tenant_id = %s
                      AND (%s::uuid IS NULL OR sandbox_id > %s::uuid)
                    ORDER BY sandbox_id
                    LIMIT %s
                    """,
                    (
                        str(context.tenant_id),
                        after_sandbox_id,
                        after_sandbox_id,
                        limit + 1,
                    ),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        page = rows[:limit]
        result: tuple[Mapping[str, JsonValue], ...] = tuple(
            {
                "sandbox_id": str(row[0]),
                "run_id": str(row[1]),
                "task_id": str(row[2]),
                "remediation_plan_id": str(row[3]),
                "remediation_action_id": str(row[4]),
                "approval_id": str(row[5]),
                "purpose": str(row[6]),
                "risk": int(row[7]),
                "spec_digest": str(row[8]),
                "image_digest": str(row[9]),
                "policy_digest": str(row[10]) if row[10] is not None else None,
                "approval_scope_digest": (
                    str(row[11]) if row[11] is not None else None
                ),
                "status": str(row[12]),
                "cleanup_attempts": int(row[13]),
                "version": int(row[14]),
                "requested_at": row[15].isoformat(),
                "updated_at": row[16].isoformat(),
                "redacted": True,
            }
            for row in page
        )
        next_cursor = UUID(str(page[-1][0])) if len(rows) > limit and page else None
        return result, next_cursor

    async def artifact_page(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], int | None]:
        _page_limit(limit)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT ledger_position, artifact_id, content_digest,
                           size_bytes, media_type, quarantined, created_at
                    FROM sandbox_artifact_projection
                    WHERE tenant_id = %s AND sandbox_id = %s
                      AND ledger_position > %s
                    ORDER BY ledger_position, artifact_id
                    LIMIT %s
                    """,
                    (
                        str(context.tenant_id),
                        sandbox_id,
                        after_position,
                        limit + 1,
                    ),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        page = rows[:limit]
        result: tuple[Mapping[str, JsonValue], ...] = tuple(
            {
                "position": int(row[0]),
                "artifact_id": str(row[1]),
                "digest": str(row[2]),
                "size_bytes": int(row[3]),
                "media_type": str(row[4]),
                "quarantined": bool(row[5]),
                "created_at": row[6].isoformat(),
                "redacted": True,
            }
            for row in page
        )
        next_cursor = int(page[-1][0]) if len(rows) > limit and page else None
        return result, next_cursor

    async def cleanup_page(
        self,
        context: TenantContext,
        *,
        after_sandbox_id: UUID | None = None,
        limit: int = 100,
    ) -> tuple[tuple[Mapping[str, JsonValue], ...], UUID | None]:
        _page_limit(limit)
        try:
            async with _tenant_transaction(self._connection, self._lock, context):
                cursor = await self._connection.execute(
                    """
                    SELECT sandbox_id, status, attempt_count, next_attempt_at,
                           last_error_code, updated_at
                    FROM sandbox_cleanup_projection
                    WHERE tenant_id = %s
                      AND status IN ('pending', 'failed', 'quarantined')
                      AND (%s::uuid IS NULL OR sandbox_id > %s::uuid)
                    ORDER BY sandbox_id
                    LIMIT %s
                    """,
                    (
                        str(context.tenant_id),
                        after_sandbox_id,
                        after_sandbox_id,
                        limit + 1,
                    ),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        page = rows[:limit]
        result: tuple[Mapping[str, JsonValue], ...] = tuple(
            {
                "sandbox_id": str(row[0]),
                "status": str(row[1]),
                "attempts": int(row[2]),
                "next_attempt_at": row[3].isoformat(),
                "last_error_code": str(row[4]) if row[4] is not None else None,
                "updated_at": row[5].isoformat(),
                "redacted": True,
            }
            for row in page
        )
        next_cursor = UUID(str(page[-1][0])) if len(rows) > limit and page else None
        return result, next_cursor

    async def rebuild_projection(
        self,
        context: TenantContext,
        sandbox_id: UUID,
    ) -> None:
        for _attempt in range(3):
            events = await self.load(context, sandbox_id)
            if not events:
                return
            state = replay_sandbox(events)
            try:
                async with _tenant_transaction(self._connection, self._lock, context):
                    cursor = await self._connection.execute(
                        """
                        SELECT current_version
                        FROM event_stream_heads
                        WHERE tenant_id = %s AND aggregate_id = %s
                        FOR UPDATE
                        """,
                        (str(context.tenant_id), str(sandbox_id)),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        return
                    if int(row[0]) != len(events):
                        continue
                    await self._connection.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                        (str(context.tenant_id),),
                    )
                    await self._connection.execute(
                        """
                        DELETE FROM sandbox_artifact_projection
                        WHERE tenant_id = %s AND sandbox_id = %s
                        """,
                        (str(context.tenant_id), sandbox_id),
                    )
                    await self._connection.execute(
                        """
                        DELETE FROM sandbox_cleanup_projection
                        WHERE tenant_id = %s AND sandbox_id = %s
                        """,
                        (str(context.tenant_id), sandbox_id),
                    )
                    await self._connection.execute(
                        """
                        DELETE FROM sandbox_execution_claims
                        WHERE tenant_id = %s AND sandbox_id = %s
                        """,
                        (str(context.tenant_id), sandbox_id),
                    )
                    await _replace_projection(self._connection, state, events[-1])
                    await _apply_side_tables(
                        self._connection,
                        state,
                        events,
                        enforce_quota=False,
                    )
                    await self._connection.execute(
                        """
                        UPDATE sandbox_execution_claims
                        SET quota_reserved = true
                        WHERE tenant_id = %s AND sandbox_id = %s
                        """,
                        (str(context.tenant_id), sandbox_id),
                    )
                    await _rebuild_quota_projection(
                        self._connection,
                        str(context.tenant_id),
                    )
                    return
            except psycopg.Error as error:
                raise classify_storage_error(error) from error
        raise PermanentStorageError("sandbox projection rebuild could not stabilize")

    async def _candidate(
        self,
        context: TenantContext,
        sandbox_id: UUID,
        events: Sequence[EventEnvelope],
        expected_version: int,
    ) -> tuple[SandboxState, tuple[EventEnvelope, ...]]:
        if not events:
            raise ValueError("sandbox append requires events")
        current = await self.load(context, sandbox_id)
        if len(current) != expected_version:
            raise ConcurrencyError(expected_version, len(current))
        prepared = tuple(
            replace(event, aggregate_sequence=expected_version + index)
            for index, event in enumerate(events, start=1)
        )
        return replay_sandbox((*current, *prepared)), prepared


async def _replace_projection(
    connection: psycopg.AsyncConnection[Any],
    state: SandboxState,
    latest: EventEnvelope,
) -> None:
    request = state.request
    await connection.execute(
        """
        INSERT INTO sandbox_projection (
            tenant_id, sandbox_id, run_id, task_id, remediation_plan_id,
            remediation_action_id, approval_id, purpose, risk, spec_digest,
            image_digest, input_digest, policy_digest, approval_scope_digest,
            status, backend_reference, lease_token, lease_generation,
            cleanup_attempts, aggregate_version, requested_at, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (tenant_id, sandbox_id) DO UPDATE SET
            run_id = EXCLUDED.run_id,
            task_id = EXCLUDED.task_id,
            remediation_plan_id = EXCLUDED.remediation_plan_id,
            remediation_action_id = EXCLUDED.remediation_action_id,
            approval_id = EXCLUDED.approval_id,
            purpose = EXCLUDED.purpose,
            risk = EXCLUDED.risk,
            spec_digest = EXCLUDED.spec_digest,
            image_digest = EXCLUDED.image_digest,
            input_digest = EXCLUDED.input_digest,
            policy_digest = EXCLUDED.policy_digest,
            approval_scope_digest = EXCLUDED.approval_scope_digest,
            status = EXCLUDED.status,
            backend_reference = EXCLUDED.backend_reference,
            lease_token = EXCLUDED.lease_token,
            lease_generation = EXCLUDED.lease_generation,
            cleanup_attempts = EXCLUDED.cleanup_attempts,
            aggregate_version = EXCLUDED.aggregate_version,
            requested_at = EXCLUDED.requested_at,
            updated_at = EXCLUDED.updated_at
        """,
        (
            request.linkage.tenant_id,
            request.sandbox_id,
            request.linkage.run_id,
            request.linkage.task_id,
            request.linkage.remediation_plan_id,
            request.linkage.remediation_action_id,
            request.linkage.approval_id,
            request.purpose.value,
            int(request.risk),
            request.spec.digest,
            request.spec.image_digest,
            request.spec.input_snapshot.digest,
            state.policy_digest,
            state.approval_scope_digest,
            state.status.value,
            state.backend_reference,
            latest.payload.get("lease_token"),
            latest.payload.get("lease_generation"),
            state.cleanup_attempts,
            state.version,
            request.requested_at,
            latest.occurred_at,
        ),
    )


async def _apply_side_tables(
    connection: psycopg.AsyncConnection[Any],
    state: SandboxState,
    events: Sequence[EventEnvelope],
    *,
    enforce_quota: bool = True,
) -> None:
    request = state.request
    await connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (request.linkage.tenant_id,),
    )
    for event in events:
        try:
            event_type = DomainEventType(event.event_type)
        except ValueError:
            continue
        if event_type is DomainEventType.SANDBOX_ARTIFACT_CAPTURED:
            await connection.execute(
                """
                INSERT INTO sandbox_artifact_projection (
                    tenant_id, sandbox_id, artifact_id, ledger_position,
                    content_digest, size_bytes, media_type, quarantined,
                    retention_until, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event.tenant_id,
                    request.sandbox_id,
                    UUID(str(event.payload["artifact_id"])),
                    event.aggregate_sequence,
                    event.payload["digest"],
                    event.payload["size_bytes"],
                    event.payload["media_type"],
                    event.payload.get("quarantined", False),
                    event.occurred_at
                    + timedelta(
                        seconds=request.spec.cleanup_policy.maximum_retention_seconds
                    ),
                    event.occurred_at,
                ),
            )
        elif event_type is DomainEventType.SANDBOX_ATTESTED:
            await connection.execute(
                """
                INSERT INTO sandbox_attestations (
                    tenant_id, attestation_event_id, sandbox_id, spec_digest,
                    image_digest, input_digest, result_digest, policy_digest,
                    approval_scope_digest, backend_identity, recorded_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, attestation_event_id) DO NOTHING
                """,
                (
                    event.tenant_id,
                    event.event_id,
                    request.sandbox_id,
                    event.payload["spec_digest"],
                    event.payload["image_digest"],
                    event.payload["input_digest"],
                    event.payload["result_digest"],
                    event.payload["policy_digest"],
                    event.payload["approval_scope_digest"],
                    event.payload["backend_identity"],
                    event.occurred_at,
                ),
            )
        elif event_type is DomainEventType.SANDBOX_DISPATCH_CLAIMED:
            await _claim_execution(
                connection,
                state,
                event,
                enforce_quota=enforce_quota,
            )
        elif event_type is DomainEventType.SANDBOX_STARTED:
            await _update_claim(connection, state, event, "running")
        elif event_type in {
            DomainEventType.SANDBOX_COMPLETED,
            DomainEventType.SANDBOX_FAILED,
            DomainEventType.SANDBOX_TIMED_OUT,
            DomainEventType.SANDBOX_OOM_KILLED,
            DomainEventType.SANDBOX_POLICY_VIOLATION,
            DomainEventType.SANDBOX_CANCELLED,
        }:
            await _terminal_claim(
                connection,
                state,
                event,
                enforce_quota=enforce_quota,
            )
        elif event_type is DomainEventType.SANDBOX_CLEANUP_REQUESTED:
            await _upsert_cleanup(connection, state, event, "pending")
            await _update_claim(connection, state, event, "cleanup_pending")
        elif event_type is DomainEventType.SANDBOX_CLEANUP_COMPLETED:
            await _upsert_cleanup(connection, state, event, "completed")
            await _update_claim(connection, state, event, "cleaned")
        elif event_type is DomainEventType.SANDBOX_CLEANUP_FAILED:
            await _upsert_cleanup(connection, state, event, "failed")
            await _update_claim(connection, state, event, "cleanup_failed")
        elif event_type is DomainEventType.SANDBOX_QUARANTINED:
            await _upsert_cleanup(connection, state, event, "quarantined")
            await _update_claim(connection, state, event, "quarantined")


async def _claim_execution(
    connection: psycopg.AsyncConnection[Any],
    state: SandboxState,
    event: EventEnvelope,
    *,
    enforce_quota: bool,
) -> None:
    request = state.request
    await connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (request.linkage.tenant_id,),
    )
    period = event.occurred_at.date().isoformat()
    await connection.execute(
        """
        INSERT INTO sandbox_quota_projection (
            tenant_id, usage_period, updated_at
        ) VALUES (%s, %s, %s)
        ON CONFLICT (tenant_id, usage_period) DO NOTHING
        """,
        (event.tenant_id, period, event.occurred_at),
    )
    quota_cursor = await connection.execute(
        """
        SELECT runs_started, active_runs, cpu_millis_seconds, artifact_bytes
        FROM sandbox_quota_projection
        WHERE tenant_id = %s AND usage_period = %s
        FOR UPDATE
        """,
        (event.tenant_id, period),
    )
    quota = await quota_cursor.fetchone()
    if quota is None:
        raise PermanentStorageError("sandbox quota projection is missing")
    existing_cursor = await connection.execute(
        """
        SELECT spec_digest
        FROM sandbox_execution_claims
        WHERE tenant_id = %s AND idempotency_key = %s
        FOR UPDATE
        """,
        (event.tenant_id, request.idempotency_key),
    )
    existing = await existing_cursor.fetchone()
    if existing is not None:
        if str(existing[0]) != request.spec.digest:
            raise SandboxIdempotencyConflictError(
                "sandbox_execution_claim_scope_conflict"
            )
        return
    estimated_cpu = _payload_int(event, "estimated_cpu_millis_seconds")
    estimated_artifacts = _payload_int(event, "estimated_artifact_bytes")
    if enforce_quota and (
        int(quota[0]) >= _payload_int(event, "max_runs_per_period")
        or int(quota[1]) >= _payload_int(event, "max_concurrent_runs")
        or int(quota[2]) + estimated_cpu
        > _payload_int(event, "max_cpu_millis_seconds_per_period")
        or int(quota[3]) + estimated_artifacts
        > _payload_int(event, "max_artifact_bytes_per_period")
    ):
        raise PermissionError("sandbox_atomic_quota_denied")
    await connection.execute(
        """
        INSERT INTO sandbox_execution_claims (
            tenant_id, idempotency_key, sandbox_id, spec_digest,
            lease_generation, attempt, reserved_cpu_millis_seconds,
            reserved_artifact_bytes, quota_reserved, status, last_event_id,
            started_at, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s,
            'intent_recorded', %s, %s, %s
        )
        """,
        (
            event.tenant_id,
            request.idempotency_key,
            request.sandbox_id,
            request.spec.digest,
            event.payload["lease_generation"],
            event.payload["attempt"],
            estimated_cpu,
            estimated_artifacts,
            enforce_quota,
            event.event_id,
            event.occurred_at,
            event.occurred_at,
        ),
    )
    if enforce_quota:
        await connection.execute(
            """
            UPDATE sandbox_quota_projection
            SET runs_started = runs_started + 1,
                active_runs = active_runs + 1,
                cpu_millis_seconds = cpu_millis_seconds + %s,
                artifact_bytes = artifact_bytes + %s,
                updated_at = %s
            WHERE tenant_id = %s AND usage_period = %s
            """,
            (
                estimated_cpu,
                estimated_artifacts,
                event.occurred_at,
                event.tenant_id,
                period,
            ),
        )


async def _rebuild_quota_projection(
    connection: psycopg.AsyncConnection[Any],
    tenant_id: str,
) -> None:
    await connection.execute(
        "DELETE FROM sandbox_quota_projection WHERE tenant_id = %s",
        (tenant_id,),
    )
    await connection.execute(
        """
        INSERT INTO sandbox_quota_projection (
            tenant_id, usage_period, runs_started, active_runs,
            cpu_millis_seconds, artifact_bytes, last_global_position,
            updated_at
        )
        WITH dispatches AS (
            SELECT aggregate_id, aggregate_sequence, global_position,
                   occurred_at,
                   (payload ->> 'estimated_cpu_millis_seconds')::bigint
                       AS estimated_cpu,
                   (payload ->> 'estimated_artifact_bytes')::bigint
                       AS estimated_artifacts
            FROM events
            WHERE tenant_id = %s
              AND event_type = %s
        ),
        ledger_usage AS (
            SELECT d.*,
                   terminal.global_position AS terminal_position,
                   terminal.occurred_at AS terminal_at
            FROM dispatches d
            LEFT JOIN LATERAL (
                SELECT global_position, occurred_at
                FROM events
                WHERE tenant_id = %s
                  AND aggregate_id = d.aggregate_id
                  AND aggregate_sequence > d.aggregate_sequence
                  AND event_type = ANY(%s)
                ORDER BY aggregate_sequence
                LIMIT 1
            ) terminal ON true
        )
        SELECT %s, occurred_at::date::text, COUNT(*)::integer,
               COUNT(*) FILTER (
                   WHERE terminal_position IS NULL
               )::integer,
               SUM(estimated_cpu), SUM(estimated_artifacts),
               MAX(GREATEST(global_position, COALESCE(
                   terminal_position, global_position
               ))),
               MAX(GREATEST(occurred_at, COALESCE(terminal_at, occurred_at)))
        FROM ledger_usage
        GROUP BY occurred_at::date
        """,
        (
            tenant_id,
            DomainEventType.SANDBOX_DISPATCH_CLAIMED.value,
            tenant_id,
            [
                DomainEventType.SANDBOX_COMPLETED.value,
                DomainEventType.SANDBOX_FAILED.value,
                DomainEventType.SANDBOX_TIMED_OUT.value,
                DomainEventType.SANDBOX_OOM_KILLED.value,
                DomainEventType.SANDBOX_POLICY_VIOLATION.value,
                DomainEventType.SANDBOX_CANCELLED.value,
            ],
            tenant_id,
        ),
    )


async def _terminal_claim(
    connection: psycopg.AsyncConnection[Any],
    state: SandboxState,
    event: EventEnvelope,
    *,
    enforce_quota: bool,
) -> None:
    cursor = await connection.execute(
        """
        SELECT status, started_at
        FROM sandbox_execution_claims
        WHERE tenant_id = %s AND idempotency_key = %s
        FOR UPDATE
        """,
        (event.tenant_id, state.request.idempotency_key),
    )
    row = await cursor.fetchone()
    if row is None:
        if (
            event.event_type == DomainEventType.SANDBOX_POLICY_VIOLATION
            and event.payload.get("error_code") == "sandbox_egress_denied"
        ):
            return
        raise PermanentStorageError("sandbox execution claim is missing")
    was_active = row[0] in {"intent_recorded", "running", "ambiguous"}
    await _update_claim(connection, state, event, "terminal")
    if was_active and enforce_quota:
        await connection.execute(
            """
            UPDATE sandbox_quota_projection
            SET active_runs = GREATEST(0, active_runs - 1), updated_at = %s
            WHERE tenant_id = %s AND usage_period = %s
            """,
            (event.occurred_at, event.tenant_id, row[1].date().isoformat()),
        )


async def _update_claim(
    connection: psycopg.AsyncConnection[Any],
    state: SandboxState,
    event: EventEnvelope,
    status: str,
) -> None:
    await connection.execute(
        """
        UPDATE sandbox_execution_claims
        SET status = %s, last_event_id = %s, updated_at = %s,
            lease_generation = %s
        WHERE tenant_id = %s AND idempotency_key = %s
        """,
        (
            status,
            event.event_id,
            event.occurred_at,
            event.payload["lease_generation"],
            event.tenant_id,
            state.request.idempotency_key,
        ),
    )


async def _upsert_cleanup(
    connection: psycopg.AsyncConnection[Any],
    state: SandboxState,
    event: EventEnvelope,
    status: str,
) -> None:
    reference = state.backend_reference or event.payload.get("backend_reference")
    if not isinstance(reference, str):
        raise PermanentStorageError("sandbox cleanup backend reference is missing")
    await connection.execute(
        """
        INSERT INTO sandbox_cleanup_projection (
            tenant_id, sandbox_id, backend_reference, status, attempt_count,
            next_attempt_at, last_error_code, lease_generation, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (tenant_id, sandbox_id) DO UPDATE SET
            status = EXCLUDED.status,
            attempt_count = EXCLUDED.attempt_count,
            next_attempt_at = EXCLUDED.next_attempt_at,
            last_error_code = EXCLUDED.last_error_code,
            lease_generation = EXCLUDED.lease_generation,
            updated_at = EXCLUDED.updated_at
        """,
        (
            event.tenant_id,
            state.request.sandbox_id,
            reference,
            status,
            max(1, state.cleanup_attempts),
            event.occurred_at,
            event.payload.get("error_code"),
            event.payload["lease_generation"],
            event.occurred_at,
        ),
    )


def _requires_fence(event: EventEnvelope) -> bool:
    return event.event_type.startswith("sandbox.") and event.event_type not in {
        DomainEventType.SANDBOX_REQUESTED,
        DomainEventType.SANDBOX_POLICY_EVALUATED,
        DomainEventType.SANDBOX_APPROVAL_BOUND,
    }


def _payload_int(event: EventEnvelope, key: str) -> int:
    value = event.payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise PermanentStorageError(f"sandbox event lacks integer {key}")
    return value


def _page_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("sandbox page limit must be between 1 and 100")


@asynccontextmanager
async def _tenant_transaction(
    connection: psycopg.AsyncConnection[Any],
    lock: asyncio.Lock,
    context: TenantContext,
) -> AsyncIterator[None]:
    async with lock, connection.transaction():
        await connection.execute(
            "SELECT set_config('aegis.tenant_id', %s, true)",
            (str(context.tenant_id),),
        )
        yield


__all__ = [
    "PostgresSandboxApprovalAuthority",
    "PostgresSandboxRepository",
]
