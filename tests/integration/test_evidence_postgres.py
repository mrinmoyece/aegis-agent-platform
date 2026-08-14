"""Live PostgreSQL evidence for fenced ingestion, idempotency, and artifacts."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import psycopg
import pytest

from aegis_agent_platform.domain import (
    EnvironmentIdentity,
    EvidenceKind,
    EvidenceSeverity,
    EvidenceSourceKind,
    PaginationCursor,
    PartialResult,
    QueryWindow,
    ServiceIdentity,
    TrustStatus,
    WorkLease,
)
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.evidence import (
    ConnectorCapability,
    ConnectorPage,
    EvidenceIngestor,
    EvidenceQuery,
    EvidenceQueryService,
    InMemoryEvidenceStore,
    RawEvidence,
)
from aegis_agent_platform.evidence.postgres import (
    PostgresEvidenceBundleStore,
    PostgresEvidenceRepository,
    PostgresEvidenceStore,
)
from aegis_agent_platform.evidence.service import EvidenceIdempotencyConflictError
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.policy import QuotaLimits, RiskLevel, TenantPolicy
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
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
CONTEXT = TenantContext(TenantId("tenant-a"))


class StaticEvidenceConnector:
    source = EvidenceSourceKind.DYNATRACE

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: object = None,
    ) -> ConnectorPage:
        del cancellation
        record = RawEvidence(
            "problem-1",
            EvidenceKind.PROBLEM,
            query.window.end - timedelta(seconds=10),
            "checkout failures",
            {"state": "open"},
            "https://tenant.example/problems/problem-1",
            service=ServiceIdentity("checkout"),
            severity=EvidenceSeverity.ERROR,
            trust=TrustStatus.VERIFIED,
        )
        return ConnectorPage(
            (record, record),
            PaginationCursor("page-2"),
            PartialResult(True, False, ("upstream_pagination",)),
        )

    async def capability(self) -> ConnectorCapability:
        return ConnectorCapability(
            self.source,
            (EvidenceKind.PROBLEM,),
            "fixture-v1",
            True,
            "ok",
        )


def _policy() -> TenantPolicy:
    return TenantPolicy(
        tenant_id=TenantId("tenant-a"),
        version="1",
        allowed_models=frozenset(),
        allowed_tools=frozenset(),
        allowed_connectors=frozenset({"dynatrace"}),
        allowed_environments=frozenset({"production"}),
        max_risk=RiskLevel.LOW,
        approval_from_risk=RiskLevel.CRITICAL,
        tools_requiring_approval=frozenset(),
        approver_roles=frozenset({Role.TENANT_ADMIN}),
        quotas=QuotaLimits(0, Decimal(0), 0, Decimal(0), 10),
    )


def test_fenced_evidence_commit_and_durable_bundle_round_trip() -> None:
    async def scenario() -> tuple[str, str]:
        assert DATABASE_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await connection.execute("SET ROLE aegis_app")
        now = datetime.now(UTC)
        query = EvidenceQuery(
            uuid4(),
            "tenant-a",
            EvidenceSourceKind.DYNATRACE,
            EnvironmentIdentity("production"),
            QueryWindow(now - timedelta(minutes=5), now),
            (EvidenceKind.PROBLEM,),
            {"service": "checkout"},
            10,
            f"evidence-integration-{uuid4()}",
        )
        events = PostgresEventStore(
            connection,
            writer_fence_resolver=integration_writer_fences("local-test", 1),
        )
        work = PostgresWorkRepository(connection, events)
        repository = PostgresEvidenceRepository(connection, events, work)
        service = EvidenceQueryService(
            connectors={"dynatrace": StaticEvidenceConnector()},
            repository=repository,
            ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
            clock=lambda: now,
        )
        token = uuid4()
        lease = WorkLease(
            query.query_id,
            query.tenant_id,
            token,
            1,
            "evidence-worker",
            1,
            now,
            now,
            now + timedelta(minutes=1),
        )
        try:
            created = await service.request(
                CONTEXT,
                query,
                _policy(),
                actor_id="integration",
            )
            duplicate = await service.request(
                CONTEXT,
                EvidenceQuery(
                    uuid4(),
                    query.tenant_id,
                    query.source,
                    query.environment,
                    query.window,
                    query.kinds,
                    query.selectors,
                    query.limit,
                    query.idempotency_key,
                ),
                _policy(),
                actor_id="integration",
            )
            assert created.created
            assert not duplicate.created
            assert duplicate.query_id == query.query_id
            with pytest.raises(EvidenceIdempotencyConflictError):
                await service.request(
                    CONTEXT,
                    EvidenceQuery(
                        uuid4(),
                        query.tenant_id,
                        query.source,
                        query.environment,
                        query.window,
                        query.kinds,
                        query.selectors,
                        query.limit + 1,
                        query.idempotency_key,
                    ),
                    _policy(),
                    actor_id="integration",
                )
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
                        query.query_id,
                        token,
                        lease.owner,
                        now,
                        now,
                        lease.expires_at,
                    ),
                )
            result = await service.execute(CONTEXT, query, lease)
            bundle = await service.correlate(
                CONTEXT,
                query,
                lease,
                result.records,
                bundle_id=f"bundle-{query.query_id}",
            )
            replay = tuple(
                [
                    item
                    async for item in events.read_stream(
                        CONTEXT,
                        str(query.query_id),
                        after_version=0,
                        limit=100,
                    )
                ]
            )
            fenced = replay[2:]
            assert fenced
            assert all(item.payload["lease_token"] == str(token) for item in fenced)
            assert any(item.event_type == "evidence.ingested.v1" for item in replay)
            assert any(item.event_type == "evidence.deduplicated.v1" for item in replay)
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-a",),
                )
                await connection.execute(
                    """
                    UPDATE outbox_messages
                    SET status = 'published', published_at = clock_timestamp()
                    WHERE tenant_id = %s
                      AND event_id = (
                          SELECT request_event_id
                          FROM work_items
                          WHERE tenant_id = %s AND work_id = %s
                      )
                    """,
                    ("tenant-a", "tenant-a", query.query_id),
                )
            return str(result.records[0].evidence_id), bundle.bundle_id
        finally:
            await connection.close()

    evidence_id, bundle_id = asyncio.run(scenario())
    assert DATABASE_URL is not None
    connection = psycopg.connect(DATABASE_URL, autocommit=True)
    connection.execute("SET ROLE aegis_app")
    try:
        store = PostgresEvidenceStore(connection)
        records = store.list(CONTEXT)
        page = store.page(CONTEXT, limit=1)
        bundle = PostgresEvidenceBundleStore(connection).get(CONTEXT, bundle_id)
        assert any(str(item.evidence_id) == evidence_id for item in records)
        assert tuple(str(item.evidence_id) for item in page.records) == (evidence_id,)
        assert page.next_cursor is None
        assert bundle is not None
        assert bundle.bundle_id == bundle_id
        assert bundle.evidence[0].provenance.source_record_id == "problem-1"
    finally:
        connection.close()
