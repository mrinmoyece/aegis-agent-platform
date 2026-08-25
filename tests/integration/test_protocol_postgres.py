"""Live PostgreSQL evidence for Layer 14 protocol truth, RLS, and rebuild."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from aegis_agent_platform.domain import (
    ProtocolDataClassification,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolRequest,
    content_digest,
)
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import (
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    TenantId,
    UserId,
)
from aegis_agent_platform.protocols import (
    FakeExternalProtocolAdapter,
    InMemoryProtocolRegistry,
    PostgresProtocolLedger,
    ProtocolGateway,
    canonical_protocol_capabilities,
    canonical_protocol_peer,
    canonical_protocol_policy,
    peer_digest,
)
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
OTHER_CONTEXT = TenantContext(TenantId("tenant-b"))


def test_protocol_operation_truth_rls_idempotency_and_rebuild() -> None:
    async def scenario() -> None:
        assert DATABASE_URL is not None
        connection = await psycopg.AsyncConnection.connect(
            DATABASE_URL,
            autocommit=True,
        )
        await connection.execute("SET ROLE aegis_app")
        now = datetime.now(UTC)
        operation_id = uuid4()
        capabilities = canonical_protocol_capabilities()
        peer = replace(
            canonical_protocol_peer(ProtocolFamily.A2A, capabilities=capabilities),
            tenant_id="tenant-a",
        )
        policy = canonical_protocol_policy((peer,))
        payload = {"incident_id": "postgres-protocol-incident"}
        request = ProtocolRequest(
            operation_id=operation_id,
            family=ProtocolFamily.A2A,
            tenant_id="tenant-a",
            peer_id=peer.peer_id,
            peer_digest=peer_digest(peer),
            capability_id=capabilities[0].capability_id,
            capability_digest=capabilities[0].digest,
            payload=payload,
            payload_digest=content_digest(payload),
            correlation_id=uuid4(),
            idempotency_key=f"protocol-postgres-{operation_id}",
            purpose=capabilities[0].purpose,
            classification=ProtocolDataClassification.INTERNAL,
            policy_digest=policy.digest,
            requested_at=now,
            deadline=now + timedelta(seconds=30),
        )
        principal = _principal(now)
        events = PostgresEventStore(
            connection,
            writer_fence_resolver=integration_writer_fences("local-test", 1),
        )
        ledger = PostgresProtocolLedger(connection, events)
        adapter = FakeExternalProtocolAdapter(
            ProtocolFamily.A2A,
            capabilities,
            card_digest=peer.card_digest,
            schema_digest=peer.schema_digest,
        )
        gateway = ProtocolGateway(
            registry=_registry(peer),
            ledger=ledger,
            adapters={ProtocolFamily.A2A: adapter},
            capabilities={
                capability.capability_id: capability for capability in capabilities
            },
        )
        try:
            result = await gateway.request(principal, CONTEXT, request, policy)
            duplicate = await gateway.request(principal, CONTEXT, request, policy)
            assert result.status is ProtocolOperationStatus.COMPLETED
            assert duplicate.status is ProtocolOperationStatus.COMPLETED
            assert len(adapter.calls) == 1
            assert await ledger.load(OTHER_CONTEXT, operation_id) == ()

            page, cursor = await ledger.page(CONTEXT, limit=1)
            assert len(page) == 1
            assert page[0].operation_id == operation_id
            assert cursor is None

            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    ("tenant-a",),
                )
                await connection.execute(
                    """
                    UPDATE protocol_operation_projection
                    SET status = 'failed'
                    WHERE tenant_id = %s AND operation_id = %s
                    """,
                    ("tenant-a", operation_id),
                )
            rebuilt = await ledger.rebuild_projection(CONTEXT, operation_id)
            projected = await ledger.by_idempotency_key(
                CONTEXT,
                request.idempotency_key,
            )
            assert rebuilt.status is ProtocolOperationStatus.COMPLETED
            assert projected is not None
            assert projected.status is ProtocolOperationStatus.COMPLETED
        finally:
            await connection.close()

    asyncio.run(scenario())


def _principal(at: datetime) -> Principal:
    tenant_id = TenantId("tenant-a")
    user_id = UserId("protocol-postgres-user")
    bindings = tuple(
        RoleBinding(
            tenant_id,
            role,
            user_id,
            at - timedelta(minutes=1),
        )
        for role in (Role.INVESTIGATOR, Role.TENANT_ADMIN)
    )
    return Principal(
        "protocol-postgres-subject",
        "https://issuer.example",
        tenant_id,
        PrincipalKind.USER,
        bindings,
        user_id=user_id,
    )


def _registry(peer: ProtocolPeer) -> InMemoryProtocolRegistry:
    registry = InMemoryProtocolRegistry()
    registry.register(CONTEXT, peer)
    return registry
