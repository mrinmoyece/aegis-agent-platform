"""Deterministic Layer 14 protocol fixtures."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from aegis_agent_platform.domain import (
    JsonValue,
    ProtocolDataClassification,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolPolicySnapshot,
    ProtocolRequest,
    WorkLease,
    content_digest,
)
from aegis_agent_platform.identity import Principal, Role
from aegis_agent_platform.protocols import (
    FakeExternalProtocolAdapter,
    InMemoryProtocolLedger,
    InMemoryProtocolRegistry,
    ProtocolGateway,
    canonical_protocol_capabilities,
    canonical_protocol_peer,
    canonical_protocol_policy,
    peer_digest,
)
from aegis_agent_platform.tenancy import TenantContext
from security_helpers import TENANT_ID, binding, identity_record

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
OPERATION_ID = UUID("27f6e175-7b24-473c-a319-f6e17c60eaa1")
CORRELATION_ID = UUID("64b5de6a-d223-45db-b70d-df6f059f34ac")
LEASE_TOKEN = UUID("66ff6811-b23b-43a0-9038-93f747f777c8")


def protocol_principal(*roles: Role) -> Principal:
    selected = roles or (Role.INVESTIGATOR, Role.OPERATOR, Role.TENANT_ADMIN)
    return identity_record(
        tuple(binding(role, assigned_at=NOW - timedelta(hours=1)) for role in selected)
    ).to_principal()


def protocol_stack(
    family: ProtocolFamily,
    *,
    responses: tuple[ProtocolOperationStatus, ...] = (),
) -> tuple[
    ProtocolGateway,
    InMemoryProtocolRegistry,
    InMemoryProtocolLedger,
    FakeExternalProtocolAdapter,
    ProtocolPeer,
    ProtocolPolicySnapshot,
]:
    capabilities = canonical_protocol_capabilities()
    peer = canonical_protocol_peer(family, capabilities=capabilities)
    policy = canonical_protocol_policy((peer,))
    registry = InMemoryProtocolRegistry()
    registry.register(TenantContext(TENANT_ID), peer)
    ledger = InMemoryProtocolLedger()
    selected_responses = responses or (ProtocolOperationStatus.COMPLETED,)
    adapter = FakeExternalProtocolAdapter(
        family,
        capabilities,
        card_digest=peer.card_digest,
        schema_digest=peer.schema_digest,
        responses=selected_responses,
    )
    gateway = ProtocolGateway(
        registry=registry,
        ledger=ledger,
        adapters={family: adapter},
        capabilities={
            capability.capability_id: capability for capability in capabilities
        },
        event_id_factory=_event_ids(),
    )
    return gateway, registry, ledger, adapter, peer, policy


def protocol_request(
    family: ProtocolFamily,
    policy: ProtocolPolicySnapshot,
    peer: ProtocolPeer,
    *,
    operation_id: UUID = OPERATION_ID,
    capability_id: str = "aegis.evidence.retrieve",
    payload: dict[str, JsonValue] | None = None,
    idempotency_key: str = "protocol-request-001",
    purpose: str = "incident_investigation",
) -> ProtocolRequest:
    capabilities = {
        capability.capability_id: capability
        for capability in canonical_protocol_capabilities()
    }
    capability = capabilities[capability_id]
    body = payload or {"incident_id": "inc-checkout-001"}
    return ProtocolRequest(
        operation_id,
        family,
        "tenant-alpha",
        peer.peer_id,
        peer_digest(peer),
        capability_id,
        capability.digest,
        body,
        content_digest(body),
        CORRELATION_ID,
        idempotency_key,
        purpose,
        ProtocolDataClassification.INTERNAL,
        policy.digest,
        NOW,
        NOW + timedelta(seconds=10),
    )


def protocol_lease(
    operation_id: UUID = OPERATION_ID,
    *,
    generation: int = 1,
) -> WorkLease:
    return WorkLease(
        operation_id,
        "tenant-alpha",
        LEASE_TOKEN,
        generation,
        "protocol-worker-1",
        1,
        NOW - timedelta(seconds=1),
        NOW,
        NOW + timedelta(minutes=1),
    )


def _event_ids() -> Callable[[], UUID]:
    values = iter(UUID(int=value) for value in range(1, 1_000))
    return lambda: next(values)
