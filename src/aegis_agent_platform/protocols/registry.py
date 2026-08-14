"""Tenant-scoped protocol peer registry and immutable trust history."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol

from aegis_agent_platform.domain import (
    ProtocolCapability,
    ProtocolPeer,
    ProtocolPeerStatus,
    content_digest,
)
from aegis_agent_platform.tenancy import TenantContext


class CapabilityDriftError(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class TrustChange:
    peer_id: str
    tenant_id: str
    previous_status: ProtocolPeerStatus
    next_status: ProtocolPeerStatus
    previous_revision: int
    next_revision: int
    actor_id: str
    rationale_code: str
    peer_digest: str
    recorded_at: datetime


class ProtocolRegistry(Protocol):
    def register(self, context: TenantContext, peer: ProtocolPeer) -> None: ...

    def get(self, context: TenantContext, peer_id: str) -> ProtocolPeer | None: ...

    def page(
        self,
        context: TenantContext,
        *,
        after_peer_id: str | None = None,
        limit: int = 100,
    ) -> tuple[tuple[ProtocolPeer, ...], str | None]: ...

    def record_capabilities(
        self,
        context: TenantContext,
        peer_id: str,
        capabilities: tuple[ProtocolCapability, ...],
        *,
        card_digest: str,
        schema_digest: str,
        at: datetime,
    ) -> ProtocolPeer: ...

    def change_trust(
        self,
        context: TenantContext,
        peer_id: str,
        *,
        next_status: ProtocolPeerStatus,
        actor_id: str,
        rationale_code: str,
        confirmation_peer_digest: str,
        expected_revision: int,
        at: datetime,
        emergency_disabled: bool | None = None,
    ) -> ProtocolPeer: ...

    @property
    def trust_history(self) -> tuple[TrustChange, ...]: ...


def peer_digest(peer: ProtocolPeer) -> str:
    return content_digest(
        {
            "peer_id": peer.peer_id,
            "tenant_id": peer.tenant_id,
            "family": peer.family.value,
            "owner": peer.owner,
            "environment": peer.environment,
            "status": peer.status.value,
            "trust_tier": peer.trust_tier.value,
            "transports": tuple(transport.value for transport in peer.transports),
            "protocol_versions": peer.protocol_versions,
            "auth_scheme": peer.auth_scheme.value,
            "endpoint_origin": peer.endpoint_origin,
            "server_identity": peer.server_identity,
            "allowed_capability_digests": peer.allowed_capability_digests,
            "allowed_classifications": tuple(
                sorted(item.value for item in peer.allowed_classifications)
            ),
            "risk_ceiling": int(peer.risk_ceiling),
            "card_digest": peer.card_digest,
            "schema_digest": peer.schema_digest,
            "certificate_digest": peer.certificate_digest,
            "signing_key_digest": peer.signing_key_digest,
            "egress_destinations": peer.egress_destinations,
            "revision": peer.revision,
            "emergency_disabled": peer.emergency_disabled,
        }
    )


class InMemoryProtocolRegistry:
    """Deterministic registry; PostgreSQL remains the production projection."""

    def __init__(self) -> None:
        self._peers: dict[tuple[str, str], ProtocolPeer] = {}
        self._history: list[TrustChange] = []

    @property
    def trust_history(self) -> tuple[TrustChange, ...]:
        return tuple(self._history)

    def register(self, context: TenantContext, peer: ProtocolPeer) -> None:
        tenant_id = str(context.tenant_id)
        if peer.tenant_id != tenant_id:
            raise PermissionError("cross_tenant_peer_registration")
        key = (tenant_id, peer.peer_id)
        if key in self._peers:
            raise ValueError("protocol peer already registered")
        self._peers[key] = peer

    def get(self, context: TenantContext, peer_id: str) -> ProtocolPeer | None:
        return self._peers.get((str(context.tenant_id), peer_id))

    def page(
        self,
        context: TenantContext,
        *,
        after_peer_id: str | None = None,
        limit: int = 100,
    ) -> tuple[tuple[ProtocolPeer, ...], str | None]:
        if not 1 <= limit <= 100:
            raise ValueError("protocol peer page limit is invalid")
        tenant_id = str(context.tenant_id)
        peers = tuple(
            peer
            for (candidate_tenant, _), peer in sorted(self._peers.items())
            if candidate_tenant == tenant_id
            and (after_peer_id is None or peer.peer_id > after_peer_id)
        )
        page = peers[:limit]
        cursor = page[-1].peer_id if len(peers) > limit else None
        return page, cursor

    def record_capabilities(
        self,
        context: TenantContext,
        peer_id: str,
        capabilities: tuple[ProtocolCapability, ...],
        *,
        card_digest: str,
        schema_digest: str,
        at: datetime,
    ) -> ProtocolPeer:
        peer = self._require(context, peer_id)
        observed = {
            capability.capability_id: capability.digest for capability in capabilities
        }
        if (
            observed != dict(peer.allowed_capability_digests)
            or card_digest != peer.card_digest
            or schema_digest != peer.schema_digest
        ):
            quarantined = peer.with_status(
                ProtocolPeerStatus.QUARANTINED,
                reviewed_at=at,
                emergency_disabled=True,
            )
            self._peers[(peer.tenant_id, peer.peer_id)] = quarantined
            raise CapabilityDriftError("protocol capability or identity drift")
        return peer

    def change_trust(
        self,
        context: TenantContext,
        peer_id: str,
        *,
        next_status: ProtocolPeerStatus,
        actor_id: str,
        rationale_code: str,
        confirmation_peer_digest: str,
        expected_revision: int,
        at: datetime,
        emergency_disabled: bool | None = None,
    ) -> ProtocolPeer:
        peer = self._require(context, peer_id)
        if peer.revision != expected_revision:
            raise RuntimeError("protocol peer revision conflict")
        digest = peer_digest(peer)
        if digest != confirmation_peer_digest:
            raise ValueError("protocol trust confirmation digest is stale")
        updated = peer.with_status(
            next_status,
            reviewed_at=at,
            emergency_disabled=emergency_disabled,
        )
        self._peers[(peer.tenant_id, peer.peer_id)] = updated
        self._history.append(
            TrustChange(
                peer.peer_id,
                peer.tenant_id,
                peer.status,
                updated.status,
                peer.revision,
                updated.revision,
                actor_id,
                rationale_code,
                digest,
                at,
            )
        )
        return updated

    def quarantine(
        self,
        context: TenantContext,
        peer_id: str,
        *,
        at: datetime,
    ) -> ProtocolPeer:
        peer = self._require(context, peer_id)
        updated = replace(
            peer,
            status=ProtocolPeerStatus.QUARANTINED,
            emergency_disabled=True,
            reviewed_at=at,
            revision=peer.revision + 1,
        )
        self._peers[(peer.tenant_id, peer.peer_id)] = updated
        return updated

    def _require(self, context: TenantContext, peer_id: str) -> ProtocolPeer:
        peer = self.get(context, peer_id)
        if peer is None:
            raise LookupError("protocol peer not found")
        return peer


__all__ = [
    "CapabilityDriftError",
    "InMemoryProtocolRegistry",
    "ProtocolRegistry",
    "TrustChange",
    "peer_digest",
]
