"""Deterministic fake peers and curated Layer 14 capabilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from aegis_agent_platform.domain import (
    CapabilityKind,
    JsonValue,
    ProtocolArtifact,
    ProtocolAuthScheme,
    ProtocolCapability,
    ProtocolDataClassification,
    ProtocolErrorClass,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolPeerStatus,
    ProtocolPolicySnapshot,
    ProtocolRequest,
    ProtocolRisk,
    ProtocolTransport,
    ProtocolTrustTier,
)
from aegis_agent_platform.protocols.operations import (
    ExternalProtocolError,
    TransportResponse,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)

_OBJECT_SCHEMA: Mapping[str, JsonValue] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
}


def _schema(
    properties: Mapping[str, JsonValue],
    required: Sequence[str],
) -> Mapping[str, JsonValue]:
    return {
        **_OBJECT_SCHEMA,
        "properties": properties,
        "required": tuple(required),
    }


def canonical_protocol_capabilities() -> tuple[ProtocolCapability, ...]:
    """Curated read/analysis/proposal-only surface; no direct remediation."""
    identifier = {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    output = _schema(
        {
            "status": identifier,
            "reference": {"type": "string", "maxLength": 512},
            "digest": digest,
            "redacted": {"type": "boolean"},
        },
        ("status", "reference", "digest", "redacted"),
    )
    return (
        ProtocolCapability(
            "aegis.evidence.retrieve",
            "v1",
            CapabilityKind.RESOURCE,
            "Retrieve redacted evidence",
            "Returns bounded evidence references with provenance and citations.",
            _schema(
                {"incident_id": identifier, "cursor": identifier},
                ("incident_id",),
            ),
            output,
            "evidence:read",
            "incident_investigation",
            ProtocolRisk.READ_ONLY,
            True,
            False,
        ),
        ProtocolCapability(
            "aegis.investigation.submit",
            "v1",
            CapabilityKind.TOOL,
            "Submit safe investigation",
            "Records a bounded investigation request for local application review.",
            _schema(
                {
                    "incident_id": identifier,
                    "question": {"type": "string", "maxLength": 2048},
                },
                ("incident_id", "question"),
            ),
            output,
            "protocol:invoke",
            "incident_investigation",
            ProtocolRisk.ANALYSIS,
            False,
            False,
        ),
        ProtocolCapability(
            "aegis.sandbox.analyze",
            "v1",
            CapabilityKind.TOOL,
            "Request bounded sandbox analysis",
            "Requests a policy-approved no-network analysis; never accepts commands.",
            _schema(
                {
                    "artifact_digest": digest,
                    "analysis_profile": {
                        "type": "string",
                        "enum": ["metadata-only", "static-safe"],
                    },
                },
                ("artifact_digest", "analysis_profile"),
            ),
            output,
            "sandbox:execute",
            "incident_investigation",
            ProtocolRisk.ANALYSIS,
            True,
            False,
        ),
        ProtocolCapability(
            "aegis.remediation.propose",
            "v1",
            CapabilityKind.SKILL,
            "Submit remediation proposal",
            "Creates an exact-scope Layer 8 proposal; it cannot approve or execute.",
            _schema(
                {
                    "incident_id": identifier,
                    "proposal_digest": digest,
                    "target_fingerprint": digest,
                },
                ("incident_id", "proposal_digest", "target_fingerprint"),
            ),
            output,
            "remediation:propose",
            "remediation_proposal",
            ProtocolRisk.MUTATING,
            True,
            True,
        ),
    )


def canonical_protocol_peer(
    family: ProtocolFamily,
    *,
    capabilities: tuple[ProtocolCapability, ...] | None = None,
    status: ProtocolPeerStatus = ProtocolPeerStatus.ACTIVE,
) -> ProtocolPeer:
    selected = capabilities or canonical_protocol_capabilities()
    marker = f"aegis-{family.value}-deterministic-v1"
    return ProtocolPeer(
        f"peer-{family.value}-deterministic",
        "tenant-alpha",
        family,
        "Aegis deterministic fixtures",
        "local-test",
        status,
        ProtocolTrustTier.LOCAL_DETERMINISTIC,
        (
            (ProtocolTransport.STREAMABLE_HTTP,)
            if family is ProtocolFamily.MCP
            else (ProtocolTransport.JSONRPC_HTTP,)
        ),
        ("2026-07-28",) if family is ProtocolFamily.MCP else ("1.0",),
        ProtocolAuthScheme.MTLS,
        f"https://{family.value}.fixtures.invalid",
        f"aegis-{family.value}-fixture",
        f"secret-ref://local-only/{family.value}",
        {capability.capability_id: capability.digest for capability in selected},
        frozenset(
            {
                ProtocolDataClassification.PUBLIC,
                ProtocolDataClassification.INTERNAL,
                ProtocolDataClassification.CONFIDENTIAL,
            }
        ),
        ProtocolRisk.MUTATING,
        sha256(f"{marker}-card".encode()).hexdigest(),
        sha256(f"{marker}-schema".encode()).hexdigest(),
        sha256(f"{marker}-cert".encode()).hexdigest(),
        sha256(f"{marker}-key".encode()).hexdigest(),
        (f"{family.value}.fixtures.invalid",),
        NOW - timedelta(days=1),
        NOW,
        NOW + timedelta(days=30),
    )


def canonical_protocol_policy(
    peers: Sequence[ProtocolPeer],
) -> ProtocolPolicySnapshot:
    if not peers:
        raise ValueError("protocol policy fixtures require at least one peer")
    tenant_id = peers[0].tenant_id
    if any(peer.tenant_id != tenant_id for peer in peers):
        raise ValueError("protocol policy fixtures cannot span tenants")
    return ProtocolPolicySnapshot(
        "protocol-policy-default",
        tenant_id,
        "v1",
        frozenset(peer.peer_id for peer in peers),
        ProtocolRisk.MUTATING,
        65_536,
        262_144,
        10,
        2,
        4,
        1_000,
        True,
        NOW,
    )


class FakeExternalProtocolAdapter:
    """No-network peer supporting drift, ambiguity, cancellation, and reconciliation."""

    def __init__(
        self,
        family: ProtocolFamily,
        capabilities: tuple[ProtocolCapability, ...],
        *,
        card_digest: str,
        schema_digest: str,
        artifacts: Sequence[ProtocolArtifact] = (),
        responses: Sequence[ProtocolOperationStatus] = (
            ProtocolOperationStatus.COMPLETED,
        ),
    ) -> None:
        self.family = family
        self.capabilities = capabilities
        self.card_digest = card_digest
        self.schema_digest = schema_digest
        self.artifacts = tuple(artifacts)
        self.responses = tuple(responses)
        self.calls: list[str] = []
        self._attempt = 0
        self._observed: dict[str, TransportResponse] = {}

    async def discover(
        self,
        peer: ProtocolPeer,
    ) -> tuple[tuple[ProtocolCapability, ...], str, str]:
        self._assert_peer(peer)
        self.calls.append("discover")
        return self.capabilities, self.card_digest, self.schema_digest

    async def send(
        self,
        peer: ProtocolPeer,
        capability: ProtocolCapability,
        request: ProtocolRequest,
    ) -> TransportResponse:
        self._assert_peer(peer)
        if capability.capability_id not in peer.allowed_capability_digests:
            raise ExternalProtocolError(
                error_class=ProtocolErrorClass.AUTHORIZATION,
                code="fake_capability_denied",
                retryable=False,
            )
        self.calls.append(f"send:{request.idempotency_key}")
        outcome = self.responses[min(self._attempt, len(self.responses) - 1)]
        self._attempt += 1
        payload: Mapping[str, JsonValue] = {
            "status": (
                "proposal_recorded" if capability.proposal_only else "completed"
            ),
            "reference": f"aegis-{self.family.value}://{request.operation_id}",
            "digest": request.payload_digest,
            "redacted": True,
        }
        response = TransportResponse(
            f"fake-{self.family.value}-{self._attempt}",
            payload,
            self.artifacts,
            ProtocolOperationStatus.COMPLETED,
            request.requested_at + timedelta(seconds=1),
        )
        if outcome is ProtocolOperationStatus.AMBIGUOUS:
            self._observed[request.idempotency_key] = response
            raise ExternalProtocolError(
                ProtocolErrorClass.AMBIGUOUS,
                "fake_delivery_ambiguous",
                retryable=True,
                ambiguous=True,
            )
        if outcome is ProtocolOperationStatus.FAILED:
            raise ExternalProtocolError(
                ProtocolErrorClass.TRANSIENT,
                "fake_transient_failure",
                retryable=True,
            )
        self._observed[request.idempotency_key] = response
        return response

    async def observe(
        self,
        peer: ProtocolPeer,
        request: ProtocolRequest,
    ) -> TransportResponse | None:
        self._assert_peer(peer)
        self.calls.append(f"observe:{request.idempotency_key}")
        return self._observed.get(request.idempotency_key)

    async def cancel(self, peer: ProtocolPeer, request: ProtocolRequest) -> bool:
        self._assert_peer(peer)
        self.calls.append(f"cancel:{request.idempotency_key}")
        return request.idempotency_key in self._observed

    def _assert_peer(self, peer: ProtocolPeer) -> None:
        if peer.family is not self.family:
            raise PermissionError("fake protocol family mismatch")


__all__ = [
    "NOW",
    "FakeExternalProtocolAdapter",
    "canonical_protocol_capabilities",
    "canonical_protocol_peer",
    "canonical_protocol_policy",
]
