"""Governed MCP and A2A boundary services."""

from aegis_agent_platform.protocols.demo import (
    FakeExternalProtocolAdapter,
    canonical_protocol_capabilities,
    canonical_protocol_peer,
    canonical_protocol_policy,
)
from aegis_agent_platform.protocols.operations import (
    ExternalProtocolError,
    ExternalProtocolPort,
    ProtocolGateway,
    ProtocolPolicyDeniedError,
    TransportResponse,
)
from aegis_agent_platform.protocols.postgres import PostgresProtocolLedger
from aegis_agent_platform.protocols.registry import (
    CapabilityDriftError,
    InMemoryProtocolRegistry,
    ProtocolRegistry,
    TrustChange,
    peer_digest,
)
from aegis_agent_platform.protocols.repository import (
    InMemoryProtocolLedger,
    ProtocolLedger,
)
from aegis_agent_platform.protocols.security import (
    InMemoryReplayCache,
    NetworkTargetPolicy,
    ProtocolAuthAssertion,
    ProtocolAuthenticator,
    ProtocolSchemaValidator,
    ProtocolSecurityError,
)
from aegis_agent_platform.protocols.telemetry import (
    ProtocolBoundary,
    ProtocolMetrics,
    ProtocolTracer,
)

__all__ = [
    "CapabilityDriftError",
    "ExternalProtocolError",
    "ExternalProtocolPort",
    "FakeExternalProtocolAdapter",
    "InMemoryProtocolLedger",
    "InMemoryProtocolRegistry",
    "InMemoryReplayCache",
    "NetworkTargetPolicy",
    "PostgresProtocolLedger",
    "ProtocolAuthAssertion",
    "ProtocolAuthenticator",
    "ProtocolBoundary",
    "ProtocolGateway",
    "ProtocolLedger",
    "ProtocolMetrics",
    "ProtocolPolicyDeniedError",
    "ProtocolRegistry",
    "ProtocolSchemaValidator",
    "ProtocolSecurityError",
    "ProtocolTracer",
    "TransportResponse",
    "TrustChange",
    "canonical_protocol_capabilities",
    "canonical_protocol_peer",
    "canonical_protocol_policy",
    "peer_digest",
]
