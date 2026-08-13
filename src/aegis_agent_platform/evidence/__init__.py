"""Evidence acquisition, ingestion, storage, and deterministic correlation."""

from aegis_agent_platform.evidence.correlation import CorrelationEngine
from aegis_agent_platform.evidence.ingestion import (
    EvidenceIngestor,
    InMemoryEvidenceStore,
    QuarantineReason,
    render_citation,
)
from aegis_agent_platform.evidence.ports import (
    CancellationSignal,
    ConnectorCapability,
    ConnectorError,
    ConnectorErrorClass,
    ConnectorPage,
    EvidenceConnector,
    EvidenceQuery,
    HttpRequest,
    HttpResponse,
    HttpTransport,
    RawEvidence,
)
from aegis_agent_platform.evidence.service import (
    EvidenceQueryService,
    EvidenceRequestResult,
    InMemoryEvidenceRepository,
)

__all__ = [
    "CancellationSignal",
    "ConnectorCapability",
    "ConnectorError",
    "ConnectorErrorClass",
    "ConnectorPage",
    "CorrelationEngine",
    "EvidenceConnector",
    "EvidenceIngestor",
    "EvidenceQuery",
    "EvidenceQueryService",
    "EvidenceRequestResult",
    "HttpRequest",
    "HttpResponse",
    "HttpTransport",
    "InMemoryEvidenceRepository",
    "InMemoryEvidenceStore",
    "QuarantineReason",
    "RawEvidence",
    "render_citation",
]
