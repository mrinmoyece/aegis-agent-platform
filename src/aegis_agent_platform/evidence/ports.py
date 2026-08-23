"""Provider-neutral connector ports and bounded transport contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain import (
    EnvironmentIdentity,
    EvidenceKind,
    EvidenceReference,
    EvidenceSeverity,
    EvidenceSourceKind,
    JsonValue,
    PaginationCursor,
    PartialResult,
    QueryWindow,
    ResourceIdentity,
    ServiceIdentity,
    TrustStatus,
)


class ConnectorErrorClass(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INVALID_QUERY = "invalid_query"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    MALFORMED_RESPONSE = "malformed_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    UNAVAILABLE = "unavailable"
    CAPABILITY = "capability"


class ConnectorError(RuntimeError):
    """Secret-safe connector failure; vendor exceptions remain in adapters."""

    def __init__(
        self,
        error_class: ConnectorErrorClass,
        code: str,
        *,
        retryable: bool,
        retry_after_seconds: float | None = None,
        partial: bool = False,
    ) -> None:
        super().__init__(code)
        if not code:
            raise ValueError("connector error code is required")
        if retry_after_seconds is not None and retry_after_seconds < 0:
            raise ValueError("retry-after cannot be negative")
        self.error_class = error_class
        self.code = code
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds
        self.partial = partial


class CancellationSignal(Protocol):
    @property
    def cancelled(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class EvidenceQuery:
    query_id: UUID
    tenant_id: str
    source: EvidenceSourceKind
    environment: EnvironmentIdentity
    window: QueryWindow
    kinds: Sequence[EvidenceKind]
    selectors: Mapping[str, str]
    limit: int
    idempotency_key: str
    cursor: PaginationCursor | None = None

    def __post_init__(self) -> None:
        if (
            not self.tenant_id
            or not self.idempotency_key
            or self.idempotency_key != self.idempotency_key.strip()
            or len(self.idempotency_key.encode()) > 200
        ):
            raise ValueError("query tenant and idempotency key are required")
        kinds = tuple(sorted(set(self.kinds), key=lambda item: item.value))
        if not kinds or not 1 <= self.limit <= 1000:
            raise ValueError("query requires kinds and a limit between 1 and 1000")
        if any(not key or not value for key, value in self.selectors.items()):
            raise ValueError("query selectors cannot be empty")
        object.__setattr__(self, "kinds", kinds)
        object.__setattr__(
            self,
            "selectors",
            MappingProxyType(dict(sorted(self.selectors.items()))),
        )


@dataclass(frozen=True, slots=True)
class RawEvidence:
    source_record_id: str
    kind: EvidenceKind
    observed_at: datetime
    summary: str
    fields: Mapping[str, JsonValue]
    provenance_uri: str
    service: ServiceIdentity | None = None
    resource: ResourceIdentity | None = None
    severity: EvidenceSeverity = EvidenceSeverity.UNKNOWN
    source_confidence: float | None = None
    references: Sequence[EvidenceReference] = ()
    trust: TrustStatus = TrustStatus.UNVERIFIED
    knowledge: bool = False

    def __post_init__(self) -> None:
        if not self.source_record_id or not self.summary:
            raise ValueError("source record id and summary are required")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        object.__setattr__(self, "fields", dict(self.fields))
        object.__setattr__(self, "references", tuple(self.references))


@dataclass(frozen=True, slots=True)
class ConnectorPage:
    records: Sequence[RawEvidence]
    next_cursor: PaginationCursor | None
    result: PartialResult

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(self.records))


@dataclass(frozen=True, slots=True)
class ConnectorCapability:
    source: EvidenceSourceKind
    kinds: Sequence[EvidenceKind]
    api_version: str
    healthy: bool
    detail_code: str

    def __post_init__(self) -> None:
        if not self.api_version or not self.detail_code:
            raise ValueError("capability version and detail code are required")
        object.__setattr__(
            self,
            "kinds",
            tuple(sorted(set(self.kinds), key=lambda item: item.value)),
        )


class EvidenceConnector(Protocol):
    source: EvidenceSourceKind

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> ConnectorPage: ...

    async def capability(self) -> ConnectorCapability: ...


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int
    body: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.method not in {"GET", "POST"}:
            raise ValueError("HTTP method is not allowed")
        if not self.url.startswith("https://"):
            raise ValueError("connector transport requires HTTPS")
        if not 0 < self.timeout_seconds <= 120:
            raise ValueError("HTTP timeout must be between 0 and 120 seconds")
        if not 1 <= self.max_response_bytes <= 50_000_000:
            raise ValueError("response cap must be between 1 and 50000000 bytes")
        object.__setattr__(self, "headers", dict(self.headers))


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        if not 100 <= self.status <= 599:
            raise ValueError("invalid HTTP response status")
        object.__setattr__(
            self,
            "headers",
            {key.lower(): value for key, value in self.headers.items()},
        )


class HttpTransport(Protocol):
    async def send(self, request: HttpRequest) -> HttpResponse: ...


__all__ = [
    "CancellationSignal",
    "ConnectorCapability",
    "ConnectorError",
    "ConnectorErrorClass",
    "ConnectorPage",
    "EvidenceConnector",
    "EvidenceQuery",
    "HttpRequest",
    "HttpResponse",
    "HttpTransport",
    "RawEvidence",
]
