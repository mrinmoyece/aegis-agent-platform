"""Pure provider-neutral contracts for MCP and A2A boundaries."""

from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import IntEnum, StrEnum
from hashlib import sha256
from types import MappingProxyType
from uuid import UUID

from aegis_agent_platform.domain.events import EventEnvelope, JsonValue, thaw_json

MAX_PROTOCOL_IDENTIFIER = 128
MAX_PROTOCOL_TEXT = 4_096
MAX_PROTOCOL_SCHEMA_BYTES = 65_536
MAX_PROTOCOL_CONTENT_BYTES = 1_048_576
MAX_PROTOCOL_JSON_DEPTH = 16
MAX_PROTOCOL_COLLECTION_ITEMS = 256
_DANGEROUS_UNICODE = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


class ProtocolFamily(StrEnum):
    MCP = "mcp"
    A2A = "a2a"


class ProtocolTransport(StrEnum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"
    JSONRPC_HTTP = "jsonrpc_http"
    HTTP_JSON = "http_json"
    GRPC = "grpc"


class ProtocolAuthScheme(StrEnum):
    LOCAL_PROCESS = "local_process"
    OAUTH2_DPOP = "oauth2_dpop"
    OIDC_MTLS = "oidc_mtls"
    MTLS = "mtls"


class ProtocolTrustTier(StrEnum):
    LOCAL_DETERMINISTIC = "local_deterministic"
    INTERNAL = "internal"
    PARTNER = "partner"
    UNTRUSTED = "untrusted"


class ProtocolPeerStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CapabilityKind(StrEnum):
    RESOURCE = "resource"
    PROMPT_TEMPLATE = "prompt_template"
    TOOL = "tool"
    SKILL = "skill"


class ProtocolRisk(IntEnum):
    READ_ONLY = 0
    ANALYSIS = 1
    PROPOSAL = 2
    MUTATING = 3


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ProtocolOperationStatus(StrEnum):
    REQUESTED = "requested"
    STARTED = "started"
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


class ProtocolErrorClass(StrEnum):
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY = "policy"
    QUOTA = "quota"
    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    DRIFT = "drift"
    SECURITY = "security"
    AMBIGUOUS = "ambiguous"


def validate_identifier(value: str, name: str) -> None:
    if (
        not value
        or value != value.strip()
        or len(value) > MAX_PROTOCOL_IDENTIFIER
        or not value.replace("-", "").replace("_", "").replace(".", "").isalnum()
    ):
        raise ValueError(f"{name} must be a bounded normalized identifier")


def validate_digest(value: str, name: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def normalize_untrusted_text(
    value: str,
    *,
    name: str,
    maximum: int = MAX_PROTOCOL_TEXT,
) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized
        or normalized != normalized.strip()
        or len(normalized.encode("utf-8")) > maximum
        or any(character in _DANGEROUS_UNICODE for character in normalized)
        or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            and character not in {"\n", "\t"}
            for character in normalized
        )
    ):
        raise ValueError(f"{name} contains unsafe or unbounded text")
    return normalized


def validate_json(
    value: JsonValue,
    *,
    maximum_bytes: int = MAX_PROTOCOL_CONTENT_BYTES,
    maximum_depth: int = MAX_PROTOCOL_JSON_DEPTH,
) -> None:
    def walk(item: JsonValue, depth: int) -> None:
        if depth > maximum_depth:
            raise ValueError("protocol JSON exceeds maximum depth")
        if isinstance(item, Mapping):
            if len(item) > MAX_PROTOCOL_COLLECTION_ITEMS:
                raise ValueError("protocol JSON object exceeds item bound")
            for key, child in item.items():
                normalize_untrusted_text(
                    key,
                    name="protocol JSON key",
                    maximum=MAX_PROTOCOL_IDENTIFIER,
                )
                walk(child, depth + 1)
        elif isinstance(item, Sequence) and not isinstance(
            item, (str, bytes, bytearray)
        ):
            if len(item) > MAX_PROTOCOL_COLLECTION_ITEMS:
                raise ValueError("protocol JSON array exceeds item bound")
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            normalize_untrusted_text(item, name="protocol JSON text")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("protocol JSON numbers must be finite")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ValueError("protocol JSON contains an unsupported value")

    walk(value, 0)
    if len(canonical_json_bytes(value)) > maximum_bytes:
        raise ValueError("protocol JSON exceeds byte bound")


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Canonical bytes for the restricted protocol JSON profile.

    Protocol adapters may apply a wire-standard canonicalizer in addition to this
    core profile. Rejecting floats from trust decisions avoids cross-runtime number
    representation differences.
    """
    return json.dumps(
        thaw_json(value),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def content_digest(value: JsonValue) -> str:
    validate_json(value)
    return sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ProtocolPrincipal:
    subject: str
    issuer: str
    tenant_id: str
    audience: str
    scopes: frozenset[str]
    token_id_digest: str
    proof_thumbprint: str
    authenticated_at: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.subject, "subject"),
            (self.tenant_id, "tenant_id"),
            (self.audience, "audience"),
        ):
            validate_identifier(value, name)
        normalize_untrusted_text(self.issuer, name="issuer", maximum=512)
        validate_digest(self.token_id_digest, "token_id_digest")
        validate_digest(self.proof_thumbprint, "proof_thumbprint")
        if self.authenticated_at.tzinfo is None:
            raise ValueError("authenticated_at must be timezone-aware")
        if not self.scopes or len(self.scopes) > 64:
            raise ValueError("protocol scopes are outside the bound")
        for scope in self.scopes:
            validate_identifier(scope.replace(":", "."), "scope")


@dataclass(frozen=True, slots=True)
class ProtocolCapability:
    capability_id: str
    version: str
    kind: CapabilityKind
    title: str
    description: str
    input_schema: Mapping[str, JsonValue]
    output_schema: Mapping[str, JsonValue]
    permission: str
    purpose: str
    risk: ProtocolRisk
    idempotent: bool
    proposal_only: bool
    content_types: tuple[str, ...] = ("application/json",)
    maximum_input_bytes: int = 65_536
    maximum_output_bytes: int = 262_144

    def __post_init__(self) -> None:
        validate_identifier(self.capability_id, "capability_id")
        validate_identifier(self.version, "capability version")
        normalize_untrusted_text(self.title, name="capability title", maximum=256)
        normalize_untrusted_text(
            self.description,
            name="capability description",
            maximum=2_048,
        )
        validate_identifier(self.permission.replace(":", "."), "permission")
        validate_identifier(self.purpose, "purpose")
        if self.risk is ProtocolRisk.MUTATING and not self.proposal_only:
            raise ValueError("protocol capabilities cannot directly execute mutations")
        if not 1 <= self.maximum_input_bytes <= MAX_PROTOCOL_CONTENT_BYTES:
            raise ValueError("maximum_input_bytes is outside the bound")
        if not 1 <= self.maximum_output_bytes <= MAX_PROTOCOL_CONTENT_BYTES:
            raise ValueError("maximum_output_bytes is outside the bound")
        if not self.content_types or len(self.content_types) > 16:
            raise ValueError("content types are outside the bound")
        for content_type in self.content_types:
            normalize_untrusted_text(content_type, name="content type", maximum=128)
        validate_json(self.input_schema, maximum_bytes=MAX_PROTOCOL_SCHEMA_BYTES)
        validate_json(self.output_schema, maximum_bytes=MAX_PROTOCOL_SCHEMA_BYTES)
        object.__setattr__(
            self,
            "input_schema",
            MappingProxyType(dict(self.input_schema)),
        )
        object.__setattr__(
            self,
            "output_schema",
            MappingProxyType(dict(self.output_schema)),
        )

    @property
    def digest(self) -> str:
        return content_digest(
            {
                "capability_id": self.capability_id,
                "version": self.version,
                "kind": self.kind.value,
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
                "permission": self.permission,
                "purpose": self.purpose,
                "risk": int(self.risk),
                "idempotent": self.idempotent,
                "proposal_only": self.proposal_only,
                "content_types": self.content_types,
                "maximum_input_bytes": self.maximum_input_bytes,
                "maximum_output_bytes": self.maximum_output_bytes,
            }
        )


@dataclass(frozen=True, slots=True)
class ProtocolPeer:
    peer_id: str
    tenant_id: str
    family: ProtocolFamily
    owner: str
    environment: str
    status: ProtocolPeerStatus
    trust_tier: ProtocolTrustTier
    transports: tuple[ProtocolTransport, ...]
    protocol_versions: tuple[str, ...]
    auth_scheme: ProtocolAuthScheme
    endpoint_origin: str
    server_identity: str
    secret_reference: str
    allowed_capability_digests: Mapping[str, str]
    allowed_classifications: frozenset[DataClassification]
    risk_ceiling: ProtocolRisk
    card_digest: str
    schema_digest: str
    certificate_digest: str
    signing_key_digest: str
    egress_destinations: tuple[str, ...]
    registered_at: datetime
    reviewed_at: datetime
    expires_at: datetime
    revision: int = 1
    emergency_disabled: bool = False

    def __post_init__(self) -> None:
        for value, name in (
            (self.peer_id, "peer_id"),
            (self.tenant_id, "tenant_id"),
            (self.environment, "environment"),
            (self.server_identity, "server_identity"),
        ):
            validate_identifier(value, name)
        normalize_untrusted_text(self.owner, name="owner", maximum=256)
        normalize_untrusted_text(
            self.endpoint_origin,
            name="endpoint_origin",
            maximum=2_048,
        )
        if not self.secret_reference.startswith("secret-ref://"):
            raise ValueError("protocol credentials must use an opaque secret reference")
        if not self.transports or not self.protocol_versions:
            raise ValueError("peer requires transport and protocol versions")
        if len(self.transports) > 4 or len(self.protocol_versions) > 8:
            raise ValueError("peer negotiation configuration exceeds bounds")
        if not self.allowed_capability_digests:
            raise ValueError("peer requires an exact capability allowlist")
        for capability_id, digest in self.allowed_capability_digests.items():
            validate_identifier(capability_id, "allowed capability")
            validate_digest(digest, "allowed capability digest")
        for digest, name in (
            (self.card_digest, "card_digest"),
            (self.schema_digest, "schema_digest"),
            (self.certificate_digest, "certificate_digest"),
            (self.signing_key_digest, "signing_key_digest"),
        ):
            validate_digest(digest, name)
        if not self.allowed_classifications:
            raise ValueError("peer requires allowed data classifications")
        if not 1 <= len(self.egress_destinations) <= 16:
            raise ValueError("peer egress destinations are outside the bound")
        for destination in self.egress_destinations:
            normalize_untrusted_text(
                destination,
                name="egress destination",
                maximum=512,
            )
        if any(
            instant.tzinfo is None
            for instant in (self.registered_at, self.reviewed_at, self.expires_at)
        ):
            raise ValueError("peer timestamps must be timezone-aware")
        if not self.registered_at <= self.reviewed_at < self.expires_at:
            raise ValueError("peer review and expiry ordering is invalid")
        if self.revision < 1:
            raise ValueError("peer revision must be positive")
        object.__setattr__(
            self,
            "allowed_capability_digests",
            MappingProxyType(dict(self.allowed_capability_digests)),
        )

    def available(self, at: datetime) -> bool:
        if at.tzinfo is None:
            raise ValueError("availability time must be timezone-aware")
        return (
            self.status is ProtocolPeerStatus.ACTIVE
            and not self.emergency_disabled
            and at < self.expires_at
        )

    def with_status(
        self,
        status: ProtocolPeerStatus,
        *,
        reviewed_at: datetime,
        emergency_disabled: bool | None = None,
    ) -> ProtocolPeer:
        return replace(
            self,
            status=status,
            reviewed_at=reviewed_at,
            revision=self.revision + 1,
            emergency_disabled=(
                self.emergency_disabled
                if emergency_disabled is None
                else emergency_disabled
            ),
        )


@dataclass(frozen=True, slots=True)
class ProtocolPolicySnapshot:
    policy_id: str
    tenant_id: str
    version: str
    allowed_peer_ids: frozenset[str]
    maximum_risk: ProtocolRisk
    maximum_request_bytes: int
    maximum_response_bytes: int
    timeout_seconds: int
    maximum_attempts: int
    maximum_concurrent: int
    maximum_daily_operations: int
    require_bound_token: bool
    recorded_at: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.policy_id, "policy_id"),
            (self.tenant_id, "tenant_id"),
            (self.version, "policy version"),
        ):
            validate_identifier(value, name)
        if not self.allowed_peer_ids:
            raise ValueError("protocol policy requires allowed peers")
        for peer_id in self.allowed_peer_ids:
            validate_identifier(peer_id, "allowed peer")
        if not 1 <= self.maximum_request_bytes <= MAX_PROTOCOL_CONTENT_BYTES:
            raise ValueError("policy request byte limit is invalid")
        if not 1 <= self.maximum_response_bytes <= MAX_PROTOCOL_CONTENT_BYTES:
            raise ValueError("policy response byte limit is invalid")
        if not 1 <= self.timeout_seconds <= 300:
            raise ValueError("protocol timeout is outside the bound")
        if not 1 <= self.maximum_attempts <= 5:
            raise ValueError("protocol attempts are outside the bound")
        if not 1 <= self.maximum_concurrent <= 100:
            raise ValueError("protocol concurrency is outside the bound")
        if not 1 <= self.maximum_daily_operations <= 100_000:
            raise ValueError("protocol daily quota is outside the bound")
        if self.recorded_at.tzinfo is None:
            raise ValueError("policy recorded_at must be timezone-aware")

    @property
    def digest(self) -> str:
        return content_digest(
            {
                "policy_id": self.policy_id,
                "tenant_id": self.tenant_id,
                "version": self.version,
                "allowed_peer_ids": tuple(sorted(self.allowed_peer_ids)),
                "maximum_risk": int(self.maximum_risk),
                "maximum_request_bytes": self.maximum_request_bytes,
                "maximum_response_bytes": self.maximum_response_bytes,
                "timeout_seconds": self.timeout_seconds,
                "maximum_attempts": self.maximum_attempts,
                "maximum_concurrent": self.maximum_concurrent,
                "maximum_daily_operations": self.maximum_daily_operations,
                "require_bound_token": self.require_bound_token,
            }
        )


@dataclass(frozen=True, slots=True)
class ProtocolRequest:
    operation_id: UUID
    family: ProtocolFamily
    tenant_id: str
    peer_id: str
    peer_digest: str
    capability_id: str
    capability_digest: str
    payload: Mapping[str, JsonValue]
    payload_digest: str
    correlation_id: UUID
    idempotency_key: str
    purpose: str
    classification: DataClassification
    policy_digest: str
    requested_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.peer_id, "peer_id"),
            (self.capability_id, "capability_id"),
            (self.idempotency_key, "idempotency_key"),
            (self.purpose, "purpose"),
        ):
            validate_identifier(value, name)
        for digest, name in (
            (self.capability_digest, "capability_digest"),
            (self.peer_digest, "peer_digest"),
            (self.payload_digest, "payload_digest"),
            (self.policy_digest, "policy_digest"),
        ):
            validate_digest(digest, name)
        validate_json(self.payload)
        if content_digest(self.payload) != self.payload_digest:
            raise ValueError("payload digest does not match canonical content")
        if self.requested_at.tzinfo is None or self.deadline.tzinfo is None:
            raise ValueError("protocol request timestamps must be timezone-aware")
        if self.deadline <= self.requested_at:
            raise ValueError("protocol request deadline must follow requested_at")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


@dataclass(frozen=True, slots=True)
class ProtocolCitation:
    source_id: str
    source_version: str
    source_digest: str
    locator: str

    def __post_init__(self) -> None:
        validate_identifier(self.source_id, "source_id")
        validate_identifier(self.source_version, "source_version")
        validate_digest(self.source_digest, "source_digest")
        normalize_untrusted_text(self.locator, name="citation locator", maximum=1_024)


@dataclass(frozen=True, slots=True)
class ProtocolArtifact:
    artifact_id: str
    content_type: str
    content_digest: str
    content_reference: str
    classification: DataClassification
    trust_label: ProtocolTrustTier
    citations: tuple[ProtocolCitation, ...]
    byte_count: int
    complete: bool = True

    def __post_init__(self) -> None:
        validate_identifier(self.artifact_id, "artifact_id")
        validate_digest(self.content_digest, "artifact content_digest")
        normalize_untrusted_text(
            self.content_type,
            name="artifact content_type",
            maximum=128,
        )
        if not self.content_reference.startswith("aegis-artifact://"):
            raise ValueError("artifacts require an internal content reference")
        if not 0 <= self.byte_count <= MAX_PROTOCOL_CONTENT_BYTES:
            raise ValueError("artifact byte count is outside the bound")
        if len(self.citations) > 64:
            raise ValueError("artifact citations exceed the bound")


@dataclass(frozen=True, slots=True)
class ProtocolResult:
    operation_id: UUID
    status: ProtocolOperationStatus
    result_digest: str
    provider_reference: str
    artifacts: tuple[ProtocolArtifact, ...]
    completed_at: datetime
    retryable: bool = False
    error_class: ProtocolErrorClass | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        validate_digest(self.result_digest, "result_digest")
        normalize_untrusted_text(
            self.provider_reference,
            name="provider_reference",
            maximum=512,
        )
        if self.completed_at.tzinfo is None:
            raise ValueError("result completed_at must be timezone-aware")
        if len(self.artifacts) > 64:
            raise ValueError("protocol result has too many artifacts")
        if (self.error_class is None) != (self.error_code is None):
            raise ValueError("protocol error class and code must be supplied together")
        if self.error_code is not None:
            validate_identifier(self.error_code, "error_code")


@dataclass(frozen=True, slots=True)
class ProtocolOperationState:
    operation_id: UUID
    family: ProtocolFamily
    tenant_id: str
    peer_id: str
    capability_id: str
    request_digest: str
    policy_digest: str
    status: ProtocolOperationStatus
    version: int
    result_digest: str | None = None
    provider_reference: str | None = None
    error_code: str | None = None


def replay_protocol_operation(
    events: Sequence[EventEnvelope],
) -> ProtocolOperationState:
    if not events:
        raise ValueError("protocol operation replay requires events")
    first = events[0]
    payload = first.payload
    state = ProtocolOperationState(
        UUID(first.aggregate_id),
        ProtocolFamily(str(payload["family"])),
        first.tenant_id,
        str(payload["peer_id"]),
        str(payload["capability_id"]),
        str(payload["request_digest"]),
        str(payload["policy_digest"]),
        ProtocolOperationStatus.REQUESTED,
        1,
    )
    transitions = {
        "mcp.invocation_started.v1": ProtocolOperationStatus.STARTED,
        "mcp.invocation_completed.v1": ProtocolOperationStatus.COMPLETED,
        "mcp.invocation_failed.v1": ProtocolOperationStatus.FAILED,
        "mcp.invocation_ambiguous.v1": ProtocolOperationStatus.AMBIGUOUS,
        "mcp.invocation_cancel_requested.v1": ProtocolOperationStatus.CANCEL_REQUESTED,
        "mcp.invocation_cancelled.v1": ProtocolOperationStatus.CANCELLED,
        "mcp.reconciled.v1": ProtocolOperationStatus.COMPLETED,
        "a2a.task_accepted.v1": ProtocolOperationStatus.ACCEPTED,
        "a2a.task_progress_recorded.v1": ProtocolOperationStatus.RUNNING,
        "a2a.artifact_recorded.v1": ProtocolOperationStatus.RUNNING,
        "a2a.task_completed.v1": ProtocolOperationStatus.COMPLETED,
        "a2a.task_failed.v1": ProtocolOperationStatus.FAILED,
        "a2a.task_ambiguous.v1": ProtocolOperationStatus.AMBIGUOUS,
        "a2a.task_cancel_requested.v1": ProtocolOperationStatus.CANCEL_REQUESTED,
        "a2a.task_cancelled.v1": ProtocolOperationStatus.CANCELLED,
        "a2a.reconciled.v1": ProtocolOperationStatus.COMPLETED,
        "protocol.peer_quarantined.v1": ProtocolOperationStatus.QUARANTINED,
    }
    for index, event in enumerate(events[1:], start=2):
        if event.tenant_id != state.tenant_id or event.aggregate_id != str(
            state.operation_id
        ):
            raise ValueError("protocol replay stream identity changed")
        status = transitions.get(event.event_type)
        if status is None:
            continue
        result_digest_value = event.payload.get("result_digest")
        provider_reference_value = event.payload.get("provider_reference")
        error_code_value = event.payload.get("error_code")
        state = replace(
            state,
            status=status,
            version=index,
            result_digest=(
                str(result_digest_value)
                if isinstance(result_digest_value, str)
                else state.result_digest
            ),
            provider_reference=(
                str(provider_reference_value)
                if isinstance(provider_reference_value, str)
                else state.provider_reference
            ),
            error_code=(
                str(error_code_value)
                if isinstance(error_code_value, str)
                else state.error_code
            ),
        )
    return state


@dataclass(frozen=True, slots=True)
class CapabilityPage:
    capabilities: tuple[ProtocolCapability, ...]
    next_cursor: str | None

    def __post_init__(self) -> None:
        if len(self.capabilities) > 100:
            raise ValueError("capability page exceeds the bound")
        if self.next_cursor is not None:
            validate_identifier(self.next_cursor, "next_cursor")


@dataclass(frozen=True, slots=True)
class ProtocolAuditRecord:
    audit_id: UUID
    tenant_id: str
    peer_id: str
    operation_id: UUID | None
    action: str
    outcome: str
    principal_digest: str
    request_digest: str | None
    policy_digest: str
    recorded_at: datetime
    metadata: Mapping[str, JsonValue] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.peer_id, "peer_id"),
            (self.action, "action"),
            (self.outcome, "outcome"),
        ):
            validate_identifier(value, name)
        for digest, name in (
            (self.principal_digest, "principal_digest"),
            (self.policy_digest, "policy_digest"),
        ):
            validate_digest(digest, name)
        if self.request_digest is not None:
            validate_digest(self.request_digest, "request_digest")
        if self.recorded_at.tzinfo is None:
            raise ValueError("audit recorded_at must be timezone-aware")
        validate_json(self.metadata, maximum_bytes=16_384)
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
