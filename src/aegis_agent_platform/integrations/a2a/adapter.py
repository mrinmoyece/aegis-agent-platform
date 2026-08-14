"""A2A 1.0 wire adapter; Agent Card and task shapes stay at this boundary."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_agent_platform.domain import (
    JsonValue,
    ProtocolArtifact,
    ProtocolCapability,
    ProtocolCitation,
    ProtocolDataClassification,
    ProtocolErrorClass,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolRequest,
    ProtocolTransport,
    ProtocolTrustTier,
    canonical_json_bytes,
    content_digest,
    normalize_untrusted_text,
    validate_identifier,
    validate_json,
)
from aegis_agent_platform.protocols.operations import (
    ExternalProtocolError,
    TransportResponse,
)
from aegis_agent_platform.protocols.security import (
    NetworkTargetPolicy,
    ProtocolSecurityError,
)

A2A_PROTOCOL_VERSION = "1.0"
A2A_SPEC_TAG = "v1.0.1"
MAX_A2A_CARD_BYTES = 262_144
MAX_A2A_ARTIFACTS = 64


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True, slots=True)
class A2aAgentCardSigner:
    """Ed25519 compact JWS signer for deterministic Agent Card fixtures."""

    key_id: str
    private_key: Ed25519PrivateKey  # gitleaks:allow

    def sign(self, card: Mapping[str, JsonValue]) -> str:
        if "signatures" in card:
            raise ValueError("Agent Card signatures are excluded from signing input")
        protected = _b64url(
            json.dumps(
                {"alg": "EdDSA", "kid": self.key_id, "typ": "agent-card+jws"},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        payload = _b64url(canonical_json_bytes(card))
        signing_input = f"{protected}.{payload}".encode()
        signature = _b64url(self.private_key.sign(signing_input))
        return f"{protected}.{payload}.{signature}"

    @staticmethod
    def verify(
        compact_jws: str,
        card: Mapping[str, JsonValue],
        public_key: Ed25519PublicKey,
    ) -> None:
        try:
            protected, payload, signature = compact_jws.split(".")
        except ValueError as error:
            raise ProtocolSecurityError("a2a_card_signature_invalid") from error
        if _decode_b64url(payload) != canonical_json_bytes(card):
            raise ProtocolSecurityError("a2a_card_payload_mismatch")
        try:
            public_key.verify(
                _decode_b64url(signature),
                f"{protected}.{payload}".encode(),
            )
        except Exception as error:
            raise ProtocolSecurityError("a2a_card_signature_invalid") from error


class A2aApplicationPort(Protocol):
    async def submit(
        self,
        request: ProtocolRequest,
        skill: ProtocolCapability,
    ) -> Mapping[str, JsonValue]: ...


class A2aServerAdapter:
    """External A2A facade constrained to evidence, status, artifacts, and proposals."""

    def __init__(
        self,
        *,
        service_url: str,
        capabilities: Sequence[ProtocolCapability],
        application: A2aApplicationPort,
        signer: A2aAgentCardSigner,
        ready: bool,
    ) -> None:
        self._service_url = normalize_untrusted_text(
            service_url,
            name="A2A service URL",
            maximum=2_048,
        )
        self._capabilities = tuple(capabilities)
        self._application = application
        self._signer = signer
        self._ready = ready

    def agent_card(self) -> Mapping[str, JsonValue]:
        skills: tuple[Mapping[str, JsonValue], ...] = tuple(
            {
                "id": capability.capability_id,
                "name": capability.title,
                "description": capability.description,
                "inputModes": capability.content_types,
                "outputModes": capability.content_types,
                "tags": (
                    "evidence-backed",
                    "proposal-only" if capability.proposal_only else "read-analysis",
                ),
                "x-aegis-capability-digest": capability.digest,
                "x-aegis-risk": int(capability.risk),
            }
            for capability in self._capabilities
        )
        unsigned: Mapping[str, JsonValue] = {
            "name": "Aegis External Incident Boundary",
            "description": (
                "Evidence-backed incident investigation and proposal exchange. "
                "No approval, direct tool execution, or internal DAG authority."
            ),
            "version": "layer14-v1",
            "protocolVersion": A2A_PROTOCOL_VERSION,
            "url": self._service_url,
            "preferredTransport": "JSONRPC",
            "supportedInterfaces": (
                {
                    "url": self._service_url,
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": A2A_PROTOCOL_VERSION,
                },
            ),
            "capabilities": {
                "streaming": True,
                "pushNotifications": False,
                "extendedAgentCard": True,
            },
            "securitySchemes": {
                "oidc_mtls": {
                    "type": "openIdConnect",
                    "openIdConnectUrl": "https://identity.invalid/.well-known/openid-configuration",
                    "description": "Deployment-supplied OIDC with mTLS-bound tokens.",
                }
            },
            "security": ({"oidc_mtls": ("a2a.task",)},),
            "defaultInputModes": ("application/json",),
            "defaultOutputModes": ("application/json",),
            "skills": skills,
            "x-aegis-readiness": "ready" if self._ready else "closed",
            "x-aegis-limitations": (
                "deterministic-local-interoperability",
                "production-pki-token-brokerage-required",
            ),
        }
        signature = self._signer.sign(unsigned)
        return {**unsigned, "signatures": ({"protected": signature},)}

    async def send_message(
        self,
        request: ProtocolRequest,
        skill_id: str,
    ) -> Mapping[str, JsonValue]:
        skill = next(
            (item for item in self._capabilities if item.capability_id == skill_id),
            None,
        )
        if skill is None or skill.digest != request.capability_digest:
            raise ProtocolSecurityError("a2a_skill_denied")
        if skill.risk.value >= 3 and not skill.proposal_only:
            raise ProtocolSecurityError("a2a_direct_mutation_denied")
        result = await self._application.submit(request, skill)
        validate_json(result, maximum_bytes=skill.maximum_output_bytes)
        return {
            "id": str(request.operation_id),
            "contextId": str(request.correlation_id),
            "status": {
                "state": "completed",
                "timestamp": request.requested_at.isoformat(),
            },
            "artifacts": (
                {
                    "artifactId": f"artifact-{request.operation_id}",
                    "name": "Aegis validated result",
                    "parts": ({"data": result},),
                    "lastChunk": True,
                    "metadata": {
                        "aegisResultDigest": content_digest(result),
                        "trust": "external-untrusted",
                    },
                },
            ),
        }


class A2aWireTransport(Protocol):
    async def get_agent_card(
        self,
        endpoint: str,
        headers: Mapping[str, str],
    ) -> Mapping[str, JsonValue]: ...

    async def send_message(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: Mapping[str, JsonValue],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, JsonValue]: ...

    async def get_task(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        task_id: str,
    ) -> Mapping[str, JsonValue] | None: ...

    async def cancel_task(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        task_id: str,
    ) -> Mapping[str, JsonValue] | None: ...


class A2aClientAdapter:
    """Trusted-agent gateway with digest-pinned card and bounded task lifecycle."""

    def __init__(
        self,
        *,
        transport: A2aWireTransport,
        network_policy: NetworkTargetPolicy,
        resolved_addresses: Mapping[str, tuple[str, ...]],
        capabilities: Mapping[str, ProtocolCapability],
        clock: Callable[[], datetime],
    ) -> None:
        self._transport = transport
        self._network_policy = network_policy
        self._resolved_addresses = MappingProxyType(dict(resolved_addresses))
        self._capabilities = MappingProxyType(dict(capabilities))
        self._clock = clock

    async def discover(
        self,
        peer: ProtocolPeer,
    ) -> tuple[tuple[ProtocolCapability, ...], str, str]:
        self._validate_peer(peer)
        card = await self._transport.get_agent_card(
            f"{peer.endpoint_origin}/.well-known/agent-card.json",
            self._headers(),
        )
        validate_json(card, maximum_bytes=MAX_A2A_CARD_BYTES)
        observed_digest = content_digest(card)
        if observed_digest != peer.card_digest:
            raise ProtocolSecurityError("a2a_card_digest_drift")
        capabilities = tuple(
            capability
            for capability_id, capability in self._capabilities.items()
            if capability_id in peer.allowed_capability_digests
        )
        return capabilities, observed_digest, peer.schema_digest

    async def send(
        self,
        peer: ProtocolPeer,
        capability: ProtocolCapability,
        request: ProtocolRequest,
    ) -> TransportResponse:
        self._validate_peer(peer)
        body: Mapping[str, JsonValue] = {
            "jsonrpc": "2.0",
            "id": str(request.operation_id),
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": request.idempotency_key,
                    "role": "user",
                    "parts": ({"data": request.payload},),
                    "metadata": {
                        "aegisTenantBinding": sha256(
                            request.tenant_id.encode()
                        ).hexdigest(),
                        "aegisRequestDigest": request.payload_digest,
                        "aegisCapabilityDigest": request.capability_digest,
                    },
                },
                "configuration": {
                    "acceptedOutputModes": capability.content_types,
                    "returnImmediately": True,
                },
            },
        }
        response = await self._transport.send_message(
            peer.endpoint_origin,
            self._headers(),
            body,
            timeout_seconds=max(
                1,
                int((request.deadline - request.requested_at).total_seconds()),
            ),
        )
        payload, task_id, artifacts, status = self._parse_task(
            response,
            classification=request.classification,
        )
        self._require_completed(status)
        return TransportResponse(
            f"a2a:{task_id}",
            payload,
            artifacts,
            status,
            self._clock(),
        )

    async def observe(
        self,
        peer: ProtocolPeer,
        request: ProtocolRequest,
    ) -> TransportResponse | None:
        self._validate_peer(peer)
        task = await self._transport.get_task(
            peer.endpoint_origin,
            self._headers(),
            str(request.operation_id),
        )
        if task is None:
            return None
        payload, task_id, artifacts, status = self._parse_task(
            task,
            classification=request.classification,
        )
        return TransportResponse(
            f"a2a-observed:{task_id}",
            payload,
            artifacts,
            status,
            self._clock(),
        )

    async def cancel(self, peer: ProtocolPeer, request: ProtocolRequest) -> bool:
        self._validate_peer(peer)
        task = await self._transport.cancel_task(
            peer.endpoint_origin,
            self._headers(),
            str(request.operation_id),
        )
        if task is None:
            return False
        status = task.get("status")
        return isinstance(status, Mapping) and status.get("state") == "canceled"

    def _validate_peer(self, peer: ProtocolPeer) -> None:
        if peer.family is not ProtocolFamily.A2A:
            raise ProtocolSecurityError("a2a_peer_family_mismatch")
        if not {
            ProtocolTransport.JSONRPC_HTTP,
            ProtocolTransport.HTTP_JSON,
            ProtocolTransport.GRPC,
        }.intersection(peer.transports):
            raise ProtocolSecurityError("a2a_transport_denied")
        addresses = self._resolved_addresses.get(peer.endpoint_origin)
        if addresses is None:
            raise ProtocolSecurityError("a2a_dns_not_pinned")
        self._network_policy.validate(
            peer.endpoint_origin,
            resolved_addresses=addresses,
        )
        if A2A_PROTOCOL_VERSION not in peer.protocol_versions:
            raise ProtocolSecurityError("a2a_version_not_pinned")

    @staticmethod
    def _headers() -> Mapping[str, str]:
        return {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "A2A-Version": A2A_PROTOCOL_VERSION,
        }

    @staticmethod
    def _parse_task(
        response: Mapping[str, JsonValue],
        *,
        classification: ProtocolDataClassification,
    ) -> tuple[
        Mapping[str, JsonValue],
        str,
        tuple[ProtocolArtifact, ...],
        ProtocolOperationStatus,
    ]:
        validate_json(response, maximum_bytes=1_048_576)
        result = response.get("result", response)
        if not isinstance(result, Mapping):
            raise ProtocolSecurityError("a2a_task_missing")
        task_id = result.get("id")
        status = result.get("status")
        if not isinstance(task_id, str) or not isinstance(status, Mapping):
            raise ProtocolSecurityError("a2a_task_shape_rejected")
        try:
            validate_identifier(task_id, "A2A task_id")
        except ValueError as error:
            raise ProtocolSecurityError("a2a_task_identifier_rejected") from error
        state = status.get("state")
        statuses = {
            "submitted": ProtocolOperationStatus.ACCEPTED,
            "working": ProtocolOperationStatus.RUNNING,
            "completed": ProtocolOperationStatus.COMPLETED,
            "failed": ProtocolOperationStatus.FAILED,
            "rejected": ProtocolOperationStatus.FAILED,
            "canceled": ProtocolOperationStatus.CANCELLED,
        }
        if not isinstance(state, str) or state not in statuses:
            raise ProtocolSecurityError("a2a_task_state_rejected")
        raw_artifacts = result.get("artifacts", ())
        if not isinstance(raw_artifacts, Sequence) or isinstance(raw_artifacts, str):
            raise ProtocolSecurityError("a2a_artifacts_shape_rejected")
        if len(raw_artifacts) > MAX_A2A_ARTIFACTS:
            raise ProtocolSecurityError("a2a_artifacts_exceed_bound")
        artifacts = tuple(
            A2aClientAdapter._parse_artifact(
                artifact,
                classification=classification,
            )
            for artifact in raw_artifacts
        )
        payload: Mapping[str, JsonValue] = {
            "status": str(state),
            "reference": f"a2a-task:{task_id}",
            "digest": content_digest(result),
            "redacted": True,
        }
        return payload, task_id, artifacts, statuses[state]

    @staticmethod
    def _parse_artifact(
        value: JsonValue,
        *,
        classification: ProtocolDataClassification,
    ) -> ProtocolArtifact:
        if not isinstance(value, Mapping):
            raise ProtocolSecurityError("a2a_artifact_shape_rejected")
        artifact_id = value.get("artifactId")
        parts = value.get("parts")
        content_type = value.get("contentType", "application/json")
        if not isinstance(artifact_id, str) or not isinstance(parts, Sequence):
            raise ProtocolSecurityError("a2a_artifact_shape_rejected")
        if isinstance(parts, (str, bytes, bytearray)) or not parts:
            raise ProtocolSecurityError("a2a_artifact_parts_rejected")
        if not isinstance(content_type, str) or content_type not in {
            "application/json",
            "text/plain",
        }:
            raise ProtocolSecurityError("a2a_artifact_mime_rejected")
        A2aClientAdapter._reject_external_artifact_urls(parts)
        try:
            validate_json(parts, maximum_bytes=1_048_576)
            encoded = canonical_json_bytes(parts)
        except (TypeError, ValueError) as error:
            raise ProtocolSecurityError("a2a_artifact_content_rejected") from error
        metadata = value.get("metadata", {})
        citations: tuple[ProtocolCitation, ...] = ()
        if isinstance(metadata, Mapping):
            raw_citations = metadata.get("citations", ())
            if not isinstance(raw_citations, Sequence) or isinstance(
                raw_citations,
                (str, bytes, bytearray),
            ):
                raise ProtocolSecurityError("a2a_citations_shape_rejected")
            try:
                citations = tuple(
                    A2aClientAdapter._parse_citation(citation)
                    for citation in raw_citations
                    if isinstance(citation, Mapping)
                )
            except (KeyError, ValueError) as error:
                raise ProtocolSecurityError("a2a_citation_rejected") from error
            if len(citations) != len(raw_citations):
                raise ProtocolSecurityError("a2a_citation_rejected")
        try:
            digest = content_digest(parts)
            return ProtocolArtifact(
                artifact_id,
                content_type,
                digest,
                f"aegis-artifact://a2a/{artifact_id}/{digest}",
                classification,
                ProtocolTrustTier.UNTRUSTED,
                citations,
                len(encoded),
                bool(value.get("lastChunk", True)),
            )
        except (TypeError, ValueError) as error:
            raise ProtocolSecurityError("a2a_artifact_content_rejected") from error

    @staticmethod
    def _parse_citation(value: Mapping[str, JsonValue]) -> ProtocolCitation:
        source_id = value.get("sourceId")
        source_version = value.get("sourceVersion")
        source_digest = value.get("sourceDigest")
        locator = value.get("locator")
        if not (
            isinstance(source_id, str)
            and isinstance(source_version, str)
            and isinstance(source_digest, str)
            and isinstance(locator, str)
        ):
            raise ValueError("A2A citation fields must be strings")
        return ProtocolCitation(
            source_id,
            source_version,
            source_digest,
            locator,
        )

    @staticmethod
    def _reject_external_artifact_urls(value: JsonValue) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if (
                    key.lower() in {"url", "uri", "href", "downloadurl"}
                    and isinstance(child, str)
                    and child.startswith(("http://", "https://"))
                ):
                    raise ProtocolSecurityError("a2a_artifact_url_rejected")
                A2aClientAdapter._reject_external_artifact_urls(child)
        elif isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for child in value:
                A2aClientAdapter._reject_external_artifact_urls(child)

    @staticmethod
    def _require_completed(status: ProtocolOperationStatus) -> None:
        if status is ProtocolOperationStatus.COMPLETED:
            return
        if status in {
            ProtocolOperationStatus.ACCEPTED,
            ProtocolOperationStatus.RUNNING,
        }:
            raise ExternalProtocolError(
                ProtocolErrorClass.AMBIGUOUS,
                "a2a_remote_task_in_progress",
                retryable=True,
                ambiguous=True,
            )
        raise ExternalProtocolError(
            ProtocolErrorClass.PERMANENT,
            f"a2a_remote_task_{status.value}",
            retryable=False,
        )


class OfficialA2aSdkBoundary:
    """Import marker proving official SDK types remain adapter-local."""

    @staticmethod
    def package_name() -> str:
        import a2a

        return str(getattr(a2a, "__package__", "a2a"))


__all__ = [
    "A2A_PROTOCOL_VERSION",
    "A2A_SPEC_TAG",
    "A2aAgentCardSigner",
    "A2aClientAdapter",
    "A2aServerAdapter",
]
