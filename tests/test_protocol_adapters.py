"""MCP and A2A adapter compatibility and security tests."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_agent_platform.domain import (
    JsonValue,
    ProtocolCapability,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeerStatus,
    ProtocolRequest,
    ProtocolTransport,
    content_digest,
)
from aegis_agent_platform.integrations.a2a import (
    A2A_PROTOCOL_VERSION,
    A2aAgentCardSigner,
    A2aClientAdapter,
    A2aServerAdapter,
)
from aegis_agent_platform.integrations.a2a.adapter import OfficialA2aSdkBoundary
from aegis_agent_platform.integrations.mcp import (
    MCP_CURRENT_VERSION,
    McpClientAdapter,
    McpServerAdapter,
    McpStreamableHttpRequest,
    RegisteredStdioCommand,
    StdioCommandRegistry,
)
from aegis_agent_platform.integrations.mcp.adapter import OfficialMcpSdkBoundary
from aegis_agent_platform.protocols import (
    ExternalProtocolError,
    NetworkTargetPolicy,
    ProtocolSecurityError,
)
from aegis_agent_platform.protocols.demo import (
    NOW,
    canonical_protocol_capabilities,
    canonical_protocol_peer,
    canonical_protocol_policy,
)
from protocol_helpers import protocol_request


class FakeApplication:
    async def invoke(
        self,
        request: ProtocolRequest,
        capability: ProtocolCapability,
    ) -> dict[str, JsonValue]:
        return {
            "status": "proposal_recorded" if capability.proposal_only else "completed",
            "reference": f"aegis://{request.operation_id}",
            "digest": request.payload_digest,
            "redacted": True,
        }

    async def submit(
        self,
        request: ProtocolRequest,
        capability: ProtocolCapability,
    ) -> dict[str, JsonValue]:
        return await self.invoke(request, capability)


class FakeMcpTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, str]]] = []
        self.call_response: Mapping[str, JsonValue] = {
            "result": {
                "status": "completed",
                "reference": "external-result",
                "digest": "1" * 64,
                "redacted": True,
            }
        }
        self.observed: Mapping[str, JsonValue] | None = {
            "status": "completed",
            "reference": "observed",
            "digest": "2" * 64,
            "redacted": True,
        }

    async def discover(
        self,
        endpoint: str,
        headers: Mapping[str, str],
    ) -> Mapping[str, JsonValue]:
        self.calls.append((endpoint, headers))
        return {"protocolVersion": MCP_CURRENT_VERSION, "tools": ()}

    async def call(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: Mapping[str, JsonValue],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, JsonValue]:
        self.calls.append((endpoint, headers))
        assert body["jsonrpc"] == "2.0"
        assert timeout_seconds == 10
        return self.call_response

    async def observe(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        operation_id: str,
    ) -> Mapping[str, JsonValue] | None:
        self.calls.append((endpoint, headers))
        return self.observed

    async def cancel(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        operation_id: str,
    ) -> bool:
        self.calls.append((endpoint, headers))
        return bool(operation_id)


class FakeA2aTransport:
    def __init__(
        self,
        card: Mapping[str, JsonValue],
        task: Mapping[str, JsonValue],
    ) -> None:
        self.card = card
        self.task = task
        self.cancelled = True
        self.return_task = True
        self.calls: list[tuple[str, Mapping[str, str]]] = []

    async def get_agent_card(
        self,
        endpoint: str,
        headers: Mapping[str, str],
    ) -> Mapping[str, JsonValue]:
        self.calls.append((endpoint, headers))
        return self.card

    async def send_message(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: Mapping[str, JsonValue],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, JsonValue]:
        self.calls.append((endpoint, headers))
        assert body["jsonrpc"] == "2.0"
        assert timeout_seconds == 10
        return self.task

    async def get_task(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        task_id: str,
    ) -> Mapping[str, JsonValue] | None:
        self.calls.append((endpoint, headers))
        return self.task if task_id and self.return_task else None

    async def cancel_task(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        task_id: str,
    ) -> Mapping[str, JsonValue] | None:
        self.calls.append((endpoint, headers))
        if not self.cancelled:
            return None
        return {"id": task_id, "status": {"state": "canceled"}}


def test_mcp_streamable_http_requires_origin_auth_headers_and_current_version() -> None:
    request = McpStreamableHttpRequest(
        "POST",
        "https://operator.example",
        "application/json",
        frozenset({"application/json", "text/event-stream"}),
        MCP_CURRENT_VERSION,
        "tools/call",
        "aegis.investigation.submit",
        True,
        1024,
    )

    request.validate(frozenset({"https://operator.example"}))
    with pytest.raises(ProtocolSecurityError, match="origin_denied"):
        replace(request, origin="https://attacker.invalid").validate(
            frozenset({"https://operator.example"})
        )
    with pytest.raises(ProtocolSecurityError, match="authentication"):
        replace(request, authorization_present=False).validate(
            frozenset({"https://operator.example"})
        )


def test_mcp_streamable_http_rejects_invalid_wire_fields() -> None:
    request = McpStreamableHttpRequest(
        "POST",
        "https://operator.example",
        "application/json",
        frozenset({"application/json", "text/event-stream"}),
        MCP_CURRENT_VERSION,
        "tools/call",
        None,
        True,
        1024,
    )

    invalid_requests = (
        (replace(request, method="GET"), "method_denied"),
        (replace(request, content_type="text/plain"), "content_type_denied"),
        (
            replace(request, accept=frozenset({"application/json"})),
            "accept_denied",
        ),
        (replace(request, protocol_version="2024-01-01"), "version_denied"),
        (replace(request, mcp_method=""), "method_header_required"),
        (replace(request, body_bytes=0), "body_size_denied"),
    )
    for invalid, error in invalid_requests:
        with pytest.raises(ProtocolSecurityError, match=error):
            invalid.validate(frozenset({"https://operator.example"}))


def test_mcp_version_negotiation_reports_supported_versions_without_downgrade() -> None:
    server = McpServerAdapter(
        capabilities=canonical_protocol_capabilities(),
        application=FakeApplication(),
        server_name="aegis-test",
        allowed_origins=frozenset({"https://operator.example"}),
    )

    current = server.discover(MCP_CURRENT_VERSION)
    unsupported = server.discover("2024-01-01")

    current_result = current["result"]
    unsupported_error = unsupported["error"]
    assert isinstance(current_result, Mapping)
    assert isinstance(unsupported_error, Mapping)
    unsupported_data = unsupported_error["data"]
    assert isinstance(unsupported_data, Mapping)
    supported = unsupported_data["supported"]
    assert isinstance(supported, Sequence)
    assert current_result["protocolVersion"] == MCP_CURRENT_VERSION
    assert unsupported_error["code"] == -32022
    assert MCP_CURRENT_VERSION in supported


def test_mcp_pagination_is_opaque_bounded_and_complete() -> None:
    server = McpServerAdapter(
        capabilities=canonical_protocol_capabilities(),
        application=FakeApplication(),
        server_name="aegis-test",
        allowed_origins=frozenset({"https://operator.example"}),
    )

    first = server.list_capabilities(cursor=None, page_size=2)
    second = server.list_capabilities(cursor=first.next_cursor, page_size=2)

    assert len(first.capabilities) == len(second.capabilities) == 2
    assert second.next_cursor is None
    with pytest.raises(ValueError, match="page size"):
        server.list_capabilities(cursor=None, page_size=101)


def test_mcp_stdio_uses_fixed_registry_and_rejects_model_supplied_command() -> None:
    registry = StdioCommandRegistry(
        (
            RegisteredStdioCommand(
                "local-fixture",
                "/usr/bin/false",
                ("--safe-fixture",),
                "/var/empty",
                frozenset(),
            ),
        )
    )

    assert registry.resolve("local-fixture").arguments == ("--safe-fixture",)
    with pytest.raises(ProtocolSecurityError, match="not_registered"):
        registry.resolve("rm-rf-model-output")


def test_mcp_stdio_registry_rejects_unbounded_or_relative_configuration() -> None:
    valid = RegisteredStdioCommand(
        "fixture",
        "/usr/bin/false",
        (),
        "/var/empty",
        frozenset(),
    )
    with pytest.raises(ValueError, match="duplicate"):
        StdioCommandRegistry((valid, valid))
    with pytest.raises(ValueError, match="absolute registered"):
        replace(valid, executable="sh")
    with pytest.raises(ValueError, match="arguments"):
        replace(valid, arguments=("x" * 513,))
    with pytest.raises(ValueError, match="working directory"):
        replace(valid, working_directory=".")
    with pytest.raises(ValueError, match="environment"):
        replace(valid, environment_keys=frozenset(f"K{index}" for index in range(33)))


def test_mcp_destructive_request_is_proposal_only() -> None:
    capabilities = canonical_protocol_capabilities()
    server = McpServerAdapter(
        capabilities=capabilities,
        application=FakeApplication(),
        server_name="aegis-test",
        allowed_origins=frozenset({"https://operator.example"}),
    )
    peer = canonical_protocol_peer(ProtocolFamily.MCP)
    policy = canonical_protocol_policy((peer,))
    request = protocol_request(
        ProtocolFamily.MCP,
        policy,
        peer,
        capability_id="aegis.remediation.propose",
        payload={
            "incident_id": "inc-1",
            "proposal_digest": "1" * 64,
            "target_fingerprint": "2" * 64,
        },
        purpose="remediation_proposal",
    )

    result = asyncio.run(server.invoke(request, request.capability_id))

    assert result["status"] == "proposal_recorded"
    assert "approved" not in str(result)
    assert "executed" not in str(result)


def test_mcp_client_negotiates_calls_observes_and_cancels_approved_peer() -> None:
    peer = canonical_protocol_peer(ProtocolFamily.MCP)
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    request = protocol_request(ProtocolFamily.MCP, policy, peer)
    transport = FakeMcpTransport()
    client = McpClientAdapter(
        transport=transport,
        network_policy=NetworkTargetPolicy(frozenset({"mcp.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={
            capability.capability_id: capability for capability in capabilities
        },
        clock=lambda: NOW,
    )

    discovered, card_digest, schema_digest = asyncio.run(client.discover(peer))
    response = asyncio.run(client.send(peer, capabilities[0], request))
    observed = asyncio.run(client.observe(peer, request))
    cancelled = asyncio.run(client.cancel(peer, request))

    assert discovered == capabilities
    assert card_digest == peer.card_digest
    assert schema_digest != peer.schema_digest
    assert response.remote_status is ProtocolOperationStatus.COMPLETED
    assert observed is not None
    assert observed.provider_reference.startswith("mcp-observed:")
    assert cancelled is True
    assert all("Authorization" not in headers for _, headers in transport.calls)


def test_mcp_client_rejects_unpinned_peer_and_missing_result() -> None:
    peer = canonical_protocol_peer(ProtocolFamily.MCP)
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    request = protocol_request(ProtocolFamily.MCP, policy, peer)
    transport = FakeMcpTransport()
    client = McpClientAdapter(
        transport=transport,
        network_policy=NetworkTargetPolicy(frozenset({"mcp.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={
            capability.capability_id: capability for capability in capabilities
        },
        clock=lambda: NOW,
    )

    with pytest.raises(ProtocolSecurityError, match="family_mismatch"):
        asyncio.run(client.discover(canonical_protocol_peer(ProtocolFamily.A2A)))

    transport.call_response = {"error": {"code": -32603, "message": "failed"}}
    with pytest.raises(ProtocolSecurityError, match="result_missing"):
        asyncio.run(client.send(peer, capabilities[0], request))
    transport.observed = None
    assert asyncio.run(client.observe(peer, request)) is None

    invalid_peers = (
        (
            replace(peer, transports=(ProtocolTransport.JSONRPC_HTTP,)),
            "network_transport_denied",
        ),
        (replace(peer, protocol_versions=("2025-11-25",)), "version_not_pinned"),
    )
    for invalid, error in invalid_peers:
        with pytest.raises(ProtocolSecurityError, match=error):
            asyncio.run(client.discover(invalid))

    unpinned = McpClientAdapter(
        transport=transport,
        network_policy=NetworkTargetPolicy(frozenset({"mcp.fixtures.invalid"})),
        resolved_addresses={},
        capabilities={item.capability_id: item for item in capabilities},
        clock=lambda: NOW,
    )
    with pytest.raises(ProtocolSecurityError, match="dns_not_pinned"):
        asyncio.run(unpinned.discover(peer))


def test_a2a_agent_card_is_signed_honest_and_has_no_internal_peer_authority() -> None:
    private_key = Ed25519PrivateKey.generate()
    signer = A2aAgentCardSigner("fixture-key", private_key)
    server = A2aServerAdapter(
        service_url="https://a2a.example",
        capabilities=canonical_protocol_capabilities(),
        application=FakeApplication(),
        signer=signer,
        ready=False,
    )

    card = server.agent_card()
    signatures = card["signatures"]
    assert isinstance(signatures, Sequence)
    signature_record = signatures[0]
    assert isinstance(signature_record, Mapping)
    signature = signature_record["protected"]
    assert isinstance(signature, str)
    unsigned = {key: value for key, value in card.items() if key != "signatures"}
    A2aAgentCardSigner.verify(signature, unsigned, private_key.public_key())

    assert card["protocolVersion"] == A2A_PROTOCOL_VERSION
    assert card["x-aegis-readiness"] == "closed"
    skills = card["skills"]
    assert isinstance(skills, Sequence)
    assert all(
        isinstance(skill, Mapping)
        and isinstance(skill["x-aegis-risk"], int)
        and skill["x-aegis-risk"] <= 3
        for skill in skills
    )
    assert "coordinator" not in str(card).lower()
    assert all(
        isinstance(skill, Mapping)
        and "approval" not in str(skill["id"])
        and "execute" not in str(skill["id"])
        for skill in skills
    )


def test_a2a_agent_card_signature_tampering_fails_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    signer = A2aAgentCardSigner("fixture-key", private_key)
    card = {"name": "Aegis", "protocolVersion": A2A_PROTOCOL_VERSION}
    signature = signer.sign(card)

    with pytest.raises(ProtocolSecurityError, match="payload_mismatch"):
        A2aAgentCardSigner.verify(
            signature,
            {**card, "name": "Attacker"},
            private_key.public_key(),
        )
    with pytest.raises(ProtocolSecurityError, match="signature_invalid"):
        A2aAgentCardSigner.verify("invalid", card, private_key.public_key())
    with pytest.raises(ValueError, match="excluded"):
        signer.sign({**card, "signatures": ()})
    protected, payload, signature_value = signature.split(".")
    raw_signature = bytearray(
        base64.urlsafe_b64decode(signature_value + "=" * (-len(signature_value) % 4))
    )
    raw_signature[0] ^= 1
    corrupted_signature = (
        base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii")
    )
    corrupted = f"{protected}.{payload}.{corrupted_signature}"
    with pytest.raises(ProtocolSecurityError, match="signature_invalid"):
        A2aAgentCardSigner.verify(corrupted, card, private_key.public_key())


def test_a2a_remediation_skill_returns_artifact_not_local_approval() -> None:
    private_key = Ed25519PrivateKey.generate()
    peer = canonical_protocol_peer(ProtocolFamily.A2A)
    policy = canonical_protocol_policy((peer,))
    server = A2aServerAdapter(
        service_url="https://a2a.example",
        capabilities=canonical_protocol_capabilities(),
        application=FakeApplication(),
        signer=A2aAgentCardSigner("fixture-key", private_key),
        ready=False,
    )
    request = protocol_request(
        ProtocolFamily.A2A,
        policy,
        peer,
        capability_id="aegis.remediation.propose",
        payload={
            "incident_id": "inc-1",
            "proposal_digest": "1" * 64,
            "target_fingerprint": "2" * 64,
        },
        purpose="remediation_proposal",
    )

    task = asyncio.run(server.send_message(request, request.capability_id))

    status = task["status"]
    artifacts = task["artifacts"]
    assert isinstance(status, Mapping)
    assert isinstance(artifacts, Sequence)
    artifact = artifacts[0]
    assert isinstance(artifact, Mapping)
    assert status["state"] == "completed"
    assert artifact["lastChunk"] is True
    assert "proposal_recorded" in str(task)
    assert "approval_granted" not in str(task)


def test_a2a_client_discovers_calls_observes_and_cancels_pinned_peer() -> None:
    original_peer = canonical_protocol_peer(ProtocolFamily.A2A)
    _jws_header = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"alg": "EdDSA", "kid": original_peer.signing_key_digest},
                separators=(",", ":"),
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    card: Mapping[str, JsonValue] = {
        "name": "fixture-agent",
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "skills": (),
        "signatures": [{"protected": _jws_header, "signature": "dGVzdA"}],
    }
    task: Mapping[str, JsonValue] = {
        "result": {
            "id": "external-task-1",
            "status": {"state": "completed"},
            "artifacts": (
                {
                    "artifactId": "evidence-1",
                    "contentType": "application/json",
                    "parts": ({"data": {"finding": "bounded"}},),
                    "metadata": {
                        "citations": (
                            {
                                "sourceId": "source-1",
                                "sourceVersion": "v1",
                                "sourceDigest": "4" * 64,
                                "locator": "event:1",
                            },
                        )
                    },
                    "lastChunk": True,
                },
            ),
        }
    }
    peer = replace(original_peer, card_digest=content_digest(card))
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    transport = FakeA2aTransport(card, task)
    client = A2aClientAdapter(
        transport=transport,
        network_policy=NetworkTargetPolicy(frozenset({"a2a.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={
            capability.capability_id: capability for capability in capabilities
        },
        clock=lambda: NOW,
    )

    discovered, card_digest, schema_digest = asyncio.run(client.discover(peer))
    response = asyncio.run(client.send(peer, capabilities[0], request))
    observed = asyncio.run(client.observe(peer, request))
    cancelled = asyncio.run(client.cancel(peer, request))

    assert discovered == capabilities
    assert card_digest == peer.card_digest
    assert schema_digest == peer.schema_digest
    assert response.payload["status"] == "completed"
    assert response.artifacts[0].content_reference.startswith("aegis-artifact://")
    assert response.artifacts[0].citations[0].source_id == "source-1"
    assert observed is not None
    assert observed.provider_reference == "a2a-observed:external-task-1"
    assert cancelled is True
    assert all("Authorization" not in headers for _, headers in transport.calls)


@pytest.mark.parametrize(
    ("task", "error"),
    [
        ({"result": "bad"}, "task_missing"),
        ({"result": {"id": 1, "status": {}}}, "task_shape_rejected"),
        (
            {"result": {"id": "task-1", "status": {"state": "auth-required"}}},
            "task_state_rejected",
        ),
        (
            {
                "result": {
                    "id": "task-1",
                    "status": {"state": "completed"},
                    "artifacts": "bad",
                }
            },
            "artifacts_shape_rejected",
        ),
    ],
)
def test_a2a_client_rejects_invalid_terminal_tasks(
    task: Mapping[str, JsonValue],
    error: str,
) -> None:
    card: Mapping[str, JsonValue] = {"protocolVersion": A2A_PROTOCOL_VERSION}
    peer = replace(
        canonical_protocol_peer(ProtocolFamily.A2A),
        card_digest=content_digest(card),
    )
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    client = A2aClientAdapter(
        transport=FakeA2aTransport(card, task),
        network_policy=NetworkTargetPolicy(frozenset({"a2a.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={
            capability.capability_id: capability for capability in capabilities
        },
        clock=lambda: NOW,
    )

    with pytest.raises(ProtocolSecurityError, match=error):
        asyncio.run(client.send(peer, capabilities[0], request))


@pytest.mark.parametrize(
    ("state", "error"),
    [
        ("working", "task_in_progress"),
        ("failed", "task_failed"),
    ],
)
def test_a2a_client_surfaces_noncompleted_remote_task_status(
    state: str,
    error: str,
) -> None:
    card: Mapping[str, JsonValue] = {"protocolVersion": A2A_PROTOCOL_VERSION}
    task: Mapping[str, JsonValue] = {
        "id": "task-1",
        "status": {"state": state},
        "artifacts": (),
    }
    peer = replace(
        canonical_protocol_peer(ProtocolFamily.A2A),
        card_digest=content_digest(card),
    )
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    client = A2aClientAdapter(
        transport=FakeA2aTransport(card, task),
        network_policy=NetworkTargetPolicy(frozenset({"a2a.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={item.capability_id: item for item in capabilities},
        clock=lambda: NOW,
    )

    with pytest.raises(ExternalProtocolError, match=error):
        asyncio.run(
            client.send(
                peer,
                capabilities[0],
                protocol_request(ProtocolFamily.A2A, policy, peer),
            )
        )


def test_a2a_client_fails_closed_on_card_drift_and_unknown_cancellation() -> None:
    card: Mapping[str, JsonValue] = {"protocolVersion": A2A_PROTOCOL_VERSION}
    task: Mapping[str, JsonValue] = {
        "id": "task-1",
        "status": {"state": "completed"},
    }
    peer = canonical_protocol_peer(ProtocolFamily.A2A)
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    transport = FakeA2aTransport(card, task)
    client = A2aClientAdapter(
        transport=transport,
        network_policy=NetworkTargetPolicy(frozenset({"a2a.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={
            capability.capability_id: capability for capability in capabilities
        },
        clock=lambda: NOW,
    )

    with pytest.raises(ProtocolSecurityError, match="card_digest_drift"):
        asyncio.run(client.discover(peer))
    transport.cancelled = False
    assert asyncio.run(client.cancel(peer, request)) is False
    transport.return_task = False
    assert asyncio.run(client.observe(peer, request)) is None

    pinned_peer = replace(peer, card_digest=content_digest(card))
    invalid_peers = (
        (replace(pinned_peer, family=ProtocolFamily.MCP), "family_mismatch"),
        (
            replace(
                pinned_peer,
                transports=(ProtocolTransport.STREAMABLE_HTTP,),
            ),
            "transport_denied",
        ),
        (replace(pinned_peer, protocol_versions=("0.3",)), "version_not_pinned"),
    )
    for invalid, error in invalid_peers:
        with pytest.raises(ProtocolSecurityError, match=error):
            asyncio.run(client.discover(invalid))

    unpinned = A2aClientAdapter(
        transport=transport,
        network_policy=NetworkTargetPolicy(frozenset({"a2a.fixtures.invalid"})),
        resolved_addresses={},
        capabilities={item.capability_id: item for item in capabilities},
        clock=lambda: NOW,
    )
    with pytest.raises(ProtocolSecurityError, match="dns_not_pinned"):
        asyncio.run(unpinned.discover(pinned_peer))


@pytest.mark.parametrize(
    ("artifact", "error"),
    [
        (
            {
                "artifactId": "artifact-1",
                "contentType": "application/octet-stream",
                "parts": ({"data": "opaque"},),
            },
            "mime_rejected",
        ),
        (
            {
                "artifactId": "artifact-1",
                "contentType": "application/json",
                "parts": ({"url": "https://attacker.invalid/exfiltrate"},),
            },
            "url_rejected",
        ),
        (
            {
                "artifactId": "artifact-1",
                "contentType": "application/json",
                "parts": (),
            },
            "parts_rejected",
        ),
        (
            {
                "artifactId": "artifact id with spaces",
                "contentType": "application/json",
                "parts": ({"data": "bounded"},),
            },
            "content_rejected",
        ),
    ],
)
def test_a2a_client_rejects_unsafe_artifacts(
    artifact: Mapping[str, JsonValue],
    error: str,
) -> None:
    card: Mapping[str, JsonValue] = {"protocolVersion": A2A_PROTOCOL_VERSION}
    task: Mapping[str, JsonValue] = {
        "id": "task-1",
        "status": {"state": "completed"},
        "artifacts": (artifact,),
    }
    peer = replace(
        canonical_protocol_peer(ProtocolFamily.A2A),
        card_digest=content_digest(card),
    )
    capabilities = canonical_protocol_capabilities()
    policy = canonical_protocol_policy((peer,))
    client = A2aClientAdapter(
        transport=FakeA2aTransport(card, task),
        network_policy=NetworkTargetPolicy(frozenset({"a2a.fixtures.invalid"})),
        resolved_addresses={peer.endpoint_origin: ("93.184.216.34",)},
        capabilities={item.capability_id: item for item in capabilities},
        clock=lambda: NOW,
    )

    with pytest.raises(ProtocolSecurityError, match=error):
        asyncio.run(
            client.send(
                peer,
                capabilities[0],
                protocol_request(ProtocolFamily.A2A, policy, peer),
            )
        )


def test_protocol_official_sdk_imports_remain_adapter_local() -> None:
    assert OfficialMcpSdkBoundary.package_version()
    assert OfficialA2aSdkBoundary.package_name() == "a2a"


def test_revoked_peer_card_is_not_a_trust_grant() -> None:
    peer = replace(
        canonical_protocol_peer(ProtocolFamily.A2A),
        status=ProtocolPeerStatus.REVOKED,
        emergency_disabled=True,
    )

    assert peer.available(NOW + timedelta(seconds=1)) is False
