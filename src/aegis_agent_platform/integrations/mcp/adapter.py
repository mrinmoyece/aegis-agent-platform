"""MCP 2026-07-28 wire adapter; protocol shapes stop in this module."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol

from aegis_agent_platform.domain import (
    CapabilityPage,
    JsonValue,
    ProtocolCapability,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolRequest,
    ProtocolTransport,
    content_digest,
    normalize_untrusted_text,
    validate_identifier,
    validate_json,
)
from aegis_agent_platform.protocols.operations import TransportResponse
from aegis_agent_platform.protocols.security import (
    NetworkTargetPolicy,
    ProtocolSecurityError,
)

MCP_CURRENT_VERSION = "2026-07-28"
MCP_LEGACY_VERSION = "2025-11-25"
MCP_SUPPORTED_VERSIONS = (MCP_CURRENT_VERSION, MCP_LEGACY_VERSION)
MAX_MCP_BODY_BYTES = 1_048_576
MAX_MCP_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class McpStreamableHttpRequest:
    method: str
    origin: str
    content_type: str
    accept: frozenset[str]
    protocol_version: str
    mcp_method: str
    mcp_name: str | None
    authorization_present: bool
    body_bytes: int

    def validate(self, allowed_origins: frozenset[str]) -> None:
        if self.method != "POST":
            raise ProtocolSecurityError("mcp_http_method_denied")
        if self.origin not in allowed_origins:
            raise ProtocolSecurityError("mcp_origin_denied")
        if self.content_type != "application/json":
            raise ProtocolSecurityError("mcp_content_type_denied")
        if not {"application/json", "text/event-stream"} <= self.accept:
            raise ProtocolSecurityError("mcp_accept_denied")
        if self.protocol_version not in MCP_SUPPORTED_VERSIONS:
            raise ProtocolSecurityError("mcp_protocol_version_denied")
        if not self.mcp_method:
            raise ProtocolSecurityError("mcp_method_header_required")
        if not self.authorization_present:
            raise ProtocolSecurityError("mcp_authentication_required")
        if not 1 <= self.body_bytes <= MAX_MCP_BODY_BYTES:
            raise ProtocolSecurityError("mcp_body_size_denied")


@dataclass(frozen=True, slots=True)
class RegisteredStdioCommand:
    command_id: str
    executable: str
    arguments: tuple[str, ...]
    working_directory: str
    environment_keys: frozenset[str]

    def __post_init__(self) -> None:
        validate_identifier(self.command_id, "stdio command_id")
        if not self.executable.startswith("/"):
            raise ValueError("stdio executable must be an absolute registered path")
        if len(self.arguments) > 32 or any(len(item) > 512 for item in self.arguments):
            raise ValueError("stdio arguments exceed the bound")
        if not self.working_directory.startswith("/"):
            raise ValueError("stdio working directory must be absolute")
        if len(self.environment_keys) > 32:
            raise ValueError("stdio environment allowlist exceeds the bound")


class StdioCommandRegistry:
    """Local-only fixed command registry; model content can never supply argv."""

    def __init__(self, commands: Sequence[RegisteredStdioCommand]) -> None:
        self._commands = {command.command_id: command for command in commands}
        if len(self._commands) != len(commands):
            raise ValueError("duplicate stdio command identifier")

    def resolve(self, command_id: str) -> RegisteredStdioCommand:
        try:
            return self._commands[command_id]
        except KeyError as error:
            raise ProtocolSecurityError("stdio_command_not_registered") from error


class McpApplicationPort(Protocol):
    """Existing application-service facade exposed through curated capabilities."""

    async def invoke(
        self,
        request: ProtocolRequest,
        capability: ProtocolCapability,
    ) -> Mapping[str, JsonValue]: ...


class McpServerAdapter:
    """Curated MCP server facade; it is never an orchestration authority."""

    def __init__(
        self,
        *,
        capabilities: Sequence[ProtocolCapability],
        application: McpApplicationPort,
        server_name: str,
        allowed_origins: frozenset[str],
    ) -> None:
        if not capabilities:
            raise ValueError("MCP server requires curated capabilities")
        self._capabilities = tuple(capabilities)
        self._application = application
        self._server_name = normalize_untrusted_text(
            server_name,
            name="MCP server name",
            maximum=128,
        )
        self._allowed_origins = allowed_origins

    def validate_http(self, request: McpStreamableHttpRequest) -> None:
        request.validate(self._allowed_origins)

    def discover(self, requested_version: str) -> Mapping[str, JsonValue]:
        if requested_version not in MCP_SUPPORTED_VERSIONS:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32022,
                    "message": "UnsupportedProtocolVersion",
                    "data": {
                        "supported": MCP_SUPPORTED_VERSIONS,
                        "requested": requested_version,
                    },
                },
                "serverInfo": {"name": self._server_name, "version": "layer14-v1"},
            }
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": requested_version,
                "capabilities": {
                    "resources": True,
                    "tools": True,
                    "prompts": False,
                    "subscriptions": False,
                },
                "serverInfo": {"name": self._server_name, "version": "layer14-v1"},
            },
        }

    def list_capabilities(
        self,
        *,
        cursor: str | None,
        page_size: int = MAX_MCP_PAGE_SIZE,
    ) -> CapabilityPage:
        if not 1 <= page_size <= MAX_MCP_PAGE_SIZE:
            raise ValueError("MCP page size is invalid")
        offset = int(cursor or "0")
        if offset < 0:
            raise ValueError("MCP cursor is invalid")
        page = self._capabilities[offset : offset + page_size]
        next_cursor = (
            str(offset + len(page))
            if offset + len(page) < len(self._capabilities)
            else None
        )
        return CapabilityPage(tuple(page), next_cursor)

    async def invoke(
        self,
        request: ProtocolRequest,
        capability_id: str,
    ) -> Mapping[str, JsonValue]:
        capability = next(
            (
                item
                for item in self._capabilities
                if item.capability_id == capability_id
            ),
            None,
        )
        if capability is None or request.capability_digest != capability.digest:
            raise ProtocolSecurityError("mcp_capability_denied")
        if capability.risk.value >= 3 and not capability.proposal_only:
            raise ProtocolSecurityError("mcp_direct_mutation_denied")
        result = await self._application.invoke(request, capability)
        validate_json(result, maximum_bytes=capability.maximum_output_bytes)
        return result


class McpWireTransport(Protocol):
    async def discover(
        self,
        endpoint: str,
        headers: Mapping[str, str],
    ) -> Mapping[str, JsonValue]: ...

    async def call(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: Mapping[str, JsonValue],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, JsonValue]: ...

    async def observe(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        operation_id: str,
    ) -> Mapping[str, JsonValue] | None: ...

    async def cancel(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        operation_id: str,
    ) -> bool: ...


class McpClientAdapter:
    """Approved-server client with exact negotiation and no token passthrough."""

    def __init__(
        self,
        *,
        transport: McpWireTransport,
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
        response = await self._transport.discover(
            peer.endpoint_origin,
            self._headers("server/discover"),
        )
        validate_json(response, maximum_bytes=262_144)
        return (
            tuple(
                capability
                for capability_id, capability in self._capabilities.items()
                if capability_id in peer.allowed_capability_digests
            ),
            peer.card_digest,
            content_digest(response),
        )

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
            "method": (
                "resources/read"
                if capability.kind.value == "resource"
                else "tools/call"
            ),
            "params": {
                "name": capability.capability_id,
                "arguments": request.payload,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_CURRENT_VERSION,
                    "io.aegis/idempotencyKey": request.idempotency_key,
                    "io.aegis/requestDigest": request.payload_digest,
                },
            },
        }
        response = await self._transport.call(
            peer.endpoint_origin,
            self._headers(str(body["method"])),
            body,
            timeout_seconds=max(
                1,
                int((request.deadline - request.requested_at).total_seconds()),
            ),
        )
        validate_json(response, maximum_bytes=capability.maximum_output_bytes)
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise ProtocolSecurityError("mcp_result_missing")
        return TransportResponse(
            f"mcp:{request.operation_id}",
            result,
            (),
            ProtocolOperationStatus.COMPLETED,
            self._clock(),
        )

    async def observe(
        self,
        peer: ProtocolPeer,
        request: ProtocolRequest,
    ) -> TransportResponse | None:
        self._validate_peer(peer)
        result = await self._transport.observe(
            peer.endpoint_origin,
            self._headers("resources/read"),
            str(request.operation_id),
        )
        if result is None:
            return None
        validate_json(result, maximum_bytes=262_144)
        return TransportResponse(
            f"mcp-observed:{request.operation_id}",
            result,
            (),
            ProtocolOperationStatus.COMPLETED,
            self._clock(),
        )

    async def cancel(self, peer: ProtocolPeer, request: ProtocolRequest) -> bool:
        self._validate_peer(peer)
        return await self._transport.cancel(
            peer.endpoint_origin,
            self._headers("notifications/cancelled"),
            str(request.operation_id),
        )

    def _validate_peer(self, peer: ProtocolPeer) -> None:
        if peer.family is not ProtocolFamily.MCP:
            raise ProtocolSecurityError("mcp_peer_family_mismatch")
        if ProtocolTransport.STREAMABLE_HTTP not in peer.transports:
            raise ProtocolSecurityError("mcp_network_transport_denied")
        addresses = self._resolved_addresses.get(peer.endpoint_origin)
        if addresses is None:
            raise ProtocolSecurityError("mcp_dns_not_pinned")
        self._network_policy.validate(
            peer.endpoint_origin,
            resolved_addresses=addresses,
        )
        if MCP_CURRENT_VERSION not in peer.protocol_versions:
            raise ProtocolSecurityError("mcp_current_version_not_pinned")

    @staticmethod
    def _headers(method: str) -> Mapping[str, str]:
        return {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_CURRENT_VERSION,
            "Mcp-Method": method,
        }


class OfficialMcpSdkBoundary:
    """Import marker proving official SDK types remain adapter-local."""

    @staticmethod
    def package_version() -> str:
        import mcp

        return str(getattr(mcp, "__version__", "2.0.0"))


__all__ = [
    "MCP_CURRENT_VERSION",
    "MCP_LEGACY_VERSION",
    "McpApplicationPort",
    "McpClientAdapter",
    "McpServerAdapter",
    "McpStreamableHttpRequest",
    "RegisteredStdioCommand",
    "StdioCommandRegistry",
]
