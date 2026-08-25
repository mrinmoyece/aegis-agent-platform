"""Fail-closed protocol authentication, schema, and network guards."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from aegis_agent_platform.domain import (
    JsonValue,
    ProtocolAuthScheme,
    ProtocolPeer,
    ProtocolPrincipal,
    content_digest,
    normalize_untrusted_text,
    thaw_json,
    validate_digest,
    validate_identifier,
    validate_json,
)

_FORBIDDEN_SCHEMA_KEYS = frozenset({"$dynamicRef", "$recursiveRef"})
_FORBIDDEN_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
    )
)


class ProtocolSecurityError(PermissionError):
    """Secret-safe security failure with one bounded machine code."""

    def __init__(self, code: str) -> None:
        validate_identifier(code, "security error code")
        super().__init__(code)
        self.code = code


class ProtocolSchemaValidator:
    """Validate schemas and payloads without resolving remote references."""

    def compile(self, schema: Mapping[str, JsonValue]) -> Draft202012Validator:
        try:
            validate_json(schema, maximum_bytes=65_536)
        except ValueError as error:
            raise ProtocolSecurityError("invalid_protocol_schema") from error
        self._reject_remote_references(schema)
        thawed = thaw_json(schema)
        if not isinstance(thawed, Mapping):
            raise ProtocolSecurityError("invalid_protocol_schema")
        try:
            Draft202012Validator.check_schema(thawed)
        except Exception as error:
            raise ProtocolSecurityError("invalid_protocol_schema") from error
        return Draft202012Validator(thawed, format_checker=FormatChecker())

    def validate(
        self,
        schema: Mapping[str, JsonValue],
        payload: Mapping[str, JsonValue],
        *,
        maximum_bytes: int,
    ) -> str:
        try:
            validate_json(payload, maximum_bytes=maximum_bytes)
        except ValueError as error:
            raise ProtocolSecurityError("protocol_payload_bounds_rejected") from error
        validator = self.compile(schema)
        thawed_payload = thaw_json(payload)
        try:
            validator.validate(thawed_payload)
        except ValidationError as error:
            raise ProtocolSecurityError("protocol_schema_rejected") from error
        return content_digest(payload)

    def _reject_remote_references(self, value: JsonValue) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in _FORBIDDEN_SCHEMA_KEYS:
                    raise ProtocolSecurityError("schema_reference_forbidden")
                if (
                    key == "$ref"
                    and isinstance(child, str)
                    and not child.startswith("#")
                ):
                    raise ProtocolSecurityError("remote_schema_reference_forbidden")
                self._reject_remote_references(child)
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            for child in value:
                self._reject_remote_references(child)


@dataclass(frozen=True, slots=True)
class NetworkTargetPolicy:
    """Pre-resolved target policy used before connect and after every redirect."""

    allowed_hosts: frozenset[str]
    allowed_ports: frozenset[int] = frozenset({443})
    maximum_redirects: int = 0

    def __post_init__(self) -> None:
        if not self.allowed_hosts or len(self.allowed_hosts) > 64:
            raise ValueError("network target allowlist is outside the bound")
        for host in self.allowed_hosts:
            normalize_untrusted_text(host, name="allowed host", maximum=253)
        if not self.allowed_ports or any(
            port < 1 or port > 65535 for port in self.allowed_ports
        ):
            raise ValueError("network target ports are invalid")
        if not 0 <= self.maximum_redirects <= 3:
            raise ValueError("redirect bound is invalid")

    def validate(
        self,
        url: str,
        *,
        resolved_addresses: Sequence[str],
        redirect_count: int = 0,
    ) -> tuple[str, int]:
        if redirect_count > self.maximum_redirects:
            raise ProtocolSecurityError("redirect_denied")
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or parts.hostname is None
        ):
            raise ProtocolSecurityError("unsafe_protocol_url")
        host = parts.hostname.rstrip(".").lower()
        if host not in self.allowed_hosts:
            raise ProtocolSecurityError("egress_host_denied")
        port = parts.port or 443
        if port not in self.allowed_ports:
            raise ProtocolSecurityError("egress_port_denied")
        if not resolved_addresses or len(resolved_addresses) > 16:
            raise ProtocolSecurityError("dns_resolution_invalid")
        for address_text in resolved_addresses:
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as error:
                raise ProtocolSecurityError("dns_address_invalid") from error
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
                or any(address in network for network in _FORBIDDEN_NETWORKS)
            ):
                raise ProtocolSecurityError("dns_address_denied")
        return host, port


@dataclass(frozen=True, slots=True)
class ProtocolAuthAssertion:
    """Claims already cryptographically verified by an authentication adapter."""

    subject: str
    issuer: str
    tenant_id: str
    audiences: frozenset[str]
    scopes: frozenset[str]
    token_id: str
    issued_at: datetime
    expires_at: datetime
    proof_thumbprint: str | None
    nonce: str | None
    certificate_digest: str | None

    def __post_init__(self) -> None:
        for value, name in (
            (self.subject, "subject"),
            (self.tenant_id, "tenant_id"),
            (self.token_id, "token_id"),
        ):
            validate_identifier(value, name)
        normalize_untrusted_text(self.issuer, name="issuer", maximum=512)
        if not self.audiences or not self.scopes:
            raise ValueError("protocol assertion requires audience and scopes")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("protocol assertion timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("protocol assertion expiry is invalid")
        if self.proof_thumbprint is not None:
            validate_digest(self.proof_thumbprint, "proof_thumbprint")
        if self.certificate_digest is not None:
            validate_digest(self.certificate_digest, "certificate_digest")
        if self.nonce is not None:
            validate_identifier(self.nonce, "nonce")


class ReplayCache(Protocol):
    def consume(
        self,
        tenant_id: str,
        token_id_digest: str,
        expires_at: datetime,
    ) -> bool:
        """Return false when the token identifier has already been consumed."""
        ...


class InMemoryReplayCache:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], datetime] = {}

    def consume(
        self,
        tenant_id: str,
        token_id_digest: str,
        expires_at: datetime,
    ) -> bool:
        key = (tenant_id, token_id_digest)
        if key in self._entries:
            return False
        self._entries[key] = expires_at
        return True

    def purge(self, at: datetime) -> None:
        self._entries = {
            key: expiry for key, expiry in self._entries.items() if expiry > at
        }


class ProtocolAuthenticator:
    """Bind verified claims to one tenant, peer audience, scope, and proof."""

    def __init__(
        self,
        *,
        trusted_issuers: Mapping[str, frozenset[str]],
        replay_cache: ReplayCache,
        maximum_token_lifetime_seconds: int = 900,
        production_boundary_ready: bool = False,
    ) -> None:
        if not trusted_issuers:
            raise ValueError("trusted protocol issuers are required")
        self._trusted_issuers = MappingProxyType(dict(trusted_issuers))
        self._replay_cache = replay_cache
        self._maximum_token_lifetime_seconds = maximum_token_lifetime_seconds
        self._production_boundary_ready = production_boundary_ready

    @property
    def production_ready(self) -> bool:
        return self._production_boundary_ready

    def authenticate(
        self,
        assertion: ProtocolAuthAssertion,
        peer: ProtocolPeer,
        *,
        tenant_id: str,
        audience: str,
        required_scope: str,
        at: datetime,
        consume_replay_token: bool = True,
    ) -> ProtocolPrincipal:
        if at.tzinfo is None:
            raise ValueError("authentication time must be timezone-aware")
        if assertion.tenant_id != tenant_id or peer.tenant_id != tenant_id:
            raise ProtocolSecurityError("cross_tenant_protocol_identity")
        issuer_audiences = self._trusted_issuers.get(assertion.issuer)
        if issuer_audiences is None or audience not in issuer_audiences:
            raise ProtocolSecurityError("protocol_issuer_or_audience_denied")
        if audience not in assertion.audiences:
            raise ProtocolSecurityError("protocol_audience_denied")
        if required_scope not in assertion.scopes:
            raise ProtocolSecurityError("protocol_scope_denied")
        if not assertion.issued_at <= at < assertion.expires_at:
            raise ProtocolSecurityError("protocol_token_expired_or_early")
        lifetime = (assertion.expires_at - assertion.issued_at).total_seconds()
        if lifetime > self._maximum_token_lifetime_seconds:
            raise ProtocolSecurityError("protocol_token_lifetime_denied")
        proof = assertion.proof_thumbprint or assertion.certificate_digest
        if (
            peer.auth_scheme
            in {
                ProtocolAuthScheme.OAUTH2_DPOP,
                ProtocolAuthScheme.OIDC_MTLS,
                ProtocolAuthScheme.MTLS,
            }
            and proof is None
        ):
            raise ProtocolSecurityError("bound_token_required")
        if (
            peer.auth_scheme in {ProtocolAuthScheme.OIDC_MTLS, ProtocolAuthScheme.MTLS}
            and assertion.certificate_digest != peer.certificate_digest
        ):
            raise ProtocolSecurityError("peer_certificate_mismatch")
        token_id_digest = sha256(assertion.token_id.encode()).hexdigest()
        if consume_replay_token and not self._replay_cache.consume(
            tenant_id,
            token_id_digest,
            assertion.expires_at,
        ):
            raise ProtocolSecurityError("protocol_replay_denied")
        return ProtocolPrincipal(
            assertion.subject,
            assertion.issuer,
            tenant_id,
            audience,
            assertion.scopes,
            token_id_digest,
            proof or "0" * 64,
            at,
        )
