"""Typed provider transport settings and explicit secret bindings."""

from __future__ import annotations

from dataclasses import dataclass

from aegis_agent_platform.secrets_boundary import SecretReference


@dataclass(frozen=True, slots=True)
class ProviderClientSettings:
    api_key: SecretReference
    base_url: str | None = None
    proxy_url: str | None = None
    connect_timeout_seconds: float = 5
    read_timeout_seconds: float = 60
    max_connections: int = 32
    max_keepalive_connections: int = 16
    verify_tls: bool = True

    def __post_init__(self) -> None:
        if self.base_url is not None and not self.base_url.startswith("https://"):
            raise ValueError("provider base URL must use HTTPS")
        if self.proxy_url is not None and not self.proxy_url.startswith(
            ("https://", "http://")
        ):
            raise ValueError("proxy URL must use HTTP or HTTPS")
        if self.connect_timeout_seconds <= 0 or self.read_timeout_seconds <= 0:
            raise ValueError("provider timeouts must be positive")
        if self.max_connections < 1 or self.max_keepalive_connections < 0:
            raise ValueError("provider pool sizes are invalid")
        if self.max_keepalive_connections > self.max_connections:
            raise ValueError("keepalive pool cannot exceed total connections")
        if not self.verify_tls:
            raise ValueError("provider TLS verification cannot be disabled")


__all__ = ["ProviderClientSettings"]
