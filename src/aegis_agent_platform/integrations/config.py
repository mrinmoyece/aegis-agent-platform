"""Typed disabled-by-default live connector configuration."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.secrets_boundary import SecretReference


@dataclass(frozen=True, slots=True)
class ConnectorLimits:
    timeout_seconds: float = 20
    max_response_bytes: int = 5_000_000
    max_records: int = 500
    max_pages: int = 10
    max_window_seconds: int = 86_400

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 120:
            raise ValueError("connector timeout must be between 0 and 120")
        if not 1024 <= self.max_response_bytes <= 50_000_000:
            raise ValueError("connector response cap is invalid")
        if not 1 <= self.max_records <= 10_000:
            raise ValueError("connector record cap is invalid")
        if not 1 <= self.max_pages <= 100:
            raise ValueError("connector page cap is invalid")
        if not 60 <= self.max_window_seconds <= 604_800:
            raise ValueError("connector window cap is invalid")


@dataclass(frozen=True, slots=True)
class DynatraceConnectorConfig:
    tenant_id: TenantId
    environment: str
    environment_url: str
    account_url: str
    client_id: SecretReference
    client_secret: SecretReference
    oauth_scopes: tuple[str, ...]
    limits: ConnectorLimits = ConnectorLimits()
    enabled: bool = False

    def __post_init__(self) -> None:
        _tenant_secrets(self.tenant_id, self.client_id, self.client_secret)
        _https_origin(self.environment_url)
        _https_origin(self.account_url)
        if not self.environment or not self.oauth_scopes:
            raise ValueError("Dynatrace environment and OAuth scopes are required")


@dataclass(frozen=True, slots=True)
class GitHubConnectorConfig:
    tenant_id: TenantId
    app_id: str
    installation_id: int
    private_key: SecretReference
    repositories: frozenset[str]
    api_url: str = "https://api.github.com"
    limits: ConnectorLimits = ConnectorLimits()
    enabled: bool = False

    def __post_init__(self) -> None:
        _tenant_secrets(self.tenant_id, self.private_key)
        _https_origin(self.api_url)
        if not self.app_id or self.installation_id < 1 or not self.repositories:
            raise ValueError(
                "GitHub App identity and repository allowlist are required"
            )
        if any(repository.count("/") != 1 for repository in self.repositories):
            raise ValueError("GitHub repositories must use owner/name")


@dataclass(frozen=True, slots=True)
class KubernetesConnectorConfig:
    tenant_id: TenantId
    cluster: str
    namespaces: frozenset[str]
    allow_logs: bool = False
    max_log_bytes: int = 256_000
    max_log_lines: int = 2_000
    limits: ConnectorLimits = ConnectorLimits()
    enabled: bool = False

    def __post_init__(self) -> None:
        if not self.cluster or not self.namespaces:
            raise ValueError("cluster and namespace allowlist are required")
        if not 1024 <= self.max_log_bytes <= 5_000_000:
            raise ValueError("Kubernetes log byte cap is invalid")
        if not 1 <= self.max_log_lines <= 20_000:
            raise ValueError("Kubernetes log line cap is invalid")


@dataclass(frozen=True, slots=True)
class RunbookConnectorConfig:
    tenant_id: TenantId
    roots: tuple[str, ...]
    trusted_digests: frozenset[str]
    limits: ConnectorLimits = ConnectorLimits(max_response_bytes=1_000_000)
    enabled: bool = False

    def __post_init__(self) -> None:
        if not self.roots:
            raise ValueError("runbook source roots are required")
        if any(not root.startswith(("file://", "git+https://")) for root in self.roots):
            raise ValueError("runbook roots require file:// or git+https://")


def _tenant_secrets(tenant_id: TenantId, *references: SecretReference) -> None:
    if any(reference.tenant_id != tenant_id for reference in references):
        raise ValueError("connector secrets must belong to the configured tenant")


def _https_origin(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None:
        raise ValueError("connector URL must be an HTTPS origin without user info")
    if parsed.query or parsed.fragment:
        raise ValueError("connector base URL cannot include query or fragment")


__all__ = [
    "ConnectorLimits",
    "DynatraceConnectorConfig",
    "GitHubConnectorConfig",
    "KubernetesConnectorConfig",
    "RunbookConnectorConfig",
]
