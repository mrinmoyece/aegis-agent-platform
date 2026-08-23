"""Environment-backed process configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class ConfigurationError(ValueError):
    """Raised when process configuration violates an invariant."""


class Environment(StrEnum):
    """Supported deployment environment classes."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated settings shared by process entry points."""

    environment: Environment = Environment.DEVELOPMENT
    service_name: str = "aegis-control-plane"
    host: str = "0.0.0.0"  # noqa: S104 - required inside the container network
    port: int = 8080
    log_level: str = "INFO"
    database_url: str = ""
    redis_url: str = ""
    oidc_issuer: str = ""
    oidc_jwks_url: str = ""
    oidc_audience: str = ""
    oidc_clock_skew_seconds: int = 30
    redis_max_connections: int = 32
    redis_connect_timeout_seconds: float = 2.0
    redis_socket_timeout_seconds: float = 5.0
    worker_max_concurrency: int = 16
    worker_lease_seconds: int = 30
    worker_heartbeat_seconds: int = 10

    def __post_init__(self) -> None:
        """Enforce invariants for every construction path."""
        self.validate()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Build and validate settings from an environment mapping."""
        values = os.environ if environ is None else environ
        environment_raw = values.get("AEGIS_ENVIRONMENT", "development")
        try:
            environment = Environment(environment_raw)
        except ValueError as error:
            choices = ", ".join(member.value for member in Environment)
            raise ConfigurationError(
                f"AEGIS_ENVIRONMENT must be one of: {choices}"
            ) from error

        port_raw = values.get("AEGIS_PORT", "8080")
        try:
            port = int(port_raw)
        except ValueError as error:
            raise ConfigurationError("AEGIS_PORT must be an integer") from error
        clock_skew_raw = values.get("AEGIS_OIDC_CLOCK_SKEW_SECONDS", "30")
        try:
            clock_skew_seconds = int(clock_skew_raw)
        except ValueError as error:
            raise ConfigurationError(
                "AEGIS_OIDC_CLOCK_SKEW_SECONDS must be an integer"
            ) from error
        try:
            redis_max_connections = int(values.get("AEGIS_REDIS_MAX_CONNECTIONS", "32"))
            redis_connect_timeout_seconds = float(
                values.get("AEGIS_REDIS_CONNECT_TIMEOUT_SECONDS", "2")
            )
            redis_socket_timeout_seconds = float(
                values.get("AEGIS_REDIS_SOCKET_TIMEOUT_SECONDS", "5")
            )
            worker_max_concurrency = int(
                values.get("AEGIS_WORKER_MAX_CONCURRENCY", "16")
            )
            worker_lease_seconds = int(values.get("AEGIS_WORKER_LEASE_SECONDS", "30"))
            worker_heartbeat_seconds = int(
                values.get("AEGIS_WORKER_HEARTBEAT_SECONDS", "10")
            )
        except ValueError as error:
            raise ConfigurationError(
                "Redis and worker numeric settings must be numbers"
            ) from error

        return cls(
            environment=environment,
            service_name=values.get(
                "AEGIS_SERVICE_NAME",
                "aegis-control-plane",
            ),
            host=values.get(
                "AEGIS_HOST",
                "0.0.0.0",  # noqa: S104 - container process must accept traffic
            ),
            port=port,
            log_level=values.get("AEGIS_LOG_LEVEL", "INFO").upper(),
            database_url=values.get("AEGIS_DATABASE_URL", ""),
            redis_url=values.get("AEGIS_REDIS_URL", ""),
            oidc_issuer=values.get("AEGIS_OIDC_ISSUER", ""),
            oidc_jwks_url=values.get("AEGIS_OIDC_JWKS_URL", ""),
            oidc_audience=values.get(
                "AEGIS_OIDC_AUDIENCE",
                "",
            ),
            oidc_clock_skew_seconds=clock_skew_seconds,
            redis_max_connections=redis_max_connections,
            redis_connect_timeout_seconds=redis_connect_timeout_seconds,
            redis_socket_timeout_seconds=redis_socket_timeout_seconds,
            worker_max_concurrency=worker_max_concurrency,
            worker_lease_seconds=worker_lease_seconds,
            worker_heartbeat_seconds=worker_heartbeat_seconds,
        )

    def validate(self) -> None:
        """Reject settings that would make process behavior ambiguous or unsafe."""
        if not 1 <= self.port <= 65_535:
            raise ConfigurationError("AEGIS_PORT must be between 1 and 65535")
        if self.log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ConfigurationError("AEGIS_LOG_LEVEL is not recognized")
        if not self.service_name.strip():
            raise ConfigurationError("AEGIS_SERVICE_NAME cannot be empty")
        if not 0 <= self.oidc_clock_skew_seconds <= 300:
            raise ConfigurationError(
                "AEGIS_OIDC_CLOCK_SKEW_SECONDS must be between 0 and 300"
            )
        if not 1 <= self.redis_max_connections <= 1_000:
            raise ConfigurationError(
                "AEGIS_REDIS_MAX_CONNECTIONS must be between 1 and 1000"
            )
        if not 0.1 <= self.redis_connect_timeout_seconds <= 30:
            raise ConfigurationError(
                "AEGIS_REDIS_CONNECT_TIMEOUT_SECONDS must be between 0.1 and 30"
            )
        if not 0.1 <= self.redis_socket_timeout_seconds <= 60:
            raise ConfigurationError(
                "AEGIS_REDIS_SOCKET_TIMEOUT_SECONDS must be between 0.1 and 60"
            )
        if not 1 <= self.worker_max_concurrency <= 1_000:
            raise ConfigurationError(
                "AEGIS_WORKER_MAX_CONCURRENCY must be between 1 and 1000"
            )
        if not 5 <= self.worker_lease_seconds <= 3_600:
            raise ConfigurationError(
                "AEGIS_WORKER_LEASE_SECONDS must be between 5 and 3600"
            )
        if not 1 <= self.worker_heartbeat_seconds < self.worker_lease_seconds:
            raise ConfigurationError(
                "worker heartbeat must be positive and shorter than its lease"
            )
        if self.environment is Environment.PRODUCTION:
            required = {
                "AEGIS_DATABASE_URL": self.database_url,
                "AEGIS_REDIS_URL": self.redis_url,
                "AEGIS_OIDC_ISSUER": self.oidc_issuer,
                "AEGIS_OIDC_JWKS_URL": self.oidc_jwks_url,
                "AEGIS_OIDC_AUDIENCE": self.oidc_audience,
            }
            missing = [name for name, value in required.items() if not value.strip()]
            if missing:
                raise ConfigurationError(
                    "production requires: " + ", ".join(sorted(missing))
                )
            if not self.redis_url.startswith("rediss://"):
                raise ConfigurationError(
                    "production AEGIS_REDIS_URL must use rediss:// TLS"
                )
