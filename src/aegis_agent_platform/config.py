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
    oidc_audience: str = "aegis-control-plane"

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

        settings = cls(
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
                "aegis-control-plane",
            ),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        """Reject settings that would make process behavior ambiguous or unsafe."""
        if not 1 <= self.port <= 65_535:
            raise ConfigurationError("AEGIS_PORT must be between 1 and 65535")
        if self.log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ConfigurationError("AEGIS_LOG_LEVEL is not recognized")
        if not self.service_name.strip():
            raise ConfigurationError("AEGIS_SERVICE_NAME cannot be empty")
        if self.environment is Environment.PRODUCTION:
            required = {
                "AEGIS_DATABASE_URL": self.database_url,
                "AEGIS_REDIS_URL": self.redis_url,
                "AEGIS_OIDC_ISSUER": self.oidc_issuer,
                "AEGIS_OIDC_JWKS_URL": self.oidc_jwks_url,
                "AEGIS_OIDC_AUDIENCE": self.oidc_audience,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ConfigurationError(
                    "production requires: " + ", ".join(sorted(missing))
                )
