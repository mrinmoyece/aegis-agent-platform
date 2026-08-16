"""Configuration contract tests."""

from __future__ import annotations

import pytest

from aegis_agent_platform.config import (
    ConfigurationError,
    Environment,
    Settings,
)


def test_development_defaults_are_valid() -> None:
    settings = Settings.from_env({})

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.port == 8080


def test_direct_construction_enforces_validation() -> None:
    with pytest.raises(ConfigurationError, match="between 1 and 65535"):
        Settings(port=0)


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"AEGIS_PORT": "not-a-port"}, "must be an integer"),
        ({"AEGIS_PORT": "70000"}, "between 1 and 65535"),
        ({"AEGIS_LOG_LEVEL": "verbose"}, "not recognized"),
        ({"AEGIS_ENVIRONMENT": "preview"}, "must be one of"),
        ({"AEGIS_SERVICE_NAME": " "}, "cannot be empty"),
    ],
)
def test_invalid_configuration_is_rejected(
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        Settings.from_env(environment)


def test_production_requires_external_dependencies_and_identity() -> None:
    with pytest.raises(ConfigurationError, match="AEGIS_DATABASE_URL"):
        Settings.from_env({"AEGIS_ENVIRONMENT": "production"})


def test_production_requires_explicit_audience() -> None:
    environment = {
        "AEGIS_ENVIRONMENT": "production",
        "AEGIS_DATABASE_URL": "postgresql://database/aegis",
        "AEGIS_REDIS_URL": "rediss://cache/0",
        "AEGIS_OIDC_ISSUER": "https://identity.example/realms/aegis",
        "AEGIS_OIDC_JWKS_URL": "https://identity.example/realms/aegis/certs",
    }

    with pytest.raises(ConfigurationError, match="AEGIS_OIDC_AUDIENCE"):
        Settings.from_env(environment)


def test_production_rejects_whitespace_only_dependency() -> None:
    environment = {
        "AEGIS_ENVIRONMENT": "production",
        "AEGIS_DATABASE_URL": " ",
        "AEGIS_REDIS_URL": "rediss://cache/0",
        "AEGIS_OIDC_ISSUER": "https://identity.example/realms/aegis",
        "AEGIS_OIDC_JWKS_URL": "https://identity.example/realms/aegis/certs",
        "AEGIS_OIDC_AUDIENCE": "aegis",
    }

    with pytest.raises(ConfigurationError, match="AEGIS_DATABASE_URL"):
        Settings.from_env(environment)


def test_complete_production_configuration_is_valid() -> None:
    settings = Settings.from_env(
        {
            "AEGIS_ENVIRONMENT": "production",
            "AEGIS_DATABASE_URL": "postgresql://database/aegis",
            "AEGIS_REDIS_URL": "rediss://cache/0",
            "AEGIS_OIDC_ISSUER": "https://identity.example/realms/aegis",
            "AEGIS_OIDC_JWKS_URL": "https://identity.example/realms/aegis/certs",
            "AEGIS_OIDC_AUDIENCE": "aegis",
        }
    )

    assert settings.environment is Environment.PRODUCTION
