"""Configuration contract tests."""

from __future__ import annotations

import pytest

from aegis_agent_platform.config import (
    RDS_GLOBAL_BUNDLE_PATH,
    ConfigurationError,
    Environment,
    ProcessRole,
    Settings,
)

PROTECTED_DATABASE_URL = (
    "postgresql://database/aegis?sslmode=verify-full"
    f"&sslrootcert={RDS_GLOBAL_BUNDLE_PATH}"
)


def test_development_defaults_are_valid() -> None:
    settings = Settings.from_env({})

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.process_role is ProcessRole.API
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
        ({"AEGIS_PROCESS_ROLE": "unknown"}, "must be one of"),
        ({"AEGIS_SERVICE_NAME": " "}, "cannot be empty"),
        (
            {"AEGIS_OIDC_CLOCK_SKEW_SECONDS": "invalid"},
            "must be an integer",
        ),
        (
            {"AEGIS_OIDC_CLOCK_SKEW_SECONDS": "301"},
            "between 0 and 300",
        ),
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
            "AEGIS_DATABASE_URL": PROTECTED_DATABASE_URL,
            "AEGIS_REDIS_URL": "rediss://cache/0",
            "AEGIS_OIDC_ISSUER": "https://identity.example/realms/aegis",
            "AEGIS_OIDC_JWKS_URL": "https://identity.example/realms/aegis/certs",
            "AEGIS_OIDC_AUDIENCE": "aegis",
            "AEGIS_CREDENTIAL_PROVIDER": "external-secrets",
            "AEGIS_SIGNING_KEY_REFERENCE": "secret-ref://aegis/signing",
            "AEGIS_WRITER_FENCES_FILE": "/var/run/secrets/aegis/writer-fences.json",
            "AEGIS_SCHEMA_MIN_VERSION": "10",
            "AEGIS_SCHEMA_MAX_VERSION": "11",
        }
    )

    assert settings.environment is Environment.PRODUCTION
    assert settings.writer_fences_file.endswith("writer-fences.json")


def test_process_role_is_explicitly_parsed() -> None:
    settings = Settings.from_env({"AEGIS_PROCESS_ROLE": "outbox-publisher"})

    assert settings.process_role is ProcessRole.OUTBOX_PUBLISHER


def test_staging_uses_production_security_validation() -> None:
    environment = {
        "AEGIS_ENVIRONMENT": "staging",
        "AEGIS_DATABASE_URL": PROTECTED_DATABASE_URL,
        "AEGIS_REDIS_URL": "rediss://cache/0",
        "AEGIS_OIDC_ISSUER": "https://identity.example",
        "AEGIS_OIDC_JWKS_URL": "https://identity.example/certs",
        "AEGIS_OIDC_AUDIENCE": "aegis",
        "AEGIS_CREDENTIAL_PROVIDER": "external-secrets",
        "AEGIS_SIGNING_KEY_REFERENCE": "secret-ref://aegis/signing",
        "AEGIS_WRITER_FENCES_FILE": "/var/run/secrets/aegis/writer-fences.json",
    }

    assert Settings.from_env(environment).environment is Environment.STAGING


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"AEGIS_DATABASE_URL": "postgresql://database/aegis"}, "verify-full"),
        (
            {
                "AEGIS_DATABASE_URL": (
                    "postgresql://database/aegis?sslmode=verify-full&sslmode=disable"
                )
            },
            "verify-full",
        ),
        (
            {
                "AEGIS_DATABASE_URL": (
                    "postgresql://database/aegis?sslmode=verify-full"
                    "&sslrootcert=/tmp/untrusted.pem"
                )
            },
            "sslrootcert",
        ),
        ({"AEGIS_REDIS_URL": "redis://cache/0"}, "rediss"),
        ({"AEGIS_OIDC_ISSUER": "http://identity"}, "issuer must use HTTPS"),
        ({"AEGIS_WRITER_FENCES_FILE": "relative.json"}, "must be absolute"),
        ({"AEGIS_SCHEMA_MIN_VERSION": "12"}, "compatibility"),
    ],
)
def test_production_security_configuration_fails_closed(
    override: dict[str, str],
    message: str,
) -> None:
    environment = {
        "AEGIS_ENVIRONMENT": "production",
        "AEGIS_DATABASE_URL": PROTECTED_DATABASE_URL,
        "AEGIS_REDIS_URL": "rediss://cache/0",
        "AEGIS_OIDC_ISSUER": "https://identity.example",
        "AEGIS_OIDC_JWKS_URL": "https://identity.example/certs",
        "AEGIS_OIDC_AUDIENCE": "aegis",
        "AEGIS_CREDENTIAL_PROVIDER": "external-secrets",
        "AEGIS_SIGNING_KEY_REFERENCE": "secret-ref://aegis/signing",
        "AEGIS_WRITER_FENCES_FILE": "/var/run/secrets/aegis/writer-fences.json",
    }
    environment.update(override)

    with pytest.raises(ConfigurationError, match=message):
        Settings.from_env(environment)
