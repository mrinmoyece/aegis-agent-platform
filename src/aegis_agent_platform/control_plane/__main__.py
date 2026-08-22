"""Control-plane process entry point."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from hashlib import sha256
from typing import Any

import psycopg
import uvicorn

from aegis_agent_platform.config import Environment, Settings
from aegis_agent_platform.control_plane.api import ControlPlaneApp
from aegis_agent_platform.event_store import EventPage
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.identity import (
    AuthenticationService,
    JwtValidationConfig,
    JwtVerifier,
    RemoteJwksProvider,
)
from aegis_agent_platform.observability.health import (
    ComponentProbe,
    DependencyCriticality,
    HealthRegistry,
    HealthStatus,
    ProbeResult,
)
from aegis_agent_platform.observability.logging import configure_json_logging
from aegis_agent_platform.observability.operations import ObservabilityOperations
from aegis_agent_platform.observability.replay import ReplayDebugger
from aegis_agent_platform.persistence.postgres import (
    PostgresAuditStore,
    PostgresIdentityDirectory,
    PostgresPolicyRepository,
    PostgresTenantRepository,
)
from aegis_agent_platform.tenancy import TenantContext


class _AsyncPostgresReadStore:
    """Lazy per-call PostgreSQL reader used by the control-plane composition root."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    async def read_stream(
        self,
        context: TenantContext,
        aggregate_id: str,
        *,
        after_version: int = 0,
        limit: int = 100,
    ) -> AsyncIterator[object]:
        connection = await psycopg.AsyncConnection.connect(self._database_url)
        try:
            store = PostgresEventStore(connection)
            events = [
                event
                async for event in store.read_stream(
                    context,
                    aggregate_id,
                    after_version=after_version,
                    limit=limit,
                )
            ]
        finally:
            await connection.close()
        for event in events:
            yield event

    async def read_all(
        self,
        context: TenantContext,
        *,
        after_position: int = 0,
        limit: int = 100,
    ) -> EventPage:
        connection = await psycopg.AsyncConnection.connect(self._database_url)
        try:
            return await PostgresEventStore(connection).read_all(
                context,
                after_position=after_position,
                limit=limit,
            )
        finally:
            await connection.close()


async def _storage_ready(settings: Settings) -> bool:
    if not settings.database_url:
        return False
    try:
        connection = await psycopg.AsyncConnection.connect(settings.database_url)
        try:
            await connection.execute("SELECT 1")
        finally:
            await connection.close()
    except psycopg.Error:
        return False
    return True


def _health_registry(settings: Settings) -> HealthRegistry | None:
    if not settings.database_url:
        return None

    async def postgres_probe() -> ProbeResult:
        ready = await _storage_ready(settings)
        return ProbeResult(
            HealthStatus.HEALTHY if ready else HealthStatus.UNAVAILABLE,
            "postgres_ready" if ready else "postgres_unavailable",
        )

    return HealthRegistry(
        (
            ComponentProbe(
                "postgres",
                DependencyCriticality.CORRECTNESS,
                postgres_probe,
            ),
        ),
        cache_seconds=5,
        transition_threshold=2,
        probe_timeout_seconds=1.0,
    )


def _authentication(
    settings: Settings,
    connection: psycopg.Connection[Any],
) -> AuthenticationService | None:
    if not settings.oidc_issuer or not settings.oidc_jwks_url:
        return None
    verifier = JwtVerifier(
        JwtValidationConfig(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            clock_skew=timedelta(seconds=settings.oidc_clock_skew_seconds),
        ),
        RemoteJwksProvider(
            settings.oidc_jwks_url,
            allow_http=settings.environment is Environment.DEVELOPMENT,
        ),
    )
    return AuthenticationService(verifier, PostgresIdentityDirectory(connection))


def _observability_operations(
    settings: Settings,
    audit: PostgresAuditStore,
) -> ObservabilityOperations | None:
    if not settings.database_url:
        return None
    event_store = _AsyncPostgresReadStore(settings.database_url)
    identifier_hash_key = sha256(
        f"{settings.service_name}:{settings.database_url}".encode()
    ).digest()
    return ObservabilityOperations(
        ReplayDebugger(
            event_store,
            identifier_hash_key=identifier_hash_key,
            hash_key_version=f"{settings.environment.value}-bootstrap-v1",
        ),
        audit,
        identifier_hash_key=identifier_hash_key,
        hash_key_version=f"{settings.environment.value}-bootstrap-v1",
    )


def _application(settings: Settings) -> ControlPlaneApp:
    connection = (
        psycopg.connect(settings.database_url) if settings.database_url else None
    )
    tenants = PostgresTenantRepository(connection) if connection is not None else None
    policies = PostgresPolicyRepository(connection) if connection is not None else None
    audit = PostgresAuditStore(connection) if connection is not None else None
    return ControlPlaneApp(
        authentication=(
            _authentication(settings, connection) if connection is not None else None
        ),
        tenants=tenants,
        policies=policies,
        audit=audit,
        event_store=(
            _AsyncPostgresReadStore(settings.database_url)
            if settings.database_url
            else None
        ),
        storage_ready=lambda: _storage_ready(settings),
        observability_operations=(
            _observability_operations(settings, audit) if audit is not None else None
        ),
        health_registry=_health_registry(settings),
    )


def main() -> None:
    """Run the ASGI control-plane service with production observability wiring."""
    settings = Settings.from_env()
    configure_json_logging(level=settings.log_level)
    uvicorn.run(
        _application(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
