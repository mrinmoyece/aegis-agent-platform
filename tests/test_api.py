"""Authenticated ASGI control-plane tests."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest

from aegis_agent_platform.audit import REDACTED, AuditEventType, InMemoryAuditStore
from aegis_agent_platform.config import Environment
from aegis_agent_platform.control_plane.api import (
    ControlPlaneApp,
    RunStatusReader,
    application,
)
from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    ModelCapabilities,
    ModelIdentity,
    PricingVersion,
)
from aegis_agent_platform.event_store import (
    EventPage,
    EventStore,
    TransientStorageError,
)
from aegis_agent_platform.gateway import (
    GatewayOperations,
    ModelCatalog,
    ModelCatalogEntry,
    ProviderControls,
)
from aegis_agent_platform.identity import (
    PLATFORM_TENANT_ID,
    AuthenticationPort,
    Principal,
)
from aegis_agent_platform.policy import InMemoryPolicyRepository
from aegis_agent_platform.tenancy import (
    InMemoryTenantRepository,
    Tenant,
    TenantContext,
)
from security_helpers import (
    TENANT_ID,
    authentication_service,
    signing_fixture,
    tenant_policy,
    token,
)
from security_helpers import (
    principal as fixture_principal,
)


def request(
    path: str,
    *,
    app: ControlPlaneApp = application,
    environment: dict[str, str] | None = None,
    authorization: str | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
    method: str = "GET",
    query_string: str = "",
) -> tuple[int, dict[str, Any], list[tuple[bytes, bytes]]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    request_headers = list(headers or [])
    if authorization is not None:
        request_headers.append((b"authorization", authorization.encode()))

    async def invoke() -> None:
        await app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": request_headers,
                "query_string": query_string.encode(),
            },
            receive,
            send,
        )

    with PatchedEnvironment(environment or {}):
        asyncio.run(invoke())

    status = messages[0]["status"]
    response_headers = messages[0]["headers"]
    body = json.loads(messages[1]["body"])
    return status, body, response_headers


def bearer(encoded: str) -> str:
    return "Bearer " + encoded


class PatchedEnvironment:
    """Narrow environment patcher that does not require an HTTP test framework."""

    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.original: dict[str, str | None] = {}

    def __enter__(self) -> None:
        import os

        keys = {
            "AEGIS_ENVIRONMENT",
            "AEGIS_PORT",
            "AEGIS_LOG_LEVEL",
            "AEGIS_SERVICE_NAME",
            "AEGIS_DATABASE_URL",
            "AEGIS_REDIS_URL",
            "AEGIS_OIDC_ISSUER",
            "AEGIS_OIDC_JWKS_URL",
            "AEGIS_OIDC_AUDIENCE",
        }
        self.original = {key: os.environ.get(key) for key in keys}
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update(self.values)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        import os

        del exc_type, exc_value, traceback
        for key, value in self.original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def secured_app(
    *,
    event_store: EventStore | None = None,
    authentication: AuthenticationPort | None = None,
    projections: RunStatusReader | None = None,
    gateway_operations: GatewayOperations | None = None,
) -> tuple[ControlPlaneApp, str, InMemoryAuditStore]:
    signing = signing_fixture()
    audit = InMemoryAuditStore()
    app = ControlPlaneApp(
        authentication=authentication or authentication_service(signing),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=audit,
        event_store=event_store,
        projections=projections,
        gateway_operations=gateway_operations,
    )
    return app, token(signing), audit


class StaticUsageReader:
    async def usage_summary(self, context: TenantContext) -> dict[str, JsonValue]:
        assert context.tenant_id == TENANT_ID
        return {"tokens": 12, "cost_usd": "0.001", "calls": 1}


def model_operations() -> GatewayOperations:
    identity = ModelIdentity("mock", "model-safe")
    catalog = ModelCatalog(
        (
            ModelCatalogEntry(
                identity=identity,
                capabilities=ModelCapabilities(8_192, 1_024, True, False, True),
                pricing=PricingVersion(
                    "mock-price-v1",
                    datetime(2026, 1, 1, tzinfo=UTC),
                    Decimal("1"),
                    Decimal("2"),
                ),
                environments=frozenset({Environment.PRODUCTION}),
                data_residencies=frozenset({"eu"}),
                provider_retains_data=False,
                cost_rank=0,
                latency_rank=0,
            ),
        )
    )
    return GatewayOperations(
        catalog,
        ProviderControls(
            (identity,),
            concurrency=1,
            requests_per_minute=10,
            tokens_per_minute=10_000,
            clock=lambda: 0,
        ),
        StaticUsageReader(),
    )


class TimelineEventStore:
    def __init__(self, event: EventEnvelope) -> None:
        self.event = event
        self.after_position = -1
        self.after_version = -1

    async def append(self, *args: object, **kwargs: object) -> int:
        del args, kwargs
        raise NotImplementedError

    async def append_from_inbox(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise NotImplementedError

    async def read_stream(
        self, *args: object, **kwargs: object
    ) -> AsyncIterator[EventEnvelope]:
        del args
        after_version = kwargs["after_version"]
        assert isinstance(after_version, int)
        self.after_version = after_version
        if self.event.aggregate_sequence > after_version:
            yield self.event

    async def read_all(self, *args: object, **kwargs: object) -> EventPage:
        del args
        after_position = kwargs["after_position"]
        assert isinstance(after_position, int)
        self.after_position = after_position
        return EventPage(
            (self.event,)
            if (self.event.global_position or 0) > self.after_position
            else (),
            None,
        )


def test_liveness_and_compatibility_alias() -> None:
    status, body, headers = request("/health/live")
    alias_status, _, _ = request("/healthz")

    assert status == alias_status == 200
    assert body == {"status": "ok", "service": "control-plane"}
    assert (b"cache-control", b"no-store") in headers


def test_configuration_readiness() -> None:
    status, body, _ = request("/health/ready")

    assert status == 200
    assert body["checks"] == ["configuration"]


def test_invalid_configuration_is_not_ready() -> None:
    status, body, _ = request(
        "/readyz",
        environment={"AEGIS_PORT": "invalid"},
    )

    assert status == 503
    assert body["status"] == "not-ready"


def test_current_principal_comes_only_from_verified_identity() -> None:
    app, encoded, _ = secured_app()

    status, body, _ = request(
        "/v1/me",
        app=app,
        authorization=f"Bearer {encoded}",
        headers=[
            (b"x-user-id", b"attacker"),
            (b"x-tenant-id", b"tenant-evil"),
            (b"x-approver-id", b"attacker"),
        ],
    )

    assert status == 200
    assert body == {
        "actor_id": "user-alice",
        "kind": "user",
        "tenant_id": "tenant-alpha",
        "roles": ["viewer"],
    }


def test_tenant_resource_and_policy_are_tenant_scoped() -> None:
    app, encoded, audit = secured_app()
    authorization = f"Bearer {encoded}"

    tenant_status, tenant_body, _ = request(
        "/v1/tenants/tenant-alpha",
        app=app,
        authorization=authorization,
    )
    policy_status, policy_body, _ = request(
        "/v1/tenants/tenant-alpha/policy",
        app=app,
        authorization=authorization,
    )

    assert tenant_status == policy_status == 200
    assert tenant_body["display_name"] == "Tenant Alpha"
    assert policy_body["allow"]["models"] == ["model-safe"]
    assert policy_body["allow"]["providers"] == ["mock"]
    assert policy_body["allow"]["data_residencies"] == ["eu"]
    assert policy_body["data"]["allow_provider_retention"] is False
    events = audit.query(TenantContext(TENANT_ID))
    assert [event.event_type for event in events] == [
        AuditEventType.AUTHENTICATION_OUTCOME,
        AuditEventType.AUTHORIZATION_DECISION,
        AuditEventType.AUTHENTICATION_OUTCOME,
        AuditEventType.AUTHORIZATION_DECISION,
    ]
    assert events[0].correlation_id == events[1].correlation_id
    assert events[2].correlation_id == events[3].correlation_id
    assert events[0].correlation_id != events[2].correlation_id


def test_cross_tenant_confused_deputy_attempt_is_forbidden() -> None:
    app, encoded, audit = secured_app()

    status, body, _ = request(
        "/v1/tenants/tenant-beta",
        app=app,
        authorization=f"Bearer {encoded}",
    )

    assert status == 403
    assert body["error"]["reason"] == "cross_tenant_access_denied"
    tenant_events = audit.query(TenantContext(TENANT_ID))
    assert tenant_events[-1].details["attempted_tenant_id"] == "tenant-beta"


def test_missing_invalid_or_duplicate_credentials_are_unauthorized_and_audited() -> (
    None
):
    app, _, audit = secured_app()

    missing_status, _, missing_headers = request("/v1/me", app=app)
    duplicate_status, duplicate_body, _ = request(
        "/v1/me",
        app=app,
        headers=[
            (b"authorization", b"Bearer one"),
            (b"authorization", b"Bearer two"),
        ],
    )

    assert missing_status == duplicate_status == 401
    assert duplicate_body["error"]["code"] == "missing_token"
    assert any(key == b"www-authenticate" for key, _ in missing_headers)
    assert len(audit.query(TenantContext(PLATFORM_TENANT_ID))) == 2


def test_protected_surface_has_no_fake_success_without_authentication() -> None:
    status, body, _ = request("/v1/me")

    assert status == 503
    assert body["error"]["code"] == "authentication_not_configured"


def test_method_and_unknown_routes_are_explicit() -> None:
    method_status, _, _ = request("/v1/me", method="POST")
    unknown_status, body, _ = request("/runs")

    assert method_status == 405
    assert unknown_status == 404
    assert body == {"status": "not-found"}


def test_authorized_ledger_and_timeline_are_bounded_and_redacted() -> None:
    item = EventEnvelope(
        event_id=uuid4(),
        tenant_id=str(TENANT_ID),
        aggregate_id="run-1",
        event_type=DomainEventType.RUN_STARTED,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        recorded_at=datetime(2025, 1, 1, tzinfo=UTC),
        aggregate_sequence=1,
        global_position=1,
        payload={
            "context": {
                "api_token": "do-not-return",
                "steps": [{"password": "never-return"}],
            },
            "status": "running",
        },
        metadata={
            "authorization": "Bearer very-secret",
            "nested": {"token": "hide-me"},
        },
    )
    store = TimelineEventStore(item)
    app, encoded, _ = secured_app(event_store=store)  # type: ignore[arg-type]

    ledger_status, ledger, _ = request(
        "/v1/tenants/tenant-alpha/ledger",
        app=app,
        authorization=f"Bearer {encoded}",
        query_string="cursor=0",
    )
    timeline_status, timeline, _ = request(
        "/v1/tenants/tenant-alpha/runs/run-1/timeline",
        app=app,
        authorization=f"Bearer {encoded}",
        query_string="cursor=0",
    )

    assert ledger_status == timeline_status == 200
    assert store.after_position == 0
    assert store.after_version == 0
    assert ledger["events"][0]["payload"]["context"]["api_token"] == REDACTED
    assert ledger["events"][0]["payload"]["context"]["steps"][0]["password"] == REDACTED
    assert ledger["events"][0]["metadata"]["authorization"] == REDACTED
    assert ledger["events"][0]["metadata"]["nested"]["token"] == REDACTED
    assert timeline["events"][0]["aggregate_sequence"] == 1
    assert timeline["next_cursor"] is None


def test_authentication_runs_in_a_worker_thread() -> None:
    class ThreadRecordingAuthentication:
        def __init__(self) -> None:
            self.thread_id: int | None = None

        def authenticate(self, authorization_header: str | None) -> Principal:
            self.thread_id = threading.get_ident()
            assert authorization_header == "Bearer test-token"
            return fixture_principal()

    authentication = ThreadRecordingAuthentication()
    app = ControlPlaneApp(authentication=authentication)

    status, body, _ = request(
        "/v1/me",
        app=app,
        authorization="Bearer test-token",
    )

    assert status == 200
    assert body["actor_id"] == "user-alice"
    assert authentication.thread_id is not None
    assert authentication.thread_id != threading.get_ident()


def test_storage_routes_fail_closed_when_adapter_is_not_configured() -> None:
    app, encoded, _ = secured_app()
    authorization = f"Bearer {encoded}"

    ledger_status, ledger, _ = request(
        "/v1/tenants/tenant-alpha/ledger",
        app=app,
        authorization=authorization,
    )
    projection_status, projection, _ = request(
        "/v1/tenants/tenant-alpha/projections/run-status",
        app=app,
        authorization=authorization,
    )

    assert ledger_status == projection_status == 503
    assert ledger["error"]["code"] == "storage_not_configured"
    assert projection["error"]["code"] == "storage_not_configured"


def test_storage_routes_translate_transient_store_failures() -> None:
    class FailingTimelineStore(TimelineEventStore):
        async def read_stream(
            self, *args: object, **kwargs: object
        ) -> AsyncIterator[EventEnvelope]:
            del args, kwargs
            raise TransientStorageError("database unavailable")
            yield  # type: ignore[unreachable]  # pragma: no cover

        async def read_all(self, *args: object, **kwargs: object) -> EventPage:
            del args, kwargs
            raise TransientStorageError("database unavailable")

    item = EventEnvelope(
        event_id=uuid4(),
        tenant_id=str(TENANT_ID),
        aggregate_id="run-1",
        event_type=DomainEventType.RUN_STARTED,
        schema_version=1,
        occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        payload={},
    )
    app, encoded, _ = secured_app(event_store=FailingTimelineStore(item))  # type: ignore[arg-type]

    ledger_status, ledger, _ = request(
        "/v1/tenants/tenant-alpha/ledger",
        app=app,
        authorization=f"Bearer {encoded}",
    )
    timeline_status, timeline, _ = request(
        "/v1/tenants/tenant-alpha/runs/run-1/timeline",
        app=app,
        authorization=f"Bearer {encoded}",
    )

    assert ledger_status == timeline_status == 503
    assert ledger["error"]["code"] == "storage_unavailable"
    assert timeline["error"]["code"] == "storage_unavailable"


def test_authentication_translates_transient_storage_failures() -> None:
    class FailingAuthentication:
        def authenticate(self, authorization_header: str | None) -> Principal:
            del authorization_header
            raise TransientStorageError("database unavailable")

    app, encoded, _ = secured_app(authentication=FailingAuthentication())

    status, body, _ = request("/v1/me", app=app, authorization=f"Bearer {encoded}")

    assert status == 503
    assert body["error"]["code"] == "storage_unavailable"


def test_projection_route_translates_transient_storage_failures() -> None:
    class FailingRunStatusReader:
        async def run_status(
            self, context: TenantContext, *, limit: int = 100
        ) -> tuple[Mapping[str, JsonValue], ...]:
            del context, limit
            raise TransientStorageError("database unavailable")

    app, encoded, _ = secured_app(projections=FailingRunStatusReader())

    status, body, _ = request(
        "/v1/tenants/tenant-alpha/projections/run-status",
        app=app,
        authorization=f"Bearer {encoded}",
    )

    assert status == 503
    assert body["error"]["code"] == "storage_unavailable"


def test_duplicate_tenant_records_are_rejected() -> None:
    tenant = Tenant(TENANT_ID, "Tenant Alpha")

    with pytest.raises(ValueError, match="duplicate tenant records"):
        InMemoryTenantRepository((tenant, tenant))


def test_authorized_model_catalog_usage_and_health_views_are_bounded() -> None:
    app, encoded, _ = secured_app(gateway_operations=model_operations())
    authorization = bearer(encoded)

    models_status, models, _ = request(
        "/v1/tenants/tenant-alpha/models",
        app=app,
        authorization=authorization,
    )
    usage_status, usage, _ = request(
        "/v1/tenants/tenant-alpha/model-usage",
        app=app,
        authorization=authorization,
    )
    health_status, health, _ = request(
        "/v1/tenants/tenant-alpha/provider-health",
        app=app,
        authorization=authorization,
    )

    assert models_status == usage_status == health_status == 200
    assert models["models"][0]["model"] == "model-safe"
    assert models["models"][0]["pricing_version"] == "mock-price-v1"
    assert usage == {"tokens": 12, "cost_usd": "0.001", "calls": 1}
    assert health["providers"][0]["circuit_state"] == "closed"
    assert "tenant_id" not in health["providers"][0]


def test_model_views_fail_closed_without_gateway_or_across_tenants() -> None:
    app, encoded, _ = secured_app()
    missing_status, missing, _ = request(
        "/v1/tenants/tenant-alpha/models",
        app=app,
        authorization=bearer(encoded),
    )
    secured, secured_encoded, _ = secured_app(gateway_operations=model_operations())
    denied_status, denied, _ = request(
        "/v1/tenants/tenant-beta/models",
        app=secured,
        authorization=bearer(secured_encoded),
    )

    assert missing_status == 503
    assert missing["error"]["code"] == "gateway_not_configured"
    assert denied_status == 403
    assert denied["error"]["code"] == "authorization_denied"


def test_ledger_rejects_invalid_cursor() -> None:
    app, encoded, _ = secured_app()

    status, body, _ = request(
        "/v1/tenants/tenant-alpha/ledger",
        app=app,
        authorization=f"Bearer {encoded}",
        query_string="cursor=-1",
    )

    assert status == 400
    assert body["error"]["code"] == "invalid_cursor"


def test_readiness_includes_configured_storage_dependency() -> None:
    async def available() -> bool:
        return True

    async def unavailable() -> bool:
        return False

    ready_status, ready, _ = request(
        "/health/ready",
        app=ControlPlaneApp(storage_ready=available),
    )
    failed_status, failed, _ = request(
        "/health/ready",
        app=ControlPlaneApp(storage_ready=unavailable),
    )

    assert ready_status == 200
    assert ready["checks"] == ["configuration", "storage"]
    assert failed_status == 503
    assert failed["reason"] == "storage_unavailable"
