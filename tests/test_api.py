"""Authenticated ASGI control-plane tests."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from aegis_agent_platform.audit import AuditEventType, InMemoryAuditStore
from aegis_agent_platform.control_plane.api import ControlPlaneApp, application
from aegis_agent_platform.identity import PLATFORM_TENANT_ID
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


def request(
    path: str,
    *,
    app: ControlPlaneApp = application,
    environment: dict[str, str] | None = None,
    authorization: str | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
    method: str = "GET",
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


def secured_app() -> tuple[ControlPlaneApp, str, InMemoryAuditStore]:
    signing = signing_fixture()
    audit = InMemoryAuditStore()
    app = ControlPlaneApp(
        authentication=authentication_service(signing),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=audit,
    )
    return app, token(signing), audit


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
    app, encoded, audit = secured_app()

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
    events = audit.query(TenantContext(TENANT_ID))
    assert [event.event_type for event in events] == [
        AuditEventType.AUTHENTICATION_OUTCOME
    ]


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
