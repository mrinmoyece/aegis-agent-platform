"""Authenticated ASGI control-plane tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest

from aegis_agent_platform.agents import (
    CanonicalCheckoutEngine,
    DurableCoordinator,
    InMemoryAgentRepository,
    canonical_checkout_citations,
    canonical_checkout_plan,
)
from aegis_agent_platform.agents.operations import AgentOperations
from aegis_agent_platform.audit import REDACTED, AuditEventType, InMemoryAuditStore
from aegis_agent_platform.config import Environment
from aegis_agent_platform.control_plane.api import ControlPlaneApp, application
from aegis_agent_platform.domain import (
    DomainEventType,
    EventEnvelope,
    JsonValue,
    ModelCapabilities,
    ModelIdentity,
    PartialResult,
    PricingVersion,
    WorkLease,
)
from aegis_agent_platform.event_store import EventPage, EventStore
from aegis_agent_platform.evidence import (
    ConnectorPage,
    EvidenceIngestor,
    EvidenceQueryService,
    InMemoryEvidenceRepository,
    InMemoryEvidenceStore,
)
from aegis_agent_platform.evidence.operations import (
    EvidenceOperations,
    InMemoryEvidenceBundleStore,
)
from aegis_agent_platform.gateway import (
    GatewayOperations,
    ModelCatalog,
    ModelCatalogEntry,
    ProviderControls,
)
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
    query_string: str = "",
    body: bytes = b"",
    body_chunks: tuple[bytes, ...] | None = None,
) -> tuple[int, dict[str, Any], list[tuple[bytes, bytes]]]:
    messages: list[dict[str, Any]] = []

    request_bodies = body_chunks or (body,)
    request_index = 0

    async def receive() -> dict[str, Any]:
        nonlocal request_index
        request_body = request_bodies[request_index]
        request_index += 1
        return {
            "type": "http.request",
            "body": request_body,
            "more_body": request_index < len(request_bodies),
        }

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
    response_body = json.loads(messages[1]["body"])
    return status, response_body, response_headers


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
    gateway_operations: GatewayOperations | None = None,
    evidence_operations: EvidenceOperations | None = None,
    agent_operations: AgentOperations | None = None,
) -> tuple[ControlPlaneApp, str, InMemoryAuditStore]:
    signing = signing_fixture()
    audit = InMemoryAuditStore()
    app = ControlPlaneApp(
        authentication=authentication_service(signing),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=audit,
        event_store=event_store,
        gateway_operations=gateway_operations,
        evidence_operations=evidence_operations,
        agent_operations=agent_operations,
    )
    return app, token(signing), audit


class EmptyEvidenceConnector:
    source = "dynatrace"

    async def query(self, *args: object, **kwargs: object) -> ConnectorPage:
        del args, kwargs
        return ConnectorPage((), None, PartialResult(False, False))

    async def capability(self) -> object:
        raise NotImplementedError


def evidence_operations() -> EvidenceOperations:
    records = InMemoryEvidenceStore()
    service = EvidenceQueryService(
        connectors={"dynatrace": EmptyEvidenceConnector()},  # type: ignore[dict-item]
        repository=InMemoryEvidenceRepository(),
        ingestor=EvidenceIngestor(records),
    )
    return EvidenceOperations(
        service,
        records,
        InMemoryEvidenceBundleStore(),
    )


class StaticUsageReader:
    def usage_summary(self, tenant_id: str) -> dict[str, JsonValue]:
        assert tenant_id == str(TENANT_ID)
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
    events = audit.query(TenantContext(TENANT_ID))
    assert [event.event_type for event in events] == [
        AuditEventType.AUTHENTICATION_OUTCOME,
        AuditEventType.AUTHORIZATION_DECISION,
        AuditEventType.AUTHENTICATION_OUTCOME,
        AuditEventType.AUTHORIZATION_DECISION,
    ]


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
        payload={"api_token": "do-not-return", "status": "running"},
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
    assert ledger["events"][0]["payload"]["api_token"] == REDACTED
    assert timeline["events"][0]["aggregate_sequence"] == 1
    assert timeline["next_cursor"] is None


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


def test_evidence_api_accepts_durable_work_and_exposes_bounded_views() -> None:
    from aegis_agent_platform.identity import Role
    from security_helpers import binding, identity_record

    signing = signing_fixture()
    app = ControlPlaneApp(
        authentication=authentication_service(
            signing,
            records=(identity_record((binding(Role.INVESTIGATOR),)),),
        ),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=InMemoryAuditStore(),
        evidence_operations=evidence_operations(),
    )
    authorization = bearer(token(signing))
    payload = json.dumps(
        {
            "source": "dynatrace",
            "environment": "production",
            "start": "2026-08-13T08:00:00+00:00",
            "end": "2026-08-13T09:00:00+00:00",
            "kinds": ["log"],
            "selectors": {"service": "checkout"},
            "limit": 50,
            "cursor": "2",
            "idempotency_key": "api-evidence-1",
        }
    ).encode()

    created_status, created, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=app,
        authorization=authorization,
        method="POST",
        body=payload,
    )
    duplicate_status, duplicate, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=app,
        authorization=authorization,
        method="POST",
        body=payload,
    )
    capabilities_status, capabilities, _ = request(
        "/v1/tenants/tenant-alpha/evidence/capabilities",
        app=app,
        authorization=authorization,
    )
    query_status, status, _ = request(
        f"/v1/tenants/tenant-alpha/evidence/queries/{created['query_id']}",
        app=app,
        authorization=authorization,
    )

    assert created_status == 202
    assert created["status"] == "requested"
    assert duplicate_status == 200
    assert duplicate == {
        "query_id": created["query_id"],
        "accepted": False,
        "status": "duplicate",
    }
    assert capabilities_status == query_status == 200
    assert capabilities["capabilities"][0]["source"] == "dynatrace"
    assert status["event_type"] == "evidence.query_requested.v1"


def test_evidence_api_fails_closed_and_validates_identifiers_and_payloads() -> None:
    from aegis_agent_platform.identity import Role
    from security_helpers import binding, identity_record

    signing = signing_fixture()
    authorization = bearer(token(signing))
    authentication = authentication_service(
        signing,
        records=(identity_record((binding(Role.INVESTIGATOR),)),),
    )
    tenants = InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),))
    policies = InMemoryPolicyRepository((tenant_policy(),))
    unavailable = ControlPlaneApp(
        authentication=authentication,
        tenants=tenants,
        policies=policies,
        audit=InMemoryAuditStore(),
    )
    configured = ControlPlaneApp(
        authentication=authentication,
        tenants=tenants,
        policies=policies,
        audit=InMemoryAuditStore(),
        evidence_operations=evidence_operations(),
    )

    missing_status, missing, _ = request(
        "/v1/tenants/tenant-alpha/evidence/records",
        app=unavailable,
        authorization=authorization,
    )
    invalid_body_status, invalid_body, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=configured,
        authorization=authorization,
        method="POST",
        body=b"not-json",
    )
    invalid_id_status, invalid_id, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries/not-a-uuid",
        app=configured,
        authorization=authorization,
    )
    missing_query_status, missing_query, _ = request(
        f"/v1/tenants/tenant-alpha/evidence/queries/{uuid4()}",
        app=configured,
        authorization=authorization,
    )
    missing_bundle_status, missing_bundle, _ = request(
        "/v1/tenants/tenant-alpha/evidence/bundles/missing",
        app=configured,
        authorization=authorization,
    )
    records_status, records, _ = request(
        "/v1/tenants/tenant-alpha/evidence/records",
        app=configured,
        authorization=authorization,
    )
    citations_status, citations, _ = request(
        "/v1/tenants/tenant-alpha/evidence/citations",
        app=configured,
        authorization=authorization,
    )

    assert missing_status == 503
    assert missing["error"]["code"] == "evidence_not_configured"
    assert invalid_body_status == 400
    assert invalid_body["error"]["code"] == "invalid_evidence_query"
    assert invalid_id_status == 400
    assert invalid_id["error"]["code"] == "invalid_query_id"
    assert missing_query_status == missing_bundle_status == 404
    assert missing_query["error"]["code"] == "query_not_found"
    assert missing_bundle["error"]["code"] == "bundle_not_found"
    assert records_status == citations_status == 200
    assert records["records"] == citations["citations"] == []


def test_evidence_api_enforces_query_rbac_policy_and_cursor_bounds() -> None:
    signing = signing_fixture()
    authorization = bearer(token(signing))
    operations = evidence_operations()
    viewer_app = ControlPlaneApp(
        authentication=authentication_service(signing),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=InMemoryAuditStore(),
        evidence_operations=operations,
    )
    payload = json.dumps(
        {
            "source": "dynatrace",
            "environment": "production",
            "start": "2026-08-13T08:00:00+00:00",
            "end": "2026-08-13T09:00:00+00:00",
            "kinds": ["log"],
            "selectors": {"service": "checkout"},
            "idempotency_key": "viewer-denied",
        }
    ).encode()
    denied_status, denied, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=viewer_app,
        authorization=authorization,
        method="POST",
        body=payload,
    )
    cursor_status, cursor, _ = request(
        "/v1/tenants/tenant-alpha/evidence/records",
        app=viewer_app,
        authorization=authorization,
        query_string="cursor=-1",
    )
    no_policy_app = ControlPlaneApp(
        authentication=authentication_service(signing),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository(()),
        audit=InMemoryAuditStore(),
        evidence_operations=operations,
    )
    policy_status, policy_body, _ = request(
        "/v1/tenants/tenant-alpha/evidence/capabilities",
        app=no_policy_app,
        authorization=authorization,
    )

    assert denied_status == 403
    assert denied["error"]["code"] == "authorization_denied"
    assert cursor_status == 400
    assert cursor["error"]["code"] == "invalid_cursor"
    assert policy_status == 503
    assert policy_body["error"]["code"] == "policy_not_configured"


def test_evidence_api_accepts_chunked_json_and_rejects_idempotency_reuse() -> None:
    from aegis_agent_platform.identity import Role
    from security_helpers import binding, identity_record

    signing = signing_fixture()
    authorization = bearer(token(signing))
    app = ControlPlaneApp(
        authentication=authentication_service(
            signing,
            records=(identity_record((binding(Role.INVESTIGATOR),)),),
        ),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=InMemoryAuditStore(),
        evidence_operations=evidence_operations(),
    )
    payload = {
        "source": "dynatrace",
        "environment": "production",
        "start": "2026-08-13T08:00:00+00:00",
        "end": "2026-08-13T09:00:00+00:00",
        "kinds": ["log"],
        "selectors": {"service": "checkout"},
        "idempotency_key": "chunked-request",
        "limit": 10,
    }
    encoded = json.dumps(payload).encode()

    accepted_status, _, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=app,
        authorization=authorization,
        method="POST",
        body_chunks=(encoded[:20], encoded[20:]),
    )
    payload["limit"] = 11
    conflict_status, conflict, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=app,
        authorization=authorization,
        method="POST",
        body=json.dumps(payload).encode(),
    )
    payload["idempotency_key"] = None
    invalid_status, invalid, _ = request(
        "/v1/tenants/tenant-alpha/evidence/queries",
        app=app,
        authorization=authorization,
        method="POST",
        body=json.dumps(payload).encode(),
    )

    assert accepted_status == 202
    assert conflict_status == 409
    assert conflict["error"]["code"] == "evidence_idempotency_key_reused"
    assert invalid_status == 400
    assert invalid["error"]["code"] == "invalid_evidence_query"


def test_evidence_page_cursor_round_trips_highwater_and_position() -> None:
    from aegis_agent_platform.control_plane.api import (
        _encode_evidence_cursor,
        _evidence_cursor_parameter,
    )

    encoded = _encode_evidence_cursor((250, 100))

    decoded = _evidence_cursor_parameter({"query_string": f"cursor={encoded}".encode()})

    assert decoded == (250, 100)
    with pytest.raises(ValueError, match="query string must be bytes"):
        _evidence_cursor_parameter({"query_string": "cursor=invalid"})
    with pytest.raises(ValueError, match="cursor must occur once"):
        _evidence_cursor_parameter({"query_string": b"cursor=a&cursor=b"})
    with pytest.raises(ValueError, match="cursor is invalid"):
        _evidence_cursor_parameter({"query_string": b"cursor=not-base64"})


def test_investigation_views_are_authorized_redacted_and_paginated() -> None:
    async def seed() -> tuple[InMemoryAgentRepository, str]:
        now = datetime.now(UTC)
        run_id = uuid4()
        repository = InMemoryAgentRepository()
        coordinator = DurableCoordinator(
            repository,
            CanonicalCheckoutEngine(clock=lambda: now),
            clock=lambda: now,
        )
        plan = canonical_checkout_plan(
            tenant_id=str(TENANT_ID),
            incident_id="checkout-api",
            run_id=run_id,
            created_at=now,
        )
        await coordinator.request(
            TenantContext(TENANT_ID),
            plan,
            actor_id="api-test",
            idempotency_key=f"api-investigation:{run_id}",
        )
        lease = WorkLease(
            run_id,
            str(TENANT_ID),
            uuid4(),
            1,
            "api-worker",
            1,
            now,
            now,
            now + timedelta(minutes=5),
        )
        repository.register_lease(lease)
        await coordinator.execute(
            TenantContext(TENANT_ID),
            run_id,
            lease,
            canonical_checkout_citations(),
        )
        return repository, str(run_id)

    repository, run_id = asyncio.run(seed())
    app, encoded, _audit = secured_app(
        agent_operations=AgentOperations(repository),
    )
    prefix = f"/v1/tenants/{TENANT_ID}/investigations/{run_id}"

    status, body, _headers = request(
        prefix,
        app=app,
        authorization=bearer(encoded),
    )
    assert status == 200
    assert body["status"] == "succeeded"

    tasks_status, tasks, _headers = request(
        prefix + "/tasks",
        app=app,
        authorization=bearer(encoded),
        query_string="cursor=0",
    )
    assert tasks_status == 200
    assert len(tasks["tasks"]) == 10
    assert tasks["tasks"][0]["ordinal"] == 0

    artifacts_status, artifacts, _headers = request(
        prefix + "/artifacts",
        app=app,
        authorization=bearer(encoded),
    )
    assert artifacts_status == 200
    assert artifacts["artifacts"]
    assert all(item["redacted"] is True for item in artifacts["artifacts"])
    assert all("artifact_content" not in item for item in artifacts["artifacts"])

    invalid_status, invalid, _headers = request(
        prefix + "/artifacts",
        app=app,
        authorization=bearer(encoded),
        query_string="cursor=-1",
    )
    assert invalid_status == 400
    assert invalid["error"]["code"] == "invalid_cursor"
