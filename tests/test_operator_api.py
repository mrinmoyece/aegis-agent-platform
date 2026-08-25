"""Secure operator BFF, session, contract, and demo tests."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aegis_agent_platform.audit import AuditEventType, InMemoryAuditStore
from aegis_agent_platform.identity import (
    AuthorizationService,
    Principal,
    Role,
    TenantId,
)
from aegis_agent_platform.operator import (
    ApprovalDecisionCommand,
    ApprovalDecisionResult,
    DemoOperatorCommands,
    DemoOperatorViews,
    InMemoryOperatorSessionStore,
    OidcAuthorizationStateStore,
    OperatorBffApp,
    OperatorEventPage,
    OperatorSession,
    OperatorSnapshot,
    canonical_operator_snapshot,
)
from aegis_agent_platform.operator.contracts import DataAuthority, OperatorItem
from aegis_agent_platform.operator.demo import (
    DEMO_MCP_PEER_DIGEST,
    DEMO_PLAN_DIGEST,
    DEMO_POLICY_DIGEST,
)
from aegis_agent_platform.tenancy import TenantContext
from security_helpers import TENANT_ID, binding, identity_record

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 13, 8, 42, tzinfo=UTC)
ORIGIN = "http://127.0.0.1:4173"


class Tokens:
    def __init__(self) -> None:
        self._counter = 0

    def __call__(self) -> str:
        self._counter += 1
        return f"token-{self._counter:04d}-" + "x" * 48


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def principal() -> Principal:
    return identity_record(
        (
            binding(Role.APPROVER, assigned_at=NOW - timedelta(hours=1)),
            binding(Role.OPERATOR, assigned_at=NOW - timedelta(hours=1)),
            binding(Role.TENANT_ADMIN, assigned_at=NOW - timedelta(hours=1)),
        ),
    ).to_principal()


def operator_app() -> tuple[OperatorBffApp, InMemoryAuditStore]:
    audit = InMemoryAuditStore()
    app = OperatorBffApp(
        sessions=InMemoryOperatorSessionStore(token_factory=Tokens()),
        views=DemoOperatorViews(),
        commands=DemoOperatorCommands(),
        authorization=AuthorizationService(),
        audit=audit,
        demo_principal=principal(),
        allowed_origins=frozenset({ORIGIN}),
        clock=lambda: NOW,
    )
    return app, audit


def request(
    app: OperatorBffApp,
    path: str,
    *,
    method: str = "GET",
    headers: list[tuple[bytes, bytes]] | None = None,
    query_string: str = "",
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, Any], list[tuple[bytes, bytes]]]:
    messages: list[dict[str, Any]] = []
    encoded = json.dumps(body or {}).encode()

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": encoded, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(
        app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "query_string": query_string.encode(),
                "headers": headers or [],
            },
            receive,
            send,
        )
    )
    status = messages[0]["status"]
    response_headers = messages[0]["headers"]
    response_body = messages[1]["body"]
    return (
        status,
        json.loads(response_body) if response_body else {},
        response_headers,
    )


def raw_request(
    app: OperatorBffApp,
    scope: dict[str, Any],
    incoming: list[dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return incoming.pop(0)

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    body = messages[1]["body"]
    return messages[0]["status"], json.loads(body) if body else {}


def session(app: OperatorBffApp) -> tuple[str, str]:
    status, body, headers = request(
        app,
        "/operator/api/demo/session",
        method="POST",
        headers=[(b"origin", ORIGIN.encode())],
    )
    assert status == 201
    cookie = next(value for key, value in headers if key == b"set-cookie")
    csrf = body["csrf_token"]
    assert isinstance(csrf, str)
    return cookie.decode().split(";", 1)[0], csrf


def security_header_names(headers: list[tuple[bytes, bytes]]) -> set[bytes]:
    return {name for name, _ in headers}


def test_operator_config_is_honest_and_security_headers_are_complete() -> None:
    app, _ = operator_app()

    status, body, headers = request(app, "/operator/api/config")

    assert status == 200
    assert body["production_ready"] is False
    assert body["auth_mode"] == "deterministic_demo"
    assert body["oidc_boundary"]["live_exchange_configured"] is False
    assert {
        b"content-security-policy",
        b"strict-transport-security",
        b"x-content-type-options",
        b"x-frame-options",
        b"referrer-policy",
        b"permissions-policy",
        b"cache-control",
        b"x-request-id",
    } <= security_header_names(headers)
    csp = next(value for name, value in headers if name == b"content-security-policy")
    assert b"unsafe-inline" not in csp
    assert b"unsafe-eval" not in csp


def test_session_cookie_is_http_only_secure_same_site_and_origin_bound() -> None:
    app, _ = operator_app()

    denied, _, _ = request(
        app,
        "/operator/api/demo/session",
        method="POST",
        headers=[(b"origin", b"https://attacker.invalid")],
    )
    cookie, _ = session(app)

    assert denied == 403
    status, _, headers = request(
        app,
        "/operator/api/demo/session",
        method="POST",
        headers=[(b"origin", ORIGIN.encode())],
    )
    assert status == 201
    set_cookie = next(value for name, value in headers if name == b"set-cookie")
    assert b"Secure" in set_cookie
    assert b"HttpOnly" in set_cookie
    assert b"SameSite=Strict" in set_cookie
    assert cookie.startswith("__Host-aegis-session=")


def test_session_store_expires_rotates_and_never_indexes_raw_cookie() -> None:
    tokens = Tokens()
    store = InMemoryOperatorSessionStore(token_factory=tokens)
    handle = store.create(principal(), now=NOW)

    resolved = store.resolve(handle.session_id, now=NOW + timedelta(minutes=11))

    assert resolved is not None
    assert store.needs_rotation(resolved, now=NOW + timedelta(minutes=11))
    rotated = store.rotate(
        handle.session_id,
        resolved,
        now=NOW + timedelta(minutes=11),
    )
    assert rotated.session_id != handle.session_id
    assert store.resolve(handle.session_id, now=NOW + timedelta(minutes=11)) is None
    assert (
        store.resolve(
            rotated.session_id,
            now=NOW + timedelta(minutes=42),
        )
        is None
    )


def test_oidc_pkce_state_nonce_are_one_use_bounded_and_local_redirect_only() -> None:
    store = OidcAuthorizationStateStore(token_factory=Tokens())
    handle = store.begin(return_path="/incidents/checkout", now=NOW)

    assert len(handle.record.code_challenge) == 43
    record = store.consume(
        state=handle.state,
        nonce=handle.nonce,
        code_verifier=handle.code_verifier,
        now=NOW + timedelta(minutes=1),
    )
    assert record.return_path == "/incidents/checkout"
    with pytest.raises(ValueError, match="missing or expired"):
        store.consume(
            state=handle.state,
            nonce=handle.nonce,
            code_verifier=handle.code_verifier,
            now=NOW + timedelta(minutes=1),
        )

    for hostile in ("https://attacker.invalid", "//attacker.invalid", ""):
        try:
            store.begin(return_path=hostile, now=NOW)
        except ValueError:
            pass
        else:
            raise AssertionError("hostile return path was accepted")


def test_snapshot_is_tenant_scoped_bounded_audited_and_openapi_valid() -> None:
    app, audit = operator_app()
    cookie, _ = session(app)

    status, body, headers = request(
        app,
        "/operator/api/tenants/tenant-alpha/snapshot",
        headers=[(b"cookie", cookie.encode())],
    )

    assert status == 200
    assert body["tenant_id"] == "tenant-alpha"
    assert body["demo"] is True
    assert len(body["sections"]) == 13
    assert all(len(items) <= 100 for items in body["sections"].values())
    assert (b"etag", b'"46"') in headers
    document = json.loads(
        (ROOT / "contracts" / "operator-api.openapi.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(
        {
            "$ref": "#/components/schemas/OperatorSnapshot",
            "components": document["components"],
        }
    )
    validator.validate(body)
    events = audit.query(TenantContext(TENANT_ID))
    assert events[-1].event_type is AuditEventType.OPERATOR_PRIVILEGED_READ


def test_cross_tenant_request_is_anti_enumerating_and_audited() -> None:
    app, audit = operator_app()
    cookie, _ = session(app)

    status, body, _ = request(
        app,
        "/operator/api/tenants/tenant-beta/snapshot",
        headers=[(b"cookie", cookie.encode())],
    )

    assert status == 404
    assert body["error"]["code"] == "not_found"
    event = audit.query(TenantContext(TENANT_ID))[-1]
    assert event.outcome.value == "denied"
    assert event.resource == "tenant/tenant-beta/operator"


def test_mutation_requires_csrf_origin_permission_and_exact_scope() -> None:
    app, _ = operator_app()
    cookie, csrf = session(app)
    body: dict[str, object] = {
        "approval_id": "approval-checkout-001",
        "plan_digest": DEMO_PLAN_DIGEST,
        "policy_digest": DEMO_POLICY_DIGEST,
        "decision": "grant",
        "rationale_code": "scope_reviewed",
        "comment": "Exact scope reviewed.",
    }
    common = [
        (b"cookie", cookie.encode()),
        (b"origin", ORIGIN.encode()),
        (b"x-csrf-token", csrf.encode()),
        (b"idempotency-key", b"decision-001"),
        (b"if-match", b'"approval-v3"'),
    ]

    missing_csrf, _, _ = request(
        app,
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record",
        method="POST",
        headers=[item for item in common if item[0] != b"x-csrf-token"],
        body=body,
    )
    stale, stale_body, _ = request(
        app,
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record",
        method="POST",
        headers=common,
        body={**body, "plan_digest": "0" * 64},
    )

    assert missing_csrf == 403
    assert stale == 422
    assert stale_body["error"]["code"] == "invalid_or_stale_approval_scope"


def test_mutation_deduplicates_and_never_reports_false_success() -> None:
    app, audit = operator_app()
    cookie, csrf = session(app)
    headers = [
        (b"cookie", cookie.encode()),
        (b"origin", ORIGIN.encode()),
        (b"x-csrf-token", csrf.encode()),
        (b"idempotency-key", b"decision-002"),
        (b"if-match", b'"approval-v3"'),
    ]
    body: dict[str, object] = {
        "approval_id": "approval-checkout-001",
        "plan_digest": DEMO_PLAN_DIGEST,
        "policy_digest": DEMO_POLICY_DIGEST,
        "decision": "grant",
        "rationale_code": "scope_reviewed",
        "comment": "Exact scope reviewed.",
    }
    path = (
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record"
    )

    first_status, first, first_headers = request(
        app,
        path,
        method="POST",
        headers=headers,
        body=body,
    )
    duplicate_status, duplicate, _ = request(
        app,
        path,
        method="POST",
        headers=headers,
        body=body,
    )

    assert first_status == duplicate_status == 202
    assert first["status"] == "decision_recorded"
    assert first["verification"] == "pending"
    assert "success" not in first
    assert duplicate["duplicate"] is True
    assert (b"etag", b'"approval-v4"') in first_headers
    assert audit.query(TenantContext(TENANT_ID))[-1].event_type is (
        AuditEventType.OPERATOR_MUTATION
    )


def test_peer_trust_change_requires_exact_digest_version_csrf_and_permission() -> None:
    app, audit = operator_app()
    cookie, csrf = session(app)
    path = (
        "/operator/api/tenants/tenant-alpha/protocol-peers/"
        "peer-mcp-deterministic/trust/record"
    )
    headers = [
        (b"cookie", cookie.encode()),
        (b"origin", ORIGIN.encode()),
        (b"x-csrf-token", csrf.encode()),
        (b"idempotency-key", b"peer-trust-001"),
        (b"if-match", b'"peer-v1"'),
    ]
    body: dict[str, object] = {
        "peer_id": "peer-mcp-deterministic",
        "peer_digest": DEMO_MCP_PEER_DIGEST,
        "decision": "quarantine",
        "rationale_code": "capability-review",
    }

    stale_status, stale, _ = request(
        app,
        path,
        method="POST",
        headers=headers,
        body={**body, "peer_digest": "0" * 64},
    )
    status, result, response_headers = request(
        app,
        path,
        method="POST",
        headers=headers,
        body=body,
    )
    duplicate_status, duplicate, _ = request(
        app,
        path,
        method="POST",
        headers=headers,
        body=body,
    )

    assert stale_status == 422
    assert stale["error"]["code"] == "invalid_or_stale_peer_scope"
    assert status == duplicate_status == 202
    assert result["status"] == "quarantined"
    assert duplicate["duplicate"] is True
    assert (b"etag", b'"peer-v2"') in response_headers
    assert audit.query(TenantContext(TENANT_ID))[-1].resource == (
        "tenant/tenant-alpha/operator"
    )


def test_event_cursor_is_bounded_ordered_and_rejects_hostile_values() -> None:
    app, _ = operator_app()
    cookie, _ = session(app)

    status, body, _ = request(
        app,
        "/operator/api/tenants/tenant-alpha/events",
        headers=[(b"cookie", cookie.encode())],
        query_string="cursor=2",
    )
    invalid_status, _, _ = request(
        app,
        "/operator/api/tenants/tenant-alpha/events",
        headers=[(b"cookie", cookie.encode())],
        query_string="cursor=-1",
    )

    assert status == 200
    assert len(body["events"]) <= 100
    assert body["events"] == sorted(
        body["events"],
        key=lambda item: (item["occurred_at"], item["id"]),
    )
    assert invalid_status == 400


def test_operator_contracts_reject_unbounded_or_ambiguous_values() -> None:
    item = OperatorItem(
        "event-1",
        "event",
        "Deployment observed",
        "A bounded event fact.",
        "observed",
        DataAuthority.EVENT_FACT,
        NOW,
    )
    with pytest.raises(ValueError, match="item_id"):
        replace(item, item_id="../event")
    with pytest.raises(ValueError, match="title"):
        replace(item, title=" ")
    with pytest.raises(ValueError, match="timezone"):
        replace(item, occurred_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="metadata"):
        replace(item, metadata={str(index): index for index in range(33)})

    snapshot = OperatorSnapshot(
        1, "tenant-alpha", NOW, "1", False, True, {"x": (item,)}
    )
    assert snapshot.to_dict()["sections"]
    with pytest.raises(ValueError, match="schema"):
        replace(snapshot, schema_version=2)
    with pytest.raises(ValueError, match="timezone"):
        replace(snapshot, generated_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="sections"):
        replace(snapshot, sections={})
    with pytest.raises(ValueError, match="item bound"):
        replace(snapshot, sections={"x": (item,) * 101})

    page = OperatorEventPage((item,), "2", NOW)
    assert page.to_dict()["next_cursor"] == "2"
    with pytest.raises(ValueError, match="item bound"):
        replace(page, events=(item,) * 101)
    with pytest.raises(ValueError, match="timezone"):
        replace(page, server_time=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="next_cursor"):
        replace(page, next_cursor=" ")

    command = ApprovalDecisionCommand(
        "approval-1",
        "a" * 64,
        "b" * 64,
        "grant",
        "reviewed",
        "bounded",
        "version-1",
        "idempotency-1",
    )
    with pytest.raises(ValueError, match="plan_digest"):
        replace(command, plan_digest="A" * 64)
    with pytest.raises(ValueError, match="decision"):
        replace(command, decision="approve")
    with pytest.raises(ValueError, match="comment"):
        replace(command, comment="x" * 1_001)

    result = ApprovalDecisionResult(
        "approval-1",
        "decision_recorded",
        "pending",
        "version-2",
        False,
        NOW,
    )
    assert result.to_dict()["verification"] == "pending"
    with pytest.raises(ValueError, match="timezone"):
        replace(result, server_time=NOW.replace(tzinfo=None))


def test_session_and_oidc_models_fail_closed_on_invalid_material() -> None:
    with pytest.raises(ValueError, match="timezone"):
        OperatorSession("a", "b", principal(), NOW.replace(tzinfo=None), NOW, NOW)
    with pytest.raises(ValueError, match="expiry"):
        OperatorSession("a", "b", principal(), NOW, NOW, NOW)
    with pytest.raises(ValueError, match="rotation"):
        OperatorSession("a", "b", principal(), NOW, NOW + timedelta(minutes=1), NOW, -1)

    short_store = InMemoryOperatorSessionStore(token_factory=lambda: "short")
    with pytest.raises(ValueError, match="at least 32"):
        short_store.create(principal(), now=NOW)
    store = InMemoryOperatorSessionStore(token_factory=Tokens())
    handle = store.create(principal(), now=NOW)
    assert store.resolve("missing-" + "x" * 48, now=NOW) is None
    assert store.validate_csrf(handle.session, None) is False
    assert store.validate_csrf(handle.session, "wrong-" + "x" * 48) is False
    store.invalidate(None)

    short_oidc = OidcAuthorizationStateStore(token_factory=lambda: "short")
    with pytest.raises(ValueError, match="at least 43"):
        short_oidc.begin(return_path="/incidents", now=NOW)
    for mismatch in ("nonce", "verifier"):
        oidc = OidcAuthorizationStateStore(token_factory=Tokens())
        authorization = oidc.begin(return_path="/incidents", now=NOW)
        with pytest.raises(ValueError, match=mismatch):
            oidc.consume(
                state=authorization.state,
                nonce="wrong" if mismatch == "nonce" else authorization.nonce,
                code_verifier=(
                    "wrong" if mismatch == "verifier" else authorization.code_verifier
                ),
                now=NOW,
            )
    expired = OidcAuthorizationStateStore(token_factory=Tokens())
    authorization = expired.begin(return_path="/incidents", now=NOW)
    with pytest.raises(ValueError, match="expired"):
        expired.consume(
            state=authorization.state,
            nonce=authorization.nonce,
            code_verifier=authorization.code_verifier,
            now=NOW + timedelta(minutes=6),
        )


def test_bff_session_logout_routing_and_production_boundary() -> None:
    with pytest.raises(ValueError, match="trusted origins"):
        OperatorBffApp(
            sessions=InMemoryOperatorSessionStore(),
            views=DemoOperatorViews(),
            commands=None,
            authorization=AuthorizationService(),
            audit=InMemoryAuditStore(),
            demo_principal=principal(),
            allowed_origins=frozenset({"http://attacker.invalid"}),
        )
    with pytest.raises(ValueError, match="production ready"):
        OperatorBffApp(
            sessions=InMemoryOperatorSessionStore(),
            views=DemoOperatorViews(),
            commands=None,
            authorization=AuthorizationService(),
            audit=InMemoryAuditStore(),
            demo_principal=principal(),
            allowed_origins=frozenset({"https://operator.example"}),
            production_ready=True,
        )

    app, _ = operator_app()
    missing_status, missing, _ = request(app, "/outside")
    unauthenticated, body, unauthenticated_headers = request(
        app, "/operator/api/tenants/tenant-alpha/snapshot"
    )
    cookie, csrf = session(app)
    current, current_body, _ = request(
        app,
        "/operator/api/session",
        headers=[(b"cookie", cookie.encode())],
    )
    denied_logout, _, _ = request(
        app,
        "/operator/api/session/logout",
        method="POST",
        headers=[(b"cookie", cookie.encode())],
    )
    logout, _, logout_headers = request(
        app,
        "/operator/api/session/logout",
        method="POST",
        headers=[
            (b"cookie", cookie.encode()),
            (b"origin", ORIGIN.encode()),
            (b"x-csrf-token", csrf.encode()),
        ],
    )
    expired, _, _ = request(
        app,
        "/operator/api/session",
        headers=[(b"cookie", cookie.encode())],
    )

    assert missing_status == 404
    assert missing["error"]["code"] == "not_found"
    assert unauthenticated == 401
    assert body["error"]["code"] == "session_required"
    assert (b"www-authenticate", b'Session realm="operator"') in unauthenticated_headers
    assert current == 200
    assert current_body["csrf_token"] is None
    assert denied_logout == 403
    assert logout == 204
    assert any(
        b"Max-Age=0" in value for name, value in logout_headers if name == b"set-cookie"
    )
    assert expired == 401

    production = OperatorBffApp(
        sessions=InMemoryOperatorSessionStore(),
        views=DemoOperatorViews(),
        commands=None,
        authorization=AuthorizationService(),
        audit=InMemoryAuditStore(),
        demo_principal=None,
        allowed_origins=frozenset({"https://operator.example"}),
        clock=lambda: NOW,
        production_ready=True,
    )
    config_status, config, _ = request(production, "/operator/api/config")
    demo_status, _, _ = request(
        production,
        "/operator/api/demo/session",
        method="POST",
        headers=[(b"origin", b"https://operator.example")],
    )
    assert config_status == 200
    assert config["auth_mode"] == "oidc_bff"
    assert demo_status == 404


def test_bff_denials_missing_commands_and_invalid_mutations() -> None:
    denied_principal = identity_record(
        (binding(Role.APPROVER, assigned_at=NOW + timedelta(hours=1)),)
    ).to_principal()
    denied = OperatorBffApp(
        sessions=InMemoryOperatorSessionStore(token_factory=Tokens()),
        views=DemoOperatorViews(),
        commands=DemoOperatorCommands(),
        authorization=AuthorizationService(),
        audit=InMemoryAuditStore(),
        demo_principal=denied_principal,
        allowed_origins=frozenset({ORIGIN}),
        clock=lambda: NOW,
    )
    denied_cookie, _ = session(denied)
    denied_status, _, _ = request(
        denied,
        "/operator/api/tenants/tenant-alpha/snapshot",
        headers=[(b"cookie", denied_cookie.encode())],
    )
    assert denied_status == 403

    no_commands = OperatorBffApp(
        sessions=InMemoryOperatorSessionStore(token_factory=Tokens()),
        views=DemoOperatorViews(),
        commands=None,
        authorization=AuthorizationService(),
        audit=InMemoryAuditStore(),
        demo_principal=principal(),
        allowed_origins=frozenset({ORIGIN}),
        clock=lambda: NOW,
    )
    cookie, csrf = session(no_commands)
    path = (
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record"
    )
    headers = [
        (b"cookie", cookie.encode()),
        (b"origin", ORIGIN.encode()),
        (b"x-csrf-token", csrf.encode()),
        (b"idempotency-key", b"decision-003"),
        (b"if-match", b'"approval-v3"'),
    ]
    unavailable, unavailable_body, _ = request(
        no_commands,
        path,
        method="POST",
        headers=headers,
        body={},
    )
    assert unavailable == 503
    assert unavailable_body["error"]["retryable"] is True

    app, _ = operator_app()
    cookie, csrf = session(app)
    missing_headers, _, _ = request(
        app,
        path,
        method="POST",
        headers=[
            (b"cookie", cookie.encode()),
            (b"origin", ORIGIN.encode()),
            (b"x-csrf-token", csrf.encode()),
        ],
        body={},
    )
    mismatched, _, _ = request(
        app,
        path,
        method="POST",
        headers=[
            (b"cookie", cookie.encode()),
            (b"origin", ORIGIN.encode()),
            (b"x-csrf-token", csrf.encode()),
            (b"idempotency-key", b"decision-004"),
            (b"if-match", b'"approval-v3"'),
        ],
        body={"approval_id": "another-approval"},
    )
    unknown, _, _ = request(
        app,
        "/operator/api/tenants/tenant-alpha/unknown",
        headers=[(b"cookie", cookie.encode())],
    )
    assert missing_headers == 422
    assert mismatched == 422
    assert unknown == 404


def test_bff_covers_denied_events_conflicts_rotation_and_invalid_routes() -> None:
    denied_principal = identity_record(
        (binding(Role.APPROVER, assigned_at=NOW + timedelta(hours=1)),)
    ).to_principal()
    denied = OperatorBffApp(
        sessions=InMemoryOperatorSessionStore(token_factory=Tokens()),
        views=DemoOperatorViews(),
        commands=DemoOperatorCommands(),
        authorization=AuthorizationService(),
        audit=InMemoryAuditStore(),
        demo_principal=denied_principal,
        allowed_origins=frozenset({ORIGIN}),
        clock=lambda: NOW,
    )
    denied_cookie, denied_csrf = session(denied)
    denied_events, _, _ = request(
        denied,
        "/operator/api/tenants/tenant-alpha/events",
        headers=[(b"cookie", denied_cookie.encode())],
    )
    denied_mutation, _, _ = request(
        denied,
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record",
        method="POST",
        headers=[
            (b"cookie", denied_cookie.encode()),
            (b"origin", ORIGIN.encode()),
            (b"x-csrf-token", denied_csrf.encode()),
        ],
        body={},
    )
    assert denied_events == 403
    assert denied_mutation == 403

    app, _ = operator_app()
    cookie, csrf = session(app)
    common = [
        (b"cookie", cookie.encode()),
        (b"origin", ORIGIN.encode()),
        (b"x-csrf-token", csrf.encode()),
        (b"idempotency-key", b"decision-005"),
    ]
    body: dict[str, object] = {
        "approval_id": "approval-checkout-001",
        "plan_digest": DEMO_PLAN_DIGEST,
        "policy_digest": DEMO_POLICY_DIGEST,
        "decision": "grant",
        "rationale_code": "scope_reviewed",
        "comment": "Exact scope reviewed.",
    }
    path = (
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record"
    )
    conflict, conflict_body, _ = request(
        app,
        path,
        method="POST",
        headers=[*common, (b"if-match", b'"stale-version"')],
        body=body,
    )
    missing_path = (
        "/operator/api/tenants/tenant-alpha/approvals/approval-missing/decisions/record"
    )
    missing_body = {**body, "approval_id": "approval-missing"}
    not_found, _, _ = request(
        app,
        missing_path,
        method="POST",
        headers=[
            *common[:-1],
            (b"idempotency-key", b"decision-006"),
            (b"if-match", b'"approval-v3"'),
        ],
        body=missing_body,
    )
    invalid_type, _, _ = request(
        app,
        path,
        method="POST",
        headers=[
            *common[:-1],
            (b"idempotency-key", b"decision-007"),
            (b"if-match", b'"approval-v3"'),
        ],
        body={**body, "comment": 42},
    )
    invalid_route, _, _ = request(
        app,
        "/operator/api/not-tenants",
        headers=[(b"cookie", cookie.encode())],
    )
    invalid_tenant, _, _ = request(
        app,
        "/operator/api/tenants/bad tenant/snapshot",
        headers=[(b"cookie", cookie.encode())],
    )
    duplicate_cursor, _, _ = request(
        app,
        "/operator/api/tenants/tenant-alpha/events",
        headers=[(b"cookie", cookie.encode())],
        query_string="cursor=1&cursor=2",
    )
    assert conflict == 409
    assert conflict_body["error"]["retryable"] is True
    assert not_found == 404
    assert invalid_type == 422
    assert invalid_route == 404
    assert invalid_tenant == 404
    assert duplicate_cursor == 400

    clock = Clock(NOW)
    rotating = OperatorBffApp(
        sessions=InMemoryOperatorSessionStore(token_factory=Tokens()),
        views=DemoOperatorViews(),
        commands=DemoOperatorCommands(),
        authorization=AuthorizationService(),
        audit=InMemoryAuditStore(),
        demo_principal=principal(),
        allowed_origins=frozenset({ORIGIN}),
        clock=clock,
    )
    rotating_cookie, _ = session(rotating)
    clock.now = NOW + timedelta(minutes=11)
    rotated, rotated_body, rotated_headers = request(
        rotating,
        "/operator/api/session",
        headers=[(b"cookie", rotating_cookie.encode())],
    )
    assert rotated == 200
    assert isinstance(rotated_body["csrf_token"], str)
    assert any(name == b"set-cookie" for name, _ in rotated_headers)


def test_bff_ignores_non_http_scopes() -> None:
    app, _ = operator_app()
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.receive"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(app({"type": "websocket"}, receive, send))
    assert messages == []


def test_session_recheck_fails_closed_if_record_disappears() -> None:
    class VanishingStore(InMemoryOperatorSessionStore):
        def __init__(self) -> None:
            super().__init__(token_factory=Tokens())
            self.resolutions = 0

        def resolve(
            self,
            session_id: str | None,
            *,
            now: datetime,
        ) -> OperatorSession | None:
            self.resolutions += 1
            return (
                super().resolve(session_id, now=now) if self.resolutions == 1 else None
            )

    store = VanishingStore()
    app = OperatorBffApp(
        sessions=store,
        views=DemoOperatorViews(),
        commands=DemoOperatorCommands(),
        authorization=AuthorizationService(),
        audit=InMemoryAuditStore(),
        demo_principal=principal(),
        allowed_origins=frozenset({ORIGIN}),
        clock=lambda: NOW,
    )
    cookie, _ = session(app)
    status, body, headers = request(
        app,
        "/operator/api/session",
        headers=[(b"cookie", cookie.encode())],
    )
    assert status == 401
    assert body["error"]["code"] == "session_expired"
    assert (b"www-authenticate", b'Session realm="operator"') in headers


def test_bff_rejects_malformed_scope_query_and_body_shapes() -> None:
    app, _ = operator_app()
    cookie, csrf = session(app)
    base_scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/operator/api/tenants/tenant-alpha/events",
        "headers": [(b"cookie", cookie.encode())],
        "query_string": "not-bytes",
    }
    query_status, _ = raw_request(
        app,
        base_scope,
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    missing_headers, _ = raw_request(
        app,
        {
            **base_scope,
            "path": "/operator/api/tenants/tenant-alpha/snapshot",
            "headers": {},
            "query_string": b"",
        },
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    malformed_headers, _ = raw_request(
        app,
        {
            **base_scope,
            "path": "/operator/api/tenants/tenant-alpha/snapshot",
            "headers": [("cookie", cookie.encode())],
            "query_string": b"",
        },
        [{"type": "http.request", "body": b"", "more_body": False}],
    )

    path = (
        "/operator/api/tenants/tenant-alpha/approvals/"
        "approval-checkout-001/decisions/record"
    )
    mutation_scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": path,
        "query_string": b"",
        "headers": [
            (b"cookie", cookie.encode()),
            (b"origin", ORIGIN.encode()),
            (b"x-csrf-token", csrf.encode()),
            (b"idempotency-key", b"decision-008"),
            (b"if-match", b'"approval-v3"'),
        ],
    }
    invalid_message, _ = raw_request(
        app,
        mutation_scope,
        [{"type": "websocket.receive", "body": b""}],
    )
    invalid_json_shape, _ = raw_request(
        app,
        mutation_scope,
        [{"type": "http.request", "body": b"[]", "more_body": False}],
    )
    oversized, _ = raw_request(
        app,
        mutation_scope,
        [{"type": "http.request", "body": b"x" * 70_000, "more_body": False}],
    )

    assert query_status == 400
    assert missing_headers == 401
    assert malformed_headers == 401
    assert invalid_message == 422
    assert invalid_json_shape == 422
    assert oversized == 422


def test_demo_adapters_reject_cross_tenant_and_negative_cursor() -> None:
    views = DemoOperatorViews()
    other_context = TenantContext(TenantId("tenant-other"))
    with pytest.raises(PermissionError, match="tenant mismatch"):
        asyncio.run(views.snapshot(principal(), other_context, at=NOW))
    with pytest.raises(ValueError, match="negative"):
        asyncio.run(
            views.events(
                principal(),
                TenantContext(TENANT_ID),
                after_cursor="-1",
                at=NOW,
            )
        )
    commands = DemoOperatorCommands()
    with pytest.raises(PermissionError, match="tenant mismatch"):
        asyncio.run(
            commands.decide_approval(
                principal(),
                other_context,
                ApprovalDecisionCommand(
                    "approval-checkout-001",
                    DEMO_PLAN_DIGEST,
                    DEMO_POLICY_DIGEST,
                    "grant",
                    "reviewed",
                    "",
                    "approval-v3",
                    "decision-009",
                ),
                at=NOW,
            )
        )


def test_canonical_demo_contains_all_required_operator_surfaces() -> None:
    snapshot = canonical_operator_snapshot(at=NOW)

    assert set(snapshot.sections) == {
        "actions",
        "approvals",
        "audit",
        "evaluations",
        "health",
        "incidents",
        "memory",
        "protocols",
        "replay",
        "sandboxes",
        "specialists",
        "timeline",
        "usage",
    }
    ambiguous = snapshot.sections["actions"][0]
    assert ambiguous.status == "ambiguous"
    assert ambiguous.metadata["verification"] == "pending"
