"""Secure cookie-session BFF for bounded operator views and commands."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditStore,
)
from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
    TenantId,
)
from aegis_agent_platform.identity.authorization import ROLE_PERMISSIONS
from aegis_agent_platform.operator.contracts import (
    ApprovalDecisionCommand,
    OperatorCommandService,
    OperatorViewService,
    PeerTrustCommand,
)
from aegis_agent_platform.operator.session import InMemoryOperatorSessionStore
from aegis_agent_platform.tenancy import TenantContext

type AsgiMessage = dict[str, Any]
type Receive = Callable[[], Awaitable[AsgiMessage]]
type Send = Callable[[AsgiMessage], Awaitable[None]]

SESSION_COOKIE = "__Host-aegis-session"
MAX_REQUEST_BODY = 32_768
SECURITY_HEADERS = (
    (
        b"content-security-policy",
        b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        b"form-action 'self'; script-src 'self'; style-src 'self'; "
        b"img-src 'self' data:; connect-src 'self'",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (
        b"permissions-policy",
        b"camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    ),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    (b"cache-control", b"no-store"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
)


class OperatorBffApp:
    """Cookie BFF; live OIDC exchange and shared sessions remain adapter-owned."""

    def __init__(
        self,
        *,
        sessions: InMemoryOperatorSessionStore,
        views: OperatorViewService,
        commands: OperatorCommandService | None,
        authorization: AuthorizationService,
        audit: AuditStore,
        demo_principal: Principal | None,
        allowed_origins: frozenset[str],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        production_ready: bool = False,
        live_exchange_configured: bool = False,
    ) -> None:
        if not allowed_origins or any(
            not origin.startswith("https://") and origin != "http://127.0.0.1:4173"
            for origin in allowed_origins
        ):
            raise ValueError("operator BFF requires explicit trusted origins")
        if production_ready and demo_principal is not None:
            raise ValueError("demo authentication cannot be production ready")
        self._sessions = sessions
        self._views = views
        self._commands = commands
        self._authorization = authorization
        self._audit = audit
        self._demo_principal = demo_principal
        self._allowed_origins = allowed_origins
        self._clock = clock
        self._production_ready = production_ready
        self._live_exchange_configured = live_exchange_configured

    async def __call__(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
    ) -> None:
        request_id = _request_id(scope)
        if scope.get("type") != "http":
            return
        path = scope.get("path")
        method = scope.get("method")
        if not isinstance(path, str) or not path.startswith("/operator/api/"):
            await _respond(
                send, 404, _error("not_found", request_id), request_id=request_id
            )
            return
        if path == "/operator/api/config" and method == "GET":
            await _respond(
                send,
                200,
                {
                    "schema_version": 1,
                    "production_ready": self._production_ready,
                    "auth_mode": "oidc_bff"
                    if self._production_ready
                    else "deterministic_demo",
                    "demo": not self._production_ready,
                    "server_time": self._clock().isoformat(),
                    "oidc_boundary": {
                        "authorization_code": True,
                        "pkce": True,
                        "state": True,
                        "nonce": True,
                        "live_exchange_configured": self._live_exchange_configured,
                    },
                },
                request_id=request_id,
            )
            return
        if path == "/operator/api/demo/session" and method == "POST":
            await self._create_demo_session(scope, send, request_id)
            return
        session_id = _cookie(scope, SESSION_COOKIE)
        session = self._sessions.resolve(session_id, now=self._clock())
        if session is None:
            await _respond(
                send,
                401,
                _error("session_required", request_id, retryable=False),
                request_id=request_id,
                extra_headers=[(b"www-authenticate", b'Session realm="operator"')],
            )
            return
        if path == "/operator/api/session" and method == "GET":
            await self._session(scope, send, request_id, session_id, session.principal)
            return
        if path == "/operator/api/session/logout" and method == "POST":
            if not self._mutation_guard(scope, session):
                await _respond(
                    send,
                    403,
                    _error("csrf_or_origin_denied", request_id),
                    request_id=request_id,
                )
                return
            self._sessions.invalidate(session_id)
            await _respond(
                send,
                204,
                {},
                request_id=request_id,
                extra_headers=[_clear_cookie()],
            )
            return
        segments = [segment for segment in path.split("/") if segment]
        if len(segments) < 5 or segments[:3] != ["operator", "api", "tenants"]:
            await _respond(
                send, 404, _error("not_found", request_id), request_id=request_id
            )
            return
        try:
            tenant_id = TenantId(segments[3])
        except ValueError:
            await _respond(
                send, 404, _error("not_found", request_id), request_id=request_id
            )
            return
        principal = session.principal
        if principal.tenant_id != tenant_id:
            await self._audit_access(
                principal,
                tenant_id,
                "operator.cross_tenant",
                AuditOutcome.DENIED,
                request_id,
            )
            await _respond(
                send, 404, _error("not_found", request_id), request_id=request_id
            )
            return
        if method == "GET" and len(segments) == 5 and segments[4] == "snapshot":
            # The snapshot is an aggregate surface: it includes audit, approval, and
            # other surface-specific data. Require both TENANT_READ and AUDIT_READ so
            # that roles such as APPROVER (which lacks audit-read) cannot see it.
            if not await self._authorized(
                principal,
                tenant_id,
                Permission.TENANT_READ,
                "operator.snapshot",
                request_id,
            ) or not await self._authorized(
                principal,
                tenant_id,
                Permission.AUDIT_READ,
                "operator.snapshot.audit",
                request_id,
            ):
                await _respond(
                    send,
                    403,
                    _error("authorization_denied", request_id),
                    request_id=request_id,
                )
                return
            snapshot = await self._views.snapshot(
                principal,
                TenantContext(tenant_id),
                at=self._clock(),
            )
            await _respond(
                send,
                200,
                snapshot.to_dict(),
                request_id=request_id,
                extra_headers=[(b"etag", f'"{snapshot.source_cursor}"'.encode())],
            )
            return
        if method == "GET" and len(segments) == 5 and segments[4] == "events":
            if not await self._authorized(
                principal,
                tenant_id,
                Permission.TENANT_READ,
                "operator.events",
                request_id,
            ):
                await _respond(
                    send,
                    403,
                    _error("authorization_denied", request_id),
                    request_id=request_id,
                )
                return
            try:
                cursor = _cursor(scope)
                page = await self._views.events(
                    principal,
                    TenantContext(tenant_id),
                    after_cursor=cursor,
                    at=self._clock(),
                )
            except ValueError:
                await _respond(
                    send,
                    400,
                    _error("invalid_cursor", request_id),
                    request_id=request_id,
                )
                return
            await _respond(send, 200, page.to_dict(), request_id=request_id)
            return
        if (
            method == "POST"
            and len(segments) == 8
            and segments[4] == "approvals"
            and segments[6:] == ["decisions", "record"]
        ):
            await self._decide(
                scope,
                receive,
                send,
                request_id,
                principal,
                tenant_id,
                segments[5],
                session,
            )
            return
        if (
            method == "POST"
            and len(segments) == 8
            and segments[4] == "protocol-peers"
            and segments[6:] == ["trust", "record"]
        ):
            await self._change_peer_trust(
                scope,
                receive,
                send,
                request_id,
                principal,
                tenant_id,
                segments[5],
                session,
            )
            return
        await _respond(
            send, 404, _error("not_found", request_id), request_id=request_id
        )

    async def _create_demo_session(
        self,
        scope: AsgiMessage,
        send: Send,
        request_id: str,
    ) -> None:
        if self._production_ready or self._demo_principal is None:
            await _respond(
                send,
                404,
                _error("not_found", request_id),
                request_id=request_id,
            )
            return
        if not self._origin_allowed(scope):
            await _respond(
                send,
                403,
                _error("origin_denied", request_id),
                request_id=request_id,
            )
            return
        now = self._clock()
        handle = self._sessions.create(self._demo_principal, now=now)
        await _respond(
            send,
            201,
            self._session_body(handle.session.principal, handle.csrf_token, now),
            request_id=request_id,
            extra_headers=[_session_cookie(handle.session_id)],
        )

    async def _session(
        self,
        scope: AsgiMessage,
        send: Send,
        request_id: str,
        session_id: str | None,
        principal: Principal,
    ) -> None:
        now = self._clock()
        session = self._sessions.resolve(session_id, now=now)
        if session is None or session_id is None:
            await _respond(
                send,
                401,
                _error("session_expired", request_id),
                request_id=request_id,
                extra_headers=[(b"www-authenticate", b'Session realm="operator"')],
            )
            return
        headers: list[tuple[bytes, bytes]] = []
        csrf_token: str | None = None
        if self._sessions.needs_rotation(session, now=now):
            rotated = self._sessions.rotate(session_id, session, now=now)
            headers.append(_session_cookie(rotated.session_id))
            csrf_token = rotated.csrf_token
        await _respond(
            send,
            200,
            self._session_body(principal, csrf_token, now),
            request_id=request_id,
            extra_headers=headers,
        )

    def _session_body(
        self,
        principal: Principal,
        csrf_token: str | None,
        now: datetime,
    ) -> dict[str, JsonValue]:
        active_roles = tuple(
            sorted(
                {
                    binding.role
                    for binding in principal.role_bindings
                    if binding.is_active(now)
                },
                key=lambda role: role.value,
            )
        )
        permissions = tuple(
            sorted(
                {
                    permission.value
                    for role in active_roles
                    for permission in ROLE_PERMISSIONS.get(role, frozenset())
                }
            )
        )
        return {
            "schema_version": 1,
            "actor_id": principal.actor_id,
            "tenant_id": str(principal.tenant_id),
            "roles": [role.value for role in active_roles],
            "permissions": list(permissions),
            "csrf_token": csrf_token,
            "server_time": now.isoformat(),
            "production_ready": self._production_ready,
            "demo": not self._production_ready,
            "stale": False,
        }

    async def _decide(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
        request_id: str,
        principal: Principal,
        tenant_id: TenantId,
        approval_id: str,
        session: object,
    ) -> None:
        from aegis_agent_platform.operator.session import OperatorSession

        if not isinstance(session, OperatorSession) or not self._mutation_guard(
            scope, session
        ):
            await _respond(
                send,
                403,
                _error("csrf_or_origin_denied", request_id),
                request_id=request_id,
            )
            return
        if not await self._authorized(
            principal,
            tenant_id,
            Permission.APPROVAL_DECIDE,
            "operator.approval.decide",
            request_id,
        ):
            await _respond(
                send,
                403,
                _error("authorization_denied", request_id),
                request_id=request_id,
            )
            return
        if self._commands is None:
            await _respond(
                send,
                503,
                _error("operator_commands_not_configured", request_id, retryable=True),
                request_id=request_id,
            )
            return
        try:
            body = await _request_json(receive)
            idempotency_key = _single_header(scope, b"idempotency-key")
            expected_version = _unquote_etag(_single_header(scope, b"if-match"))
            if idempotency_key is None or expected_version is None:
                raise KeyError("mutation headers are required")
            if body.get("approval_id") != approval_id:
                raise ValueError("approval route and body differ")
            allowed_approval_keys = frozenset(
                {
                    "approval_id",
                    "plan_digest",
                    "policy_digest",
                    "decision",
                    "rationale_code",
                    "comment",
                }
            )
            unknown = set(body) - allowed_approval_keys
            if unknown:
                raise ValueError(
                    f"unknown approval request properties: {sorted(unknown)}"
                )
            command = ApprovalDecisionCommand(
                approval_id,
                _required_string(body, "plan_digest"),
                _required_string(body, "policy_digest"),
                _required_string(body, "decision"),
                _required_string(body, "rationale_code"),
                _required_string(body, "comment"),
                expected_version,
                idempotency_key,
            )
            result = await self._commands.decide_approval(
                principal,
                TenantContext(tenant_id),
                command,
                at=self._clock(),
            )
        except KeyError:
            await _respond(
                send,
                422,
                _error("invalid_or_stale_approval_scope", request_id),
                request_id=request_id,
            )
            return
        except LookupError:
            await _respond(
                send, 404, _error("not_found", request_id), request_id=request_id
            )
            return
        except RuntimeError:
            await _respond(
                send,
                409,
                _error("concurrency_conflict", request_id, retryable=True),
                request_id=request_id,
            )
            return
        except (TypeError, ValueError, json.JSONDecodeError):
            await _respond(
                send,
                422,
                _error("invalid_or_stale_approval_scope", request_id),
                request_id=request_id,
            )
            return
        await self._audit_access(
            principal,
            tenant_id,
            "operator.approval.decide",
            AuditOutcome.SUCCESS,
            request_id,
            event_type=AuditEventType.OPERATOR_MUTATION,
            details={
                "approval_id": approval_id,
                "decision_status": result.status,
                "duplicate": result.duplicate,
            },
        )
        await _respond(
            send,
            202,
            result.to_dict(),
            request_id=request_id,
            extra_headers=[(b"etag", f'"{result.version}"'.encode())],
        )

    async def _change_peer_trust(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
        request_id: str,
        principal: Principal,
        tenant_id: TenantId,
        peer_id: str,
        session: object,
    ) -> None:
        from aegis_agent_platform.operator.session import OperatorSession

        if not isinstance(session, OperatorSession) or not self._mutation_guard(
            scope, session
        ):
            await _respond(
                send,
                403,
                _error("csrf_or_origin_denied", request_id),
                request_id=request_id,
            )
            return
        if not await self._authorized(
            principal,
            tenant_id,
            Permission.PROTOCOL_TRUST_MANAGE,
            "operator.protocol.trust",
            request_id,
        ):
            await _respond(
                send,
                403,
                _error("authorization_denied", request_id),
                request_id=request_id,
            )
            return
        if self._commands is None:
            await _respond(
                send,
                503,
                _error(
                    "operator_commands_not_configured",
                    request_id,
                    retryable=True,
                ),
                request_id=request_id,
            )
            return
        try:
            body = await _request_json(receive)
            idempotency_key = _single_header(scope, b"idempotency-key")
            expected_version = _unquote_etag(_single_header(scope, b"if-match"))
            if idempotency_key is None or expected_version is None:
                raise KeyError("mutation headers are required")
            if body.get("peer_id") != peer_id:
                raise ValueError("protocol peer route and body differ")
            command = PeerTrustCommand(
                peer_id,
                _required_string(body, "peer_digest"),
                _required_string(body, "decision"),
                _required_string(body, "rationale_code"),
                expected_version,
                idempotency_key,
            )
            result = await self._commands.change_peer_trust(
                principal,
                TenantContext(tenant_id),
                command,
                at=self._clock(),
            )
        except KeyError:
            await _respond(
                send,
                422,
                _error("invalid_or_stale_peer_scope", request_id),
                request_id=request_id,
            )
            return
        except LookupError:
            await _respond(
                send, 404, _error("not_found", request_id), request_id=request_id
            )
            return
        except RuntimeError:
            await _respond(
                send,
                409,
                _error("concurrency_conflict", request_id, retryable=True),
                request_id=request_id,
            )
            return
        except (TypeError, ValueError, json.JSONDecodeError):
            await _respond(
                send,
                422,
                _error("invalid_or_stale_peer_scope", request_id),
                request_id=request_id,
            )
            return
        await self._audit_access(
            principal,
            tenant_id,
            "operator.protocol.trust",
            AuditOutcome.SUCCESS,
            request_id,
            event_type=AuditEventType.OPERATOR_MUTATION,
            details={
                "peer_id": peer_id,
                "trust_status": result.status,
                "duplicate": result.duplicate,
            },
        )
        await _respond(
            send,
            202,
            result.to_dict(),
            request_id=request_id,
            extra_headers=[(b"etag", f'"{result.version}"'.encode())],
        )

    def _mutation_guard(self, scope: AsgiMessage, session: object) -> bool:
        from aegis_agent_platform.operator.session import OperatorSession

        return (
            isinstance(session, OperatorSession)
            and self._origin_allowed(scope)
            and self._sessions.validate_csrf(
                session,
                _single_header(scope, b"x-csrf-token"),
            )
        )

    def _origin_allowed(self, scope: AsgiMessage) -> bool:
        origin = _single_header(scope, b"origin")
        return origin is not None and origin in self._allowed_origins

    async def _authorized(
        self,
        principal: Principal,
        tenant_id: TenantId,
        permission: Permission,
        resource: str,
        request_id: str,
    ) -> bool:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=tenant_id,
            permission=permission,
            at=self._clock(),
        )
        await self._audit_access(
            principal,
            tenant_id,
            resource,
            AuditOutcome.SUCCESS if decision.allowed else AuditOutcome.DENIED,
            request_id,
            details={"permission": permission.value, "reason": decision.reason},
        )
        return decision.allowed

    async def _audit_access(
        self,
        principal: Principal,
        tenant_id: TenantId,
        action: str,
        outcome: AuditOutcome,
        request_id: str,
        *,
        event_type: AuditEventType = AuditEventType.OPERATOR_PRIVILEGED_READ,
        details: Mapping[str, JsonValue] | None = None,
    ) -> None:
        event = AuditEvent(
            uuid4(),
            principal.tenant_id,
            event_type,
            self._clock(),
            outcome,
            principal.actor_id,
            action,
            f"tenant/{tenant_id}/operator",
            UUID(request_id),
            details or {},
        )
        self._audit.append(TenantContext(principal.tenant_id), event)


def _error(
    code: str, request_id: str, *, retryable: bool = False
) -> dict[str, JsonValue]:
    return {
        "error": {
            "code": code,
            "request_id": request_id,
            "retryable": retryable,
        }
    }


def _request_id(scope: AsgiMessage) -> str:
    candidate = _single_header(scope, b"x-request-id")
    try:
        return str(UUID(candidate)) if candidate is not None else str(uuid4())
    except ValueError:
        return str(uuid4())


def _single_header(scope: AsgiMessage, name: bytes) -> str | None:
    raw_headers = scope.get("headers", [])
    if not isinstance(raw_headers, list):
        return None
    values = [
        item[1].decode("latin-1")
        for item in raw_headers
        if (
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], bytes)
            and isinstance(item[1], bytes)
            and item[0].lower() == name
        )
    ]
    return values[0] if len(values) == 1 else None


def _cookie(scope: AsgiMessage, name: str) -> str | None:
    header = _single_header(scope, b"cookie")
    if header is None or len(header) > 4_096:
        return None
    cookie = SimpleCookie()
    try:
        cookie.load(header)
    except ValueError:
        return None
    morsel = cookie.get(name)
    return morsel.value if morsel is not None else None


def _cursor(scope: AsgiMessage) -> str | None:
    raw = scope.get("query_string", b"")
    if not isinstance(raw, bytes):
        raise ValueError("query string must be bytes")
    values = parse_qs(raw.decode("ascii"), keep_blank_values=True).get("cursor")
    if values is None:
        return None
    if len(values) != 1 or not values[0].isdigit() or len(values[0]) > 10:
        raise ValueError("cursor is invalid")
    return values[0]


async def _request_json(receive: Receive) -> Mapping[str, object]:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        body = message.get("body", b"")
        if message.get("type") != "http.request" or not isinstance(body, bytes):
            raise ValueError("request body is invalid")
        size += len(body)
        if size > MAX_REQUEST_BODY:
            raise ValueError("request body exceeds the bound")
        chunks.append(body)
        if not message.get("more_body", False):
            break
    value = json.loads(b"".join(chunks))
    if not isinstance(value, dict):
        raise ValueError("request JSON must be an object")
    return value


def _required_string(body: Mapping[str, object], key: str) -> str:
    value = body[key]
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _unquote_etag(value: str | None) -> str | None:
    if value is None or len(value) < 3 or value[0] != '"' or value[-1] != '"':
        return None
    candidate = value[1:-1]
    return candidate if candidate and len(candidate) <= 128 else None


def _session_cookie(value: str) -> tuple[bytes, bytes]:
    return (
        b"set-cookie",
        (
            f"{SESSION_COOKIE}={value}; Path=/; Secure; HttpOnly; "
            "SameSite=Strict; Max-Age=1800"
        ).encode(),
    )


def _clear_cookie() -> tuple[bytes, bytes]:
    return (
        b"set-cookie",
        (
            f"{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
        ).encode(),
    )


async def _respond(
    send: Send,
    status: int,
    body: dict[str, JsonValue],
    *,
    request_id: str,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    encoded = b"" if status == 204 else json.dumps(body, separators=(",", ":")).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(encoded)).encode()),
        (b"x-request-id", request_id.encode()),
        *SECURITY_HEADERS,
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": encoded})


__all__ = ["SECURITY_HEADERS", "SESSION_COOKIE", "OperatorBffApp"]
