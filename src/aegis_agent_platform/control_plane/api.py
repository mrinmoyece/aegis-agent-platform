"""Authenticated ASGI control-plane vertical slice."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditStore,
    InMemoryAuditStore,
    redact_details,
)
from aegis_agent_platform.config import ConfigurationError, Settings
from aegis_agent_platform.domain import (
    EnvironmentIdentity,
    EventEnvelope,
    EvidenceKind,
    EvidenceSourceKind,
    JsonValue,
    PaginationCursor,
    QueryWindow,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import EventStore, TransientStorageError
from aegis_agent_platform.evidence import EvidenceQuery
from aegis_agent_platform.evidence.operations import EvidenceOperations
from aegis_agent_platform.evidence.service import EvidenceIdempotencyConflictError
from aegis_agent_platform.gateway.operations import GatewayOperations
from aegis_agent_platform.identity import (
    PLATFORM_TENANT_ID,
    AuthenticationError,
    AuthenticationPort,
    AuthorizationDecision,
    AuthorizationService,
    Permission,
    Principal,
    TenantId,
)
from aegis_agent_platform.policy import (
    InMemoryPolicyRepository,
    PolicyRepository,
    TenantPolicy,
)
from aegis_agent_platform.tenancy import (
    InMemoryTenantRepository,
    TenantContext,
    TenantRepository,
)

type AsgiMessage = dict[str, Any]
type Receive = Callable[[], Awaitable[AsgiMessage]]
type Send = Callable[[AsgiMessage], Awaitable[None]]


class RunStatusReader(Protocol):
    """Tenant-scoped read-model query port for the control plane."""

    async def run_status(
        self,
        context: TenantContext,
        *,
        limit: int = 100,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        """Return a bounded run-status view."""
        ...


class ControlPlaneApp:
    """Small injectable API showing the complete security boundary."""

    def __init__(
        self,
        *,
        authentication: AuthenticationPort | None = None,
        authorization: AuthorizationService | None = None,
        tenants: TenantRepository | None = None,
        policies: PolicyRepository | None = None,
        audit: AuditStore | None = None,
        event_store: EventStore | None = None,
        projections: RunStatusReader | None = None,
        storage_ready: Callable[[], Awaitable[bool]] | None = None,
        gateway_operations: GatewayOperations | None = None,
        evidence_operations: EvidenceOperations | None = None,
    ) -> None:
        self._authentication = authentication
        self._authorization = authorization or AuthorizationService()
        self._tenants = tenants or InMemoryTenantRepository(())
        self._policies = policies or InMemoryPolicyRepository(())
        self._audit = audit or InMemoryAuditStore()
        self._event_store = event_store
        self._projections = projections
        self._storage_ready = storage_ready
        self._gateway_operations = gateway_operations
        self._evidence_operations = evidence_operations

    async def __call__(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            return
        path = scope.get("path")
        method = scope.get("method", "GET")
        if method not in {"GET", "POST"}:
            await _respond(send, 405, {"error": {"code": "method_not_allowed"}})
            return
        if path in {"/healthz", "/health/live"}:
            await _respond(send, 200, {"status": "ok", "service": "control-plane"})
            return
        if path in {"/readyz", "/health/ready"}:
            await self._readiness(send)
            return
        if not isinstance(path, str) or not path.startswith("/v1/"):
            await _respond(send, 404, {"status": "not-found"})
            return
        correlation_id = uuid4()
        if method == "POST":
            post_segments = [segment for segment in path.split("/") if segment]
            if not (
                len(post_segments) == 5
                and post_segments[:2] == ["v1", "tenants"]
                and post_segments[3:] == ["evidence", "queries"]
            ):
                await _respond(send, 405, {"error": {"code": "method_not_allowed"}})
                return
        principal = await self._authenticate(scope, send, correlation_id)
        if principal is None:
            return
        if path == "/v1/me":
            await _respond(send, 200, _principal_body(principal, datetime.now(UTC)))
            return
        segments = [segment for segment in path.split("/") if segment]
        if len(segments) < 3 or segments[:2] != ["v1", "tenants"]:
            await _respond(send, 404, {"status": "not-found"})
            return
        try:
            tenant_id = TenantId(segments[2])
        except ValueError:
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_tenant_id"}},
            )
            return
        if len(segments) == 3:
            await self._get_tenant(send, principal, tenant_id, correlation_id)
            return
        if len(segments) == 4 and segments[3] == "policy":
            await self._get_policy(send, principal, tenant_id, correlation_id)
            return
        if len(segments) == 4 and segments[3] in {
            "models",
            "model-usage",
            "provider-health",
        }:
            await self._get_model_view(
                send,
                principal,
                tenant_id,
                correlation_id=correlation_id,
                view=segments[3],
            )
            return
        if (
            method == "POST"
            and len(segments) == 5
            and segments[3:] == ["evidence", "queries"]
        ):
            await self._request_evidence(
                send,
                receive,
                principal,
                tenant_id,
            )
            return
        if (
            method == "GET"
            and len(segments) == 5
            and segments[3] == "evidence"
            and segments[4] in {"records", "citations", "capabilities"}
        ):
            try:
                cursor = _evidence_cursor_parameter(scope)
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_evidence_view(
                send,
                principal,
                tenant_id,
                segments[4],
                cursor=cursor,
            )
            return
        if (
            method == "GET"
            and len(segments) == 6
            and segments[3:5] == ["evidence", "queries"]
        ):
            await self._get_evidence_status(
                send,
                principal,
                tenant_id,
                segments[5],
            )
            return
        if (
            method == "GET"
            and len(segments) == 6
            and segments[3:5] == ["evidence", "bundles"]
        ):
            await self._get_evidence_bundle(
                send,
                principal,
                tenant_id,
                segments[5],
            )
            return
        if len(segments) == 4 and segments[3] == "ledger":
            try:
                after_position = _cursor_parameter(scope)
            except ValueError:
                await _respond(
                    send,
                    400,
                    {"error": {"code": "invalid_cursor"}},
                )
                return
            await self._get_ledger(
                send,
                principal,
                tenant_id,
                correlation_id=correlation_id,
                after_position=after_position,
            )
            return
        if len(segments) == 6 and segments[3] == "runs" and segments[5] == "timeline":
            try:
                after_version = _cursor_parameter(scope)
            except ValueError:
                await _respond(
                    send,
                    400,
                    {"error": {"code": "invalid_cursor"}},
                )
                return
            await self._get_timeline(
                send,
                principal,
                tenant_id,
                segments[4],
                correlation_id=correlation_id,
                after_version=after_version,
            )
            return
        if (
            len(segments) == 5
            and segments[3] == "projections"
            and segments[4] == "run-status"
        ):
            await self._get_run_status(send, principal, tenant_id, correlation_id)
            return
        await _respond(send, 404, {"status": "not-found"})

    async def _request_evidence(
        self,
        send: Send,
        receive: Receive,
        principal: Principal,
        tenant_id: TenantId,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_QUERY,
            resource=f"tenant/{tenant_id}/evidence/queries",
        ):
            return
        if self._evidence_operations is None:
            await _respond(send, 503, {"error": {"code": "evidence_not_configured"}})
            return
        policy = self._policies.get(TenantContext(tenant_id))
        if policy is None:
            await _respond(send, 503, {"error": {"code": "policy_not_configured"}})
            return
        try:
            body = await _request_json(receive)
            query = _evidence_query(body, tenant_id)
            result = await self._evidence_operations.request(
                principal,
                TenantContext(tenant_id),
                query,
                policy,
                at=datetime.now(UTC),
            )
        except EvidenceIdempotencyConflictError:
            await _respond(
                send,
                409,
                {"error": {"code": "evidence_idempotency_key_reused"}},
            )
            return
        except (KeyError, TypeError, ValueError):
            await _respond(send, 400, {"error": {"code": "invalid_evidence_query"}})
            return
        except PermissionError as error:
            await _respond(
                send,
                403,
                {"error": {"code": "evidence_query_denied", "reason": str(error)}},
            )
            return
        await _respond(
            send,
            202 if result.created else 200,
            {
                "query_id": str(result.query_id),
                "accepted": result.created,
                "status": "requested" if result.created else "duplicate",
            },
        )

    async def _get_evidence_view(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        view: str,
        *,
        cursor: tuple[int, int] | None,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_READ,
            resource=f"tenant/{tenant_id}/evidence/{view}",
        ):
            return
        if self._evidence_operations is None:
            await _respond(send, 503, {"error": {"code": "evidence_not_configured"}})
            return
        context = TenantContext(tenant_id)
        at = datetime.now(UTC)
        next_cursor: str | None = None
        if view == "records":
            record_page, page_cursor = self._evidence_operations.evidence_page(
                principal,
                context,
                at=at,
                cursor=cursor,
                limit=100,
            )
            items: object = record_page
            next_cursor = (
                _encode_evidence_cursor(page_cursor)
                if page_cursor is not None
                else None
            )
        elif view == "citations":
            citation_page, page_cursor = self._evidence_operations.citation_page(
                principal,
                context,
                at=at,
                cursor=cursor,
                limit=100,
            )
            items = citation_page
            next_cursor = (
                _encode_evidence_cursor(page_cursor)
                if page_cursor is not None
                else None
            )
        else:
            policy = self._policies.get(context)
            if policy is None:
                await _respond(send, 503, {"error": {"code": "policy_not_configured"}})
                return
            items = self._evidence_operations.capabilities(
                principal, context, policy, at=at
            )
        await _respond(send, 200, {view: items, "next_cursor": next_cursor})

    async def _get_evidence_status(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        query_id: str,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_READ,
            resource=f"tenant/{tenant_id}/evidence/query",
        ):
            return
        if self._evidence_operations is None:
            await _respond(send, 503, {"error": {"code": "evidence_not_configured"}})
            return
        try:
            identifier = UUID(query_id)
        except ValueError:
            await _respond(send, 400, {"error": {"code": "invalid_query_id"}})
            return
        result = await self._evidence_operations.status(
            principal,
            TenantContext(tenant_id),
            identifier,
            at=datetime.now(UTC),
        )
        await _respond(
            send,
            200 if result is not None else 404,
            (
                dict(result)
                if result is not None
                else {"error": {"code": "query_not_found"}}
            ),
        )

    async def _get_evidence_bundle(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        bundle_id: str,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_READ,
            resource=f"tenant/{tenant_id}/evidence/bundle",
        ):
            return
        if self._evidence_operations is None:
            await _respond(send, 503, {"error": {"code": "evidence_not_configured"}})
            return
        result = self._evidence_operations.bundle(
            principal,
            TenantContext(tenant_id),
            bundle_id,
            at=datetime.now(UTC),
        )
        await _respond(
            send,
            200 if result is not None else 404,
            (
                dict(result)
                if result is not None
                else {"error": {"code": "bundle_not_found"}}
            ),
        )

    async def _readiness(self, send: Send) -> None:
        try:
            Settings.from_env()
        except ConfigurationError as error:
            await _respond(
                send,
                503,
                {"status": "not-ready", "reason": str(error)},
            )
            return
        if self._storage_ready is not None and not await self._storage_ready():
            await _respond(
                send,
                503,
                {"status": "not-ready", "reason": "storage_unavailable"},
            )
            return
        await _respond(
            send,
            200,
            {
                "status": "ready",
                "checks": (
                    ["configuration", "storage"]
                    if self._storage_ready is not None
                    else ["configuration"]
                ),
            },
        )

    async def _authenticate(
        self,
        scope: AsgiMessage,
        send: Send,
        correlation_id: UUID,
    ) -> Principal | None:
        if self._authentication is None:
            await _respond(
                send,
                503,
                {"error": {"code": "authentication_not_configured"}},
            )
            return None
        authorization_header = _single_header(scope, b"authorization")
        try:
            principal = await asyncio.get_event_loop().run_in_executor(
                None,
                self._authentication.authenticate,
                authorization_header,
            )
        except AuthenticationError as error:
            self._audit_event(
                tenant_id=PLATFORM_TENANT_ID,
                event_type=AuditEventType.AUTHENTICATION_OUTCOME,
                outcome=AuditOutcome.FAILURE,
                actor_id="unauthenticated",
                action="authenticate",
                resource="control-plane",
                correlation_id=correlation_id,
                details={"error_code": error.code.value},
            )
            await _respond(
                send,
                401,
                {
                    "error": {
                        "code": error.code.value,
                        "message": "authentication failed",
                    }
                },
                extra_headers=[(b"www-authenticate", b'Bearer realm="aegis"')],
            )
            return None
        self._audit_event(
            tenant_id=principal.tenant_id,
            event_type=AuditEventType.AUTHENTICATION_OUTCOME,
            outcome=AuditOutcome.SUCCESS,
            actor_id=principal.actor_id,
            action="authenticate",
            resource="control-plane",
            correlation_id=correlation_id,
            details={"subject": principal.subject, "issuer": principal.issuer},
        )
        return principal

    async def _get_tenant(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        correlation_id: UUID,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.TENANT_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}",
        ):
            return
        tenant = self._tenants.get(TenantContext(tenant_id))
        if tenant is None:
            await _respond(send, 404, {"error": {"code": "tenant_not_found"}})
            return
        await _respond(
            send,
            200,
            {
                "tenant_id": str(tenant.tenant_id),
                "display_name": tenant.display_name,
                "enabled": tenant.enabled,
            },
        )

    async def _get_policy(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        correlation_id: UUID,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.POLICY_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}/policy",
        ):
            return
        policy = self._policies.get(TenantContext(tenant_id))
        if policy is None:
            await _respond(send, 404, {"error": {"code": "policy_not_found"}})
            return
        await _respond(send, 200, _policy_body(policy))

    async def _get_model_view(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        *,
        correlation_id: UUID,
        view: str,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.MODEL_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}/{view}",
        ):
            return
        if self._gateway_operations is None:
            await _respond(send, 503, {"error": {"code": "gateway_not_configured"}})
            return
        context = TenantContext(tenant_id)
        policy = self._policies.get(context)
        if policy is None:
            await _respond(send, 404, {"error": {"code": "policy_not_found"}})
            return
        at = datetime.now(UTC)
        try:
            if view == "models":
                body: dict[str, Any] = {
                    "models": self._gateway_operations.catalog(
                        principal,
                        context,
                        policy,
                        at=at,
                    )
                }
            elif view == "model-usage":
                body = dict(self._gateway_operations.usage(principal, context, at=at))
            else:
                body = {
                    "providers": self._gateway_operations.health(
                        principal,
                        context,
                        policy,
                        at=at,
                    )
                }
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        await _respond(send, 200, body)

    async def _get_ledger(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        *,
        correlation_id: UUID,
        after_position: int,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.RESOURCE_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}/ledger",
        ):
            return
        if self._event_store is None:
            await _respond(send, 503, {"error": {"code": "storage_not_configured"}})
            return
        try:
            page = await self._event_store.read_all(
                TenantContext(tenant_id),
                after_position=after_position,
                limit=100,
            )
        except TransientStorageError:
            await _respond(send, 503, {"error": {"code": "storage_unavailable"}})
            return
        await _respond(
            send,
            200,
            {
                "events": [_event_body(event) for event in page.events],
                "next_cursor": page.next_cursor,
            },
        )

    async def _get_timeline(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        run_id: str,
        *,
        correlation_id: UUID,
        after_version: int,
    ) -> None:
        if not run_id:
            await _respond(send, 400, {"error": {"code": "invalid_run_id"}})
            return
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.RESOURCE_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}/runs/{run_id}/timeline",
        ):
            return
        if self._event_store is None:
            await _respond(send, 503, {"error": {"code": "storage_not_configured"}})
            return
        try:
            events = [
                event
                async for event in self._event_store.read_stream(
                    TenantContext(tenant_id),
                    run_id,
                    after_version=after_version,
                    limit=100,
                )
            ]
        except TransientStorageError:
            await _respond(send, 503, {"error": {"code": "storage_unavailable"}})
            return
        await _respond(
            send,
            200,
            {
                "run_id": run_id,
                "events": list(map(_event_body, events)),
                "next_cursor": (
                    events[-1].aggregate_sequence if len(events) == 100 else None
                ),
            },
        )

    async def _get_run_status(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        correlation_id: UUID,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.RESOURCE_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}/projections/run-status",
        ):
            return
        if self._projections is None:
            await _respond(send, 503, {"error": {"code": "storage_not_configured"}})
            return
        rows = await self._projections.run_status(TenantContext(tenant_id), limit=100)
        await _respond(send, 200, {"runs": list(rows)})

    async def _authorize(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        permission: Permission,
        *,
        correlation_id: UUID,
        resource: str,
    ) -> bool:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=tenant_id,
            permission=permission,
            at=datetime.now(UTC),
        )
        self._audit_authorization(principal, resource, decision, correlation_id)
        if decision.allowed:
            return True
        await _respond(
            send,
            403,
            {
                "error": {
                    "code": "authorization_denied",
                    "reason": decision.reason,
                }
            },
        )
        return False

    def _audit_authorization(
        self,
        principal: Principal,
        resource: str,
        decision: AuthorizationDecision,
        correlation_id: UUID,
    ) -> None:
        self._audit_event(
            tenant_id=principal.tenant_id,
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            outcome=(AuditOutcome.SUCCESS if decision.allowed else AuditOutcome.DENIED),
            actor_id=principal.actor_id,
            action=decision.permission,
            resource=resource,
            correlation_id=correlation_id,
            details={
                "attempted_tenant_id": str(decision.tenant_id),
                "reason": decision.reason,
                "roles": [role.value for role in decision.active_roles],
            },
        )

    def _audit_event(
        self,
        *,
        tenant_id: TenantId,
        event_type: AuditEventType,
        outcome: AuditOutcome,
        actor_id: str,
        action: str,
        resource: str,
        correlation_id: UUID,
        details: Mapping[str, JsonValue],
    ) -> None:
        event = AuditEvent(
            event_id=uuid4(),
            tenant_id=tenant_id,
            event_type=event_type,
            occurred_at=datetime.now(UTC),
            outcome=outcome,
            actor_id=actor_id,
            action=action,
            resource=resource,
            correlation_id=correlation_id,
            details=details,
        )
        self._audit.append(TenantContext(tenant_id), event)


def _single_header(scope: AsgiMessage, name: bytes) -> str | None:
    raw_headers: object = scope.get("headers", [])
    if not isinstance(raw_headers, list):
        return None
    values = [
        value
        for item in raw_headers
        if (value := _matching_header(item, name)) is not None
    ]
    if len(values) != 1:
        return None
    return values[0]


def _cursor_parameter(scope: AsgiMessage) -> int:
    raw_query = scope.get("query_string", b"")
    if not isinstance(raw_query, bytes):
        raise ValueError("query string must be bytes")
    try:
        parameters = parse_qs(
            raw_query.decode("ascii"),
            keep_blank_values=True,
        )
    except UnicodeDecodeError as error:
        raise ValueError("query string must be ASCII") from error
    values = parameters.get("cursor")
    if values is None:
        return 0
    if len(values) != 1 or not values[0].isdigit():
        raise ValueError("cursor must be one non-negative integer")
    return int(values[0])


def _evidence_cursor_parameter(
    scope: AsgiMessage,
) -> tuple[int, int] | None:
    raw_query = scope.get("query_string", b"")
    if not isinstance(raw_query, bytes):
        raise ValueError("query string must be bytes")
    try:
        parameters = parse_qs(
            raw_query.decode("ascii"),
            keep_blank_values=True,
        )
    except UnicodeDecodeError as error:
        raise ValueError("query string must be ASCII") from error
    values = parameters.get("cursor")
    if values is None:
        return None
    if len(values) != 1:
        raise ValueError("cursor must occur once")
    try:
        encoded = values[0].encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        value = json.loads(base64.urlsafe_b64decode(encoded))
        if (
            not isinstance(value, list)
            or len(value) != 2
            or not isinstance(value[0], int)
            or isinstance(value[0], bool)
            or value[0] < 0
            or not isinstance(value[1], int)
            or isinstance(value[1], bool)
            or value[1] < 0
            or value[1] > value[0]
        ):
            raise ValueError("cursor payload is invalid")
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("cursor is invalid") from error
    return value[0], value[1]


def _encode_evidence_cursor(cursor: tuple[int, int]) -> str:
    value = json.dumps(cursor, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


async def _request_json(receive: Receive) -> Mapping[str, object]:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        body = message.get("body", b"")
        if message.get("type") != "http.request" or not isinstance(body, bytes):
            raise ValueError("request body is invalid")
        size += len(body)
        if size > 65_536:
            raise ValueError("request body is too large")
        chunks.append(body)
        if not message.get("more_body", False):
            break
    value = json.loads(b"".join(chunks))
    if not isinstance(value, dict):
        raise ValueError("request JSON must be an object")
    return value


def _evidence_query(
    body: Mapping[str, object],
    tenant_id: TenantId,
) -> EvidenceQuery:
    raw_kinds = body["kinds"]
    raw_selectors = body.get("selectors", {})
    if not isinstance(raw_kinds, list) or not all(
        isinstance(value, str) for value in raw_kinds
    ):
        raise ValueError("kinds must be strings")
    if not isinstance(raw_selectors, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in raw_selectors.items()
    ):
        raise ValueError("selectors must be strings")
    idempotency_key = body["idempotency_key"]
    if not isinstance(idempotency_key, str):
        raise ValueError("idempotency key must be a string")
    return EvidenceQuery(
        query_id=UUID(str(body.get("query_id", uuid4()))),
        tenant_id=str(tenant_id),
        source=EvidenceSourceKind(str(body["source"])),
        environment=EnvironmentIdentity(str(body["environment"])),
        window=QueryWindow(
            datetime.fromisoformat(str(body["start"])),
            datetime.fromisoformat(str(body["end"])),
        ),
        kinds=tuple(EvidenceKind(value) for value in raw_kinds),
        selectors=raw_selectors,
        limit=int(str(body.get("limit", 100))),
        idempotency_key=idempotency_key,
        cursor=(
            PaginationCursor(str(body["cursor"]))
            if body.get("cursor") is not None
            else None
        ),
    )


def _matching_header(item: object, name: bytes) -> str | None:
    if (
        isinstance(item, tuple)
        and len(item) == 2
        and isinstance(item[0], bytes)
        and isinstance(item[1], bytes)
        and item[0].lower() == name
    ):
        return item[1].decode("latin-1")
    return None


def _principal_body(principal: Principal, at: datetime) -> dict[str, Any]:
    active_roles = sorted(
        {
            binding.role.value
            for binding in principal.role_bindings
            if binding.is_active(at)
        }
    )
    return {
        "actor_id": principal.actor_id,
        "kind": principal.kind.value,
        "tenant_id": str(principal.tenant_id),
        "roles": active_roles,
    }


def _policy_body(policy: TenantPolicy) -> dict[str, Any]:
    quotas = policy.quotas
    return {
        "tenant_id": str(policy.tenant_id),
        "version": policy.version,
        "allow": {
            "models": sorted(policy.allowed_models),
            "tools": sorted(policy.allowed_tools),
            "connectors": sorted(policy.allowed_connectors),
            "environments": sorted(policy.allowed_environments),
        },
        "risk": {
            "maximum": policy.max_risk.name.lower(),
            "approval_from": policy.approval_from_risk.name.lower(),
        },
        "quotas": {
            "max_run_tokens": quotas.max_run_tokens,
            "max_run_cost_usd": _decimal_string(quotas.max_run_cost_usd),
            "max_tenant_tokens_per_period": quotas.max_tenant_tokens_per_period,
            "max_tenant_cost_usd_per_period": _decimal_string(
                quotas.max_tenant_cost_usd_per_period
            ),
            "max_concurrent_runs": quotas.max_concurrent_runs,
        },
    }


def _event_body(event: EventEnvelope) -> dict[str, Any]:
    """Render a bounded redacted timeline representation."""
    return {
        "event_id": str(event.event_id),
        "aggregate_id": event.aggregate_id,
        "aggregate_sequence": event.aggregate_sequence,
        "global_position": event.global_position,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "occurred_at": event.occurred_at.isoformat(),
        "recorded_at": (
            event.recorded_at.isoformat() if event.recorded_at is not None else None
        ),
        "correlation_id": (
            str(event.correlation_id) if event.correlation_id is not None else None
        ),
        "payload": thaw_json(redact_details(event.payload)),
        "metadata": thaw_json(redact_details(event.metadata)),
    }


def _decimal_string(value: Decimal) -> str:
    return format(value, "f")


async def _respond(
    send: Send,
    status: int,
    body: dict[str, Any],
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    encoded = json.dumps(body, separators=(",", ":")).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(encoded)).encode()),
        (b"cache-control", b"no-store"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": encoded})


application = ControlPlaneApp()
