"""Authenticated ASGI control-plane vertical slice."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditStore,
    InMemoryAuditStore,
)
from aegis_agent_platform.config import ConfigurationError, Settings
from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.identity import (
    PLATFORM_TENANT_ID,
    AuthenticationError,
    AuthenticationService,
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


class ControlPlaneApp:
    """Small injectable API showing the complete security boundary."""

    def __init__(
        self,
        *,
        authentication: AuthenticationService | None = None,
        authorization: AuthorizationService | None = None,
        tenants: TenantRepository | None = None,
        policies: PolicyRepository | None = None,
        audit: AuditStore | None = None,
    ) -> None:
        self._authentication = authentication
        self._authorization = authorization or AuthorizationService()
        self._tenants = tenants or InMemoryTenantRepository(())
        self._policies = policies or InMemoryPolicyRepository(())
        self._audit = audit or InMemoryAuditStore()

    async def __call__(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
    ) -> None:
        del receive
        if scope.get("type") != "http":
            return
        path = scope.get("path")
        method = scope.get("method", "GET")
        if method != "GET":
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
        principal = await self._authenticate(scope, send)
        if principal is None:
            return
        if path == "/v1/me":
            await _respond(send, 200, _principal_body(principal, datetime.now(UTC)))
            return
        segments = [segment for segment in path.split("/") if segment]
        if len(segments) not in {3, 4} or segments[:2] != ["v1", "tenants"]:
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
            await self._get_tenant(send, principal, tenant_id)
            return
        if segments[3] == "policy":
            await self._get_policy(send, principal, tenant_id)
            return
        await _respond(send, 404, {"status": "not-found"})

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
        await _respond(
            send,
            200,
            {"status": "ready", "checks": ["configuration"]},
        )

    async def _authenticate(
        self,
        scope: AsgiMessage,
        send: Send,
    ) -> Principal | None:
        correlation_id = uuid4()
        if self._authentication is None:
            await _respond(
                send,
                503,
                {"error": {"code": "authentication_not_configured"}},
            )
            return None
        authorization_header = _single_header(scope, b"authorization")
        try:
            principal = self._authentication.authenticate(authorization_header)
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
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.TENANT_READ,
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
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.POLICY_READ,
            resource=f"tenant/{tenant_id}/policy",
        ):
            return
        policy = self._policies.get(TenantContext(tenant_id))
        if policy is None:
            await _respond(send, 404, {"error": {"code": "policy_not_found"}})
            return
        await _respond(send, 200, _policy_body(policy))

    async def _authorize(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        permission: Permission,
        *,
        resource: str,
    ) -> bool:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=tenant_id,
            permission=permission,
            at=datetime.now(UTC),
        )
        self._audit_authorization(principal, resource, decision)
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
    ) -> None:
        self._audit_event(
            tenant_id=principal.tenant_id,
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            outcome=(AuditOutcome.SUCCESS if decision.allowed else AuditOutcome.DENIED),
            actor_id=principal.actor_id,
            action=decision.permission,
            resource=resource,
            correlation_id=uuid4(),
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
