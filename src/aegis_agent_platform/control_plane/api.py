"""Authenticated ASGI control-plane vertical slice."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from time import monotonic
from typing import Any, Protocol, cast
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from aegis_agent_platform.agents.operations import AgentOperations
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
    SandboxApprovalBinding,
    SandboxPurpose,
    SandboxRisk,
    plan_from_payload,
    sandbox_request_from_payload,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import EventStore
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
from aegis_agent_platform.memory.api import MemoryHttpApi
from aegis_agent_platform.memory.operations import MemoryOperations
from aegis_agent_platform.observability.context import (
    TraceContextError,
    extract_context,
)
from aegis_agent_platform.observability.health import HealthRegistry
from aegis_agent_platform.observability.operations import ObservabilityOperations
from aegis_agent_platform.observability.replay import SupportReportTooLargeError
from aegis_agent_platform.observability.runtime import RuntimeTracer
from aegis_agent_platform.policy import (
    InMemoryPolicyRepository,
    PolicyRepository,
    TenantPolicy,
)
from aegis_agent_platform.remediation import (
    ApprovalDecision,
    ApprovalDeniedError,
    RemediationIdempotencyConflictError,
    RemediationOperations,
)
from aegis_agent_platform.sandbox import (
    SandboxIdempotencyConflictError,
    SandboxOperations,
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
        agent_operations: AgentOperations | None = None,
        remediation_operations: RemediationOperations | None = None,
        sandbox_operations: SandboxOperations | None = None,
        memory_operations: MemoryOperations | None = None,
        tracer: RuntimeTracer | None = None,
        observability_operations: ObservabilityOperations | None = None,
        health_registry: HealthRegistry | None = None,
        health_clock: Callable[[], float] = monotonic,
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
        self._agent_operations = agent_operations
        self._remediation_operations = remediation_operations
        self._sandbox_operations = sandbox_operations
        self._memory_api = (
            MemoryHttpApi(memory_operations) if memory_operations is not None else None
        )
        self._tracer = tracer or RuntimeTracer("aegis.control-plane")
        self._observability_operations = observability_operations
        self._health_registry = health_registry
        self._health_clock = health_clock

    async def __call__(
        self,
        scope: AsgiMessage,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            return
        try:
            parent = extract_context(_propagation_headers(scope))
        except TraceContextError:
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_trace_context"}},
            )
            return
        with self._tracer.span("api.request", parent=parent):
            await self._handle(scope, receive, send)

    async def _handle(
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
            evidence_post = (
                len(post_segments) == 5
                and post_segments[:2] == ["v1", "tenants"]
                and post_segments[3:] == ["evidence", "queries"]
            )
            remediation_post = (
                len(post_segments) == 4
                and post_segments[:2] == ["v1", "tenants"]
                and post_segments[3] == "remediations"
            ) or (
                len(post_segments) == 8
                and post_segments[:2] == ["v1", "tenants"]
                and post_segments[3] == "remediations"
                and post_segments[5] == "approvals"
                and post_segments[7] in {"decisions", "revocations"}
            )
            sandbox_post = (
                len(post_segments) == 4
                and post_segments[:2] == ["v1", "tenants"]
                and post_segments[3] == "sandboxes"
            )
            memory_post = (
                len(post_segments) >= 4
                and post_segments[:2] == ["v1", "tenants"]
                and post_segments[3] == "memories"
            )
            if (
                not evidence_post
                and not remediation_post
                and not sandbox_post
                and not memory_post
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
        if len(segments) >= 4 and segments[3] == "memories":
            if self._memory_api is None:
                await _respond(
                    send,
                    503,
                    {"error": {"code": "memory_not_configured"}},
                )
                return
            raw_query = scope.get("query_string", b"")
            if not isinstance(raw_query, bytes):
                await _respond(
                    send,
                    400,
                    {"error": {"code": "invalid_memory_request"}},
                )
                return
            response = await self._memory_api.handle(
                method=method,
                tail=tuple(segments[4:]),
                query_string=raw_query,
                receive=receive,
                principal=principal,
                context=TenantContext(tenant_id),
            )
            await _respond(send, response.status, response.body)
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
        if method == "POST" and len(segments) == 4 and segments[3] == "remediations":
            await self._request_remediation(
                send,
                receive,
                principal,
                tenant_id,
            )
            return
        if method == "POST" and len(segments) == 4 and segments[3] == "sandboxes":
            await self._request_sandbox(
                send,
                receive,
                principal,
                tenant_id,
            )
            return
        if method == "GET" and len(segments) == 4 and segments[3] == "sandboxes":
            try:
                sandbox_cursor = _uuid_cursor_parameter(
                    scope,
                    "after_sandbox_id",
                )
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_sandboxes(
                send,
                principal,
                tenant_id,
                after_sandbox_id=sandbox_cursor,
            )
            return
        if (
            method == "GET"
            and len(segments) == 5
            and segments[3:] == ["sandboxes", "cleanup"]
        ):
            try:
                cleanup_cursor = _uuid_cursor_parameter(
                    scope,
                    "after_sandbox_id",
                )
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_sandbox_cleanup(
                send,
                principal,
                tenant_id,
                after_sandbox_id=cleanup_cursor,
            )
            return
        if (
            method == "GET"
            and len(segments) == 6
            and segments[3] == "sandboxes"
            and segments[5] == "artifacts"
        ):
            try:
                artifact_cursor = _cursor_parameter(scope)
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_sandbox_artifacts(
                send,
                principal,
                tenant_id,
                segments[4],
                after_position=artifact_cursor,
            )
            return
        if method == "GET" and len(segments) == 5 and segments[3] == "sandboxes":
            await self._get_sandbox(
                send,
                principal,
                tenant_id,
                segments[4],
            )
            return
        if method == "GET" and len(segments) == 4 and segments[3] == "remediations":
            try:
                remediation_cursor = _remediation_cursor_parameter(scope)
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_remediations(
                send,
                principal,
                tenant_id,
                after_plan_id=remediation_cursor,
            )
            return
        if method == "GET" and len(segments) == 5 and segments[3] == "remediations":
            await self._get_remediation(
                send,
                principal,
                tenant_id,
                segments[4],
            )
            return
        if (
            method == "POST"
            and len(segments) == 8
            and segments[3] == "remediations"
            and segments[5] == "approvals"
            and segments[7] in {"decisions", "revocations"}
        ):
            await self._decide_remediation(
                send,
                receive,
                principal,
                tenant_id,
                plan_id=segments[4],
                approval_id=segments[6],
                revoke=segments[7] == "revocations",
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
                correlation_id=correlation_id,
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
                correlation_id=correlation_id,
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
                correlation_id=correlation_id,
            )
            return
        if (
            method == "GET"
            and len(segments) in {5, 6}
            and segments[3] == "investigations"
        ):
            view = "status" if len(segments) == 5 else segments[5]
            if view not in {"status", "tasks", "artifacts"}:
                await _respond(send, 404, {"status": "not-found"})
                return
            try:
                investigation_cursor = _cursor_parameter(scope)
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_investigation_view(
                send,
                principal,
                tenant_id,
                segments[4],
                view,
                correlation_id=correlation_id,
                cursor=investigation_cursor,
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
                correlation_id=correlation_id,
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
        if (
            method == "GET"
            and len(segments) == 5
            and segments[3:] == ["observability", "slos"]
        ):
            await self._get_observability_slos(send, principal, tenant_id)
            return
        if (
            method == "GET"
            and len(segments) == 6
            and segments[3:5] == ["observability", "timeline"]
        ):
            try:
                after_version = _cursor_parameter(scope)
            except ValueError:
                await _respond(send, 400, {"error": {"code": "invalid_cursor"}})
                return
            await self._get_observability_timeline(
                send,
                principal,
                tenant_id,
                segments[5],
                after_version=after_version,
            )
            return
        if (
            method == "GET"
            and len(segments) == 6
            and segments[3:5] == ["observability", "support-reports"]
        ):
            await self._get_support_report(
                send,
                principal,
                tenant_id,
                segments[5],
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
        *,
        correlation_id: UUID,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_QUERY,
            correlation_id=correlation_id,
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

    async def _request_sandbox(
        self,
        send: Send,
        receive: Receive,
        principal: Principal,
        tenant_id: TenantId,
    ) -> None:
        if self._sandbox_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "sandbox_not_configured"}},
            )
            return
        try:
            body = await _request_json(receive)
            request_value = body.get("request")
            approval_value = body.get("approval")
            if not isinstance(request_value, Mapping) or not isinstance(
                approval_value,
                Mapping,
            ):
                raise ValueError("request and approval are required")
            sandbox_request = sandbox_request_from_payload(
                cast(Mapping[str, JsonValue], request_value)
            )
            if sandbox_request.linkage.tenant_id != str(tenant_id):
                raise PermissionError("sandbox_request_tenant_mismatch")
            approval = _sandbox_approval_binding(
                cast(Mapping[str, JsonValue], approval_value)
            )
            decision = await self._sandbox_operations.request(
                principal,
                TenantContext(tenant_id),
                sandbox_request,
                approval,
            )
        except SandboxIdempotencyConflictError:
            await _respond(
                send,
                409,
                {"error": {"code": "sandbox_idempotency_conflict"}},
            )
            return
        except PermissionError as error:
            await _respond(
                send,
                403,
                {"error": {"code": "sandbox_denied", "reason": str(error)}},
            )
            return
        except (KeyError, TypeError, ValueError):
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_sandbox_request"}},
            )
            return
        await _respond(
            send,
            202 if decision.result.created else 200,
            {
                "accepted": decision.result.created,
                "policy_reasons": decision.policy.reasons,
                "redacted": True,
                "sandbox_id": str(decision.result.sandbox_id),
                "spec_digest": decision.state.request.spec.digest,
                "status": decision.state.status.value,
            },
        )

    async def _get_sandboxes(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        *,
        after_sandbox_id: UUID | None,
    ) -> None:
        if self._sandbox_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "sandbox_not_configured"}},
            )
            return
        try:
            rows, cursor = await self._sandbox_operations.page(
                principal,
                TenantContext(tenant_id),
                at=datetime.now(UTC),
                after_sandbox_id=after_sandbox_id,
                limit=100,
            )
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        await _respond(
            send,
            200,
            {
                "next_cursor": str(cursor) if cursor is not None else None,
                "redacted": True,
                "sandboxes": tuple(dict(row) for row in rows),
            },
        )

    async def _get_sandbox(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        sandbox_id: str,
    ) -> None:
        if self._sandbox_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "sandbox_not_configured"}},
            )
            return
        try:
            result = await self._sandbox_operations.status(
                principal,
                TenantContext(tenant_id),
                UUID(sandbox_id),
                at=datetime.now(UTC),
            )
        except ValueError:
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_sandbox_id"}},
            )
            return
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        if result is None:
            await _respond(
                send,
                404,
                {"error": {"code": "sandbox_not_found"}},
            )
            return
        await _respond(send, 200, dict(result))

    async def _get_sandbox_artifacts(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        sandbox_id: str,
        *,
        after_position: int,
    ) -> None:
        if self._sandbox_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "sandbox_not_configured"}},
            )
            return
        try:
            rows, cursor = await self._sandbox_operations.artifacts(
                principal,
                TenantContext(tenant_id),
                UUID(sandbox_id),
                at=datetime.now(UTC),
                after_position=after_position,
                limit=100,
            )
        except ValueError:
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_sandbox_id"}},
            )
            return
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        await _respond(
            send,
            200,
            {
                "artifacts": tuple(dict(row) for row in rows),
                "next_cursor": cursor,
                "redacted": True,
            },
        )

    async def _get_sandbox_cleanup(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        *,
        after_sandbox_id: UUID | None,
    ) -> None:
        if self._sandbox_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "sandbox_not_configured"}},
            )
            return
        try:
            rows, cursor = await self._sandbox_operations.cleanup_queue(
                principal,
                TenantContext(tenant_id),
                at=datetime.now(UTC),
                after_sandbox_id=after_sandbox_id,
                limit=100,
            )
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        await _respond(
            send,
            200,
            {
                "cleanup": tuple(dict(row) for row in rows),
                "next_cursor": str(cursor) if cursor is not None else None,
                "redacted": True,
            },
        )

    async def _request_remediation(
        self,
        send: Send,
        receive: Receive,
        principal: Principal,
        tenant_id: TenantId,
    ) -> None:
        if self._remediation_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "remediation_not_configured"}},
            )
            return
        try:
            body = await _request_json(receive)
            plan_value = body.get("plan")
            idempotency_key = body.get("idempotency_key")
            if not isinstance(plan_value, Mapping) or not isinstance(
                idempotency_key, str
            ):
                raise ValueError("plan and idempotency key are required")
            plan = plan_from_payload(cast(Mapping[str, JsonValue], plan_value))
            decision = await self._remediation_operations.propose(
                principal,
                TenantContext(tenant_id),
                plan,
                idempotency_key=idempotency_key,
            )
        except RemediationIdempotencyConflictError:
            await _respond(
                send,
                409,
                {"error": {"code": "remediation_idempotency_conflict"}},
            )
            return
        except ApprovalDeniedError:
            await _respond(
                send,
                403,
                {"error": {"code": "remediation_proposal_denied"}},
            )
            return
        except PermissionError:
            await _respond(
                send,
                403,
                {"error": {"code": "remediation_policy_not_configured"}},
            )
            return
        except (KeyError, TypeError, ValueError):
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_remediation_plan"}},
            )
            return
        await _respond(
            send,
            202 if decision.result.created else 200,
            {
                "accepted": decision.result.created,
                "plan_id": str(decision.state.plan.plan_id),
                "plan_digest": decision.state.plan.digest,
                "policy_digest": decision.state.plan.approval_policy.digest,
                "redacted": True,
            },
        )

    async def _decide_remediation(
        self,
        send: Send,
        receive: Receive,
        principal: Principal,
        tenant_id: TenantId,
        *,
        plan_id: str,
        approval_id: str,
        revoke: bool,
    ) -> None:
        if self._remediation_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "remediation_not_configured"}},
            )
            return
        try:
            parsed_plan_id = UUID(plan_id)
            parsed_approval_id = UUID(approval_id)
            body = await _request_json(receive)
            rationale_code = body.get("rationale_code")
            if not isinstance(rationale_code, str):
                raise ValueError("rationale code is required")
            if revoke:
                revocation_id = body.get("revocation_id")
                if not isinstance(revocation_id, str):
                    raise ValueError("revocation id is required")
                result = await self._remediation_operations.revoke(
                    principal,
                    TenantContext(tenant_id),
                    parsed_plan_id,
                    parsed_approval_id,
                    revocation_id=UUID(revocation_id),
                    rationale_code=rationale_code,
                )
            else:
                decision_id = body.get("decision_id")
                decision_value = body.get("decision")
                comment = body.get("comment")
                if (
                    not isinstance(decision_id, str)
                    or not isinstance(decision_value, str)
                    or not isinstance(comment, str)
                ):
                    raise ValueError("approval decision fields are required")
                result = await self._remediation_operations.decide(
                    principal,
                    TenantContext(tenant_id),
                    parsed_plan_id,
                    parsed_approval_id,
                    ApprovalDecision(decision_value),
                    decision_id=UUID(decision_id),
                    rationale_code=rationale_code,
                    comment=comment,
                )
        except ApprovalDeniedError:
            await _respond(
                send,
                403,
                {"error": {"code": "remediation_approval_denied"}},
            )
            return
        except RemediationIdempotencyConflictError:
            await _respond(
                send,
                409,
                {"error": {"code": "approval_idempotency_conflict"}},
            )
            return
        except PermissionError:
            await _respond(
                send,
                403,
                {"error": {"code": "remediation_policy_not_configured"}},
            )
            return
        except (KeyError, TypeError, ValueError):
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_approval_decision"}},
            )
            return
        await _respond(send, 200, dict(result))

    async def _get_remediations(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        *,
        after_plan_id: UUID | None,
    ) -> None:
        if self._remediation_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "remediation_not_configured"}},
            )
            return
        try:
            rows, cursor = await self._remediation_operations.page(
                principal,
                TenantContext(tenant_id),
                at=datetime.now(UTC),
                after_plan_id=after_plan_id,
                limit=100,
            )
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        await _respond(
            send,
            200,
            {
                "remediations": rows,
                "next_cursor": str(cursor) if cursor is not None else None,
            },
        )

    async def _get_remediation(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        plan_id: str,
    ) -> None:
        if self._remediation_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "remediation_not_configured"}},
            )
            return
        try:
            result = await self._remediation_operations.status(
                principal,
                TenantContext(tenant_id),
                UUID(plan_id),
                at=datetime.now(UTC),
            )
        except ValueError:
            await _respond(
                send,
                400,
                {"error": {"code": "invalid_remediation_id"}},
            )
            return
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "permission_denied"}})
            return
        if result is None:
            await _respond(
                send,
                404,
                {"error": {"code": "remediation_not_found"}},
            )
            return
        await _respond(send, 200, dict(result))

    async def _get_evidence_view(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        view: str,
        *,
        correlation_id: UUID,
        cursor: tuple[int, int] | None,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_READ,
            correlation_id=correlation_id,
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
        *,
        correlation_id: UUID,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_READ,
            correlation_id=correlation_id,
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
        *,
        correlation_id: UUID,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.EVIDENCE_READ,
            correlation_id=correlation_id,
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

    async def _get_investigation_view(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        run_id: str,
        view: str,
        *,
        correlation_id: UUID,
        cursor: int,
    ) -> None:
        if not await self._authorize(
            send,
            principal,
            tenant_id,
            Permission.INVESTIGATION_READ,
            correlation_id=correlation_id,
            resource=f"tenant/{tenant_id}/investigations/{view}",
        ):
            return
        if self._agent_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "investigation_not_configured"}},
            )
            return
        try:
            identifier = UUID(run_id)
        except ValueError:
            await _respond(send, 400, {"error": {"code": "invalid_run_id"}})
            return
        context = TenantContext(tenant_id)
        at = datetime.now(UTC)
        if view == "status":
            result = await self._agent_operations.status(
                principal,
                context,
                identifier,
                at=at,
            )
            await _respond(
                send,
                200 if result is not None else 404,
                (
                    dict(result)
                    if result is not None
                    else {"error": {"code": "investigation_not_found"}}
                ),
            )
            return
        if view == "tasks":
            items, task_cursor = await self._agent_operations.tasks(
                principal,
                context,
                identifier,
                at=at,
                after_ordinal=cursor - 1,
                limit=100,
            )
            next_cursor = task_cursor + 1 if task_cursor is not None else None
        else:
            items, next_cursor = await self._agent_operations.artifacts(
                principal,
                context,
                identifier,
                at=at,
                after_position=cursor,
                limit=100,
            )
        await _respond(
            send,
            200,
            {view: items, "next_cursor": next_cursor},
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
        health = (
            await self._health_registry.report(monotonic_time=self._health_clock())
            if self._health_registry is not None
            else None
        )
        if health is not None and not health.ready:
            await _respond(
                send,
                503,
                {
                    "status": "not-ready",
                    "reason": "correctness_dependency_unavailable",
                    "components": {
                        name: {
                            "status": result.status.value,
                            "reason_code": result.reason_code,
                        }
                        for name, result in health.components.items()
                    },
                },
            )
            return
        await _respond(
            send,
            200,
            {
                "status": (
                    "degraded"
                    if health is not None and health.status.value == "degraded"
                    else "ready"
                ),
                "checks": (
                    ["configuration", "storage"]
                    if self._storage_ready is not None
                    else ["configuration"]
                ),
                "capabilities": {
                    "remediation": (
                        "configured"
                        if self._remediation_operations is not None
                        else "disabled"
                    ),
                    "telemetry": (
                        "degraded"
                        if health is not None and health.status.value == "degraded"
                        else "configured"
                        if self._health_registry is not None
                        else "unprobed"
                    ),
                },
                "components": (
                    {
                        name: {
                            "status": result.status.value,
                            "reason_code": result.reason_code,
                        }
                        for name, result in health.components.items()
                    }
                    if health is not None
                    else {}
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

    async def _get_observability_slos(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
    ) -> None:
        if self._observability_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "observability_not_configured"}},
            )
            return
        try:
            summaries = self._observability_operations.slo_summary(
                principal,
                TenantContext(tenant_id),
                at=datetime.now(UTC),
            )
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "authorization_denied"}})
            return
        await _respond(
            send,
            200,
            {
                "authoritative": False,
                "source": "derived_sli_windows",
                "objectives": [
                    {
                        "objective": summary.objective,
                        "window": summary.window,
                        "target": summary.target,
                        "status": summary.status,
                        "measured": summary.measured,
                        "reason_code": summary.reason_code,
                    }
                    for summary in summaries
                ],
            },
        )

    async def _get_observability_timeline(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        aggregate_id: str,
        *,
        after_version: int,
    ) -> None:
        if self._observability_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "observability_not_configured"}},
            )
            return
        try:
            timeline = await self._observability_operations.timeline(
                principal,
                TenantContext(tenant_id),
                aggregate_id,
                at=datetime.now(UTC),
                after_sequence=after_version,
            )
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "authorization_denied"}})
            return
        await _respond(send, 200, cast(dict[str, Any], thaw_json(timeline)))

    async def _get_support_report(
        self,
        send: Send,
        principal: Principal,
        tenant_id: TenantId,
        aggregate_id: str,
    ) -> None:
        if self._observability_operations is None:
            await _respond(
                send,
                503,
                {"error": {"code": "observability_not_configured"}},
            )
            return
        try:
            report = await self._observability_operations.support_report(
                principal,
                TenantContext(tenant_id),
                aggregate_id,
                at=datetime.now(UTC),
            )
        except PermissionError:
            await _respond(send, 403, {"error": {"code": "authorization_denied"}})
            return
        except SupportReportTooLargeError:
            await _respond(
                send,
                422,
                {"error": {"code": "support_report_too_large"}},
            )
            return
        await _respond(
            send,
            200,
            {
                "schema_version": report.schema_version,
                "tenant_reference": report.tenant_reference,
                "aggregate_reference": report.aggregate_reference,
                "content_digest": report.content_digest,
                "signature_algorithm": report.signature_algorithm,
                "signer": report.signer,
                "signature": report.signature,
                "validation": {
                    "valid": report.validation.valid,
                    "event_count": report.validation.event_count,
                    "stream_digest": report.validation.stream_digest,
                    "reason_codes": list(report.validation.reason_codes),
                },
                "authoritative_source": "event_ledger",
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


def _propagation_headers(scope: AsgiMessage) -> Mapping[str, str]:
    raw_headers: object = scope.get("headers", [])
    if not isinstance(raw_headers, list):
        return {}
    output: dict[str, str] = {}
    for name in (b"traceparent", b"tracestate", b"baggage"):
        values = [
            value
            for item in raw_headers
            if (value := _matching_header(item, name)) is not None
        ]
        if len(values) > 1:
            raise TraceContextError("duplicate propagation header")
        if values:
            output[name.decode()] = values[0]
    return output


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


def _uuid_cursor_parameter(
    scope: AsgiMessage,
    name: str,
) -> UUID | None:
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
    values = parameters.get(name)
    if values is None:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError("UUID cursor must occur once")
    return UUID(values[0])


def _remediation_cursor_parameter(scope: AsgiMessage) -> UUID | None:
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
    values = parameters.get("after_plan_id")
    if values is None:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError("remediation cursor must occur once")
    return UUID(values[0])


def _sandbox_approval_binding(
    value: Mapping[str, JsonValue],
) -> SandboxApprovalBinding:
    approver_values = value["approver_ids"]
    if not isinstance(approver_values, (list, tuple)) or any(
        not isinstance(item, str) for item in approver_values
    ):
        raise ValueError("sandbox approver identifiers are invalid")
    schema_version = value.get("schema_version", 1)
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise ValueError("sandbox approval schema is invalid")
    risk = value["risk"]
    if not isinstance(risk, int) or isinstance(risk, bool):
        raise ValueError("sandbox approval risk is invalid")
    return SandboxApprovalBinding(
        approval_id=UUID(str(value["approval_id"])),
        plan_id=UUID(str(value["plan_id"])),
        action_id=UUID(str(value["action_id"])),
        plan_digest=str(value["plan_digest"]),
        action_digest=str(value["action_digest"]),
        policy_digest=str(value["policy_digest"]),
        spec_digest=str(value["spec_digest"]),
        purpose=SandboxPurpose(str(value["purpose"])),
        risk=SandboxRisk(risk),
        approver_ids=tuple(cast(str, item) for item in approver_values),
        issued_at=datetime.fromisoformat(str(value["issued_at"])),
        expires_at=datetime.fromisoformat(str(value["expires_at"])),
        schema_version=schema_version,
    )


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
