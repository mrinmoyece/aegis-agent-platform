"""Durable governed MCP invocation and A2A task orchestration."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EventEnvelope,
    JsonValue,
    ProtocolArtifact,
    ProtocolCapability,
    ProtocolErrorClass,
    ProtocolFamily,
    ProtocolOperationState,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolPeerStatus,
    ProtocolPolicySnapshot,
    ProtocolRequest,
    ProtocolResult,
    WorkLease,
    canonical_json_bytes,
    content_digest,
)
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
)
from aegis_agent_platform.protocols.registry import (
    CapabilityDriftError,
    ProtocolRegistry,
    peer_digest,
)
from aegis_agent_platform.protocols.repository import ProtocolLedger
from aegis_agent_platform.protocols.security import (
    ProtocolSchemaValidator,
    ProtocolSecurityError,
)
from aegis_agent_platform.protocols.telemetry import (
    ProtocolBoundary,
    ProtocolMetrics,
    ProtocolTracer,
)
from aegis_agent_platform.tenancy import TenantContext


class ProtocolPolicyDeniedError(PermissionError):
    pass


class ExternalProtocolError(RuntimeError):
    def __init__(
        self,
        error_class: ProtocolErrorClass,
        code: str,
        *,
        retryable: bool,
        ambiguous: bool = False,
    ) -> None:
        super().__init__(code)
        self.error_class = error_class
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


@dataclass(frozen=True, slots=True)
class TransportResponse:
    provider_reference: str
    payload: Mapping[str, JsonValue]
    artifacts: tuple[ProtocolArtifact, ...]
    remote_status: ProtocolOperationStatus
    completed_at: datetime


class ExternalProtocolPort(Protocol):
    async def discover(
        self,
        peer: ProtocolPeer,
    ) -> tuple[tuple[ProtocolCapability, ...], str, str]: ...

    async def send(
        self,
        peer: ProtocolPeer,
        capability: ProtocolCapability,
        request: ProtocolRequest,
    ) -> TransportResponse: ...

    async def observe(
        self,
        peer: ProtocolPeer,
        request: ProtocolRequest,
    ) -> TransportResponse | None: ...

    async def cancel(self, peer: ProtocolPeer, request: ProtocolRequest) -> bool: ...


class ProtocolGateway:
    """Durable at-least-once boundary; network exactly-once is never claimed."""

    def __init__(
        self,
        *,
        registry: ProtocolRegistry,
        ledger: ProtocolLedger,
        adapters: Mapping[ProtocolFamily, ExternalProtocolPort],
        capabilities: Mapping[str, ProtocolCapability],
        authorization: AuthorizationService | None = None,
        schema_validator: ProtocolSchemaValidator | None = None,
        metrics: ProtocolMetrics | None = None,
        tracer: ProtocolTracer | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        event_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._registry = registry
        self._ledger = ledger
        self._adapters = dict(adapters)
        self._capabilities = dict(capabilities)
        self._authorization = authorization or AuthorizationService()
        self._schemas = schema_validator or ProtocolSchemaValidator()
        self._metrics = metrics
        self._tracer = tracer
        self._monotonic = monotonic
        self._event_id_factory = event_id_factory

    async def refresh_capabilities(
        self,
        principal: Principal,
        context: TenantContext,
        peer_id: str,
        *,
        at: datetime,
    ) -> ProtocolPeer:
        self._require(principal, context, Permission.PROTOCOL_TRUST_MANAGE, at)
        peer = self._peer(context, peer_id)
        adapter = self._adapter(peer.family)
        capabilities, card_digest, schema_digest = await adapter.discover(peer)
        try:
            return self._registry.record_capabilities(
                context,
                peer_id,
                capabilities,
                card_digest=card_digest,
                schema_digest=schema_digest,
                at=at,
            )
        except CapabilityDriftError:
            if self._metrics is not None:
                boundary = self._boundary(peer)
                self._metrics.add("drift", boundary, "drift")
                self._metrics.add("quarantine", boundary, "quarantined")
            raise

    async def request(
        self,
        principal: Principal,
        context: TenantContext,
        request: ProtocolRequest,
        policy: ProtocolPolicySnapshot,
        *,
        lease: WorkLease | None = None,
    ) -> ProtocolResult:
        capability = self._validate_request(
            principal,
            context,
            request,
            policy,
        )
        duplicate = await self._ledger.by_idempotency_key(
            context,
            request.idempotency_key,
        )
        if duplicate is not None:
            if duplicate.request_digest != request.payload_digest:
                raise ProtocolPolicyDeniedError("idempotency_key_payload_conflict")
            return self._state_result(duplicate, request.requested_at)
        peer = self._peer(context, request.peer_id)
        boundary = self._boundary(peer)
        if self._metrics is not None:
            self._metrics.add("operations", boundary, "requested")
            self._metrics.observe_bytes(
                "request",
                boundary,
                "requested",
                len(canonical_json_bytes(request.payload)),
            )
        requested_type = (
            DomainEventType.MCP_INVOCATION_REQUESTED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_TASK_REQUESTED
        )
        events = (
            self._event(
                request,
                DomainEventType.PROTOCOL_POLICY_DECIDED,
                {
                    **self._base_payload(request, lease),
                    "decision": "allowed",
                    "risk": int(capability.risk),
                },
                principal=principal,
            ),
            self._event(
                request,
                requested_type,
                self._base_payload(request, lease),
                principal=principal,
            ),
        )
        version = await self._ledger.append(
            context,
            request.operation_id,
            events,
            expected_version=0,
            lease=lease,
        )
        adapter = self._adapter(peer.family)
        started_type = (
            DomainEventType.MCP_INVOCATION_STARTED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_TASK_ACCEPTED
        )
        version = await self._ledger.append(
            context,
            request.operation_id,
            (
                self._event(
                    request,
                    started_type,
                    self._base_payload(request, lease),
                    principal=principal,
                ),
            ),
            expected_version=version,
            lease=lease,
        )
        started = self._monotonic()
        trace_scope = (
            self._tracer.operation(boundary)
            if self._tracer is not None
            else nullcontext()
        )
        try:
            with trace_scope:
                response = await asyncio.wait_for(
                    adapter.send(peer, capability, request),
                    timeout=policy.timeout_seconds,
                )
            result_digest = self._schemas.validate(
                capability.output_schema,
                response.payload,
                maximum_bytes=min(
                    capability.maximum_output_bytes,
                    policy.maximum_response_bytes,
                ),
            )
            terminal_type = (
                DomainEventType.MCP_INVOCATION_COMPLETED
                if request.family is ProtocolFamily.MCP
                else DomainEventType.A2A_TASK_COMPLETED
            )
            result = ProtocolResult(
                request.operation_id,
                ProtocolOperationStatus.COMPLETED,
                result_digest,
                response.provider_reference,
                response.artifacts,
                response.completed_at,
            )
            artifact_events = (
                tuple(
                    self._event(
                        request,
                        DomainEventType.A2A_ARTIFACT_RECORDED,
                        {
                            **self._base_payload(request, lease),
                            "artifact": self._artifact_payload(artifact),
                        },
                        principal=principal,
                        occurred_at=response.completed_at,
                    )
                    for artifact in response.artifacts
                )
                if request.family is ProtocolFamily.A2A
                else ()
            )
            await self._ledger.append(
                context,
                request.operation_id,
                (
                    *artifact_events,
                    self._event(
                        request,
                        terminal_type,
                        {
                            **self._base_payload(request, lease),
                            "result_digest": result.result_digest,
                            "provider_reference": result.provider_reference,
                            "artifact_digests": tuple(
                                artifact.content_digest for artifact in result.artifacts
                            ),
                            "artifacts": tuple(
                                self._artifact_payload(artifact)
                                for artifact in result.artifacts
                            ),
                        },
                        principal=principal,
                        occurred_at=response.completed_at,
                    ),
                ),
                expected_version=version,
                lease=lease,
            )
            if self._metrics is not None:
                self._metrics.add(
                    "latency_ms",
                    boundary,
                    "completed",
                    (self._monotonic() - started) * 1_000,
                )
                self._metrics.add("operations", boundary, "completed")
                self._metrics.observe_bytes(
                    "response",
                    boundary,
                    "completed",
                    len(canonical_json_bytes(response.payload)),
                )
            return result
        except TimeoutError:
            self._record_telemetry_failure(boundary, started, "ambiguous")
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                ProtocolErrorClass.AMBIGUOUS,
                "protocol_timeout_ambiguous",
                ambiguous=True,
                lease=lease,
            )
        except ExternalProtocolError as error:
            self._record_telemetry_failure(
                boundary,
                started,
                "ambiguous" if error.ambiguous else "failed",
            )
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                error.error_class,
                error.code,
                ambiguous=error.ambiguous,
                retryable=error.retryable,
                lease=lease,
            )
        except ProtocolSecurityError as error:
            self._record_telemetry_failure(boundary, started, "failed")
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                ProtocolErrorClass.SECURITY,
                error.code,
                ambiguous=False,
                retryable=False,
                lease=lease,
            )

    async def reconcile(
        self,
        principal: Principal,
        context: TenantContext,
        request: ProtocolRequest,
        *,
        at: datetime,
        lease: WorkLease | None = None,
    ) -> ProtocolResult:
        self._require(principal, context, Permission.PROTOCOL_RECONCILE, at)
        events = await self._ledger.load(context, request.operation_id)
        if not events:
            raise LookupError("protocol operation not found")
        state = await self._ledger.by_idempotency_key(
            context,
            request.idempotency_key,
        )
        if state is None or state.status is not ProtocolOperationStatus.AMBIGUOUS:
            raise ProtocolPolicyDeniedError("only_ambiguous_operations_reconcile")
        peer = self._peer(context, request.peer_id)
        boundary = self._boundary(peer)
        if self._metrics is not None:
            self._metrics.add("reconciliations", boundary, "requested")
        request_type = (
            DomainEventType.MCP_RECONCILIATION_REQUESTED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_RECONCILIATION_REQUESTED
        )
        version = await self._ledger.append(
            context,
            request.operation_id,
            (
                self._event(
                    request,
                    request_type,
                    self._base_payload(request, lease),
                    principal=principal,
                    occurred_at=at,
                ),
            ),
            expected_version=len(events),
            lease=lease,
        )
        try:
            observed = await self._adapter(peer.family).observe(peer, request)
        except TimeoutError:
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                ProtocolErrorClass.AMBIGUOUS,
                "protocol_reconciliation_timeout",
                ambiguous=True,
                retryable=True,
                lease=lease,
            )
        except ExternalProtocolError as error:
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                error.error_class,
                error.code,
                ambiguous=True,
                retryable=error.retryable,
                lease=lease,
            )
        except ProtocolSecurityError as error:
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                ProtocolErrorClass.SECURITY,
                error.code,
                ambiguous=True,
                retryable=False,
                lease=lease,
            )
        if observed is None:
            return ProtocolResult(
                request.operation_id,
                ProtocolOperationStatus.AMBIGUOUS,
                "0" * 64,
                "reconciliation-pending",
                (),
                at,
                retryable=True,
                error_class=ProtocolErrorClass.AMBIGUOUS,
                error_code="remote_status_unavailable",
            )
        if observed.remote_status is not ProtocolOperationStatus.COMPLETED:
            error_class = (
                ProtocolErrorClass.AMBIGUOUS
                if observed.remote_status
                in {
                    ProtocolOperationStatus.ACCEPTED,
                    ProtocolOperationStatus.RUNNING,
                }
                else ProtocolErrorClass.PERMANENT
            )
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                error_class,
                f"remote_status_{observed.remote_status.value}",
                ambiguous=error_class is ProtocolErrorClass.AMBIGUOUS,
                retryable=error_class is ProtocolErrorClass.AMBIGUOUS,
                lease=lease,
            )
        result_digest = content_digest(observed.payload)
        completed_type = (
            DomainEventType.MCP_RECONCILED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_RECONCILED
        )
        await self._ledger.append(
            context,
            request.operation_id,
            (
                self._event(
                    request,
                    completed_type,
                    {
                        **self._base_payload(request, lease),
                        "result_digest": result_digest,
                        "provider_reference": observed.provider_reference,
                    },
                    principal=principal,
                    occurred_at=observed.completed_at,
                ),
            ),
            expected_version=version,
            lease=lease,
        )
        return ProtocolResult(
            request.operation_id,
            ProtocolOperationStatus.COMPLETED,
            result_digest,
            observed.provider_reference,
            observed.artifacts,
            observed.completed_at,
        )

    async def cancel(
        self,
        principal: Principal,
        context: TenantContext,
        request: ProtocolRequest,
        *,
        at: datetime,
        lease: WorkLease | None = None,
    ) -> ProtocolResult:
        self._require(principal, context, Permission.PROTOCOL_INVOKE, at)
        events = await self._ledger.load(context, request.operation_id)
        if not events:
            raise LookupError("protocol operation not found")
        peer = self._peer(context, request.peer_id)
        boundary = self._boundary(peer)
        requested_type = (
            DomainEventType.MCP_INVOCATION_CANCEL_REQUESTED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_TASK_CANCEL_REQUESTED
        )
        version = await self._ledger.append(
            context,
            request.operation_id,
            (
                self._event(
                    request,
                    requested_type,
                    self._base_payload(request, lease),
                    principal=principal,
                    occurred_at=at,
                ),
            ),
            expected_version=len(events),
            lease=lease,
        )
        try:
            cancelled = await self._adapter(peer.family).cancel(peer, request)
        except TimeoutError:
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                ProtocolErrorClass.AMBIGUOUS,
                "protocol_cancellation_timeout",
                ambiguous=True,
                retryable=True,
                lease=lease,
            )
        except ExternalProtocolError as error:
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                error.error_class,
                error.code,
                ambiguous=True,
                retryable=error.retryable,
                lease=lease,
            )
        except ProtocolSecurityError as error:
            return await self._record_failure(
                principal,
                context,
                request,
                version,
                ProtocolErrorClass.SECURITY,
                error.code,
                ambiguous=True,
                retryable=False,
                lease=lease,
            )
        if not cancelled:
            return ProtocolResult(
                request.operation_id,
                ProtocolOperationStatus.CANCEL_REQUESTED,
                "0" * 64,
                "remote-cancellation-pending",
                (),
                at,
                retryable=True,
                error_class=ProtocolErrorClass.AMBIGUOUS,
                error_code="cancellation_unconfirmed",
            )
        completed_type = (
            DomainEventType.MCP_INVOCATION_CANCELLED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_TASK_CANCELLED
        )
        await self._ledger.append(
            context,
            request.operation_id,
            (
                self._event(
                    request,
                    completed_type,
                    {
                        **self._base_payload(request, lease),
                        "result_digest": "0" * 64,
                        "provider_reference": "remote-cancelled",
                    },
                    principal=principal,
                    occurred_at=at,
                ),
            ),
            expected_version=version,
            lease=lease,
        )
        if self._metrics is not None:
            self._metrics.add("operations", boundary, "cancelled")
        return ProtocolResult(
            request.operation_id,
            ProtocolOperationStatus.CANCELLED,
            "0" * 64,
            "remote-cancelled",
            (),
            at,
        )

    def _validate_request(
        self,
        principal: Principal,
        context: TenantContext,
        request: ProtocolRequest,
        policy: ProtocolPolicySnapshot,
    ) -> ProtocolCapability:
        if request.tenant_id != str(context.tenant_id):
            raise ProtocolPolicyDeniedError("cross_tenant_protocol_request")
        if (
            policy.tenant_id != request.tenant_id
            or request.policy_digest != policy.digest
        ):
            raise ProtocolPolicyDeniedError("protocol_policy_binding_mismatch")
        peer = self._peer(context, request.peer_id)
        if request.peer_digest != peer_digest(peer):
            raise ProtocolPolicyDeniedError("protocol_peer_digest_mismatch")
        if request.family is not peer.family:
            raise ProtocolPolicyDeniedError("protocol_family_mismatch")
        if not peer.available(request.requested_at):
            raise ProtocolPolicyDeniedError("protocol_peer_not_available")
        if peer.peer_id not in policy.allowed_peer_ids:
            raise ProtocolPolicyDeniedError("protocol_peer_not_allowed")
        capability = self._capabilities.get(request.capability_id)
        if capability is None:
            raise ProtocolPolicyDeniedError("protocol_capability_unknown")
        if request.capability_digest != capability.digest:
            raise ProtocolPolicyDeniedError("protocol_capability_digest_mismatch")
        if (
            peer.allowed_capability_digests.get(capability.capability_id)
            != capability.digest
        ):
            raise ProtocolPolicyDeniedError("protocol_capability_not_allowlisted")
        if capability.risk > peer.risk_ceiling or capability.risk > policy.maximum_risk:
            raise ProtocolPolicyDeniedError("protocol_risk_ceiling_exceeded")
        if request.classification not in peer.allowed_classifications:
            raise ProtocolPolicyDeniedError("protocol_classification_denied")
        if request.purpose != capability.purpose:
            raise ProtocolPolicyDeniedError("protocol_purpose_mismatch")
        permission = Permission(capability.permission)
        self._require(principal, context, permission, request.requested_at)
        self._schemas.validate(
            capability.input_schema,
            request.payload,
            maximum_bytes=min(
                capability.maximum_input_bytes,
                policy.maximum_request_bytes,
            ),
        )
        return capability

    def _peer(self, context: TenantContext, peer_id: str) -> ProtocolPeer:
        peer = self._registry.get(context, peer_id)
        if peer is None:
            raise LookupError("protocol peer not found")
        if peer.status in {
            ProtocolPeerStatus.QUARANTINED,
            ProtocolPeerStatus.REVOKED,
            ProtocolPeerStatus.EXPIRED,
        }:
            raise ProtocolPolicyDeniedError("protocol_peer_denied")
        return peer

    @staticmethod
    def _boundary(peer: ProtocolPeer) -> ProtocolBoundary:
        return ProtocolBoundary(
            peer.family,
            peer.protocol_versions[0],
            peer.transports[0],
        )

    def _record_telemetry_failure(
        self,
        boundary: ProtocolBoundary,
        started: float,
        outcome: str,
    ) -> None:
        if self._metrics is None:
            return
        self._metrics.add(
            "latency_ms",
            boundary,
            outcome,
            (self._monotonic() - started) * 1_000,
        )
        self._metrics.add("operations", boundary, outcome)

    def _adapter(self, family: ProtocolFamily) -> ExternalProtocolPort:
        adapter = self._adapters.get(family)
        if adapter is None:
            raise ProtocolPolicyDeniedError("protocol_adapter_not_configured")
        return adapter

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        permission: Permission,
        at: datetime,
    ) -> None:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=permission,
            at=at,
        )
        if not decision.allowed:
            raise ProtocolPolicyDeniedError(decision.reason)

    async def _record_failure(
        self,
        principal: Principal,
        context: TenantContext,
        request: ProtocolRequest,
        version: int,
        error_class: ProtocolErrorClass,
        error_code: str,
        *,
        ambiguous: bool,
        retryable: bool = True,
        lease: WorkLease | None,
    ) -> ProtocolResult:
        event_type = (
            DomainEventType.MCP_INVOCATION_AMBIGUOUS
            if request.family is ProtocolFamily.MCP and ambiguous
            else DomainEventType.A2A_TASK_AMBIGUOUS
            if request.family is ProtocolFamily.A2A and ambiguous
            else DomainEventType.MCP_INVOCATION_FAILED
            if request.family is ProtocolFamily.MCP
            else DomainEventType.A2A_TASK_FAILED
        )
        status = (
            ProtocolOperationStatus.AMBIGUOUS
            if ambiguous
            else ProtocolOperationStatus.FAILED
        )
        await self._ledger.append(
            context,
            request.operation_id,
            (
                self._event(
                    request,
                    event_type,
                    {
                        **self._base_payload(request, lease),
                        "error_class": error_class.value,
                        "error_code": error_code,
                        "retryable": retryable,
                        "result_digest": "0" * 64,
                        "provider_reference": "unconfirmed",
                    },
                    principal=principal,
                ),
            ),
            expected_version=version,
            lease=lease,
        )
        return ProtocolResult(
            request.operation_id,
            status,
            "0" * 64,
            "unconfirmed",
            (),
            request.requested_at,
            retryable=retryable,
            error_class=error_class,
            error_code=error_code,
        )

    def _event(
        self,
        request: ProtocolRequest,
        event_type: DomainEventType,
        payload: Mapping[str, JsonValue],
        *,
        principal: Principal,
        occurred_at: datetime | None = None,
    ) -> EventEnvelope:
        return EventEnvelope(
            self._event_id_factory(),
            request.tenant_id,
            str(request.operation_id),
            event_type.value,
            1,
            occurred_at or request.requested_at,
            payload,
            correlation_id=request.correlation_id,
            aggregate_sequence=0,
            actor=ActorReference(principal.actor_id, ActorKind.SERVICE),
            policy_reference=request.policy_digest,
            idempotency_key=(
                request.idempotency_key
                if event_type is DomainEventType.PROTOCOL_POLICY_DECIDED
                else None
            ),
        )

    @staticmethod
    def _base_payload(
        request: ProtocolRequest,
        lease: WorkLease | None,
    ) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "family": request.family.value,
            "peer_id": request.peer_id,
            "peer_digest": request.peer_digest,
            "capability_id": request.capability_id,
            "capability_digest": request.capability_digest,
            "request_digest": request.payload_digest,
            "policy_digest": request.policy_digest,
            "classification": request.classification.value,
            "purpose": request.purpose,
            "deadline": request.deadline.isoformat(),
        }
        if lease is not None:
            payload["lease_token"] = str(lease.token)
            payload["lease_generation"] = lease.generation
        return payload

    @staticmethod
    def _artifact_payload(artifact: ProtocolArtifact) -> dict[str, JsonValue]:
        return {
            "artifact_id": artifact.artifact_id,
            "content_type": artifact.content_type,
            "content_digest": artifact.content_digest,
            "content_reference": artifact.content_reference,
            "classification": artifact.classification.value,
            "trust_label": artifact.trust_label.value,
            "citation_digests": tuple(
                citation.source_digest for citation in artifact.citations
            ),
            "byte_count": artifact.byte_count,
            "complete": artifact.complete,
        }

    @staticmethod
    def _state_result(
        state: ProtocolOperationState,
        at: datetime,
    ) -> ProtocolResult:
        return ProtocolResult(
            state.operation_id,
            state.status,
            state.result_digest or "0" * 64,
            state.provider_reference or "duplicate-request-recorded",
            (),
            at,
            retryable=state.status
            in {
                ProtocolOperationStatus.AMBIGUOUS,
                ProtocolOperationStatus.CANCEL_REQUESTED,
            },
            error_class=(
                ProtocolErrorClass.AMBIGUOUS
                if state.status is ProtocolOperationStatus.AMBIGUOUS
                else None
            ),
            error_code=(
                state.error_code or "ambiguous_duplicate"
                if state.status is ProtocolOperationStatus.AMBIGUOUS
                else None
            ),
        )
