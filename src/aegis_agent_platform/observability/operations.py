"""Authorized tenant observability and privileged support operations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

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
)
from aegis_agent_platform.observability.replay import (
    ReplayDebugger,
    ReplayQuery,
    SupportReport,
)
from aegis_agent_platform.observability.safety import hash_identifier
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class SloSummary:
    """Derived objective state; never a claim of production attainment."""

    objective: str
    window: str
    target: str
    status: str
    measured: bool
    reason_code: str


class ObservabilityOperations:
    """Deny-by-default redacted timeline, SLO, and support-report facade."""

    def __init__(
        self,
        replay: ReplayDebugger,
        audit: AuditStore,
        *,
        identifier_hash_key: bytes,
        hash_key_version: str,
        authorization: AuthorizationService | None = None,
        slo_reader: Callable[[], tuple[SloSummary, ...]] | None = None,
    ) -> None:
        self._replay = replay
        self._audit = audit
        self._hash_key = identifier_hash_key
        self._hash_key_version = hash_key_version
        self._authorization = authorization or AuthorizationService()
        self._slo_reader = slo_reader or (lambda: ())

    async def timeline(
        self,
        principal: Principal,
        context: TenantContext,
        aggregate_id: str,
        *,
        at: datetime,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> Mapping[str, JsonValue]:
        """Return a bounded redacted causal timeline after purpose authorization."""
        self._require(principal, context, Permission.OBSERVABILITY_READ, at)
        if not 1 <= limit <= 100:
            raise ValueError("timeline limit must be between 1 and 100")
        events = await self._replay.load(
            context,
            ReplayQuery(
                aggregate_id,
                after_sequence=after_sequence,
                max_events=limit,
            ),
        )
        chain = self._replay.causal_chain(events)
        self._audit_access(
            principal,
            context,
            at,
            action="observability:read",
            purpose="incident-investigation",
            outcome=AuditOutcome.SUCCESS,
        )
        aggregate_reference = hash_identifier(
            aggregate_id,
            key=self._hash_key,
            key_version=self._hash_key_version,
        )
        return MappingProxyType(
            {
                "schema_version": 1,
                "aggregate_reference": aggregate_reference,
                "events": tuple(
                    MappingProxyType(
                        {
                            "sequence": item.sequence,
                            "event_type": item.event_type,
                            "occurred_at": item.occurred_at,
                            "causation_sequence": item.causation_sequence,
                            "trace_link_present": item.trace_link_present,
                            "linkage": _linkage(item.event_type),
                        }
                    )
                    for item in chain
                ),
                "next_cursor": (
                    events[-1].aggregate_sequence if len(events) == limit else None
                ),
                "authoritative_source": "event_ledger",
            }
        )

    def slo_summary(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
    ) -> tuple[SloSummary, ...]:
        """Return current derived SLO summaries with honest unmeasured states."""
        self._require(principal, context, Permission.OBSERVABILITY_READ, at)
        self._audit_access(
            principal,
            context,
            at,
            action="observability:slo:read",
            purpose="operations",
            outcome=AuditOutcome.SUCCESS,
        )
        return self._slo_reader()

    async def support_report(
        self,
        principal: Principal,
        context: TenantContext,
        aggregate_id: str,
        *,
        at: datetime,
        signer: str | None = None,
        signing_key: bytes | None = None,
    ) -> SupportReport:
        """Export a bounded report only for explicitly privileged operators."""
        self._require(principal, context, Permission.SUPPORT_EXPORT, at)
        events = await self._replay.load(context, ReplayQuery(aggregate_id))
        report = self._replay.support_report(
            context,
            events,
            signer=signer,
            signing_key=signing_key,
        )
        self._audit_access(
            principal,
            context,
            at,
            action="observability:support:export",
            purpose="support",
            outcome=AuditOutcome.SUCCESS,
        )
        return report

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
            self._audit_access(
                principal,
                context,
                at,
                action=permission.value,
                purpose="denied",
                outcome=AuditOutcome.DENIED,
            )
            raise PermissionError("observability access denied")

    def _audit_access(
        self,
        principal: Principal,
        context: TenantContext,
        at: datetime,
        *,
        action: str,
        purpose: str,
        outcome: AuditOutcome,
    ) -> None:
        from uuid import uuid4

        event = AuditEvent(
            uuid4(),
            context.tenant_id,
            AuditEventType.OBSERVABILITY_ACCESS,
            at,
            outcome,
            principal.actor_id,
            action,
            "tenant/observability",
            uuid4(),
            {"purpose": purpose},
        )
        self._audit.append(context, event)


def _linkage(event_type: str) -> str:
    prefix = event_type.partition(".")[0]
    return {
        "artifact": "artifact",
        "work": "work",
        "model": "model",
        "evidence": "evidence",
        "specialist": "specialist",
        "remediation": "action",
        "action": "action",
        "sandbox": "sandbox",
        "memory": "memory",
    }.get(prefix, "event")


__all__ = ["ObservabilityOperations", "SloSummary"]
