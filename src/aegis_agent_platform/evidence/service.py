"""Durable fenced evidence query and correlation orchestration."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    DomainEventType,
    EventEnvelope,
    EvidenceBundle,
    EvidenceRecord,
    JsonValue,
    PartialResult,
    WorkLease,
)
from aegis_agent_platform.event_store import FencingError, OutboxMessage
from aegis_agent_platform.evidence.correlation import CorrelationEngine
from aegis_agent_platform.evidence.ingestion import (
    EvidenceIngestor,
    EvidenceStore,
    QuarantinedEvidence,
)
from aegis_agent_platform.evidence.ports import (
    CancellationSignal,
    ConnectorError,
    ConnectorErrorClass,
    EvidenceConnector,
    EvidenceQuery,
)
from aegis_agent_platform.evidence.telemetry import EvidenceMetrics, EvidenceTracer
from aegis_agent_platform.policy import TenantPolicy
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class QueryExecutionResult:
    records: Sequence[EvidenceRecord]
    result: PartialResult

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(self.records))


class EvidenceRepository(Protocol):
    async def request(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        event: EventEnvelope,
        outbox: OutboxMessage,
    ) -> EvidenceRequestResult: ...

    async def append_fenced(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        records: Sequence[EvidenceRecord] = (),
        quarantined: Sequence[QuarantinedEvidence] = (),
        store: EvidenceStore | None = None,
        bundle: EvidenceBundle | None = None,
    ) -> int: ...

    async def status(
        self,
        context: TenantContext,
        query_id: UUID,
    ) -> Mapping[str, JsonValue] | None: ...


@dataclass(frozen=True, slots=True)
class EvidenceRequestResult:
    created: bool
    query_id: UUID

    def __bool__(self) -> bool:
        return self.created


class EvidenceIdempotencyConflictError(ValueError):
    """An idempotency key was already bound to a different durable request."""


class InMemoryEvidenceRepository:
    """Deterministic repository that models durable idempotency and lease fencing."""

    def __init__(self) -> None:
        self.events: dict[tuple[str, UUID], list[EventEnvelope]] = {}
        self.outbox: list[OutboxMessage] = []
        self._idempotency: dict[tuple[str, str], tuple[UUID, str]] = {}
        self._leases: dict[tuple[str, UUID], tuple[UUID, int, datetime]] = {}
        self._bundles: dict[tuple[str, str], EvidenceBundle] = {}
        self._query_order: dict[tuple[str, UUID], int] = {}
        self._cursors: dict[tuple[str, str, str], tuple[int, int, str]] = {}
        self._request_order = 0

    def register_lease(self, lease: WorkLease) -> None:
        self._leases[(lease.tenant_id, lease.work_id)] = (
            lease.token,
            lease.generation,
            lease.expires_at,
        )

    async def request(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        event: EventEnvelope,
        outbox: OutboxMessage,
    ) -> EvidenceRequestResult:
        _require_tenant(context, query)
        key = (query.tenant_id, query.idempotency_key)
        existing = self._idempotency.get(key)
        if existing is not None:
            if existing[1] != _query_fingerprint(query):
                raise EvidenceIdempotencyConflictError(
                    "evidence_idempotency_key_reused"
                )
            return EvidenceRequestResult(False, existing[0])
        self._idempotency[key] = (query.query_id, _query_fingerprint(query))
        self._request_order += 1
        self._query_order[(query.tenant_id, query.query_id)] = self._request_order
        self.events[(query.tenant_id, query.query_id)] = [event]
        self.outbox.append(outbox)
        return EvidenceRequestResult(True, query.query_id)

    async def append_fenced(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        lease: WorkLease,
        events: Sequence[EventEnvelope],
        *,
        records: Sequence[EvidenceRecord] = (),
        quarantined: Sequence[QuarantinedEvidence] = (),
        store: EvidenceStore | None = None,
        bundle: EvidenceBundle | None = None,
    ) -> int:
        _require_tenant(context, query)
        events = _with_fence(events, lease)
        current = self._leases.get((query.tenant_id, query.query_id))
        if (
            lease.work_id != query.query_id
            or lease.tenant_id != query.tenant_id
            or current is None
            or current[0] != lease.token
            or current[1] != lease.generation
            or current[2] <= events[0].occurred_at
        ):
            raise FencingError(lease.generation, current[1] if current else 0)
        if (records or quarantined) and store is None:
            raise ValueError("evidence persistence requires a store")
        duplicate_digests: set[str] = set()
        if store is not None:
            for item in quarantined:
                store.quarantine(context, item)
            for record in records:
                if not store.put(context, record):
                    duplicate_digests.add(record.content_digest)
        if bundle is not None:
            if bundle.tenant_id != query.tenant_id:
                raise PermissionError("cross_tenant_bundle")
            self._bundles[(bundle.tenant_id, bundle.bundle_id)] = bundle
        prepared = tuple(
            _deduplicated_event(event)
            if event.event_type == DomainEventType.EVIDENCE_INGESTED
            and event.payload.get("digest") in duplicate_digests
            else event
            for event in events
        )
        cursor_key = (
            query.tenant_id,
            query.source.value,
            query.environment.name,
        )
        query_order = self._query_order[(query.tenant_id, query.query_id)]
        current_cursor = self._cursors.get(cursor_key)
        cursor_events = tuple(
            event
            for event in prepared
            if event.event_type == DomainEventType.SOURCE_CURSOR_ADVANCED
        )
        if cursor_events and (
            current_cursor is None
            or (query_order, lease.generation) >= current_cursor[:2]
        ):
            self._cursors[cursor_key] = (
                query_order,
                lease.generation,
                str(cursor_events[-1].payload["cursor"]),
            )
        elif cursor_events:
            cursor_ids = {event.event_id for event in cursor_events}
            prepared = tuple(
                event for event in prepared if event.event_id not in cursor_ids
            )
        self.events[(query.tenant_id, query.query_id)].extend(prepared)
        return len(duplicate_digests)

    def get(self, context: TenantContext, bundle_id: str) -> EvidenceBundle | None:
        return self._bundles.get((str(context.tenant_id), bundle_id))

    async def status(
        self,
        context: TenantContext,
        query_id: UUID,
    ) -> Mapping[str, JsonValue] | None:
        events = self.events.get((str(context.tenant_id), query_id))
        if not events:
            return None
        latest = events[-1]
        return {
            "query_id": str(query_id),
            "event_type": latest.event_type,
            "updated_at": latest.occurred_at.isoformat(),
        }


class EvidenceQueryService:
    """Persist intent before reads, then commit only through a live worker fence."""

    def __init__(
        self,
        *,
        connectors: Mapping[str, EvidenceConnector],
        repository: EvidenceRepository,
        ingestor: EvidenceIngestor,
        correlation: CorrelationEngine | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        uuid_factory: Callable[[], UUID] = uuid4,
        max_window: timedelta = timedelta(hours=24),
        metrics: EvidenceMetrics | None = None,
        tracer: EvidenceTracer | None = None,
    ) -> None:
        if not connectors:
            raise ValueError("at least one connector is required")
        if max_window <= timedelta(0) or max_window > timedelta(days=7):
            raise ValueError(
                "maximum query window must be positive and at most seven days"
            )
        self._connectors = dict(connectors)
        self._repository = repository
        self._ingestor = ingestor
        self._correlation = correlation or CorrelationEngine()
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._max_window = max_window
        self._metrics = metrics or EvidenceMetrics()
        self._tracer = tracer or EvidenceTracer()

    async def request(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        policy: TenantPolicy,
        *,
        actor_id: str,
    ) -> EvidenceRequestResult:
        self._validate_request(context, query, policy)
        event = self._event(
            query,
            DomainEventType.EVIDENCE_QUERY_REQUESTED,
            {
                "source": query.source.value,
                "environment": query.environment.name,
                "window_start": query.window.start.isoformat(),
                "window_end": query.window.end.isoformat(),
                "kinds": [kind.value for kind in query.kinds],
                "limit": query.limit,
                "policy_version": policy.version,
            },
            actor_id=actor_id,
            idempotency_suffix="requested",
        )
        outbox = OutboxMessage(
            message_id=self._uuid_factory(),
            destination="aegis.work.evidence",
            payload={
                "query_id": str(query.query_id),
                "tenant_id": query.tenant_id,
                "source": query.source.value,
            },
            headers={"schema_version": 1},
            available_at=self._clock(),
            event_id=event.event_id,
        )
        return await self._repository.request(context, query, event, outbox)

    async def execute(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        lease: WorkLease,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> QueryExecutionResult:
        connector = self._connectors.get(query.source.value)
        if connector is None:
            raise ConnectorError(
                ConnectorErrorClass.CAPABILITY,
                "connector_not_configured",
                retryable=False,
            )
        started_at = self._clock()
        await self._repository.append_fenced(
            context,
            query,
            lease,
            (
                self._event(
                    query,
                    DomainEventType.EVIDENCE_QUERY_STARTED,
                    _lease_details(lease),
                    idempotency_suffix=f"started:{lease.generation}",
                ),
            ),
        )
        if cancellation is not None and cancellation.cancelled:
            await self._terminal(
                context,
                query,
                lease,
                DomainEventType.EVIDENCE_QUERY_CANCELLED,
                {"reason": "cancelled_before_network"},
            )
            raise ConnectorError(
                ConnectorErrorClass.CANCELLED,
                "query_cancelled",
                retryable=False,
            )
        try:
            self._metrics.add("queries", query.source)
            with self._tracer.query(query.source):
                page = await connector.query(query, cancellation=cancellation)
        except ConnectorError as error:
            self._metrics.add("errors", query.source)
            if error.error_class is ConnectorErrorClass.RATE_LIMIT:
                self._metrics.add("rate_limits", query.source)
            event_type = {
                ConnectorErrorClass.RATE_LIMIT: (
                    DomainEventType.EVIDENCE_QUERY_RATE_LIMITED
                ),
                ConnectorErrorClass.TIMEOUT: DomainEventType.EVIDENCE_QUERY_TIMED_OUT,
                ConnectorErrorClass.CANCELLED: DomainEventType.EVIDENCE_QUERY_CANCELLED,
            }.get(error.error_class, DomainEventType.EVIDENCE_QUERY_FAILED)
            details: dict[str, JsonValue] = {
                "error_class": error.error_class.value,
                "code": error.code,
                "retryable": error.retryable,
            }
            if error.retry_after_seconds is not None:
                details["retry_after_seconds"] = error.retry_after_seconds
            await self._terminal(context, query, lease, event_type, details)
            raise
        except (TypeError, ValueError) as error:
            await self._terminal(
                context,
                query,
                lease,
                DomainEventType.EVIDENCE_QUERY_FAILED,
                {
                    "error_class": ConnectorErrorClass.MALFORMED_RESPONSE.value,
                    "code": "connector_contract_violation",
                    "retryable": False,
                },
            )
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "connector_contract_violation",
                retryable=False,
            ) from error
        now = self._clock()
        records: list[EvidenceRecord] = []
        quarantined: list[QuarantinedEvidence] = []
        events: list[EventEnvelope] = []
        seen_digests: set[str] = set()
        page_duplicates: dict[str, tuple[str, int]] = {}
        quarantine_keys: set[tuple[str, str]] = set()
        for raw in page.records:
            outcome = self._ingestor.ingest(
                context,
                raw,
                source=query.source,
                environment=query.environment,
                window=query.window,
                ingested_at=now,
                persist=False,
            )
            if outcome.quarantined is not None:
                self._metrics.add("quarantined", query.source)
                assert outcome.quarantine_item is not None
                quarantine_key = (
                    outcome.quarantine_item.source_record_id,
                    outcome.quarantined.value,
                )
                if quarantine_key in quarantine_keys:
                    continue
                quarantine_keys.add(quarantine_key)
                quarantined.append(outcome.quarantine_item)
                events.append(
                    self._event(
                        query,
                        DomainEventType.EVIDENCE_QUARANTINED,
                        {
                            "source_record_id": (
                                outcome.quarantine_item.source_record_id
                            ),
                            "reason": outcome.quarantined.value,
                        },
                        idempotency_suffix=(
                            "quarantine:"
                            f"{outcome.quarantine_item.source_record_id}:"
                            f"{outcome.quarantined.value}"
                        ),
                    )
                )
                continue
            assert outcome.record is not None
            digest = outcome.record.content_digest
            if digest in seen_digests:
                evidence_id, count = page_duplicates.get(
                    digest,
                    (str(outcome.record.evidence_id), 0),
                )
                page_duplicates[digest] = (evidence_id, count + 1)
                continue
            seen_digests.add(digest)
            records.append(outcome.record)
            event_type = DomainEventType.EVIDENCE_INGESTED
            self._metrics.add("evidence_records", query.source)
            events.append(
                self._event(
                    query,
                    event_type,
                    {
                        "evidence_id": str(outcome.record.evidence_id),
                        "digest": outcome.record.content_digest,
                        "kind": outcome.record.kind.value,
                        "provenance_uri": outcome.record.provenance.uri,
                    },
                    idempotency_suffix=(
                        f"{event_type.value}:{outcome.record.content_digest}"
                    ),
                )
            )
            if outcome.record.redaction.applied:
                events.append(
                    self._event(
                        query,
                        DomainEventType.EVIDENCE_REDACTED,
                        {
                            "evidence_id": str(outcome.record.evidence_id),
                            "rules": tuple(outcome.record.redaction.rule_ids),
                            "removed_bytes": outcome.record.redaction.removed_bytes,
                        },
                        idempotency_suffix=(
                            f"redacted:{outcome.record.content_digest}"
                        ),
                    )
                )
        for digest, (evidence_id, count) in sorted(page_duplicates.items()):
            events.append(
                self._event(
                    query,
                    DomainEventType.EVIDENCE_DEDUPLICATED,
                    {
                        "evidence_id": evidence_id,
                        "digest": digest,
                        "duplicate_count": count,
                    },
                    idempotency_suffix=f"page-deduplicated:{digest}",
                )
            )
        if page.next_cursor is not None:
            self._metrics.add("cursor_advanced", query.source)
            events.append(
                self._event(
                    query,
                    DomainEventType.SOURCE_CURSOR_ADVANCED,
                    {"cursor": page.next_cursor.value},
                    idempotency_suffix=f"cursor:{page.next_cursor.value}",
                )
            )
        effective_result = page.result
        if quarantined:
            effective_result = PartialResult(
                partial=True,
                truncated=page.result.truncated,
                reasons=tuple(sorted({*page.result.reasons, "ingestion_quarantine"})),
                omitted_records=page.result.omitted_records + len(quarantined),
                omitted_bytes=page.result.omitted_bytes,
            )
        terminal = (
            DomainEventType.EVIDENCE_QUERY_PARTIALLY_SUCCEEDED
            if effective_result.partial or effective_result.truncated
            else DomainEventType.EVIDENCE_QUERY_SUCCEEDED
        )
        if effective_result.partial or effective_result.truncated:
            self._metrics.add("partial_results", query.source)
        self._metrics.add(
            "latency_ms",
            query.source,
            max(0, int((now - started_at).total_seconds() * 1000)),
        )
        events.append(
            self._event(
                query,
                terminal,
                {
                    "record_count": len(records),
                    "partial": effective_result.partial,
                    "truncated": effective_result.truncated,
                    "reasons": tuple(effective_result.reasons),
                    "omitted_records": effective_result.omitted_records,
                    "omitted_bytes": effective_result.omitted_bytes,
                    "latency_ms": max(
                        0, int((now - started_at).total_seconds() * 1000)
                    ),
                },
                idempotency_suffix=f"terminal:{lease.generation}",
            )
        )
        deduplicated = await self._repository.append_fenced(
            context,
            query,
            lease,
            tuple(events),
            records=records,
            quarantined=quarantined,
            store=self._ingestor.store,
        )
        self._metrics.add(
            "deduplicated",
            query.source,
            deduplicated + sum(count for _, count in page_duplicates.values()),
        )
        return QueryExecutionResult(records, effective_result)

    async def correlate(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        lease: WorkLease,
        evidence: Sequence[EvidenceRecord],
        *,
        bundle_id: str,
    ) -> EvidenceBundle:
        await self._repository.append_fenced(
            context,
            query,
            lease,
            (
                self._event(
                    query,
                    DomainEventType.CORRELATION_STARTED,
                    {"evidence_count": len(evidence)},
                    idempotency_suffix=f"correlation-started:{bundle_id}",
                ),
            ),
        )
        try:
            with self._tracer.correlation():
                bundle = self._correlation.correlate(
                    bundle_id=bundle_id,
                    tenant_id=query.tenant_id,
                    environment=query.environment,
                    generated_at=self._clock(),
                    evidence=tuple(evidence),
                )
        except (TypeError, ValueError, PermissionError) as error:
            await self._repository.append_fenced(
                context,
                query,
                lease,
                (
                    self._event(
                        query,
                        DomainEventType.CORRELATION_FAILED,
                        {"code": "deterministic_correlation_failed"},
                        idempotency_suffix=f"correlation-failed:{bundle_id}",
                    ),
                ),
            )
            raise error
        await self._repository.append_fenced(
            context,
            query,
            lease,
            (
                self._event(
                    query,
                    DomainEventType.CORRELATION_COMPLETED,
                    {
                        "bundle_id": bundle.bundle_id,
                        "timeline_entries": len(bundle.timeline),
                        "links": len(bundle.links),
                        "conflicts": len(bundle.source_conflicts),
                    },
                    idempotency_suffix=f"correlation-completed:{bundle_id}",
                ),
            ),
            bundle=bundle,
        )
        self._metrics.add("correlation_completed", query.source)
        self._metrics.add(
            "correlation_conflicts",
            query.source,
            len(bundle.source_conflicts),
        )
        return bundle

    async def status(
        self,
        context: TenantContext,
        query_id: UUID,
    ) -> Mapping[str, JsonValue] | None:
        return await self._repository.status(context, query_id)

    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._connectors))

    def _validate_request(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        policy: TenantPolicy,
    ) -> None:
        _require_tenant(context, query)
        if str(policy.tenant_id) != query.tenant_id:
            raise PermissionError("cross_tenant_policy")
        if query.source.value not in policy.allowed_connectors:
            raise PermissionError("connector_not_allowed")
        if query.environment.name not in policy.allowed_environments:
            raise PermissionError("environment_not_allowed")
        if query.window.end - query.window.start > self._max_window:
            raise PermissionError("query_window_exceeds_policy")

    async def _terminal(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        lease: WorkLease,
        event_type: DomainEventType,
        details: Mapping[str, JsonValue],
    ) -> None:
        await self._repository.append_fenced(
            context,
            query,
            lease,
            (
                self._event(
                    query,
                    event_type,
                    details,
                    idempotency_suffix=f"terminal:{lease.generation}",
                ),
            ),
        )

    def _event(
        self,
        query: EvidenceQuery,
        event_type: DomainEventType,
        payload: Mapping[str, JsonValue],
        *,
        actor_id: str | None = None,
        idempotency_suffix: str,
    ) -> EventEnvelope:
        return EventEnvelope(
            event_id=self._uuid_factory(),
            tenant_id=query.tenant_id,
            aggregate_id=str(query.query_id),
            event_type=event_type,
            schema_version=1,
            occurred_at=self._clock(),
            payload=payload,
            correlation_id=query.query_id,
            actor=(
                ActorReference(actor_id, ActorKind.USER)
                if actor_id is not None
                else ActorReference("evidence-worker", ActorKind.SERVICE)
            ),
            idempotency_key=f"{query.idempotency_key}:{idempotency_suffix}",
        )


def _require_tenant(context: TenantContext, query: EvidenceQuery) -> None:
    if str(context.tenant_id) != query.tenant_id:
        raise PermissionError("cross_tenant_query")


def _query_fingerprint(query: EvidenceQuery) -> str:
    return json.dumps(
        {
            "source": query.source.value,
            "environment": query.environment.name,
            "window_start": query.window.start.isoformat(),
            "window_end": query.window.end.isoformat(),
            "kinds": tuple(kind.value for kind in query.kinds),
            "selectors": dict(query.selectors),
            "limit": query.limit,
            "cursor": query.cursor.value if query.cursor else None,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _lease_details(lease: WorkLease) -> Mapping[str, JsonValue]:
    return {
        "lease_token": str(lease.token),
        "lease_generation": lease.generation,
        "attempt": lease.attempt,
    }


def _deduplicated_event(event: EventEnvelope) -> EventEnvelope:
    suffix = f":{DomainEventType.EVIDENCE_INGESTED.value}:"
    replacement = f":{DomainEventType.EVIDENCE_DEDUPLICATED.value}:"
    key = event.idempotency_key or ""
    if suffix not in key:
        raise ValueError("ingestion event idempotency suffix is invalid")
    return replace(
        event,
        event_type=DomainEventType.EVIDENCE_DEDUPLICATED,
        idempotency_key=key.replace(suffix, replacement, 1),
    )


def _with_fence(
    events: Sequence[EventEnvelope],
    lease: WorkLease,
) -> tuple[EventEnvelope, ...]:
    details = _lease_details(lease)
    return tuple(
        replace(event, payload={**event.payload, **details}) for event in events
    )


__all__ = [
    "EvidenceIdempotencyConflictError",
    "EvidenceQueryService",
    "EvidenceRepository",
    "InMemoryEvidenceRepository",
    "QueryExecutionResult",
]
