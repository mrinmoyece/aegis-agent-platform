"""PostgreSQL evidence persistence integrated with Layer 3/4 fencing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from datetime import datetime
from threading import RLock
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from aegis_agent_platform.domain import (
    ChangeReference,
    CorrelationLink,
    CorrelationLinkKind,
    DataClassification,
    DeploymentReference,
    DomainEventType,
    EnvironmentIdentity,
    EventEnvelope,
    EvidenceBundle,
    EvidenceId,
    EvidenceKind,
    EvidenceRecord,
    EvidenceReference,
    EvidenceSeverity,
    EvidenceSourceKind,
    JsonValue,
    LogReference,
    MetricReference,
    ProblemReference,
    Provenance,
    QueryWindow,
    RedactionMetadata,
    ResourceIdentity,
    RetentionClass,
    RunbookReference,
    ServiceIdentity,
    SpanReference,
    TimelineEntry,
    TraceReference,
    TrustStatus,
    WorkLease,
    WorkRequest,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import ConcurrencyError, PermanentStorageError
from aegis_agent_platform.event_store.postgres import PostgresEventStore
from aegis_agent_platform.evidence.ingestion import (
    EvidenceStore,
    QuarantinedEvidence,
    StoredEvidencePage,
)
from aegis_agent_platform.evidence.ports import EvidenceQuery
from aegis_agent_platform.evidence.service import (
    EvidenceIdempotencyConflictError,
    EvidenceRepository,
    EvidenceRequestResult,
    _with_fence,
)
from aegis_agent_platform.runtime.postgres import PostgresWorkRepository
from aegis_agent_platform.tenancy import TenantContext


class PostgresEvidenceStore(EvidenceStore):
    """Immutable redacted evidence projection keyed by tenant and digest."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection
        self._lock = RLock()

    def put(self, context: TenantContext, record: EvidenceRecord) -> bool:
        if str(context.tenant_id) != record.tenant_id:
            raise PermissionError("cross_tenant_evidence")
        with _transaction(self._connection, self._lock, context):
            self._connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (record.tenant_id,),
            )
            cursor = self._connection.execute(
                """
                INSERT INTO evidence_records (
                    tenant_id, evidence_id, content_digest, source_kind,
                    evidence_kind, environment, service, resource_kind,
                    resource_name, resource_namespace, resource_cluster,
                    observed_at, ingested_at, query_window_start,
                    query_window_end, summary, structured_fields, severity,
                    source_confidence, provenance_uri, source_record_id,
                    provenance_trust, classification, retention_class,
                    redaction, evidence_references, raw_payload_reference,
                    is_knowledge
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s
                )
                ON CONFLICT (tenant_id, content_digest) DO NOTHING
                """,
                _record_values(record),
            )
        return cursor.rowcount == 1

    def quarantine(
        self,
        context: TenantContext,
        item: QuarantinedEvidence,
    ) -> None:
        if str(context.tenant_id) != item.tenant_id:
            raise PermissionError("cross_tenant_quarantine")
        with _transaction(self._connection, self._lock, context):
            self._connection.execute(
                """
                INSERT INTO evidence_quarantine (
                    quarantine_id, tenant_id, source_kind, source_record_id,
                    reason, observed_at, quarantined_at
                ) VALUES (%s, %s, %s, %s, %s, %s, statement_timestamp())
                """,
                (
                    uuid4(),
                    item.tenant_id,
                    item.source.value,
                    item.source_record_id,
                    item.reason.value,
                    item.observed_at,
                ),
            )

    def list(
        self,
        context: TenantContext,
        *,
        offset: int = 0,
        limit: int = 100,
        ingested_before: datetime | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("invalid evidence page")
        with _transaction(self._connection, self._lock, context):
            rows = self._connection.execute(
                """
                SELECT evidence_id, tenant_id, source_kind, evidence_kind,
                    environment, service, resource_kind, resource_name,
                    resource_namespace, resource_cluster, observed_at,
                    ingested_at, query_window_start, query_window_end, summary,
                    structured_fields, severity, source_confidence,
                    provenance_uri, source_record_id, provenance_trust,
                    content_digest, classification, retention_class, redaction,
                    evidence_references, raw_payload_reference, is_knowledge
                FROM evidence_records
                WHERE tenant_id = %s
                  AND (%s::timestamptz IS NULL OR ingested_at <= %s)
                ORDER BY observed_at, evidence_id
                OFFSET %s LIMIT %s
                """,
                (
                    str(context.tenant_id),
                    ingested_before,
                    ingested_before,
                    offset,
                    limit,
                ),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)

    def page(
        self,
        context: TenantContext,
        *,
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
    ) -> StoredEvidencePage:
        if not 1 <= limit <= 1000:
            raise ValueError("invalid evidence page")
        with _transaction(self._connection, self._lock, context):
            if cursor is None:
                self._connection.execute(
                    "SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))",
                    (str(context.tenant_id),),
                )
                highwater_row = self._connection.execute(
                    """
                    SELECT COALESCE(max(evidence_position), 0)
                    FROM evidence_records
                    WHERE tenant_id = %s
                    """,
                    (str(context.tenant_id),),
                ).fetchone()
                highwater = int(highwater_row[0]) if highwater_row is not None else 0
                after = 0
            else:
                highwater, after = cursor
            rows = self._connection.execute(
                """
                SELECT evidence_position, evidence_id, tenant_id, source_kind,
                    evidence_kind, environment, service, resource_kind,
                    resource_name, resource_namespace, resource_cluster,
                    observed_at, ingested_at, query_window_start, query_window_end,
                    summary, structured_fields, severity, source_confidence,
                    provenance_uri, source_record_id, provenance_trust,
                    content_digest, classification, retention_class, redaction,
                    evidence_references, raw_payload_reference, is_knowledge
                FROM evidence_records
                WHERE tenant_id = %s
                  AND evidence_position > %s
                  AND evidence_position <= %s
                ORDER BY evidence_position
                LIMIT %s
                """,
                (str(context.tenant_id), after, highwater, limit + 1),
            ).fetchall()
        next_cursor = (
            (highwater, int(rows[limit - 1][0])) if len(rows) > limit else None
        )
        return StoredEvidencePage(
            tuple(_record_from_row(row[1:]) for row in rows[:limit]),
            next_cursor,
        )


class PostgresEvidenceBundleStore:
    """Tenant-scoped reader for durable deterministic correlation artifacts."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection
        self._lock = RLock()

    def get(self, context: TenantContext, bundle_id: str) -> EvidenceBundle | None:
        with _transaction(self._connection, self._lock, context):
            row = self._connection.execute(
                """
                SELECT environment, generated_at, bundle_content
                FROM evidence_bundle_projection
                WHERE tenant_id = %s AND bundle_id = %s
                """,
                (str(context.tenant_id), bundle_id),
            ).fetchone()
            if row is None:
                return None
            payload = row[2]
            if not isinstance(payload, Mapping):
                raise ValueError("stored evidence bundle is invalid")
            raw_ids = payload.get("evidence_ids")
            if not isinstance(raw_ids, list):
                raise ValueError("stored evidence bundle identifiers are invalid")
            evidence_rows = self._connection.execute(
                """
                SELECT evidence_id, tenant_id, source_kind, evidence_kind,
                    environment, service, resource_kind, resource_name,
                    resource_namespace, resource_cluster, observed_at,
                    ingested_at, query_window_start, query_window_end, summary,
                    structured_fields, severity, source_confidence,
                    provenance_uri, source_record_id, provenance_trust,
                    content_digest, classification, retention_class, redaction,
                    evidence_references, raw_payload_reference, is_knowledge
                FROM evidence_records
                WHERE tenant_id = %s AND evidence_id = ANY(%s)
                """,
                (str(context.tenant_id), [str(item) for item in raw_ids]),
            ).fetchall()
        return _bundle_from_payload(
            bundle_id,
            str(context.tenant_id),
            str(row[0]),
            cast(datetime, row[1]),
            payload,
            tuple(_record_from_row(item) for item in evidence_rows),
        )


class PostgresEvidenceRepository(EvidenceRepository):
    """Query lifecycle repository that composes durable work and fenced appends."""

    def __init__(
        self,
        connection: psycopg.AsyncConnection[Any],
        events: PostgresEventStore,
        work: PostgresWorkRepository,
    ) -> None:
        self._connection = connection
        self._events = events
        self._work = work

    async def request(
        self,
        context: TenantContext,
        query: EvidenceQuery,
        event: EventEnvelope,
        outbox: object,
    ) -> EvidenceRequestResult:
        del outbox
        request = WorkRequest(
            work_id=query.query_id,
            tenant_id=query.tenant_id,
            work_kind="evidence.query",
            idempotency_key=query.idempotency_key,
            correlation_id=query.query_id,
            requested_at=event.occurred_at,
            payload={
                "source": query.source.value,
                "environment": query.environment.name,
                "window_start": query.window.start.isoformat(),
                "window_end": query.window.end.isoformat(),
                "kinds": tuple(kind.value for kind in query.kinds),
                "selectors": dict(query.selectors),
                "limit": query.limit,
                "cursor": query.cursor.value if query.cursor else None,
            },
            timeout_seconds=300,
        )

        existing = await self._work.work_id_for_idempotency(
            context,
            query.idempotency_key,
            work_kind=request.work_kind,
            request_payload=request.payload,
        )
        if existing is not None:
            return EvidenceRequestResult(False, existing)
        if await self._work.idempotency_key_in_use(context, query.idempotency_key):
            raise EvidenceIdempotencyConflictError("evidence_idempotency_key_reused")

        async def insert_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            await connection.execute(
                """
                INSERT INTO evidence_query_projection (
                    tenant_id, query_id, source_kind, environment, status,
                    requested_at, query_event_position, updated_at, result_count,
                    partial, truncated
                ) VALUES (
                    %s, %s, %s, %s, 'requested', %s,
                    (SELECT global_position FROM events
                     WHERE tenant_id = %s AND event_id = %s),
                    %s, 0, false, false
                )
                """,
                (
                    query.tenant_id,
                    query.query_id,
                    query.source.value,
                    query.environment.name,
                    event.occurred_at,
                    query.tenant_id,
                    event.event_id,
                    event.occurred_at,
                ),
            )

        try:
            await self._work.register(
                context,
                request,
                requested_event_id=uuid4(),
                outbox_message_id=uuid4(),
                additional_events=(event,),
                additional_mutation=insert_projection,
            )
        except (ConcurrencyError, PermanentStorageError):
            existing = await self._work.work_id_for_idempotency(
                context,
                query.idempotency_key,
                work_kind=request.work_kind,
                request_payload=request.payload,
            )
            if existing is None:
                if await self._work.idempotency_key_in_use(
                    context,
                    query.idempotency_key,
                ):
                    raise EvidenceIdempotencyConflictError(
                        "evidence_idempotency_key_reused"
                    ) from None
                raise
            return EvidenceRequestResult(False, existing)
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
        del store
        events = _with_fence(events, lease)
        version = await self._version(context, query.query_id)
        duplicate_digests: set[str] = set()

        async def prepare_evidence(
            connection: psycopg.AsyncConnection[Any],
            pending: Sequence[EventEnvelope],
        ) -> Sequence[EventEnvelope]:
            if records:
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (query.tenant_id,),
                )
            for item in quarantined:
                await connection.execute(
                    """
                    INSERT INTO evidence_quarantine (
                        quarantine_id, tenant_id, source_kind, source_record_id,
                        reason, observed_at, quarantined_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, statement_timestamp())
                    """,
                    (
                        uuid4(),
                        item.tenant_id,
                        item.source.value,
                        item.source_record_id,
                        item.reason.value,
                        item.observed_at,
                    ),
                )
            for record in records:
                cursor = await connection.execute(
                    """
                    INSERT INTO evidence_records (
                        tenant_id, evidence_id, content_digest, source_kind,
                        evidence_kind, environment, service, resource_kind,
                        resource_name, resource_namespace, resource_cluster,
                        observed_at, ingested_at, query_window_start,
                        query_window_end, summary, structured_fields, severity,
                        source_confidence, provenance_uri, source_record_id,
                        provenance_trust, classification, retention_class,
                        redaction, evidence_references, raw_payload_reference,
                        is_knowledge
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s
                    )
                    ON CONFLICT (tenant_id, content_digest) DO NOTHING
                    RETURNING evidence_id
                    """,
                    _record_values(record),
                )
                if await cursor.fetchone() is None:
                    duplicate_digests.add(record.content_digest)
            if bundle is not None:
                payload = _bundle_payload(bundle)
                encoded = json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                await connection.execute(
                    """
                    INSERT INTO evidence_bundle_projection (
                        tenant_id, bundle_id, environment, generated_at,
                        artifact_reference, content_digest, evidence_count,
                        timeline_count, conflict_count, bundle_content
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        bundle.tenant_id,
                        bundle.bundle_id,
                        bundle.environment.name,
                        bundle.generated_at,
                        (
                            "aegis-artifact://evidence-bundles/"
                            f"{bundle.tenant_id}/{bundle.bundle_id}"
                        ),
                        hashlib.sha256(encoded).hexdigest(),
                        len(bundle.evidence),
                        len(bundle.timeline),
                        len(bundle.source_conflicts),
                        Jsonb(payload),
                    ),
                )
            advanced_cursor_events: set[UUID] = set()
            for event in pending:
                if event.event_type != DomainEventType.SOURCE_CURSOR_ADVANCED:
                    continue
                cursor = await connection.execute(
                    """
                    INSERT INTO source_cursors (
                        tenant_id, source_kind, environment, cursor_value,
                        query_id, query_event_position, lease_generation,
                        advanced_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        (SELECT query_event_position FROM evidence_query_projection
                         WHERE tenant_id = %s AND query_id = %s),
                        %s, %s
                    )
                    ON CONFLICT (tenant_id, source_kind, environment)
                    DO UPDATE SET
                        cursor_value = EXCLUDED.cursor_value,
                        query_id = EXCLUDED.query_id,
                        query_event_position = EXCLUDED.query_event_position,
                        lease_generation = EXCLUDED.lease_generation,
                        advanced_at = EXCLUDED.advanced_at
                    WHERE (
                        source_cursors.query_event_position,
                        source_cursors.lease_generation
                    ) <= (
                        EXCLUDED.query_event_position,
                        EXCLUDED.lease_generation
                    )
                    """,
                    (
                        query.tenant_id,
                        query.source.value,
                        query.environment.name,
                        str(event.payload["cursor"]),
                        query.query_id,
                        query.tenant_id,
                        query.query_id,
                        lease.generation,
                        event.occurred_at,
                    ),
                )
                if cursor.rowcount == 1:
                    advanced_cursor_events.add(event.event_id)
            return tuple(
                _deduplicated_event(event)
                if event.event_type == DomainEventType.EVIDENCE_INGESTED
                and event.payload.get("digest") in duplicate_digests
                else event
                for event in pending
                if event.event_type != DomainEventType.SOURCE_CURSOR_ADVANCED
                or event.event_id in advanced_cursor_events
            )

        async def update_projection(connection: psycopg.AsyncConnection[Any]) -> None:
            for event in events:
                status = _status(event.event_type)
                if status is not None:
                    payload = event.payload
                    record_count = payload.get("record_count", 0)
                    if not isinstance(record_count, int) or isinstance(
                        record_count, bool
                    ):
                        record_count = 0
                    await connection.execute(
                        """
                        UPDATE evidence_query_projection
                        SET status = %s, updated_at = %s,
                            result_count = result_count + %s,
                            partial = partial OR %s,
                            truncated = truncated OR %s,
                            last_error_code = %s
                        WHERE tenant_id = %s AND query_id = %s
                        """,
                        (
                            status,
                            event.occurred_at,
                            record_count,
                            bool(payload.get("partial", False)),
                            bool(payload.get("truncated", False)),
                            payload.get("code"),
                            query.tenant_id,
                            query.query_id,
                        ),
                    )

        await self._events.append_fenced(
            context,
            events,
            expected_version=version,
            work_id=lease.work_id,
            lease_token=lease.token,
            lease_generation=lease.generation,
            at=events[0].occurred_at,
            mutation=update_projection,
            prepare=(
                prepare_evidence
                if records
                or quarantined
                or bundle
                or any(
                    event.event_type == DomainEventType.SOURCE_CURSOR_ADVANCED
                    for event in events
                )
                else None
            ),
        )
        return len(duplicate_digests)

    async def status(
        self,
        context: TenantContext,
        query_id: UUID,
    ) -> Mapping[str, JsonValue] | None:
        async with self._connection.transaction():
            await self._connection.execute(
                "SELECT set_config('aegis.tenant_id', %s, true)",
                (str(context.tenant_id),),
            )
            row = await (
                await self._connection.execute(
                    """
                    SELECT query_id, source_kind, environment, status, requested_at,
                        updated_at, result_count, partial, truncated, last_error_code
                    FROM evidence_query_projection
                    WHERE tenant_id = %s AND query_id = %s
                    """,
                    (str(context.tenant_id), query_id),
                )
            ).fetchone()
        if row is None:
            return None
        return {
            "query_id": str(row[0]),
            "source": row[1],
            "environment": row[2],
            "status": row[3],
            "requested_at": row[4].isoformat(),
            "updated_at": row[5].isoformat(),
            "result_count": row[6],
            "partial": row[7],
            "truncated": row[8],
            "last_error_code": row[9],
        }

    async def _version(self, context: TenantContext, query_id: UUID) -> int:
        version = 0
        while True:
            page = tuple(
                [
                    event
                    async for event in self._events.read_stream(
                        context,
                        str(query_id),
                        after_version=version,
                        limit=1_000,
                    )
                ]
            )
            if not page:
                break
            version = page[-1].aggregate_sequence
            if len(page) < 1_000:
                break
        return version


def _status(event_type: str) -> str | None:
    statuses: dict[str, str] = {
        DomainEventType.EVIDENCE_QUERY_STARTED.value: "running",
        DomainEventType.EVIDENCE_QUERY_SUCCEEDED.value: "succeeded",
        DomainEventType.EVIDENCE_QUERY_PARTIALLY_SUCCEEDED.value: (
            "partially_succeeded"
        ),
        DomainEventType.EVIDENCE_QUERY_FAILED.value: "failed",
        DomainEventType.EVIDENCE_QUERY_TIMED_OUT.value: "timed_out",
        DomainEventType.EVIDENCE_QUERY_RATE_LIMITED.value: "rate_limited",
        DomainEventType.EVIDENCE_QUERY_CANCELLED.value: "cancelled",
    }
    return statuses.get(event_type)


def _record_values(record: EvidenceRecord) -> tuple[object, ...]:
    return (
        record.tenant_id,
        str(record.evidence_id),
        record.content_digest,
        record.source.value,
        record.kind.value,
        record.environment.name,
        record.service.name if record.service else None,
        record.resource.kind if record.resource else None,
        record.resource.name if record.resource else None,
        record.resource.namespace if record.resource else None,
        record.resource.cluster if record.resource else None,
        record.observed_at,
        record.ingested_at,
        record.query_window.start,
        record.query_window.end,
        record.summary,
        Jsonb(thaw_json(record.fields)),
        record.severity.value,
        record.source_confidence,
        record.provenance.uri,
        record.provenance.source_record_id,
        record.provenance.trust.value,
        record.classification.value,
        record.retention.value,
        Jsonb(
            {
                "applied": record.redaction.applied,
                "rules": list(record.redaction.rule_ids),
                "removed_bytes": record.redaction.removed_bytes,
            }
        ),
        Jsonb(
            [
                {
                    "type": type(reference).__name__,
                    "fields": {
                        item.name: getattr(reference, item.name)
                        for item in dataclass_fields(reference)
                    },
                }
                for reference in record.references
            ]
        ),
        record.raw_payload_reference,
        record.knowledge,
    )


def _record_from_row(row: Sequence[object]) -> EvidenceRecord:
    redaction = row[24]
    if not isinstance(redaction, Mapping):
        raise ValueError("stored evidence redaction metadata is invalid")
    raw_references = row[25]
    if not isinstance(raw_references, list):
        raise ValueError("stored evidence references are invalid")
    fields = row[15]
    if not isinstance(fields, Mapping):
        raise ValueError("stored evidence fields are invalid")
    return EvidenceRecord(
        evidence_id=EvidenceId(str(row[0])),
        tenant_id=str(row[1]),
        source=EvidenceSourceKind(str(row[2])),
        kind=EvidenceKind(str(row[3])),
        environment=EnvironmentIdentity(str(row[4])),
        service=ServiceIdentity(str(row[5])) if row[5] is not None else None,
        resource=(
            ResourceIdentity(
                str(row[6]),
                str(row[7]),
                str(row[8]) if row[8] is not None else None,
                str(row[9]) if row[9] is not None else None,
            )
            if row[6] is not None and row[7] is not None
            else None
        ),
        observed_at=cast(datetime, row[10]),
        ingested_at=cast(datetime, row[11]),
        query_window=QueryWindow(
            cast(datetime, row[12]),
            cast(datetime, row[13]),
        ),
        summary=str(row[14]),
        fields=fields,
        severity=EvidenceSeverity(str(row[16])),
        source_confidence=(
            float(cast(float | int, row[17])) if row[17] is not None else None
        ),
        provenance=Provenance(
            str(row[18]),
            str(row[19]),
            cast(datetime, row[11]),
            TrustStatus(str(row[20])),
        ),
        content_digest=str(row[21]),
        classification=DataClassification(str(row[22])),
        retention=RetentionClass(str(row[23])),
        redaction=RedactionMetadata(
            bool(redaction.get("applied", False)),
            tuple(str(item) for item in redaction.get("rules", ())),
            int(redaction.get("removed_bytes", 0)),
        ),
        references=tuple(_reference_from_json(item) for item in raw_references),
        raw_payload_reference=str(row[26]) if row[26] is not None else None,
        knowledge=bool(row[27]),
    )


def _reference_from_json(value: object) -> EvidenceReference:
    if not isinstance(value, Mapping) or not isinstance(value.get("fields"), Mapping):
        raise ValueError("stored evidence reference is invalid")
    kind = str(value.get("type"))
    raw_fields = value["fields"]
    values = {str(key): item for key, item in raw_fields.items()}
    constructors: Mapping[str, type[object]] = {
        "TraceReference": TraceReference,
        "SpanReference": SpanReference,
        "LogReference": LogReference,
        "MetricReference": MetricReference,
        "ChangeReference": ChangeReference,
        "DeploymentReference": DeploymentReference,
        "ProblemReference": ProblemReference,
        "RunbookReference": RunbookReference,
    }
    constructor = constructors.get(kind)
    if constructor is None:
        raise ValueError("stored evidence reference kind is invalid")
    reference = constructor(**values)
    if not isinstance(
        reference,
        (
            TraceReference,
            SpanReference,
            LogReference,
            MetricReference,
            ChangeReference,
            DeploymentReference,
            ProblemReference,
            RunbookReference,
        ),
    ):
        raise TypeError("stored evidence reference could not be reconstructed")
    return reference


def _bundle_payload(bundle: EvidenceBundle) -> dict[str, JsonValue]:
    def link(item: CorrelationLink) -> dict[str, JsonValue]:
        return {
            "left": str(item.left),
            "right": str(item.right),
            "kind": item.kind.value,
            "confidence": item.confidence,
            "rationale": item.rationale,
            "ambiguous": item.ambiguous,
        }

    return {
        "evidence_ids": [str(item.evidence_id) for item in bundle.evidence],
        "timeline": [
            {
                "occurred_at": item.occurred_at.isoformat(),
                "evidence_ids": [str(value) for value in item.evidence_ids],
                "summary": item.summary,
            }
            for item in bundle.timeline
        ],
        "links": [link(item) for item in bundle.links],
        "source_conflicts": [link(item) for item in bundle.source_conflicts],
        "clock_skew_seconds": bundle.clock_skew_seconds,
        "metadata": cast(dict[str, JsonValue], thaw_json(bundle.metadata)),
    }


def _bundle_from_payload(
    bundle_id: str,
    tenant_id: str,
    environment: str,
    generated_at: datetime,
    payload: Mapping[str, object],
    evidence: tuple[EvidenceRecord, ...],
) -> EvidenceBundle:
    raw_timeline = payload.get("timeline")
    raw_links = payload.get("links")
    raw_conflicts = payload.get("source_conflicts")
    metadata = payload.get("metadata")
    if not all(
        isinstance(value, list) for value in (raw_timeline, raw_links, raw_conflicts)
    ) or not isinstance(metadata, Mapping):
        raise ValueError("stored evidence bundle content is invalid")
    return EvidenceBundle(
        bundle_id=bundle_id,
        tenant_id=tenant_id,
        environment=EnvironmentIdentity(environment),
        generated_at=generated_at,
        evidence=evidence,
        timeline=tuple(
            _timeline_from_json(item) for item in cast(list[object], raw_timeline)
        ),
        links=tuple(_link_from_json(item) for item in cast(list[object], raw_links)),
        source_conflicts=tuple(
            _link_from_json(item) for item in cast(list[object], raw_conflicts)
        ),
        clock_skew_seconds=cast(int, payload.get("clock_skew_seconds", 120)),
        metadata=cast(Mapping[str, JsonValue], metadata),
    )


def _timeline_from_json(value: object) -> TimelineEntry:
    if not isinstance(value, Mapping) or not isinstance(
        value.get("evidence_ids"), list
    ):
        raise ValueError("stored timeline entry is invalid")
    return TimelineEntry(
        datetime.fromisoformat(str(value.get("occurred_at"))),
        tuple(EvidenceId(str(item)) for item in value["evidence_ids"]),
        str(value.get("summary", "")),
    )


def _link_from_json(value: object) -> CorrelationLink:
    if not isinstance(value, Mapping):
        raise ValueError("stored correlation link is invalid")
    return CorrelationLink(
        EvidenceId(str(value.get("left"))),
        EvidenceId(str(value.get("right"))),
        CorrelationLinkKind(str(value.get("kind"))),
        float(cast(float | int, value.get("confidence"))),
        str(value.get("rationale", "")),
        bool(value.get("ambiguous", False)),
    )


def _deduplicated_event(event: EventEnvelope) -> EventEnvelope:
    return replace(
        event,
        event_type=DomainEventType.EVIDENCE_DEDUPLICATED,
        idempotency_key=(event.idempotency_key or "").replace(
            DomainEventType.EVIDENCE_INGESTED,
            DomainEventType.EVIDENCE_DEDUPLICATED,
        ),
    )


@contextmanager
def _transaction(
    connection: psycopg.Connection[Any],
    lock: RLock,
    context: TenantContext,
) -> Iterator[None]:
    with lock, connection.transaction():
        connection.execute(
            "SELECT set_config('aegis.tenant_id', %s, true)",
            (str(context.tenant_id),),
        )
        yield


__all__ = ["PostgresEvidenceRepository", "PostgresEvidenceStore"]
