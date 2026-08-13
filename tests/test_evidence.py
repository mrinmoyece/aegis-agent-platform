"""Deterministic evidence contracts, ingestion, fencing, and correlation tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from aegis_agent_platform.domain import (
    ChangeReference,
    CorrelationLink,
    CorrelationLinkKind,
    DataClassification,
    DeploymentReference,
    EnvironmentIdentity,
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
    PaginationCursor,
    PartialResult,
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
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.evidence import (
    CancellationSignal,
    ConnectorCapability,
    ConnectorError,
    ConnectorErrorClass,
    ConnectorPage,
    CorrelationEngine,
    EvidenceIngestor,
    EvidenceQuery,
    EvidenceQueryService,
    HttpRequest,
    HttpResponse,
    InMemoryEvidenceRepository,
    InMemoryEvidenceStore,
    RawEvidence,
    render_citation,
)
from aegis_agent_platform.evidence.operations import (
    EvidenceOperations,
    InMemoryEvidenceBundleStore,
)
from aegis_agent_platform.evidence.telemetry import EvidenceMetrics
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.policy import QuotaLimits, RiskLevel, TenantPolicy
from aegis_agent_platform.tenancy import TenantContext
from security_helpers import binding, principal

TENANT = TenantId("tenant-evidence")
CONTEXT = TenantContext(TENANT)
NOW = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
WINDOW = QueryWindow(NOW - timedelta(minutes=15), NOW)


def policy() -> TenantPolicy:
    return TenantPolicy(
        TENANT,
        "evidence-policy-v1",
        frozenset(),
        frozenset(),
        frozenset({"dynatrace", "github", "kubernetes", "runbook"}),
        frozenset({"production"}),
        RiskLevel.LOW,
        RiskLevel.CRITICAL,
        frozenset(),
        frozenset({Role.TENANT_ADMIN}),
        QuotaLimits(0, Decimal(0), 0, Decimal(0), 10),
    )


def query(
    *,
    query_id: UUID | None = None,
    source: EvidenceSourceKind = EvidenceSourceKind.DYNATRACE,
) -> EvidenceQuery:
    return EvidenceQuery(
        query_id or uuid4(),
        str(TENANT),
        source,
        EnvironmentIdentity("production"),
        WINDOW,
        (EvidenceKind.LOG,),
        {"service": "checkout"},
        100,
        "evidence-idempotency",
    )


def raw(
    *,
    source_record_id: str = "record-1",
    summary: str = "checkout failed",
    fields: Mapping[str, JsonValue] | None = None,
) -> RawEvidence:
    return RawEvidence(
        source_record_id,
        EvidenceKind.LOG,
        NOW - timedelta(minutes=1),
        summary,
        fields or {"trace_id": "abc"},
        f"https://observability.example/records/{source_record_id}",
        service=ServiceIdentity("checkout"),
        severity=EvidenceSeverity.ERROR,
        references=(TraceReference("abc"),),
        trust=TrustStatus.VERIFIED,
    )


class StaticConnector:
    source = EvidenceSourceKind.DYNATRACE

    def __init__(
        self,
        page: ConnectorPage | None = None,
        error: ConnectorError | None = None,
    ) -> None:
        self.page = page or ConnectorPage(
            (raw(),),
            None,
            PartialResult(False, False),
        )
        self.error = error
        self.calls = 0

    async def query(
        self,
        request: EvidenceQuery,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> ConnectorPage:
        del request, cancellation
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.page

    async def capability(self) -> ConnectorCapability:
        return ConnectorCapability(
            self.source,
            (EvidenceKind.LOG,),
            "test-v1",
            True,
            "ok",
        )


class Cancelled:
    cancelled = True


def lease(request: EvidenceQuery, generation: int = 1) -> WorkLease:
    return WorkLease(
        request.query_id,
        request.tenant_id,
        uuid4(),
        generation,
        "worker-evidence",
        1,
        NOW,
        NOW,
        NOW + timedelta(minutes=5),
    )


def record(
    identifier: str,
    *,
    digest: str,
    observed_at: datetime = NOW,
    source_record_id: str | None = None,
    references: tuple[EvidenceReference, ...] = (),
) -> EvidenceRecord:
    return EvidenceRecord(
        EvidenceId(identifier),
        str(TENANT),
        EvidenceSourceKind.DYNATRACE,
        EvidenceKind.LOG,
        EnvironmentIdentity("production"),
        observed_at,
        NOW,
        WINDOW,
        "checkout failed",
        {"status": "error"},
        Provenance(
            "https://observability.example/record",
            source_record_id or identifier,
            NOW,
            TrustStatus.VERIFIED,
        ),
        digest,
        DataClassification.CONFIDENTIAL,
        RetentionClass.INCIDENT,
        RedactionMetadata(False),
        service=ServiceIdentity("checkout"),
        references=references,
    )


def test_ingestion_redacts_addresses_deduplicates_and_renders_citation() -> None:
    store = InMemoryEvidenceStore()
    ingestor = EvidenceIngestor(store)
    source = raw(
        summary="email alice@example.com token=supersecretvalue",
        fields={"authorization": "Bearer hidden-value", "count": 3},
    )

    first = ingestor.ingest(
        CONTEXT,
        source,
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )
    second = ingestor.ingest(
        CONTEXT,
        source,
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )

    assert first.record is not None
    assert first.record.redaction.applied
    assert "[REDACTED-EMAIL]" in first.record.summary
    assert first.record.fields["authorization"] == "[REDACTED]"
    assert second.deduplicated
    assert len(store.list(CONTEXT)) == 1
    assert "digest=sha256:" in render_citation(first.record)


def test_ingestion_quarantines_oversized_and_rejects_cross_tenant() -> None:
    store = InMemoryEvidenceStore()
    ingestor = EvidenceIngestor(store, max_record_bytes=1024)
    outcome = ingestor.ingest(
        CONTEXT,
        raw(fields={"payload": "x" * 2000}),
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )

    assert outcome.quarantined is not None
    assert store.quarantined[0].source_record_id == "record-1"
    with pytest.raises(PermissionError, match="cross_tenant"):
        store.put(
            TenantContext(TenantId("tenant-other")),
            record("tenant-bound-record", digest="a" * 64),
        )


def test_ingestion_quarantines_invalid_metadata_with_bounded_identifier() -> None:
    store = InMemoryEvidenceStore()
    source_id = "source-" + ("x" * 10_000)
    outcome = EvidenceIngestor(store).ingest(
        CONTEXT,
        raw(source_record_id=source_id, summary="y" * 5000),
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )

    assert outcome.quarantined is not None
    assert outcome.quarantine_item is not None
    assert len(outcome.quarantine_item.source_record_id.encode()) <= 320
    assert "sha256:" in outcome.quarantine_item.source_record_id
    untrusted = EvidenceIngestor(store).ingest(
        CONTEXT,
        replace(raw(source_record_id="untrusted"), trust=TrustStatus.UNTRUSTED),
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )
    malformed = EvidenceIngestor(store).ingest(
        CONTEXT,
        raw(source_record_id="nan", fields={"value": float("nan")}),
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )
    assert untrusted.quarantined is not None
    assert untrusted.quarantined.value == "untrusted"
    assert malformed.quarantined is not None
    assert malformed.quarantined.value == "invalid"


def test_evidence_pages_hold_their_durable_highwater() -> None:
    store = InMemoryEvidenceStore()
    first = record("first-snapshot", digest="1" * 64)
    second = record("second-snapshot", digest="2" * 64)
    assert store.put(CONTEXT, first)
    assert store.put(CONTEXT, second)

    page = store.page(CONTEXT, limit=1)
    assert store.put(CONTEXT, record("later-snapshot", digest="3" * 64))
    remainder = store.page(CONTEXT, cursor=page.next_cursor, limit=1)

    assert page.records == (first,)
    assert remainder.records == (second,)
    assert remainder.next_cursor is None
    with pytest.raises(ValueError, match="invalid evidence page"):
        store.page(CONTEXT, limit=0)
    with pytest.raises(ValueError, match="invalid evidence page"):
        store.list(CONTEXT, offset=-1)


def test_evidence_operation_fields_are_json_serializable() -> None:
    store = InMemoryEvidenceStore()
    ingestor = EvidenceIngestor(store)
    outcome = ingestor.ingest(
        CONTEXT,
        raw(fields={"nested": {"items": ("one", "two")}}),
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )
    assert outcome.record is not None
    service = EvidenceQueryService(
        connectors={"dynatrace": StaticConnector()},
        repository=InMemoryEvidenceRepository(),
        ingestor=ingestor,
        clock=lambda: NOW,
    )
    operations = EvidenceOperations(service, store, InMemoryEvidenceBundleStore())
    actor = principal(
        (binding(tenant_id=TENANT, assigned_at=NOW - timedelta(hours=1)),),
        tenant_id=TENANT,
    )

    body = operations.evidence(actor, CONTEXT, at=NOW)

    assert json.loads(json.dumps(body))[0]["fields"]["nested"]["items"] == [
        "one",
        "two",
    ]


def test_query_service_persists_intent_before_connector_and_records_partial() -> None:
    repository = InMemoryEvidenceRepository()
    connector = StaticConnector(
        ConnectorPage(
            (raw(),),
            None,
            PartialResult(True, True, ("record_cap",), omitted_records=2),
        )
    )
    service = EvidenceQueryService(
        connectors={"dynatrace": connector},
        repository=repository,
        ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
        clock=lambda: NOW,
    )
    request = query()
    active_lease = lease(request)

    assert asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    assert connector.calls == 0
    assert repository.outbox[0].destination == "aegis.work.evidence"
    repository.register_lease(active_lease)
    result = asyncio.run(service.execute(CONTEXT, request, active_lease))

    event_types = [
        event.event_type for event in repository.events[(str(TENANT), request.query_id)]
    ]
    assert result.result.partial
    assert "evidence.query_requested.v1" in event_types
    assert "evidence.query_partially_succeeded.v1" in event_types
    assert connector.calls == 1
    for event in repository.events[(str(TENANT), request.query_id)][1:]:
        assert event.payload["lease_token"] == str(active_lease.token)
        assert event.payload["lease_generation"] == active_lease.generation
    assert not asyncio.run(
        service.request(CONTEXT, request, policy(), actor_id="alice")
    )


def test_connector_contract_violation_is_a_durable_terminal_failure() -> None:
    class InvalidConnector(StaticConnector):
        async def query(
            self,
            request: EvidenceQuery,
            *,
            cancellation: CancellationSignal | None = None,
        ) -> ConnectorPage:
            del request, cancellation
            raise ValueError("vendor value violated the neutral contract")

    repository = InMemoryEvidenceRepository()
    service = EvidenceQueryService(
        connectors={"dynatrace": InvalidConnector()},
        repository=repository,
        ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
        clock=lambda: NOW,
    )
    request = query()
    active = lease(request)
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(active)

    with pytest.raises(ConnectorError, match="connector_contract_violation"):
        asyncio.run(service.execute(CONTEXT, request, active))

    events = repository.events[(str(TENANT), request.query_id)]
    assert events[-1].event_type == "evidence.query_failed.v1"
    assert events[-1].payload["code"] == "connector_contract_violation"


def test_stale_worker_cannot_query_or_advance_cursor() -> None:
    repository = InMemoryEvidenceRepository()
    connector = StaticConnector()
    service = EvidenceQueryService(
        connectors={"dynatrace": connector},
        repository=repository,
        ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
        clock=lambda: NOW,
    )
    request = query()
    stale = lease(request, 1)
    current = lease(request, 2)
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(current)

    with pytest.raises(FencingError):
        asyncio.run(service.execute(CONTEXT, request, stale))
    assert connector.calls == 0


def test_worker_reclaimed_during_read_cannot_persist_evidence() -> None:
    repository = InMemoryEvidenceRepository()
    store = InMemoryEvidenceStore()
    request = query()
    stale = lease(request, 1)
    current = lease(request, 2)

    class ReclaimingConnector(StaticConnector):
        async def query(
            self,
            query: EvidenceQuery,
            *,
            cancellation: CancellationSignal | None = None,
        ) -> ConnectorPage:
            page = await super().query(query, cancellation=cancellation)
            repository.register_lease(current)
            return page

    service = EvidenceQueryService(
        connectors={"dynatrace": ReclaimingConnector()},
        repository=repository,
        ingestor=EvidenceIngestor(store),
        clock=lambda: NOW,
    )
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(stale)

    with pytest.raises(FencingError):
        asyncio.run(service.execute(CONTEXT, request, stale))

    assert store.list(CONTEXT) == ()
    assert store.quarantined == ()


def test_quarantined_records_make_the_query_explicitly_partial() -> None:
    repository = InMemoryEvidenceRepository()
    store = InMemoryEvidenceStore()
    request = query()
    active = lease(request)
    connector = StaticConnector(
        ConnectorPage(
            (raw(summary="x" * 2000),),
            None,
            PartialResult(False, False),
        )
    )
    service = EvidenceQueryService(
        connectors={"dynatrace": connector},
        repository=repository,
        ingestor=EvidenceIngestor(store, max_record_bytes=1024),
        clock=lambda: NOW,
    )
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(active)

    result = asyncio.run(service.execute(CONTEXT, request, active))

    assert result.result.partial
    assert result.result.omitted_records == 1
    assert result.result.reasons == ("ingestion_quarantine",)
    assert len(store.quarantined) == 1


def test_content_digest_includes_environment_and_sensitive_key_redaction() -> None:
    store = InMemoryEvidenceStore()
    ingestor = EvidenceIngestor(store)
    source = raw(fields={"x-api-key": "plain-secret-value"})

    production = ingestor.ingest(
        CONTEXT,
        source,
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("production"),
        window=WINDOW,
        ingested_at=NOW,
    )
    staging = ingestor.ingest(
        CONTEXT,
        source,
        source=EvidenceSourceKind.DYNATRACE,
        environment=EnvironmentIdentity("staging"),
        window=WINDOW,
        ingested_at=NOW,
    )

    assert production.record is not None
    assert staging.record is not None
    assert production.record.fields["x-api-key"] == "[REDACTED]"
    assert production.record.content_digest != staging.record.content_digest
    assert not staging.deduplicated


def test_rate_limit_and_cancellation_are_explicit_terminal_events() -> None:
    request = query()
    for connector, cancellation, expected in (
        (
            StaticConnector(
                error=ConnectorError(
                    ConnectorErrorClass.RATE_LIMIT,
                    "upstream_rate_limit",
                    retryable=True,
                    retry_after_seconds=3,
                )
            ),
            None,
            "evidence.query_rate_limited.v1",
        ),
        (StaticConnector(), Cancelled(), "evidence.query_cancelled.v1"),
    ):
        repository = InMemoryEvidenceRepository()
        service = EvidenceQueryService(
            connectors={"dynatrace": connector},
            repository=repository,
            ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
            clock=lambda: NOW,
        )
        active = lease(request)
        asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
        repository.register_lease(active)
        with pytest.raises(ConnectorError):
            asyncio.run(
                service.execute(
                    CONTEXT,
                    request,
                    active,
                    cancellation=cancellation,
                )
            )
        assert (
            repository.events[(str(TENANT), request.query_id)][-1].event_type
            == expected
        )


def test_deterministic_correlation_preserves_ambiguity_and_source_conflict() -> None:
    left = record(
        "evidence-left",
        digest="a" * 64,
        source_record_id="same-upstream-id",
        references=(TraceReference("trace-1"), ChangeReference("abc123", "org/repo")),
    )
    right = record(
        "evidence-right",
        digest="b" * 64,
        observed_at=NOW + timedelta(seconds=30),
        source_record_id="same-upstream-id",
        references=(TraceReference("trace-1"), DeploymentReference("abc123")),
    )

    bundle = CorrelationEngine().correlate(
        bundle_id="bundle-1",
        tenant_id=str(TENANT),
        environment=EnvironmentIdentity("production"),
        generated_at=NOW,
        evidence=(right, left),
        clock_skew_seconds=60,
    )

    kinds = {link.kind for link in bundle.links}
    assert bundle.timeline[0].evidence_ids == (left.evidence_id,)
    assert CorrelationLinkKind.EXACT_IDENTIFIER in kinds
    assert CorrelationLinkKind.TEMPORAL_PROXIMITY in kinds
    assert CorrelationLinkKind.SOURCE_CONFLICT in kinds
    assert bundle.source_conflicts[0].ambiguous
    assert bundle.metadata["causality_inferred"] is False


def test_service_correlation_and_authorized_bundle_views() -> None:
    repository = InMemoryEvidenceRepository()
    store = InMemoryEvidenceStore()
    metrics = EvidenceMetrics()
    service = EvidenceQueryService(
        connectors={"dynatrace": StaticConnector()},
        repository=repository,
        ingestor=EvidenceIngestor(store),
        clock=lambda: NOW,
        metrics=metrics,
    )
    request = query()
    active = lease(request)
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(active)
    evidence = (
        record(
            "correlation-left",
            digest="c" * 64,
            references=(TraceReference("trace-correlation"),),
        ),
        record(
            "correlation-right",
            digest="d" * 64,
            observed_at=NOW + timedelta(seconds=10),
            references=(TraceReference("trace-correlation"),),
        ),
    )
    bundle = asyncio.run(
        service.correlate(
            CONTEXT,
            request,
            active,
            evidence,
            bundle_id="bundle-service",
        )
    )
    assert repository.get(CONTEXT, "bundle-service") == bundle
    bundles = InMemoryEvidenceBundleStore()
    bundles.put(CONTEXT, bundle)
    operations = EvidenceOperations(service, store, bundles)
    actor = principal(
        (binding(tenant_id=TENANT, assigned_at=NOW - timedelta(hours=1)),),
        tenant_id=TENANT,
    )

    body = operations.bundle(
        actor,
        CONTEXT,
        "bundle-service",
        at=NOW,
    )

    assert body is not None
    assert body["causality_inferred"] is False
    assert operations.bundle(actor, CONTEXT, "missing", at=NOW) is None
    assert operations.evidence(actor, CONTEXT, at=NOW) == ()
    assert operations.citations(actor, CONTEXT, at=NOW) == ()
    assert metrics.snapshot()[("correlation_completed", "dynatrace")] == 1


def test_query_policy_is_tenant_environment_connector_and_window_bound() -> None:
    service = EvidenceQueryService(
        connectors={"dynatrace": StaticConnector()},
        repository=InMemoryEvidenceRepository(),
        ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
        clock=lambda: NOW,
    )
    request = query()
    denied = policy()
    denied = TenantPolicy(
        denied.tenant_id,
        denied.version,
        denied.allowed_models,
        denied.allowed_tools,
        frozenset(),
        denied.allowed_environments,
        denied.max_risk,
        denied.approval_from_risk,
        denied.tools_requiring_approval,
        denied.approver_roles,
        denied.quotas,
    )
    with pytest.raises(PermissionError, match="connector_not_allowed"):
        asyncio.run(service.request(CONTEXT, request, denied, actor_id="alice"))
    with pytest.raises(PermissionError, match="cross_tenant"):
        asyncio.run(
            service.request(
                TenantContext(TenantId("tenant-other")),
                request,
                policy(),
                actor_id="alice",
            )
        )


def test_query_execution_records_redaction_dedup_quarantine_and_cursor() -> None:
    repository = InMemoryEvidenceRepository()
    source = raw(
        summary="alice@example.com token=secret-token-value",
        fields={"api_token": "hidden-token-value"},
    )
    connector = StaticConnector(
        ConnectorPage(
            (source, source, raw(source_record_id="large", fields={"x": "z" * 3000})),
            PaginationCursor("next-page"),
            PartialResult(True, False, ("upstream_pagination",)),
        )
    )
    service = EvidenceQueryService(
        connectors={"dynatrace": connector},
        repository=repository,
        ingestor=EvidenceIngestor(InMemoryEvidenceStore(), max_record_bytes=1024),
        clock=lambda: NOW,
    )
    request = replace(
        query(),
        idempotency_key="prefix:evidence.ingested.v1",
    )
    active = lease(request)
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(active)
    result = asyncio.run(service.execute(CONTEXT, request, active))
    kinds = {
        event.event_type for event in repository.events[(str(TENANT), request.query_id)]
    }
    assert len(result.records) == 1
    assert "evidence.redacted.v1" in kinds
    assert "evidence.deduplicated.v1" in kinds
    assert "evidence.quarantined.v1" in kinds
    assert "evidence.source_cursor_advanced.v1" in kinds
    keys = [
        event.idempotency_key
        for event in repository.events[(str(TENANT), request.query_id)]
    ]
    assert len(keys) == len(set(keys))


def test_correlation_failure_is_durable_and_secret_safe() -> None:
    repository = InMemoryEvidenceRepository()
    service = EvidenceQueryService(
        connectors={"dynatrace": StaticConnector()},
        repository=repository,
        ingestor=EvidenceIngestor(InMemoryEvidenceStore()),
        clock=lambda: NOW,
    )
    request = query()
    active = lease(request)
    asyncio.run(service.request(CONTEXT, request, policy(), actor_id="alice"))
    repository.register_lease(active)
    foreign = replace(
        record("foreign-record", digest="e" * 64),
        tenant_id="tenant-other",
    )

    with pytest.raises(PermissionError, match="cross_tenant_correlation"):
        asyncio.run(
            service.correlate(
                CONTEXT,
                request,
                active,
                (foreign,),
                bundle_id="failed-bundle",
            )
        )
    assert (
        repository.events[(str(TENANT), request.query_id)][-1].event_type
        == "evidence.correlation_failed.v1"
    )


def test_metrics_reject_unbounded_names_and_negative_values() -> None:
    metrics = EvidenceMetrics()
    with pytest.raises(ValueError, match="bounded"):
        metrics.add("tenant-query-id", EvidenceSourceKind.DYNATRACE)
    with pytest.raises(ValueError, match="bounded"):
        metrics.add("queries", EvidenceSourceKind.DYNATRACE, -1)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: EvidenceQuery(
            uuid4(),
            str(TENANT),
            EvidenceSourceKind.DYNATRACE,
            EnvironmentIdentity("production"),
            WINDOW,
            (),
            {},
            10,
            "key",
        ),
        lambda: EvidenceQuery(
            uuid4(),
            str(TENANT),
            EvidenceSourceKind.DYNATRACE,
            EnvironmentIdentity("production"),
            WINDOW,
            (EvidenceKind.LOG,),
            {"service": ""},
            10,
            "key",
        ),
        lambda: RawEvidence(
            "",
            EvidenceKind.LOG,
            NOW,
            "summary",
            {},
            "https://example.invalid",
        ),
        lambda: ConnectorCapability(
            EvidenceSourceKind.GITHUB,
            (),
            "",
            False,
            "",
        ),
        lambda: HttpRequest(
            "DELETE",
            "https://example.invalid",
            {},
            1,
            1024,
        ),
        lambda: HttpRequest(
            "GET",
            "http://example.invalid",
            {},
            1,
            1024,
        ),
        lambda: HttpResponse(99, {}, b""),
    ],
)
def test_connector_contracts_reject_unbounded_inputs(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(
        ValueError,
        match=r"require|must|allowed|invalid|HTTPS|empty",
    ):
        factory()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: EvidenceId(""),
        lambda: QueryWindow(NOW, NOW),
        lambda: RedactionMetadata(True),
        lambda: Provenance("http://unsafe", "id", NOW),
        lambda: record("bad-digest", digest="invalid"),
        lambda: ProblemReference(""),
    ],
)
def test_evidence_contracts_reject_invalid_values(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValueError, match=r"required|must|invalid|unsupported"):
        factory()


def test_http_request_repr_redacts_headers_and_body() -> None:
    request = HttpRequest(
        "POST",
        "https://example.invalid/evidence",
        {"authorization": "Bearer secret-token"},
        1,
        1024,
        b"client_secret=secret-value",
    )

    assert "secret-token" not in repr(request)
    assert "secret-value" not in repr(request)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: EnvironmentIdentity(""),
        lambda: ServiceIdentity(" "),
        lambda: ResourceIdentity("", "pod"),
        lambda: ResourceIdentity("pod", ""),
        lambda: TraceReference(""),
        lambda: SpanReference("trace", ""),
        lambda: LogReference(""),
        lambda: MetricReference(""),
        lambda: ChangeReference(""),
        lambda: DeploymentReference(""),
        lambda: RunbookReference("", "v1"),
        lambda: Provenance(
            "https://example.invalid",
            "record",
            datetime(2026, 1, 1),
        ),
        lambda: RedactionMetadata(False, (), -1),
        lambda: PaginationCursor(""),
        lambda: PartialResult(True, False),
        lambda: PartialResult(False, False, (), omitted_bytes=-1),
        lambda: CorrelationLink(
            EvidenceId("same"),
            EvidenceId("same"),
            CorrelationLinkKind.EXACT_IDENTIFIER,
            1,
            "same",
        ),
        lambda: CorrelationLink(
            EvidenceId("left"),
            EvidenceId("right"),
            CorrelationLinkKind.EXACT_IDENTIFIER,
            2,
            "invalid confidence",
        ),
        lambda: TimelineEntry(datetime(2026, 1, 1), (EvidenceId("item"),), "x"),
        lambda: TimelineEntry(NOW, (), "empty"),
        lambda: EvidenceBundle(
            "bundle",
            str(TENANT),
            EnvironmentIdentity("production"),
            NOW,
            (),
            (),
            (),
            clock_skew_seconds=4000,
        ),
        lambda: EvidenceBundle(
            "bundle",
            str(TENANT),
            EnvironmentIdentity("production"),
            NOW,
            (),
            (),
            (),
            source_conflicts=(
                CorrelationLink(
                    EvidenceId("left"),
                    EvidenceId("right"),
                    CorrelationLinkKind.SOURCE_CONFLICT,
                    1,
                    "conflict",
                ),
            ),
        ),
        lambda: replace(
            record("naive-record", digest="1" * 64),
            observed_at=datetime(2026, 1, 1),
        ),
        lambda: replace(record("empty-summary", digest="2" * 64), summary=""),
        lambda: replace(
            record("invalid-confidence", digest="3" * 64),
            source_confidence=1.1,
        ),
        lambda: replace(
            record("invalid-raw-reference", digest="4" * 64),
            raw_payload_reference="https://example.invalid/raw",
        ),
        lambda: replace(record("invalid-knowledge", digest="5" * 64), knowledge=True),
        lambda: EvidenceBundle(
            "bundle",
            str(TENANT),
            EnvironmentIdentity("production"),
            datetime(2026, 1, 1),
            (),
            (),
            (),
        ),
        lambda: QueryWindow(datetime(2026, 1, 1), NOW),
        lambda: ChangeReference("sha", repository=""),
        lambda: DeploymentReference("revision", image_digest=""),
    ],
)
def test_evidence_identity_link_and_bundle_invariants(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValueError, match=r".+"):
        factory()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ConnectorError(
            ConnectorErrorClass.INVALID_QUERY,
            "",
            retryable=False,
        ),
        lambda: ConnectorError(
            ConnectorErrorClass.RATE_LIMIT,
            "limited",
            retryable=True,
            retry_after_seconds=-1,
        ),
        lambda: replace(query(), tenant_id=""),
        lambda: replace(raw(), observed_at=datetime(2026, 1, 1)),
        lambda: ConnectorCapability(
            EvidenceSourceKind.DYNATRACE,
            (EvidenceKind.LOG,),
            "",
            True,
            "ok",
        ),
        lambda: HttpRequest("PUT", "https://example.invalid", {}, 1, 1),
        lambda: HttpRequest("GET", "http://example.invalid", {}, 1, 1),
        lambda: HttpRequest("GET", "https://example.invalid", {}, 0, 1),
        lambda: HttpRequest("GET", "https://example.invalid", {}, 1, 0),
        lambda: HttpResponse(99, {}, b""),
    ],
)
def test_connector_port_invariants(factory: Callable[[], object]) -> None:
    with pytest.raises(ValueError, match=r".+"):
        factory()


def test_correlation_links_resources_runbooks_and_rejects_invalid_inputs() -> None:
    resource = ResourceIdentity("deployment", "checkout", "store", "cluster-a")
    left = replace(
        record("resource-left", digest="6" * 64),
        resource=resource,
    )
    right = replace(
        record(
            "resource-right",
            digest="7" * 64,
            observed_at=NOW + timedelta(seconds=10),
        ),
        resource=resource,
    )
    runbook = replace(
        record("runbook", digest="8" * 64),
        kind=EvidenceKind.RUNBOOK,
        knowledge=True,
    )
    far = replace(
        record(
            "far",
            digest="9" * 64,
            observed_at=NOW + timedelta(minutes=5),
        ),
        service=ServiceIdentity("other"),
    )
    engine = CorrelationEngine()

    bundle = engine.correlate(
        bundle_id="resource-runbook",
        tenant_id=str(TENANT),
        environment=EnvironmentIdentity("production"),
        generated_at=NOW,
        evidence=(far, runbook, right, left),
    )

    kinds = {link.kind for link in bundle.links}
    assert CorrelationLinkKind.RESOURCE_MATCH in kinds
    assert CorrelationLinkKind.RUNBOOK_APPLICABILITY in kinds
    with pytest.raises(TypeError, match="invalid correlation inputs"):
        engine.correlate(
            bundle_id="invalid",
            tenant_id=str(TENANT),
            environment="production",
            generated_at=NOW,
            evidence=(),
        )
    with pytest.raises(PermissionError, match="cross_tenant"):
        engine.correlate(
            bundle_id="cross-tenant",
            tenant_id="other",
            environment=EnvironmentIdentity("production"),
            generated_at=NOW,
            evidence=(left,),
        )
