"""Canonical checkout qualification using real services and deterministic fakes."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, UUID, uuid5

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis_agent_platform.agents.__main__ import run_canonical_demo
from aegis_agent_platform.agents.artifacts import EvidenceCitation
from aegis_agent_platform.agents.engines import CanonicalScenario
from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    InMemoryAuditStore,
)
from aegis_agent_platform.control_plane.api import ControlPlaneApp
from aegis_agent_platform.domain import (
    ActorKind,
    ActorReference,
    ChangeReference,
    DeploymentReference,
    DomainEventType,
    EnvironmentIdentity,
    EventEnvelope,
    EvidenceKind,
    EvidenceRecord,
    EvidenceSeverity,
    EvidenceSourceKind,
    JsonValue,
    PartialResult,
    ProblemReference,
    QueryWindow,
    ResourceIdentity,
    RunbookReference,
    ServiceIdentity,
    TraceReference,
    TrustStatus,
    WorkLease,
)
from aegis_agent_platform.evidence import (
    ConnectorCapability,
    ConnectorPage,
    EvidenceIngestor,
    EvidenceQuery,
    EvidenceQueryService,
    InMemoryEvidenceRepository,
    InMemoryEvidenceStore,
    RawEvidence,
)
from aegis_agent_platform.gateway.__main__ import run_mock_diagnostic
from aegis_agent_platform.identity import (
    AuthenticationService,
    IdentityRecord,
    InMemoryIdentityDirectory,
    JwtValidationConfig,
    JwtVerifier,
    PrincipalKind,
    Role,
    RoleBinding,
    StaticJwksProvider,
    TenantId,
    UserId,
    VerificationKey,
)
from aegis_agent_platform.memory.demo import run_demo as run_memory_demo
from aegis_agent_platform.observability.replay import ReplayDebugger, ReplayQuery
from aegis_agent_platform.operator.demo import canonical_operator_snapshot
from aegis_agent_platform.policy import (
    Decision,
    InMemoryPolicyRepository,
    PolicyEvaluator,
    PolicyRequest,
    QuotaLimits,
    QuotaUsage,
    RiskLevel,
    TenantPolicy,
)
from aegis_agent_platform.protocols.__main__ import (
    ProtocolDemoScenario,
    run_protocol_demo,
)
from aegis_agent_platform.qualification.ledger import (
    ArchivedEvent,
    QualificationArchive,
    ReadOnlyArchiveEventStore,
    projection_digest,
    rebuild_projection,
)
from aegis_agent_platform.remediation.__main__ import (
    RemediationScenario,
    run_remediation_demo,
)
from aegis_agent_platform.sandbox.__main__ import (
    SandboxScenario,
    run_sandbox_demo,
)
from aegis_agent_platform.tenancy import (
    InMemoryTenantRepository,
    Tenant,
    TenantContext,
)

QUALIFICATION_TENANT_ID = "tenant-alpha"
QUALIFICATION_INCIDENT_ID = "checkout-failure-after-deployment"
QUALIFICATION_RUN_ID = UUID("16000000-0000-4000-8000-000000000016")
QUALIFICATION_NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
_ISSUER = "https://identity.qualification.invalid/realms/aegis"
_AUDIENCE = "aegis-control-plane"
_KEY_ID = "qualification-local-only"
_REPLAY_HASH_KEY = sha256(b"local-only-qualification-replay").digest()
_SUPPORT_HASH_KEY = sha256(b"local-only-qualification-support").digest()


async def run_qualification_demo(output_directory: Path) -> Mapping[str, JsonValue]:
    """Run and persist the complete fake-only Layer 16 qualification journey."""
    output_directory.mkdir(parents=True, exist_ok=True)
    records: list[ArchivedEvent] = []

    def sink(source: str) -> Callable[[tuple[EventEnvelope, ...]], None]:
        return lambda events: records.extend(
            ArchivedEvent(source, event) for event in events
        )

    policy = _tenant_policy()
    intake, audit_events = await _authenticated_intake(policy)
    records.extend(
        ArchivedEvent("security-audit", event)
        for event in _audit_envelopes(audit_events)
    )
    policy_decision = PolicyEvaluator().evaluate(
        policy,
        PolicyRequest(
            TenantId(QUALIFICATION_TENANT_ID),
            "mock/aegis-diagnostic-v1",
            "remediate",
            "dynatrace",
            "production",
            RiskLevel.HIGH,
            128,
            Decimal("0.01"),
        ),
        QuotaUsage(0, Decimal(0), 0),
    )
    if policy_decision.decision is not Decision.REQUIRE_APPROVAL:
        raise RuntimeError("qualification policy did not require approval")

    (
        evidence_result,
        citations,
        evidence_records,
    ) = await run_evidence_qualification_stage(records)
    gateway = await run_mock_diagnostic(
        "Return a bounded cited checkout incident assessment.",
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=QUALIFICATION_RUN_ID,
        event_sink=sink("model-gateway"),
    )
    investigation = await run_canonical_demo(
        CanonicalScenario.SUCCESS,
        tenant_id=QUALIFICATION_TENANT_ID,
        incident_id=QUALIFICATION_INCIDENT_ID,
        run_id=QUALIFICATION_RUN_ID,
        evidence=citations,
        event_sink=sink("specialist-dag"),
    )
    memory = await run_memory_demo(
        tenant_id=QUALIFICATION_TENANT_ID,
        isolation_tenant_id="tenant-beta",
        event_sink=sink("memory"),
    )
    remediation = await run_remediation_demo(
        RemediationScenario.AMBIGUOUS_RECONCILED,
        tenant_id=QUALIFICATION_TENANT_ID,
        incident_id=QUALIFICATION_INCIDENT_ID,
        investigation_run_id=QUALIFICATION_RUN_ID,
        event_sink=sink("remediation"),
    )
    sandbox = await run_sandbox_demo(
        SandboxScenario.OUTPUT_QUARANTINE,
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=QUALIFICATION_RUN_ID,
        event_sink=sink("sandbox"),
    )
    mcp = await run_protocol_demo(
        ProtocolDemoScenario.SAFE_RETRIEVAL,
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=QUALIFICATION_RUN_ID,
        event_sink=sink("mcp"),
    )
    a2a = await run_protocol_demo(
        ProtocolDemoScenario.ARTIFACT_EXCHANGE,
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=QUALIFICATION_RUN_ID,
        event_sink=sink("a2a"),
    )
    operator_snapshot = canonical_operator_snapshot(at=QUALIFICATION_NOW)

    before_projection = rebuild_projection(records)
    ledger_path = output_directory / "checkout-qualification-ledger.jsonl"
    archive_digest = QualificationArchive.write(ledger_path, records)
    restored = QualificationArchive.read(ledger_path)
    after_projection = rebuild_projection(restored.records)
    before_digest = projection_digest(before_projection)
    after_digest = projection_digest(after_projection)
    if before_digest != after_digest:
        raise RuntimeError("qualification projection did not converge after replay")

    debugger = ReplayDebugger(
        ReadOnlyArchiveEventStore(restored.records, source="specialist-dag"),
        identifier_hash_key=_REPLAY_HASH_KEY,
        hash_key_version="qv1",
    )
    context = TenantContext(TenantId(QUALIFICATION_TENANT_ID))
    replay_events = await debugger.load(
        context,
        ReplayQuery(str(QUALIFICATION_RUN_ID)),
    )
    validation = debugger.validate(replay_events)
    support = debugger.support_report(
        context,
        replay_events,
        signer="local-qualification",
        signing_key=_SUPPORT_HASH_KEY,
    )
    ordering = _ordering_assertions(restored.records)
    if not all(ordering.values()):
        raise RuntimeError("qualification intent ordering assertion failed")

    result: dict[str, JsonValue] = {
        "schema_version": 1,
        "qualification": "layer-16-local-enterprise-qualification",
        "demo_only": True,
        "uses_live_network": False,
        "uses_production_credentials": False,
        "production_certified": False,
        "claims_exactly_once": False,
        "tenant_id": QUALIFICATION_TENANT_ID,
        "incident_id": QUALIFICATION_INCIDENT_ID,
        "run_id": str(QUALIFICATION_RUN_ID),
        "journey": {
            "authenticated_intake": intake,
            "tenant_policy": {
                "decision": policy_decision.decision.value,
                "policy_version": policy_decision.policy_version,
                "required_roles": tuple(
                    role.value for role in policy_decision.required_approver_roles
                ),
            },
            "evidence": evidence_result,
            "model_gateway": cast(Mapping[str, JsonValue], gateway),
            "specialist_dag": investigation,
            "memory": cast(Mapping[str, JsonValue], memory),
            "remediation": cast(Mapping[str, JsonValue], remediation),
            "sandbox": cast(Mapping[str, JsonValue], sandbox),
            "mcp": mcp,
            "a2a": a2a,
            "operator_ui": {
                "tenant_id": operator_snapshot.tenant_id,
                "section_count": len(operator_snapshot.sections),
                "item_count": sum(
                    len(items) for items in operator_snapshot.sections.values()
                ),
                "production_ready": False,
                "synthetic_demo": operator_snapshot.demo,
                "data_authority_labels_present": all(
                    item.authority.value
                    for items in operator_snapshot.sections.values()
                    for item in items
                ),
            },
        },
        "ledger": {
            "path": ledger_path.name,
            "event_count": len(restored.records),
            "source_count": len(
                cast(Mapping[str, JsonValue], before_projection["sources"])
            ),
            "archive_digest": archive_digest,
            "archive_chain_valid": archive_digest == restored.chain_digest,
            "projection_digest_before": before_digest,
            "projection_digest_after": after_digest,
            "projection_rebuild_identical": before_digest == after_digest,
            "replay_valid": validation.valid,
            "replay_event_count": validation.event_count,
        },
        "support_bundle": {
            "content_digest": support.content_digest,
            "signature_algorithm": support.signature_algorithm,
            "signed": support.signature is not None,
            "redacted_tenant_reference": support.tenant_reference,
        },
        "assertions": {
            **ordering,
            "evidence_citations_immutable": len(citations) == 4,
            "evidence_records_persisted": len(evidence_records) == 4,
            "specialist_projection_rebuilt": bool(
                investigation["projection_rebuild_identical"]
            ),
            "remediation_reconciled_and_verified": (
                remediation["status"] == "verified"
                and "action.reconciliation_completed.v1"
                in cast(Sequence[str], remediation["event_types"])
            ),
            "sandbox_artifact_quarantined": (
                "sandbox.quarantined.v1" in cast(Sequence[str], sandbox["event_types"])
            ),
            "memory_isolated_and_compacted": (
                cast(Mapping[str, object], memory["tenant_isolation"])[
                    "tenant_b_excluded"
                ]
                is True
                and cast(Mapping[str, object], memory["compaction"])["compacted"]
                is True
            ),
            "mcp_and_a2a_bounded": (
                mcp["status"] == "completed"
                and a2a["status"] == "completed"
                and mcp["production_ready"] is False
                and a2a["production_ready"] is False
            ),
        },
    }
    result_path = output_directory / "checkout-qualification-result.json"
    _atomic_json(result_path, result)
    return result


async def _authenticated_intake(
    policy: TenantPolicy,
) -> tuple[Mapping[str, JsonValue], tuple[AuditEvent, ...]]:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tenant = TenantId(QUALIFICATION_TENANT_ID)
    user = UserId("qualification-operator")
    bindings = tuple(
        RoleBinding(
            tenant,
            role,
            UserId("qualification-admin"),
            QUALIFICATION_NOW - timedelta(days=1),
        )
        for role in (
            Role.VIEWER,
            Role.INVESTIGATOR,
            Role.OPERATOR,
            Role.APPROVER,
            Role.TENANT_ADMIN,
        )
    )
    identity = IdentityRecord(
        _ISSUER,
        "qualification-subject",
        tenant,
        PrincipalKind.USER,
        bindings,
        True,
        user_id=user,
    )
    authentication = AuthenticationService(
        JwtVerifier(
            JwtValidationConfig(_ISSUER, _AUDIENCE),
            StaticJwksProvider((VerificationKey(_KEY_ID, "RS256", public_key),)),
        ),
        InMemoryIdentityDirectory((identity,)),
    )
    now = datetime.now(UTC)
    encoded = jwt.encode(
        {
            "iss": _ISSUER,
            "sub": identity.subject,
            "aud": _AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "tenant_id": QUALIFICATION_TENANT_ID,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": _KEY_ID},
    )
    audit = InMemoryAuditStore()
    app = ControlPlaneApp(
        authentication=authentication,
        tenants=InMemoryTenantRepository((Tenant(tenant, "Tenant Alpha"),)),
        policies=InMemoryPolicyRepository((policy,)),
        audit=audit,
    )
    me_status, me = await _asgi_request(app, "/v1/me", encoded)
    policy_status, policy_body = await _asgi_request(
        app,
        f"/v1/tenants/{tenant}/policy",
        encoded,
    )
    if me_status != 200 or policy_status != 200:
        raise RuntimeError("authenticated qualification intake failed")
    context = TenantContext(tenant)
    audit.append(
        context,
        AuditEvent(
            _id("policy-audit"),
            tenant,
            AuditEventType.POLICY_EVALUATION,
            QUALIFICATION_NOW,
            AuditOutcome.SUCCESS,
            str(user),
            "qualification.policy.evaluate",
            f"tenant/{tenant}",
            QUALIFICATION_RUN_ID,
            {"policy_version": policy.version, "decision": "require_approval"},
        ),
    )
    return (
        {
            "status": me_status,
            "actor_id": cast(str, me["actor_id"]),
            "tenant_id": cast(str, me["tenant_id"]),
            "roles": cast(Sequence[JsonValue], me["roles"]),
            "policy_status": policy_status,
            "policy_version": cast(str, policy_body["version"]),
            "authentication_source": "signed-ephemeral-local-fixture",
        },
        audit.query(context, limit=100),
    )


async def run_evidence_qualification_stage(
    archived: list[ArchivedEvent],
) -> tuple[
    Mapping[str, JsonValue],
    Mapping[str, EvidenceCitation],
    tuple[EvidenceRecord, ...],
]:
    tenant = TenantId(QUALIFICATION_TENANT_ID)
    context = TenantContext(tenant)
    environment = EnvironmentIdentity("production")
    window = QueryWindow(
        QUALIFICATION_NOW - timedelta(minutes=30),
        QUALIFICATION_NOW,
    )
    raw_by_source = _raw_evidence()
    connectors = {
        source.value: _StaticConnector(source, raw)
        for source, raw in raw_by_source.items()
    }
    repository = InMemoryEvidenceRepository()
    store = InMemoryEvidenceStore()
    ids = iter(_id(f"evidence-event-{index}") for index in range(1, 200))
    service = EvidenceQueryService(
        connectors=connectors,
        repository=repository,
        ingestor=EvidenceIngestor(store),
        clock=lambda: QUALIFICATION_NOW,
        uuid_factory=lambda: next(ids),
    )
    policy = _tenant_policy()
    records: list[EvidenceRecord] = []
    queries: list[tuple[EvidenceQuery, WorkLease]] = []
    for source, raw in raw_by_source.items():
        query = EvidenceQuery(
            _id(f"query-{source.value}"),
            QUALIFICATION_TENANT_ID,
            source,
            environment,
            window,
            (raw.kind,),
            {"service": "checkout"},
            100,
            f"qualification-evidence:{source.value}",
        )
        lease = WorkLease(
            query.query_id,
            QUALIFICATION_TENANT_ID,
            _id(f"lease-{source.value}"),
            1,
            "qualification-evidence-worker",
            1,
            QUALIFICATION_NOW,
            QUALIFICATION_NOW,
            QUALIFICATION_NOW + timedelta(minutes=5),
        )
        await service.request(context, query, policy, actor_id="qualification-operator")
        repository.register_lease(lease)
        execution = await service.execute(context, query, lease)
        records.extend(execution.records)
        queries.append((query, lease))
    primary_query, primary_lease = queries[0]
    bundle = await service.correlate(
        context,
        primary_query,
        primary_lease,
        tuple(records),
        bundle_id="checkout-qualification-bundle",
    )
    for query, _lease in queries:
        archived.extend(
            ArchivedEvent("evidence", event)
            for event in repository.events[(QUALIFICATION_TENANT_ID, query.query_id)]
        )
    by_source = {record.source: record for record in records}
    citation_names = {
        EvidenceSourceKind.DYNATRACE: "ev-telemetry",
        EvidenceSourceKind.GITHUB: "ev-change",
        EvidenceSourceKind.KUBERNETES: "ev-runtime",
        EvidenceSourceKind.RUNBOOK: "ev-runbook",
    }
    citations = {
        name: EvidenceCitation(
            name,
            by_source[source].provenance.uri,
            by_source[source].content_digest,
        )
        for source, name in citation_names.items()
    }
    return (
        {
            "query_count": len(queries),
            "record_count": len(records),
            "bundle_id": bundle.bundle_id,
            "timeline_entries": len(bundle.timeline),
            "correlation_links": len(bundle.links),
            "source_conflicts": len(bundle.source_conflicts),
            "causality_inferred": bundle.metadata["causality_inferred"],
            "citation_ids": tuple(sorted(citations)),
        },
        citations,
        tuple(records),
    )


def _raw_evidence() -> Mapping[EvidenceSourceKind, RawEvidence]:
    deployment = DeploymentReference("checkout-7f4c", "sha256:" + "a" * 64)
    service = ServiceIdentity("checkout")
    resource = ResourceIdentity(
        "deployment",
        "checkout-api",
        "checkout",
        "qualification-cluster",
    )
    return {
        EvidenceSourceKind.DYNATRACE: RawEvidence(
            "problem-checkout-42",
            EvidenceKind.PROBLEM,
            QUALIFICATION_NOW - timedelta(minutes=8),
            "Checkout errors rose to 31% after deployment.",
            {"error_rate": 0.31, "authorization": "******"},
            "https://observability.qualification.invalid/problems/42",
            service=service,
            resource=resource,
            severity=EvidenceSeverity.CRITICAL,
            source_confidence=0.99,
            references=(
                ProblemReference("problem-checkout-42"),
                TraceReference("trace-checkout-42"),
                deployment,
            ),
            trust=TrustStatus.VERIFIED,
        ),
        EvidenceSourceKind.GITHUB: RawEvidence(
            "deployment-checkout-7f4c",
            EvidenceKind.DEPLOYMENT,
            QUALIFICATION_NOW - timedelta(minutes=10),
            "Deployment checkout-7f4c changed payment timeout defaults.",
            {"repository": "example/checkout", "commit": "abc1234"},
            "https://github.qualification.invalid/example/checkout/deployments/42",
            service=service,
            resource=resource,
            severity=EvidenceSeverity.INFO,
            source_confidence=0.98,
            references=(ChangeReference("abc1234", "example/checkout"), deployment),
            trust=TrustStatus.VERIFIED,
        ),
        EvidenceSourceKind.KUBERNETES: RawEvidence(
            "rollout-checkout-7f4c",
            EvidenceKind.WORKLOAD,
            QUALIFICATION_NOW - timedelta(minutes=9),
            "All checkout pods run revision checkout-7f4c.",
            {"ready_replicas": 4, "replicas": 4},
            "https://kubernetes.qualification.invalid/apis/apps/deployments/checkout-api",
            service=service,
            resource=resource,
            severity=EvidenceSeverity.WARNING,
            source_confidence=0.97,
            references=(deployment, TraceReference("trace-checkout-42")),
            trust=TrustStatus.VERIFIED,
        ),
        EvidenceSourceKind.RUNBOOK: RawEvidence(
            "runbook-checkout-rollback-v3",
            EvidenceKind.RUNBOOK,
            QUALIFICATION_NOW - timedelta(days=1),
            "Rollback only after multi-source confirmation and exact approval.",
            {"owner": "checkout-platform", "reviewed": True},
            "file:///approved/checkout-rollback.md",
            service=service,
            resource=resource,
            severity=EvidenceSeverity.INFO,
            source_confidence=1.0,
            references=(RunbookReference("checkout-rollback", "v3"),),
            trust=TrustStatus.VERIFIED,
            knowledge=True,
        ),
    }


class _StaticConnector:
    def __init__(self, source: EvidenceSourceKind, record: RawEvidence) -> None:
        self.source = source
        self._record = record

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: object | None = None,
    ) -> ConnectorPage:
        del cancellation
        if query.source is not self.source:
            raise PermissionError("qualification connector source mismatch")
        return ConnectorPage(
            (self._record,),
            None,
            PartialResult(False, False),
        )

    async def capability(self) -> ConnectorCapability:
        return ConnectorCapability(
            self.source,
            (self._record.kind,),
            "qualification-v1",
            True,
            "local_fixture",
        )


def _tenant_policy() -> TenantPolicy:
    return TenantPolicy(
        TenantId(QUALIFICATION_TENANT_ID),
        "qualification-policy-v1",
        frozenset({"mock/aegis-diagnostic-v1"}),
        frozenset({"search", "remediate"}),
        frozenset(source.value for source in EvidenceSourceKind),
        frozenset({"development", "test", "production"}),
        RiskLevel.HIGH,
        RiskLevel.HIGH,
        frozenset({"remediate"}),
        frozenset({Role.APPROVER}),
        QuotaLimits(
            20_000,
            Decimal("5"),
            100_000,
            Decimal("25"),
            4,
        ),
        allowed_providers=frozenset({"mock"}),
        allowed_data_residencies=frozenset({"local"}),
    )


async def _asgi_request(
    app: ControlPlaneApp,
    path: str,
    token: str,
) -> tuple[int, Mapping[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "query_string": b"",
        },
        receive,
        send,
    )
    return int(messages[0]["status"]), cast(
        Mapping[str, Any],
        json.loads(messages[1]["body"]),
    )


def _audit_envelopes(events: Sequence[AuditEvent]) -> tuple[EventEnvelope, ...]:
    return tuple(
        EventEnvelope(
            event.event_id,
            str(event.tenant_id),
            str(QUALIFICATION_RUN_ID),
            event.event_type.value,
            event.schema_version,
            event.occurred_at,
            {
                "outcome": event.outcome.value,
                "action": event.action,
                "resource": event.resource,
                "details": event.details,
            },
            correlation_id=event.correlation_id,
            aggregate_sequence=index,
            recorded_at=event.occurred_at,
            actor=ActorReference(event.actor_id, ActorKind.USER),
            audit_reference=event.event_id,
        )
        for index, event in enumerate(events, start=1)
    )


def _ordering_assertions(
    records: Sequence[ArchivedEvent],
) -> Mapping[str, bool]:
    by_source: dict[str, list[str]] = {}
    for record in records:
        by_source.setdefault(record.source, []).append(record.event.event_type)
    return {
        "evidence_intent_before_query": _ordered(
            by_source["evidence"],
            DomainEventType.EVIDENCE_QUERY_REQUESTED,
            DomainEventType.EVIDENCE_QUERY_STARTED,
        ),
        "model_intent_before_provider": _ordered(
            by_source["model-gateway"],
            DomainEventType.MODEL_CALL_REQUESTED,
            DomainEventType.MODEL_CALL_STARTED,
        ),
        "specialist_dispatch_before_start": _ordered(
            by_source["specialist-dag"],
            DomainEventType.SPECIALIST_TASK_DISPATCH_REQUESTED,
            DomainEventType.SPECIALIST_TASK_STARTED,
        ),
        "action_intent_before_effect": _ordered(
            by_source["remediation"],
            DomainEventType.ACTION_EXECUTION_REQUESTED,
            DomainEventType.ACTION_EXECUTION_STARTED,
        ),
        "sandbox_intent_before_backend": _ordered(
            by_source["sandbox"],
            DomainEventType.SANDBOX_PROVISIONING_REQUESTED,
            DomainEventType.SANDBOX_PROVISIONED,
        ),
        "protocol_intent_before_network": (
            _ordered(
                by_source["mcp"],
                DomainEventType.MCP_INVOCATION_REQUESTED,
                DomainEventType.MCP_INVOCATION_STARTED,
            )
            and _ordered(
                by_source["a2a"],
                DomainEventType.A2A_TASK_REQUESTED,
                DomainEventType.A2A_TASK_ACCEPTED,
            )
        ),
    }


def _ordered(events: Sequence[str], before: str, after: str) -> bool:
    """Return True when every occurrence of *before* is followed by *after*.

    Using ``list.index`` only validates the first pair and masks failures in
    subsequent repeated operations (e.g. four evidence queries).  This
    implementation verifies that every *before* event is consumed by a later
    *after* event, so that no "before" is left without a subsequent "after".
    """
    unmatched = 0
    matched = 0
    for event in events:
        if event == before:
            unmatched += 1
        elif event == after and unmatched > 0:
            unmatched -= 1
            matched += 1
    before_count = events.count(before)
    return before_count > 0 and matched == before_count


def _atomic_json(path: Path, value: Mapping[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _id(label: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"aegis-qualification:{label}")


__all__ = [
    "QUALIFICATION_INCIDENT_ID",
    "QUALIFICATION_NOW",
    "QUALIFICATION_RUN_ID",
    "QUALIFICATION_TENANT_ID",
    "run_evidence_qualification_stage",
    "run_qualification_demo",
]
