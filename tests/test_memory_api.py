"""Authenticated control-plane coverage for Layer 10 memory routes."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from aegis_agent_platform.control_plane.api import ControlPlaneApp
from aegis_agent_platform.domain import MemoryCitation, SemanticMemory, WorkLease
from aegis_agent_platform.identity import Role
from aegis_agent_platform.memory.context import ContextBuilder
from aegis_agent_platform.memory.lifecycle import MemoryLifecycleService
from aegis_agent_platform.memory.operations import MemoryOperations
from aegis_agent_platform.memory.ports import DeterministicEmbeddingProvider
from aegis_agent_platform.memory.retrieval import HybridRetriever
from aegis_agent_platform.tenancy import InMemoryTenantRepository, Tenant
from memory_helpers import NOW, MemoryHarness, identifier, lease, semantic_memory
from security_helpers import (
    TENANT_ID,
    USER_ID,
    authentication_service,
    binding,
    identity_record,
    signing_fixture,
    token,
)


def _request(
    app: ControlPlaneApp,
    path: str,
    *,
    authorization: str | None = None,
    method: str = "GET",
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {
            "type": "http.request",
            "body": json.dumps(body or {}).encode(),
            "more_body": False,
        }

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    headers = (
        [(b"authorization", f"Bearer {authorization}".encode())]
        if authorization is not None
        else []
    )

    async def invoke() -> None:
        await app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": headers,
                "query_string": b"",
            },
            receive,
            send,
        )

    asyncio.run(invoke())
    return messages[0]["status"], json.loads(messages[1]["body"])


def _memory_body(memory: SemanticMemory) -> dict[str, object]:
    return {
        "accepted_by": memory.accepted_by,
        "acl": {
            "purposes": memory.acl.purposes,
            "roles": memory.acl.roles,
            "service_ids": memory.acl.service_ids,
            "user_ids": memory.acl.user_ids,
        },
        "chunker_version": memory.chunker_version,
        "confidence": memory.confidence,
        "created_at": memory.created_at.isoformat(),
        "embedder_version": memory.embedder_version,
        "embedding_dimension": memory.embedding_dimension,
        "embedding_model": memory.embedding_model,
        "incident_id": memory.incident_id,
        "memory_id": str(memory.memory_id),
        "policy_reference": memory.policy_reference,
        "quality": memory.quality,
        "retention": {
            "deletion_scope": memory.retention.deletion_scope,
            "expires_at": (
                memory.retention.expires_at.isoformat()
                if memory.retention.expires_at is not None
                else None
            ),
            "legal_hold": memory.retention.legal_hold,
            "legal_hold_reference": memory.retention.legal_hold_reference,
            "retention_class": memory.retention.retention_class,
        },
        "run_id": str(memory.run_id) if memory.run_id is not None else None,
        "schema_version": memory.schema_version,
        "security_label": memory.security_label.value,
        "snapshot": {
            "captured_at": memory.snapshot.captured_at.isoformat(),
            "citations": tuple(
                _citation_body(citation) for citation in memory.snapshot.citations
            ),
            "content_digest": memory.snapshot.content_digest,
            "content_reference": memory.snapshot.content_reference,
            "occurred_at": memory.snapshot.occurred_at.isoformat(),
            "schema_version": memory.snapshot.schema_version,
            "snapshot_id": str(memory.snapshot.snapshot_id),
            "source_kind": memory.snapshot.source_kind.value,
            "source_reference": memory.snapshot.source_reference,
            "source_version": memory.snapshot.source_version,
            "tenant_id": memory.snapshot.tenant_id,
            "trust": memory.snapshot.trust.value,
        },
        "supersedes_memory_ids": tuple(
            str(item) for item in memory.supersedes_memory_ids
        ),
        "tenant_id": memory.tenant_id,
    }


def _citation_body(citation: MemoryCitation) -> dict[str, object]:
    return {
        "artifact_id": (
            str(citation.artifact_id) if citation.artifact_id is not None else None
        ),
        "content_digest": citation.content_digest,
        "event_id": (str(citation.event_id) if citation.event_id is not None else None),
        "source_id": citation.source_id,
        "source_uri": citation.source_uri,
    }


def _lease_body(active_lease: WorkLease) -> dict[str, object]:
    return {
        "acquired_at": active_lease.acquired_at.isoformat(),
        "attempt": active_lease.attempt,
        "expires_at": active_lease.expires_at.isoformat(),
        "generation": active_lease.generation,
        "heartbeat_at": active_lease.heartbeat_at.isoformat(),
        "owner": active_lease.owner,
        "tenant_id": active_lease.tenant_id,
        "token": str(active_lease.token),
        "work_id": str(active_lease.work_id),
    }


def test_memory_api_authenticates_ingests_retrieves_and_redacts() -> None:
    harness = MemoryHarness.create()
    operations = MemoryOperations(
        harness.ledger,
        harness.index,
        harness.ingestion,
        HybridRetriever(
            harness.ledger,
            harness.index,
            DeterministicEmbeddingProvider(),
            clock=lambda: NOW,
        ),
        ContextBuilder(harness.ledger, clock=lambda: NOW),
        MemoryLifecycleService(
            harness.ledger,
            harness.blobs,
            harness.index,
            clock=lambda: NOW,
        ),
    )
    signing = signing_fixture()
    admin_binding = binding(Role.TENANT_ADMIN)
    app = ControlPlaneApp(
        authentication=authentication_service(
            signing,
            records=(identity_record((admin_binding,)),),
        ),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        memory_operations=operations,
    )
    encoded = token(signing)
    text = "Database failover succeeded after promoting the healthy replica."
    memory = semantic_memory(
        "api",
        text,
        tenant_id=str(TENANT_ID),
        accepted_by=str(USER_ID),
        users=(str(USER_ID),),
        roles=("tenant_admin",),
    )
    path = f"/v1/tenants/{TENANT_ID}/memories"

    unauthenticated, _ = _request(app, f"{path}/{memory.memory_id}/status")
    assert unauthenticated == 401

    proposed, proposal = _request(
        app,
        f"{path}/ingest",
        authorization=encoded,
        method="POST",
        body={
            "idempotency_key": "memory-api-proposal",
            "memory": _memory_body(memory),
            "source_text": text,
        },
    )
    assert proposed == 202
    assert proposal["redacted"]

    memory_lease = lease(memory.memory_id, str(TENANT_ID))
    harness.ledger.register_lease(memory_lease)
    accepted, acceptance = _request(
        app,
        f"{path}/{memory.memory_id}/accept",
        authorization=encoded,
        method="POST",
        body={
            "acceptance_kind": "human",
            "contradiction_ids": [],
            "idempotency_key": "memory-api-accept",
            "lease": _lease_body(memory_lease),
            "memory": _memory_body(memory),
        },
    )
    assert accepted == 200
    assert acceptance["status"] == "active"

    retrieval_id = lease(memory.memory_id).token
    retrieval_lease = lease(retrieval_id, str(TENANT_ID))
    harness.ledger.register_lease(retrieval_lease)
    retrieved, result = _request(
        app,
        f"{path}/retrieve",
        authorization=encoded,
        method="POST",
        body={
            "lease": _lease_body(retrieval_lease),
            "query": {
                "candidate_limit": 20,
                "max_context_bytes": 8_192,
                "max_context_tokens": 2_048,
                "purpose": "incident-investigation",
                "retrieval_id": str(retrieval_id),
                "text": "healthy replica failover",
                "top_k": 5,
            },
        },
    )
    assert retrieved == 200
    assert result["hits"][0]["citations"]
    assert result["hits"][0]["untrusted_data"]
    assert "embedding" not in json.dumps(result)
    denied_purpose, _ = _request(
        app,
        f"{path}/retrieve",
        authorization=encoded,
        method="POST",
        body={
            "lease": _lease_body(retrieval_lease),
            "query": {
                "purpose": "unbound-export",
                "retrieval_id": str(retrieval_id),
                "text": "healthy replica failover",
            },
        },
    )
    assert denied_purpose == 403
    denied_timestamp, _ = _request(
        app,
        f"{path}/retrieve",
        authorization=encoded,
        method="POST",
        body={
            "lease": _lease_body(retrieval_lease),
            "query": {
                "as_of": NOW.isoformat(),
                "purpose": "incident-investigation",
                "retrieval_id": str(retrieval_id),
                "text": "healthy replica failover",
            },
        },
    )
    assert denied_timestamp == 403

    status_code, status = _request(
        app,
        f"{path}/{memory.memory_id}/status",
        authorization=encoded,
    )
    assert status_code == 200
    assert status["candidate_status"] == "accepted"

    page_status, page = _request(app, path, authorization=encoded)
    assert page_status == 200
    assert page["memories"][0]["memory_id"] == str(memory.memory_id)

    context_retrieval_id = identifier("api-context-retrieval")
    context_retrieval_lease = lease(context_retrieval_id, str(TENANT_ID))
    task_id = identifier("api-context-task")
    context_lease = lease(task_id, str(TENANT_ID))
    harness.ledger.register_lease(context_retrieval_lease)
    harness.ledger.register_lease(context_lease)
    context_status, selected = _request(
        app,
        f"{path}/context",
        authorization=encoded,
        method="POST",
        body={
            "budget": {
                "episodic_tokens": 128,
                "reserved_safety_tokens": 32,
                "reserved_system_tokens": 32,
                "semantic_tokens": 192,
                "total_bytes": 4_096,
                "total_tokens": 512,
                "working_tokens": 128,
            },
            "context_lease": _lease_body(context_lease),
            "episodic": [
                {
                    "artifact_ids": [],
                    "citations": [_citation_body(memory.snapshot.citations[0])],
                    "cited_summary": "Prior failover restored checkout.",
                    "event_ids": [str(memory.snapshot.citations[0].event_id)],
                    "incident_id": memory.incident_id,
                    "occurred_at": NOW.isoformat(),
                    "reference_id": "episode-api",
                    "run_id": str(memory.run_id),
                    "tenant_id": str(TENANT_ID),
                }
            ],
            "query": {
                "candidate_limit": 20,
                "max_context_bytes": 8_192,
                "max_context_tokens": 2_048,
                "purpose": "incident-investigation",
                "retrieval_id": str(context_retrieval_id),
                "text": "healthy replica failover",
                "top_k": 5,
            },
            "retrieval_lease": _lease_body(context_retrieval_lease),
            "run_id": str(memory.run_id),
            "task_id": str(task_id),
            "working": [
                {
                    "citations": [_citation_body(memory.snapshot.citations[0])],
                    "kind": "active-assessment",
                    "occurred_at": NOW.isoformat(),
                    "priority": 100,
                    "reference_id": "working-api",
                    "text": "Checkout errors remain elevated.",
                }
            ],
        },
    )
    assert context_status == 200
    assert selected["snippets"]

    feedback_status, feedback = _request(
        app,
        f"{path}/{memory.memory_id}/feedback",
        authorization=encoded,
        method="POST",
        body={"rating": 0.9, "relevant": True, "reason_code": "useful"},
    )
    assert feedback_status == 200
    assert feedback["quality"] > memory.quality

    retention_status, _ = _request(
        app,
        f"{path}/{memory.memory_id}/retention",
        authorization=encoded,
        method="POST",
        body={
            "policy_reference": "retention-policy-v2",
            "retention": {
                "deletion_scope": "derived_and_referenced_blob",
                "expires_at": None,
                "legal_hold": False,
                "legal_hold_reference": None,
                "retention_class": "incident",
            },
        },
    )
    assert retention_status == 200

    for enabled in (True, False):
        hold_status, _ = _request(
            app,
            f"{path}/{memory.memory_id}/legal-hold",
            authorization=encoded,
            method="POST",
            body={"enabled": enabled, "hold_reference": "case-api"},
        )
        assert hold_status == 200

    provenance_status, provenance = _request(
        app,
        f"{path}/{memory.memory_id}/provenance",
        authorization=encoded,
    )
    assert provenance_status == 200
    assert provenance["redacted"]
    assert memory.snapshot.content_reference not in json.dumps(provenance)

    tombstone_status, _ = _request(
        app,
        f"{path}/{memory.memory_id}/tombstone",
        authorization=encoded,
        method="POST",
        body={"reason_code": "superseded_runbook"},
    )
    assert tombstone_status == 200
    deletion_status, deletion = _request(
        app,
        f"{path}/{memory.memory_id}/delete",
        authorization=encoded,
        method="POST",
        body={"request_reference": "delete-api"},
    )
    assert deletion_status == 200
    assert deletion["immutable_ledger_retained"]

    rejected_text = "Unreviewed generated operational advice."
    rejected_memory = semantic_memory(
        "api-rejected",
        rejected_text,
        tenant_id=str(TENANT_ID),
        accepted_by=str(USER_ID),
        users=(str(USER_ID),),
        roles=("tenant_admin",),
    )
    rejected_proposal, _ = _request(
        app,
        f"{path}/ingest",
        authorization=encoded,
        method="POST",
        body={
            "idempotency_key": "memory-api-rejected-proposal",
            "memory": _memory_body(rejected_memory),
            "source_text": rejected_text,
        },
    )
    assert rejected_proposal == 202
    rejection_status, rejection = _request(
        app,
        f"{path}/{rejected_memory.memory_id}/reject",
        authorization=encoded,
        method="POST",
        body={
            "idempotency_key": "memory-api-rejected",
            "memory": _memory_body(rejected_memory),
            "reason_code": "unsupported_claim",
        },
    )
    assert rejection_status == 200
    assert rejection["status"] == "rejected"

    invalid_uuid, _ = _request(
        app,
        f"{path}/not-a-uuid/status",
        authorization=encoded,
    )
    assert invalid_uuid == 400
    wrong_method, _ = _request(
        app,
        path,
        authorization=encoded,
        method="PUT",
    )
    assert wrong_method == 405
    unknown_route, _ = _request(
        app,
        f"{path}/{rejected_memory.memory_id}/unknown",
        authorization=encoded,
        method="POST",
    )
    assert unknown_route == 404

    cross_tenant, _ = _request(
        app,
        f"/v1/tenants/tenant-other/memories/{memory.memory_id}/status",
        authorization=encoded,
    )
    assert cross_tenant == 403
