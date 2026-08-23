"""Bounded neutral memory-contract serialization for erasable blob storage."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from uuid import UUID

from aegis_agent_platform.domain import (
    DataClassification,
    MemoryAcl,
    MemoryCitation,
    MemoryRetention,
    MemorySourceKind,
    SemanticMemory,
    SourceSnapshot,
    SourceTrustTier,
)


def memory_to_document(memory: SemanticMemory) -> dict[str, object]:
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
            "citations": _citations(memory.snapshot.citations),
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


def memory_from_document(value: object) -> SemanticMemory:
    document = _mapping(value, "memory document")
    snapshot_value = _mapping(document["snapshot"], "memory snapshot")
    acl_value = _mapping(document["acl"], "memory ACL")
    retention_value = _mapping(document["retention"], "memory retention")
    return SemanticMemory(
        memory_id=UUID(str(document["memory_id"])),
        tenant_id=str(document["tenant_id"]),
        snapshot=SourceSnapshot(
            snapshot_id=UUID(str(snapshot_value["snapshot_id"])),
            tenant_id=str(snapshot_value["tenant_id"]),
            source_kind=MemorySourceKind(str(snapshot_value["source_kind"])),
            source_reference=str(snapshot_value["source_reference"]),
            source_version=str(snapshot_value["source_version"]),
            content_digest=str(snapshot_value["content_digest"]),
            content_reference=str(snapshot_value["content_reference"]),
            occurred_at=datetime.fromisoformat(str(snapshot_value["occurred_at"])),
            captured_at=datetime.fromisoformat(str(snapshot_value["captured_at"])),
            citations=_citations_from_document(snapshot_value["citations"]),
            trust=SourceTrustTier(str(snapshot_value["trust"])),
            schema_version=str(snapshot_value["schema_version"]),
        ),
        incident_id=(
            str(document["incident_id"])
            if document.get("incident_id") is not None
            else None
        ),
        run_id=(
            UUID(str(document["run_id"]))
            if document.get("run_id") is not None
            else None
        ),
        acl=MemoryAcl(
            user_ids=_strings(acl_value.get("user_ids")),
            service_ids=_strings(acl_value.get("service_ids")),
            roles=_strings(acl_value.get("roles")),
            purposes=_strings(acl_value.get("purposes")),
        ),
        security_label=DataClassification(str(document["security_label"])),
        schema_version=str(document["schema_version"]),
        chunker_version=str(document["chunker_version"]),
        embedder_version=str(document["embedder_version"]),
        embedding_model=str(document["embedding_model"]),
        embedding_dimension=int(str(document["embedding_dimension"])),
        confidence=float(str(document["confidence"])),
        quality=float(str(document["quality"])),
        retention=MemoryRetention(
            retention_class=str(retention_value["retention_class"]),
            expires_at=(
                datetime.fromisoformat(str(retention_value["expires_at"]))
                if retention_value.get("expires_at") is not None
                else None
            ),
            legal_hold=bool(retention_value["legal_hold"]),
            legal_hold_reference=(
                str(retention_value["legal_hold_reference"])
                if retention_value.get("legal_hold_reference") is not None
                else None
            ),
            deletion_scope=str(retention_value["deletion_scope"]),
        ),
        accepted_by=str(document["accepted_by"]),
        policy_reference=str(document["policy_reference"]),
        created_at=datetime.fromisoformat(str(document["created_at"])),
        supersedes_memory_ids=tuple(
            UUID(item) for item in _strings(document.get("supersedes_memory_ids"))
        ),
    )


def _citations(values: Sequence[MemoryCitation]) -> list[dict[str, object]]:
    return [
        {
            "artifact_id": (
                str(item.artifact_id) if item.artifact_id is not None else None
            ),
            "content_digest": item.content_digest,
            "event_id": str(item.event_id) if item.event_id is not None else None,
            "source_id": item.source_id,
            "source_uri": item.source_uri,
        }
        for item in values
    ]


def _citations_from_document(value: object) -> tuple[MemoryCitation, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError("memory citations must be an array")
    return tuple(
        MemoryCitation(
            source_id=str(row["source_id"]),
            source_uri=str(row["source_uri"]),
            content_digest=str(row["content_digest"]),
            event_id=(
                UUID(str(row["event_id"])) if row.get("event_id") is not None else None
            ),
            artifact_id=(
                UUID(str(row["artifact_id"]))
                if row.get("artifact_id") is not None
                else None
            ),
        )
        for item in value
        for row in (_mapping(item, "memory citation"),)
    )


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    return tuple(str(item) for item in value)


__all__ = ["memory_from_document", "memory_to_document"]
