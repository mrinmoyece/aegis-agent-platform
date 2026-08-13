"""Strict authenticated HTTP routing for tenant-scoped Layer 10 operations."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs
from uuid import UUID

from aegis_agent_platform.domain import (
    ContextBudget,
    DataClassification,
    EpisodicMemoryReference,
    MemoryAcl,
    MemoryCitation,
    MemoryRetention,
    MemorySourceKind,
    RetrievalQuery,
    SemanticMemory,
    SourceSnapshot,
    SourceTrustTier,
    WorkingMemoryItem,
    WorkLease,
)
from aegis_agent_platform.identity import Principal
from aegis_agent_platform.memory.operations import MemoryOperations
from aegis_agent_platform.memory.ports import MemoryProviderError
from aegis_agent_platform.memory.quota import MemoryQuotaExceededError
from aegis_agent_platform.tenancy import TenantContext

type Receive = Callable[[], Awaitable[dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class MemoryHttpResponse:
    status: int
    body: dict[str, Any]


class MemoryHttpApi:
    """Map bounded JSON contracts to the deny-by-default memory façade."""

    def __init__(
        self,
        operations: MemoryOperations,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._operations = operations
        self._clock = clock

    async def handle(
        self,
        *,
        method: str,
        tail: tuple[str, ...],
        query_string: bytes,
        receive: Receive,
        principal: Principal,
        context: TenantContext,
    ) -> MemoryHttpResponse:
        try:
            return await self._dispatch(
                method=method,
                tail=tail,
                query_string=query_string,
                receive=receive,
                principal=principal,
                context=context,
            )
        except PermissionError as error:
            return MemoryHttpResponse(
                403,
                {
                    "error": {
                        "code": "memory_permission_denied",
                        "reason": str(error),
                    }
                },
            )
        except MemoryProviderError as error:
            return MemoryHttpResponse(
                502,
                {
                    "error": {
                        "code": error.code,
                        "error_class": error.error_class.value,
                        "result_ambiguous": error.result_ambiguous,
                    }
                },
            )
        except MemoryQuotaExceededError as error:
            return MemoryHttpResponse(
                429,
                {"error": {"code": str(error), "retryable": False}},
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return MemoryHttpResponse(
                400,
                {"error": {"code": "invalid_memory_request"}},
            )

    async def _dispatch(
        self,
        *,
        method: str,
        tail: tuple[str, ...],
        query_string: bytes,
        receive: Receive,
        principal: Principal,
        context: TenantContext,
    ) -> MemoryHttpResponse:
        now = self._clock()
        if method == "GET" and not tail:
            after, limit = _page_parameters(query_string)
            rows, cursor = await self._operations.page(
                principal,
                context,
                at=now,
                after_memory_id=after,
                limit=limit,
            )
            return MemoryHttpResponse(
                200,
                {
                    "memories": tuple(dict(row) for row in rows),
                    "next_cursor": str(cursor) if cursor is not None else None,
                    "redacted": True,
                },
            )
        if method == "GET" and len(tail) == 2:
            memory_id = UUID(tail[0])
            if tail[1] == "status":
                value = await self._operations.status(
                    principal,
                    context,
                    memory_id,
                    at=now,
                )
            elif tail[1] == "provenance":
                value = await self._operations.provenance(
                    principal,
                    context,
                    memory_id,
                    at=now,
                )
            else:
                return _not_found()
            return (
                MemoryHttpResponse(200, dict(value))
                if value is not None
                else MemoryHttpResponse(
                    404,
                    {"error": {"code": "memory_not_found"}},
                )
            )
        if method != "POST":
            return MemoryHttpResponse(
                405,
                {"error": {"code": "method_not_allowed"}},
            )
        body = await _request_json(receive)
        if tail == ("ingest",):
            memory = _semantic_memory(_mapping(body["memory"]), context)
            source_text = _string(body["source_text"])
            idempotency_key = _identifier(body["idempotency_key"])
            proposal_result = await self._operations.propose(
                principal,
                context,
                memory,
                source_text,
                at=now,
                idempotency_key=idempotency_key,
            )
            return MemoryHttpResponse(
                202 if proposal_result.created else 200,
                {
                    "accepted": proposal_result.created,
                    "memory_id": str(proposal_result.memory_id),
                    "redacted": True,
                    "status": ("proposed" if proposal_result.created else "duplicate"),
                },
            )
        if len(tail) == 2 and tail[1] == "accept":
            memory_id = UUID(tail[0])
            memory = _semantic_memory(_mapping(body["memory"]), context)
            if memory.memory_id != memory_id:
                raise ValueError("memory path and contract identifiers differ")
            ingestion_result = await self._operations.accept(
                principal,
                context,
                memory,
                _work_lease(_mapping(body["lease"]), context),
                at=now,
                idempotency_key=_identifier(body["idempotency_key"]),
                acceptance_kind=_identifier(body.get("acceptance_kind", "human")),
                contradiction_ids=_uuid_values(body.get("contradiction_ids", [])),
            )
            return MemoryHttpResponse(
                200,
                {
                    "chunk_count": len(ingestion_result.chunks),
                    "memory_id": str(ingestion_result.memory_id),
                    "quarantine_reason": ingestion_result.quarantine_reason,
                    "redacted": True,
                    "status": ingestion_result.status,
                },
            )
        if len(tail) == 2 and tail[1] == "reject":
            memory_id = UUID(tail[0])
            memory = _semantic_memory(_mapping(body["memory"]), context)
            if memory.memory_id != memory_id:
                raise ValueError("memory path and contract identifiers differ")
            await self._operations.reject(
                principal,
                context,
                memory,
                at=now,
                reason_code=_identifier(body["reason_code"]),
                idempotency_key=_identifier(body["idempotency_key"]),
            )
            return MemoryHttpResponse(
                200,
                {
                    "memory_id": str(memory_id),
                    "redacted": True,
                    "status": "rejected",
                },
            )
        if tail == ("retrieve",):
            request = _retrieval_query(
                _mapping(body["query"]),
                principal,
                context,
                now,
            )
            retrieval_result = await self._operations.retrieve(
                principal,
                context,
                request,
                _work_lease(_mapping(body["lease"]), context),
                at=now,
            )
            return MemoryHttpResponse(200, _retrieval_body(retrieval_result))
        if tail == ("context",):
            request = _retrieval_query(
                _mapping(body["query"]),
                principal,
                context,
                now,
            )
            retrieval = await self._operations.retrieve(
                principal,
                context,
                request,
                _work_lease(_mapping(body["retrieval_lease"]), context),
                at=now,
            )
            selected = await self._operations.context(
                principal,
                context,
                run_id=UUID(_string(body["run_id"])),
                task_id=UUID(_string(body["task_id"])),
                lease=_work_lease(_mapping(body["context_lease"]), context),
                budget=_context_budget(_mapping(body["budget"])),
                working=tuple(
                    _working_memory(_mapping(item))
                    for item in _array(body.get("working", []))
                ),
                episodic=tuple(
                    _episodic_memory(_mapping(item), context)
                    for item in _array(body.get("episodic", []))
                ),
                semantic=retrieval,
                at=now,
            )
            return MemoryHttpResponse(
                200,
                {
                    "abstention_reason": selected.abstention_reason,
                    "compacted": selected.compacted,
                    "context_id": str(selected.context_id),
                    "insufficient_context": selected.insufficient_context,
                    "policy_version": selected.policy_version,
                    "redacted": True,
                    "snippets": tuple(
                        {
                            "citations": tuple(
                                _citation_body(citation)
                                for citation in snippet.citations
                            ),
                            "reference_id": snippet.reference_id,
                            "text": snippet.text,
                            "tier": snippet.tier.value,
                            "untrusted_data": True,
                        }
                        for snippet in selected.snippets
                    ),
                    "used_bytes": selected.used_bytes,
                    "used_tokens": selected.used_tokens,
                },
            )
        if len(tail) != 2:
            return _not_found()
        memory_id = UUID(tail[0])
        action = tail[1]
        if action == "feedback":
            quality = await self._operations.feedback(
                principal,
                context,
                memory_id,
                at=now,
                rating=_float(body["rating"]),
                relevant=_bool(body["relevant"]),
                reason_code=_identifier(body["reason_code"]),
            )
            return MemoryHttpResponse(
                200,
                {
                    "memory_id": str(memory_id),
                    "quality": quality,
                    "redacted": True,
                },
            )
        if action == "tombstone":
            await self._operations.tombstone(
                principal,
                context,
                memory_id,
                at=now,
                reason_code=_identifier(body["reason_code"]),
            )
        elif action == "retention":
            await self._operations.retention(
                principal,
                context,
                memory_id,
                _retention(_mapping(body["retention"])),
                at=now,
                policy_reference=_identifier(body["policy_reference"]),
            )
        elif action == "legal-hold":
            await self._operations.legal_hold(
                principal,
                context,
                memory_id,
                at=now,
                hold_reference=_identifier(body["hold_reference"]),
                enabled=_bool(body["enabled"]),
            )
        elif action == "delete":
            deleted = await self._operations.delete(
                principal,
                context,
                memory_id,
                at=now,
                request_reference=_identifier(body["request_reference"]),
            )
            return MemoryHttpResponse(
                200,
                {
                    "derived_chunks_deleted": deleted,
                    "immutable_ledger_retained": True,
                    "memory_id": str(memory_id),
                    "redacted": True,
                },
            )
        else:
            return _not_found()
        return MemoryHttpResponse(
            200,
            {"memory_id": str(memory_id), "redacted": True, "status": action},
        )


def _semantic_memory(
    value: Mapping[str, object],
    context: TenantContext,
) -> SemanticMemory:
    tenant_id = str(context.tenant_id)
    snapshot_value = _mapping(value["snapshot"])
    snapshot = SourceSnapshot(
        snapshot_id=UUID(_string(snapshot_value["snapshot_id"])),
        tenant_id=_trusted_tenant(snapshot_value["tenant_id"], tenant_id),
        source_kind=MemorySourceKind(_string(snapshot_value["source_kind"])),
        source_reference=_identifier(snapshot_value["source_reference"]),
        source_version=_identifier(snapshot_value["source_version"]),
        content_digest=_string(snapshot_value["content_digest"]),
        content_reference=_string(snapshot_value["content_reference"]),
        occurred_at=_datetime(snapshot_value["occurred_at"]),
        captured_at=_datetime(snapshot_value["captured_at"]),
        citations=tuple(
            _citation(_mapping(item)) for item in _array(snapshot_value["citations"])
        ),
        trust=SourceTrustTier(_string(snapshot_value["trust"])),
        schema_version=_identifier(
            snapshot_value.get("schema_version", "memory-source-v1")
        ),
    )
    acl_value = _mapping(value["acl"])
    return SemanticMemory(
        memory_id=UUID(_string(value["memory_id"])),
        tenant_id=_trusted_tenant(value["tenant_id"], tenant_id),
        snapshot=snapshot,
        incident_id=_optional_string(value.get("incident_id")),
        run_id=_optional_uuid(value.get("run_id")),
        acl=MemoryAcl(
            user_ids=_string_values(acl_value.get("user_ids", [])),
            service_ids=_string_values(acl_value.get("service_ids", [])),
            roles=_string_values(acl_value.get("roles", [])),
            purposes=_string_values(acl_value["purposes"]),
        ),
        security_label=DataClassification(_string(value["security_label"])),
        schema_version=_identifier(value["schema_version"]),
        chunker_version=_identifier(value["chunker_version"]),
        embedder_version=_identifier(value["embedder_version"]),
        embedding_model=_identifier(value["embedding_model"]),
        embedding_dimension=_int(value["embedding_dimension"]),
        confidence=_float(value["confidence"]),
        quality=_float(value["quality"]),
        retention=_retention(_mapping(value["retention"])),
        accepted_by=_identifier(value["accepted_by"]),
        policy_reference=_identifier(value["policy_reference"]),
        created_at=_datetime(value["created_at"]),
        supersedes_memory_ids=_uuid_values(value.get("supersedes_memory_ids", [])),
    )


def _retrieval_query(
    value: Mapping[str, object],
    principal: Principal,
    context: TenantContext,
    at: datetime,
) -> RetrievalQuery:
    roles = frozenset(
        binding.role.value
        for binding in principal.role_bindings
        if binding.is_active(at)
    )
    requested_purpose = _identifier(value["purpose"])
    if requested_purpose != "incident-investigation":
        raise PermissionError("memory retrieval purpose is not allowed on this route")
    if value.get("as_of") is not None:
        raise PermissionError("memory retrieval timestamps are server-controlled")
    return RetrievalQuery(
        retrieval_id=UUID(_string(value["retrieval_id"])),
        tenant_id=str(context.tenant_id),
        principal_id=principal.actor_id,
        service_id=(
            str(principal.service_identity)
            if principal.service_identity is not None
            else None
        ),
        roles=roles,
        purpose="incident-investigation",
        text=_string(value["text"]),
        top_k=_int(value.get("top_k", 8)),
        candidate_limit=_int(value.get("candidate_limit", 64)),
        max_context_bytes=_int(value.get("max_context_bytes", 32_000)),
        max_context_tokens=_int(value.get("max_context_tokens", 8_000)),
        minimum_quality=_float(value.get("minimum_quality", 0)),
        as_of=at,
        policy_version=_identifier(value.get("policy_version", "hybrid-v1")),
    )


def _work_lease(
    value: Mapping[str, object],
    context: TenantContext,
) -> WorkLease:
    return WorkLease(
        work_id=UUID(_string(value["work_id"])),
        tenant_id=_trusted_tenant(value["tenant_id"], str(context.tenant_id)),
        token=UUID(_string(value["token"])),
        generation=_int(value["generation"]),
        owner=_identifier(value["owner"]),
        attempt=_int(value["attempt"]),
        acquired_at=_datetime(value["acquired_at"]),
        heartbeat_at=_datetime(value["heartbeat_at"]),
        expires_at=_datetime(value["expires_at"]),
    )


def _context_budget(value: Mapping[str, object]) -> ContextBudget:
    return ContextBudget(
        total_tokens=_int(value["total_tokens"]),
        total_bytes=_int(value["total_bytes"]),
        reserved_system_tokens=_int(value["reserved_system_tokens"]),
        reserved_safety_tokens=_int(value["reserved_safety_tokens"]),
        working_tokens=_int(value["working_tokens"]),
        episodic_tokens=_int(value["episodic_tokens"]),
        semantic_tokens=_int(value["semantic_tokens"]),
    )


def _working_memory(value: Mapping[str, object]) -> WorkingMemoryItem:
    return WorkingMemoryItem(
        reference_id=_identifier(value["reference_id"]),
        text=_string(value["text"]),
        citations=tuple(
            _citation(_mapping(item)) for item in _array(value["citations"])
        ),
        priority=_int(value["priority"]),
        occurred_at=_datetime(value["occurred_at"]),
        kind=_identifier(value["kind"]),
    )


def _episodic_memory(
    value: Mapping[str, object],
    context: TenantContext,
) -> EpisodicMemoryReference:
    return EpisodicMemoryReference(
        reference_id=_identifier(value["reference_id"]),
        tenant_id=_trusted_tenant(value["tenant_id"], str(context.tenant_id)),
        incident_id=_identifier(value["incident_id"]),
        run_id=UUID(_string(value["run_id"])),
        event_ids=_uuid_values(value.get("event_ids", [])),
        artifact_ids=_uuid_values(value.get("artifact_ids", [])),
        cited_summary=_string(value["cited_summary"]),
        citations=tuple(
            _citation(_mapping(item)) for item in _array(value["citations"])
        ),
        occurred_at=_datetime(value["occurred_at"]),
    )


def _retention(value: Mapping[str, object]) -> MemoryRetention:
    return MemoryRetention(
        retention_class=_identifier(value["retention_class"]),
        expires_at=_optional_datetime(value.get("expires_at")),
        legal_hold=_bool(value.get("legal_hold", False)),
        legal_hold_reference=_optional_string(value.get("legal_hold_reference")),
        deletion_scope=_identifier(
            value.get("deletion_scope", "derived_and_referenced_blob")
        ),
    )


def _citation(value: Mapping[str, object]) -> MemoryCitation:
    return MemoryCitation(
        source_id=_identifier(value["source_id"]),
        source_uri=_string(value["source_uri"]),
        content_digest=_string(value["content_digest"]),
        event_id=_optional_uuid(value.get("event_id")),
        artifact_id=_optional_uuid(value.get("artifact_id")),
    )


def _retrieval_body(result: object) -> dict[str, Any]:
    from aegis_agent_platform.domain import RetrievalResult

    if not isinstance(result, RetrievalResult):
        raise TypeError("retrieval result has an invalid type")
    return {
        "hits": tuple(
            {
                "chunk_id": str(hit.chunk.chunk_id),
                "citations": tuple(
                    _citation_body(citation) for citation in hit.chunk.citations
                ),
                "contradiction_ids": tuple(str(item) for item in hit.contradiction_ids),
                "final_score": hit.final_score,
                "freshness": hit.freshness.value,
                "memory_id": str(hit.chunk.memory_id),
                "text": hit.chunk.text,
                "untrusted_data": True,
            }
            for hit in result.hits
        ),
        "insufficient_context": result.insufficient_context,
        "next_cursor": result.next_cursor,
        "policy_version": result.policy_version,
        "query_digest": result.query_digest,
        "redacted": True,
        "retrieval_id": str(result.retrieval_id),
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
    return _mapping(value)


def _page_parameters(value: bytes) -> tuple[UUID | None, int]:
    try:
        parameters = parse_qs(value.decode("ascii"), keep_blank_values=True)
    except UnicodeDecodeError as error:
        raise ValueError("memory query parameters must be ASCII") from error
    after_values = parameters.get("after_memory_id", [])
    limit_values = parameters.get("limit", [])
    if len(after_values) > 1 or len(limit_values) > 1:
        raise ValueError("memory query parameters must occur once")
    after = UUID(after_values[0]) if after_values else None
    limit = int(limit_values[0]) if limit_values else 100
    return after, limit


def _not_found() -> MemoryHttpResponse:
    return MemoryHttpResponse(404, {"error": {"code": "memory_route_not_found"}})


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("memory value must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError("memory object keys must be strings")
    return value


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("memory value must be an array")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("memory value must be a string")
    return value


def _identifier(value: object) -> str:
    result = _string(value)
    if not result or result != result.strip() or len(result.encode()) > 512:
        raise ValueError("memory identifier is invalid")
    return result


def _int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("memory value must be an integer")
    return value


def _float(value: object) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("memory value must be numeric")
    return float(value)


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("memory value must be a boolean")
    return value


def _datetime(value: object) -> datetime:
    result = datetime.fromisoformat(_string(value))
    if result.tzinfo is None:
        raise ValueError("memory timestamp must be timezone-aware")
    return result


def _optional_datetime(value: object) -> datetime | None:
    return None if value is None else _datetime(value)


def _optional_uuid(value: object) -> UUID | None:
    return None if value is None else UUID(_string(value))


def _optional_string(value: object) -> str | None:
    return None if value is None else _identifier(value)


def _string_values(value: object) -> tuple[str, ...]:
    return tuple(_identifier(item) for item in _array(value))


def _uuid_values(value: object) -> tuple[UUID, ...]:
    return tuple(UUID(_string(item)) for item in _array(value))


def _trusted_tenant(value: object, tenant_id: str) -> str:
    if _string(value) != tenant_id:
        raise PermissionError("memory tenant does not match authenticated route")
    return tenant_id


__all__ = ["MemoryHttpApi", "MemoryHttpResponse"]
