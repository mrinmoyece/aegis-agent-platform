"""Versioned runbook retrieval that never executes retrieved instructions."""

from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import yaml

from aegis_agent_platform.domain import (
    EvidenceKind,
    EvidenceSourceKind,
    PartialResult,
    RunbookReference,
    ServiceIdentity,
    TrustStatus,
)
from aegis_agent_platform.evidence import (
    CancellationSignal,
    ConnectorCapability,
    ConnectorError,
    ConnectorErrorClass,
    ConnectorPage,
    EvidenceQuery,
    RawEvidence,
)
from aegis_agent_platform.integrations._pagination import decode_cursor, encode_cursor
from aegis_agent_platform.integrations.config import RunbookConnectorConfig
from aegis_agent_platform.tenancy import TenantContext


@dataclass(frozen=True, slots=True)
class RunbookDocument:
    uri: str
    path: str
    version: str
    content: bytes
    committed_at: datetime

    def __post_init__(self) -> None:
        if not self.uri.startswith(("file://", "git+https://")):
            raise ValueError("runbook URI scheme is not allowed")
        if not self.path or not self.version or self.committed_at.tzinfo is None:
            raise ValueError("runbook provenance is incomplete")


class RunbookSource(Protocol):
    async def documents(
        self,
        *,
        roots: Sequence[str],
        limit: int,
        cursor: str | None,
        max_document_bytes: int,
    ) -> tuple[Sequence[RunbookDocument], str | None]: ...


class LocalRunbookSource:
    """Deterministic local fixture source confined to configured roots."""

    async def documents(
        self,
        *,
        roots: Sequence[str],
        limit: int,
        cursor: str | None,
        max_document_bytes: int,
    ) -> tuple[Sequence[RunbookDocument], str | None]:
        try:
            offset = int(cursor) if cursor is not None else 0
        except ValueError as error:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "runbook_cursor_invalid",
                retryable=False,
            ) from error
        if offset < 0:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "runbook_cursor_invalid",
                retryable=False,
            )
        if offset > 100_000:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "runbook_cursor_invalid",
                retryable=False,
            )
        return await asyncio.to_thread(
            _local_documents,
            roots,
            offset,
            limit,
            max_document_bytes,
        )


class RunbookAdapter:
    source = EvidenceSourceKind.RUNBOOK

    def __init__(
        self,
        context: TenantContext,
        config: RunbookConnectorConfig,
        source: RunbookSource,
    ) -> None:
        if context.tenant_id != config.tenant_id:
            raise PermissionError("cross_tenant_connector_config")
        if not config.enabled:
            raise ValueError("runbook connector is disabled")
        self._context = context
        self._config = config
        self._source = source

    async def capability(self) -> ConnectorCapability:
        return ConnectorCapability(
            self.source,
            (EvidenceKind.RUNBOOK,),
            "aegis-runbook-v1",
            True,
            "retrieval_only",
        )

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> ConnectorPage:
        if query.tenant_id != str(self._context.tenant_id):
            raise PermissionError("cross_tenant_query")
        if query.kinds != (EvidenceKind.RUNBOOK,):
            raise ConnectorError(
                ConnectorErrorClass.CAPABILITY,
                "runbook_kind_required",
                retryable=False,
            )
        if cancellation is not None and cancellation.cancelled:
            raise ConnectorError(
                ConnectorErrorClass.CANCELLED,
                "query_cancelled",
                retryable=False,
            )
        cursor_state = decode_cursor(
            query.cursor,
            allowed_keys=(EvidenceKind.RUNBOOK.value,),
        )
        source_cursor = (
            cursor_state.get(EvidenceKind.RUNBOOK.value)
            if cursor_state is not None
            else None
        )
        record_cap = min(query.limit, self._config.limits.max_records)
        records: list[RawEvidence] = []
        reasons: list[str] = []
        service_selector = query.selectors.get("service")
        environment = query.environment.name
        for _ in range(self._config.limits.max_pages):
            remaining = record_cap - len(records)
            if remaining <= 0:
                break
            documents, next_source_cursor = await self._source.documents(
                roots=self._config.roots,
                limit=min(remaining, 50),
                cursor=source_cursor,
                max_document_bytes=self._config.limits.max_response_bytes,
            )
            for document in documents:
                if len(document.content) > self._config.limits.max_response_bytes:
                    raise ConnectorError(
                        ConnectorErrorClass.RESPONSE_TOO_LARGE,
                        "runbook_size_cap_exceeded",
                        retryable=False,
                    )
                digest = hashlib.sha256(document.content).hexdigest()
                if digest not in self._config.trusted_digests:
                    raise ConnectorError(
                        ConnectorErrorClass.AUTHORIZATION,
                        "runbook_not_trusted",
                        retryable=False,
                    )
                metadata, body = _parse(document.content)
                services = _strings(metadata, "services")
                environments = _strings(metadata, "environments")
                if service_selector is not None and service_selector not in services:
                    continue
                if environment not in environments:
                    continue
                records.append(
                    RawEvidence(
                        f"{document.path}@{document.version}",
                        EvidenceKind.RUNBOOK,
                        document.committed_at.astimezone(UTC),
                        str(metadata["title"])[:4096],
                        {
                            "owner": str(metadata["owner"]),
                            "services": services,
                            "environments": environments,
                            "risk": str(metadata["risk"]),
                            "approval_required": bool(metadata["approval_required"]),
                            "procedures": body,
                            "execution_allowed": False,
                        },
                        document.uri,
                        service=(
                            ServiceIdentity(service_selector)
                            if service_selector is not None
                            else ServiceIdentity(services[0])
                        ),
                        references=(RunbookReference(document.path, document.version),),
                        trust=TrustStatus.VERIFIED,
                        knowledge=True,
                    )
                )
            source_cursor = next_source_cursor
            if source_cursor is None:
                break
        if source_cursor is not None:
            reasons.append(
                "record_cap" if len(records) >= record_cap else "source_page_cap"
            )
        return ConnectorPage(
            records,
            encode_cursor(
                {EvidenceKind.RUNBOOK.value: source_cursor}
                if source_cursor is not None
                else {}
            ),
            PartialResult(
                partial=bool(reasons),
                truncated="record_cap" in reasons,
                reasons=tuple(reasons),
            ),
        )


def _parse(content: bytes) -> tuple[Mapping[str, object], str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "runbook_not_utf8",
            retryable=False,
        ) from error
    if not text.startswith("---\n"):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "runbook_front_matter_missing",
            retryable=False,
        )
    try:
        front, body = text[4:].split("\n---\n", maxsplit=1)
        metadata = yaml.safe_load(front)
    except (ValueError, yaml.YAMLError) as error:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "runbook_front_matter_invalid",
            retryable=False,
        ) from error
    required = {
        "schema_version",
        "title",
        "owner",
        "services",
        "environments",
        "risk",
        "approval_required",
    }
    if (
        not isinstance(metadata, dict)
        or set(metadata) < required
        or metadata.get("schema_version") != 1
        or not isinstance(metadata.get("title"), str)
        or not isinstance(metadata.get("owner"), str)
        or not isinstance(metadata.get("approval_required"), bool)
        or metadata.get("risk") not in {"low", "medium", "high", "critical"}
    ):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "runbook_schema_invalid",
            retryable=False,
        )
    if not body.strip():
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "runbook_body_empty",
            retryable=False,
        )
    if len(body.encode()) > 64_000:
        raise ConnectorError(
            ConnectorErrorClass.RESPONSE_TOO_LARGE,
            "runbook_body_cap_exceeded",
            retryable=False,
        )
    _strings(metadata, "services")
    _strings(metadata, "environments")
    return metadata, body


def _local_documents(
    roots: Sequence[str],
    offset: int,
    limit: int,
    max_document_bytes: int,
) -> tuple[Sequence[RunbookDocument], str | None]:
    result: list[RunbookDocument] = []
    matched = 0
    scanned = 0
    for root_uri in roots:
        if not root_uri.startswith("file://"):
            raise ConnectorError(
                ConnectorErrorClass.CAPABILITY,
                "runbook_remote_source_not_configured",
                retryable=False,
            )
        root = Path(root_uri.removeprefix("file://")).resolve()
        if not root.is_dir():
            raise ConnectorError(
                ConnectorErrorClass.UNAVAILABLE,
                "runbook_root_unavailable",
                retryable=False,
            )
        for directory, directory_names, file_names in os.walk(root):
            directory_names.sort()
            file_names.sort()
            scanned += len(directory_names) + len(file_names)
            if scanned > 100_000:
                raise ConnectorError(
                    ConnectorErrorClass.RESPONSE_TOO_LARGE,
                    "runbook_traversal_cap_exceeded",
                    retryable=False,
                )
            for file_name in file_names:
                if not file_name.endswith((".md", ".yaml")):
                    continue
                if matched < offset:
                    matched += 1
                    continue
                if len(result) >= limit:
                    return tuple(result), str(offset + len(result))
                resolved = (Path(directory) / file_name).resolve()
                if root not in resolved.parents:
                    raise ConnectorError(
                        ConnectorErrorClass.AUTHORIZATION,
                        "runbook_path_escape",
                        retryable=False,
                    )
                with resolved.open("rb") as stream:
                    content = stream.read(max_document_bytes + 1)
                result.append(
                    RunbookDocument(
                        resolved.as_uri(),
                        str(resolved.relative_to(root)),
                        hashlib.sha256(content).hexdigest(),
                        content,
                        datetime.fromtimestamp(resolved.stat().st_mtime, UTC),
                    )
                )
                matched += 1
    return tuple(result), None


def _strings(metadata: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = metadata.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            f"runbook_{key}_invalid",
            retryable=False,
        )
    return tuple(value)


__all__ = [
    "LocalRunbookSource",
    "RunbookAdapter",
    "RunbookDocument",
    "RunbookSource",
]
