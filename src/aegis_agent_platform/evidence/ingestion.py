"""Bounded canonical ingestion for evidence treated as untrusted data."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from aegis_agent_platform.domain import (
    DataClassification,
    EvidenceId,
    EvidenceRecord,
    EvidenceSourceKind,
    JsonValue,
    Provenance,
    QueryWindow,
    RedactionMetadata,
    RetentionClass,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.evidence.ports import RawEvidence
from aegis_agent_platform.tenancy import TenantContext

_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+|api[_-]?key[\"'=:\s]+|token[\"'=:\s]+"
    r"|client[_-]?secret[\"'=:\s]+|access[_-]?key[\"'=:\s]+)"
    r"([A-Za-z0-9._~+/=-]{8,})"
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


class QuarantineReason(StrEnum):
    OVERSIZED = "oversized"
    INVALID = "invalid"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True, slots=True)
class QuarantinedEvidence:
    tenant_id: str
    source: EvidenceSourceKind
    source_record_id: str
    reason: QuarantineReason
    observed_at: datetime


class EvidenceStore(Protocol):
    def put(self, context: TenantContext, record: EvidenceRecord) -> bool: ...

    def quarantine(
        self,
        context: TenantContext,
        item: QuarantinedEvidence,
    ) -> None: ...

    def page(
        self,
        context: TenantContext,
        *,
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
    ) -> StoredEvidencePage: ...


class InMemoryEvidenceStore:
    """Tenant-isolated immutable content-addressed test store."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], EvidenceRecord] = {}
        self._positions: dict[tuple[str, str], int] = {}
        self._quarantine: list[QuarantinedEvidence] = []
        self._next_position = 0

    def put(self, context: TenantContext, record: EvidenceRecord) -> bool:
        if str(context.tenant_id) != record.tenant_id:
            raise PermissionError("cross_tenant_evidence")
        key = (record.tenant_id, record.content_digest)
        current = self._records.get(key)
        if current is not None:
            return False
        self._next_position += 1
        self._records[key] = record
        self._positions[key] = self._next_position
        return True

    def quarantine(
        self,
        context: TenantContext,
        item: QuarantinedEvidence,
    ) -> None:
        if str(context.tenant_id) != item.tenant_id:
            raise PermissionError("cross_tenant_quarantine")
        self._quarantine.append(item)

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
        rows = sorted(
            (
                record
                for (tenant_id, _), record in self._records.items()
                if tenant_id == str(context.tenant_id)
                and (ingested_before is None or record.ingested_at <= ingested_before)
            ),
            key=lambda item: (item.observed_at, str(item.evidence_id)),
        )
        return tuple(rows[offset : offset + limit])

    @property
    def quarantined(self) -> tuple[QuarantinedEvidence, ...]:
        return tuple(self._quarantine)

    def page(
        self,
        context: TenantContext,
        *,
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
    ) -> StoredEvidencePage:
        if not 1 <= limit <= 1000:
            raise ValueError("invalid evidence page")
        highwater, after = cursor or (self._next_position, 0)
        rows = sorted(
            (
                (self._positions[key], record)
                for key, record in self._records.items()
                if key[0] == str(context.tenant_id)
                and after < self._positions[key] <= highwater
            ),
            key=lambda item: item[0],
        )
        selected = rows[: limit + 1]
        next_cursor = (
            (highwater, selected[limit - 1][0]) if len(selected) > limit else None
        )
        return StoredEvidencePage(
            tuple(record for _, record in selected[:limit]),
            next_cursor,
        )


@dataclass(frozen=True, slots=True)
class IngestionOutcome:
    record: EvidenceRecord | None
    deduplicated: bool
    quarantined: QuarantineReason | None
    quarantine_item: QuarantinedEvidence | None = None


@dataclass(frozen=True, slots=True)
class StoredEvidencePage:
    records: tuple[EvidenceRecord, ...]
    next_cursor: tuple[int, int] | None


class EvidenceIngestor:
    """Redact, canonicalize, address, classify, and persist bounded records."""

    def __init__(
        self,
        store: EvidenceStore,
        *,
        max_record_bytes: int = 256_000,
        classification: DataClassification = DataClassification.CONFIDENTIAL,
        retention: RetentionClass = RetentionClass.INCIDENT,
    ) -> None:
        if not 1024 <= max_record_bytes <= 5_000_000:
            raise ValueError("record cap must be between 1024 and 5000000")
        self._store = store
        self._max_record_bytes = max_record_bytes
        self._classification = classification
        self._retention = retention

    @property
    def store(self) -> EvidenceStore:
        return self._store

    def ingest(
        self,
        context: TenantContext,
        raw: RawEvidence,
        *,
        source: EvidenceSourceKind,
        environment: object,
        window: QueryWindow,
        ingested_at: datetime,
        persist: bool = True,
    ) -> IngestionOutcome:
        from aegis_agent_platform.domain import EnvironmentIdentity

        if not isinstance(environment, EnvironmentIdentity):
            raise TypeError("environment must be EnvironmentIdentity")
        if raw.trust.value == "untrusted":
            return self._quarantine(
                context,
                raw,
                source,
                QuarantineReason.UNTRUSTED,
                persist=persist,
            )
        if (
            not raw.source_record_id
            or raw.source_record_id != raw.source_record_id.strip()
            or len(raw.source_record_id) > 1024
            or not raw.summary
            or len(raw.summary.encode()) > 4096
            or not raw.provenance_uri.startswith(
                ("https://", "aegis-object://", "git+https://", "file://")
            )
            or len(raw.provenance_uri) > 2048
            or (
                raw.source_confidence is not None
                and not 0 <= raw.source_confidence <= 1
            )
            or raw.knowledge != (raw.kind.value == "runbook")
        ):
            return self._quarantine(
                context,
                raw,
                source,
                QuarantineReason.INVALID,
                persist=persist,
            )
        try:
            redacted_summary, summary_rules, summary_removed = _redact(raw.summary)
            redacted_fields, field_rules, field_removed = _redact_mapping(raw.fields)
            rules = tuple(sorted(summary_rules.union(field_rules)))
            payload = {
                "source": source.value,
                "kind": raw.kind.value,
                "environment": environment.name,
                "service": raw.service.name if raw.service is not None else None,
                "resource": (
                    {
                        "kind": raw.resource.kind,
                        "name": raw.resource.name,
                        "namespace": raw.resource.namespace,
                        "cluster": raw.resource.cluster,
                    }
                    if raw.resource is not None
                    else None
                ),
                "observed_at": raw.observed_at.isoformat(),
                "summary": redacted_summary,
                "fields": thaw_json(redacted_fields),
                "severity": raw.severity.value,
                "source_confidence": raw.source_confidence,
                "references": tuple(
                    {
                        "type": type(reference).__name__,
                        "fields": {
                            item.name: getattr(reference, item.name)
                            for item in dataclass_fields(reference)
                        },
                    }
                    for reference in raw.references
                ),
                "trust": raw.trust.value,
                "knowledge": raw.knowledge,
                "provenance_uri": raw.provenance_uri,
                "source_record_id": raw.source_record_id,
            }
            canonical = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        except (TypeError, ValueError, OverflowError):
            return self._quarantine(
                context,
                raw,
                source,
                QuarantineReason.INVALID,
                persist=persist,
            )
        if len(canonical) > self._max_record_bytes:
            return self._quarantine(
                context,
                raw,
                source,
                QuarantineReason.OVERSIZED,
                persist=persist,
            )
        digest = hashlib.sha256(canonical).hexdigest()
        try:
            record = EvidenceRecord(
                evidence_id=EvidenceId(f"sha256:{digest}"),
                tenant_id=str(context.tenant_id),
                source=source,
                kind=raw.kind,
                environment=environment,
                service=raw.service,
                resource=raw.resource,
                observed_at=raw.observed_at,
                ingested_at=ingested_at,
                query_window=window,
                summary=redacted_summary,
                fields=redacted_fields,
                severity=raw.severity,
                source_confidence=raw.source_confidence,
                provenance=Provenance(
                    raw.provenance_uri,
                    raw.source_record_id,
                    ingested_at,
                    raw.trust,
                ),
                content_digest=digest,
                redaction=RedactionMetadata(
                    applied=bool(rules),
                    rule_ids=rules,
                    removed_bytes=summary_removed + field_removed,
                ),
                classification=self._classification,
                retention=self._retention,
                references=raw.references,
                knowledge=raw.knowledge,
            )
        except ValueError:
            return self._quarantine(
                context,
                raw,
                source,
                QuarantineReason.INVALID,
                persist=persist,
            )
        inserted = self._store.put(context, record) if persist else True
        return IngestionOutcome(record, not inserted, None)

    def _quarantine(
        self,
        context: TenantContext,
        raw: RawEvidence,
        source: EvidenceSourceKind,
        reason: QuarantineReason,
        *,
        persist: bool,
    ) -> IngestionOutcome:
        item = QuarantinedEvidence(
            tenant_id=str(context.tenant_id),
            source=source,
            source_record_id=_bounded_source_id(raw.source_record_id),
            reason=reason,
            observed_at=raw.observed_at,
        )
        if persist:
            self._store.quarantine(context, item)
        return IngestionOutcome(None, False, item.reason, item)


def render_citation(record: EvidenceRecord) -> str:
    """Render a deterministic source citation without copying arbitrary payloads."""
    return (
        f"[{record.source.value}:{record.kind.value}:{record.evidence_id}]"
        f"({record.provenance.uri}) observed={record.observed_at.isoformat()}"
        f" digest=sha256:{record.content_digest}"
    )


def _redact(value: str) -> tuple[str, set[str], int]:
    rules: set[str] = set()
    original = value
    if _SECRET.search(value):
        value = _SECRET.sub(r"\1[REDACTED]", value)
        rules.add("secret-pattern-v1")
    if _EMAIL.search(value):
        value = _EMAIL.sub("[REDACTED-EMAIL]", value)
        rules.add("email-v1")
    return value, rules, max(0, len(original.encode()) - len(value.encode()))


def _bounded_source_id(value: str) -> str:
    normalized = value.strip() or "missing"
    if len(normalized.encode()) <= 256:
        return normalized
    digest = hashlib.sha256(normalized.encode()).hexdigest()
    prefix = normalized.encode()[:160].decode("utf-8", errors="replace").strip()
    return f"{prefix}...sha256:{digest}"


def _redact_mapping(
    value: Mapping[str, JsonValue],
) -> tuple[dict[str, JsonValue], set[str], int]:
    rules: set[str] = set()
    removed = 0

    def visit(item: JsonValue, key: str | None = None) -> JsonValue:
        nonlocal removed
        normalized_key = re.sub(r"[-.\s]+", "_", key.lower()) if key is not None else ""
        if key is not None and any(
            token in normalized_key
            for token in (
                "secret",
                "token",
                "password",
                "authorization",
                "api_key",
                "apikey",
                "access_key",
                "client_secret",
                "private_key",
            )
        ):
            rules.add("sensitive-key-v1")
            removed += len(str(item).encode())
            return "[REDACTED]"
        if isinstance(item, str):
            updated, found, count = _redact(item)
            rules.update(found)
            removed += count
            return updated
        if isinstance(item, Mapping):
            return {name: visit(child, name) for name, child in sorted(item.items())}
        if isinstance(item, Sequence) and not isinstance(item, str):
            return tuple(visit(child) for child in item)
        return item

    return (
        {key: visit(item, key) for key, item in sorted(value.items())},
        rules,
        removed,
    )


__all__ = [
    "EvidenceIngestor",
    "EvidenceStore",
    "InMemoryEvidenceStore",
    "IngestionOutcome",
    "QuarantineReason",
    "QuarantinedEvidence",
    "StoredEvidencePage",
    "render_citation",
]
