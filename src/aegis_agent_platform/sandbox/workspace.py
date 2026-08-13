"""Safe content-addressed archive and artifact handling for untrusted data."""

from __future__ import annotations

import io
import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Protocol
from uuid import UUID

from aegis_agent_platform.domain.sandbox import MAX_ARCHIVE_EXPANSION_RATIO
from aegis_agent_platform.tenancy import TenantContext


class ScanOutcome(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    QUARANTINE = "quarantine"


@dataclass(frozen=True, slots=True)
class ScanDecision:
    outcome: ScanOutcome
    reason: str

    def __post_init__(self) -> None:
        if not self.reason or len(self.reason) > 128:
            raise ValueError("artifact scan reason must be bounded")


class ArtifactScanner(Protocol):
    def scan(
        self,
        context: TenantContext,
        *,
        media_type: str,
        content: bytes,
    ) -> ScanDecision: ...


class ArtifactRedactor(Protocol):
    def redact(self, *, media_type: str, content: bytes) -> bytes: ...


class AllowlistScanner:
    """Deterministic scanner hook for tests; production scanners are adapters."""

    def __init__(
        self,
        allowed_media_types: frozenset[str],
        *,
        denied_markers: tuple[bytes, ...] = (),
    ) -> None:
        self._allowed = allowed_media_types
        self._denied_markers = denied_markers

    def scan(
        self,
        context: TenantContext,
        *,
        media_type: str,
        content: bytes,
    ) -> ScanDecision:
        del context
        if media_type not in self._allowed:
            return ScanDecision(ScanOutcome.QUARANTINE, "media_type_denied")
        if any(marker in content for marker in self._denied_markers):
            return ScanDecision(ScanOutcome.QUARANTINE, "scanner_marker_detected")
        return ScanDecision(ScanOutcome.ALLOW, "scanner_allow")


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    tenant_id: str
    sandbox_id: UUID
    artifact_id: UUID
    digest: str
    size_bytes: int
    media_type: str
    reference: str
    scan_outcome: ScanOutcome
    retention_seconds: int


class InMemoryArtifactStore:
    """Tenant-bound deterministic content-addressed store for tests and demos."""

    def __init__(
        self,
        scanner: ArtifactScanner,
        *,
        redactor: ArtifactRedactor | None = None,
    ) -> None:
        self._scanner = scanner
        self._redactor = redactor
        self._content: dict[tuple[str, str], bytes] = {}
        self._records: dict[tuple[str, UUID], StoredArtifact] = {}

    def put(
        self,
        context: TenantContext,
        *,
        sandbox_id: UUID,
        artifact_id: UUID,
        media_type: str,
        content: bytes,
        maximum_bytes: int,
        retention_seconds: int,
    ) -> StoredArtifact:
        if len(content) > maximum_bytes:
            raise ValueError("artifact exceeds the sandbox output bound")
        decision = self._scanner.scan(
            context,
            media_type=media_type,
            content=content,
        )
        stored = content
        if decision.outcome is ScanOutcome.REDACT:
            if self._redactor is None:
                raise ValueError("artifact redaction was required but not configured")
            stored = self._redactor.redact(media_type=media_type, content=content)
            if len(stored) > maximum_bytes:
                raise ValueError("redacted artifact exceeds the output bound")
        digest = sha256(stored).hexdigest()
        tenant_id = str(context.tenant_id)
        reference = (
            f"aegis-artifact://{tenant_id}/{sandbox_id}/{digest}"
            if decision.outcome is not ScanOutcome.QUARANTINE
            else f"aegis-quarantine://{tenant_id}/{sandbox_id}/{digest}"
        )
        record = StoredArtifact(
            tenant_id=tenant_id,
            sandbox_id=sandbox_id,
            artifact_id=artifact_id,
            digest=digest,
            size_bytes=len(stored),
            media_type=media_type,
            reference=reference,
            scan_outcome=decision.outcome,
            retention_seconds=retention_seconds,
        )
        self._content[(tenant_id, digest)] = stored
        self._records[(tenant_id, artifact_id)] = record
        return record

    def get(
        self,
        context: TenantContext,
        artifact_id: UUID,
    ) -> tuple[StoredArtifact, bytes] | None:
        record = self._records.get((str(context.tenant_id), artifact_id))
        if record is None:
            return None
        return record, self._content[(record.tenant_id, record.digest)]


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_files: int
    max_compressed_bytes: int
    max_expanded_bytes: int
    max_file_bytes: int
    max_expansion_ratio: int = MAX_ARCHIVE_EXPANSION_RATIO

    def __post_init__(self) -> None:
        if (
            min(
                self.max_files,
                self.max_compressed_bytes,
                self.max_expanded_bytes,
                self.max_file_bytes,
                self.max_expansion_ratio,
            )
            < 1
        ):
            raise ValueError("archive limits must be positive")


@dataclass(frozen=True, slots=True)
class ArchiveManifestEntry:
    path: str
    size_bytes: int
    digest: str


@dataclass(frozen=True, slots=True)
class ArchiveManifest:
    archive_digest: str
    entries: tuple[ArchiveManifestEntry, ...]
    expanded_bytes: int
    manifest_digest: str


def extract_archive_atomically(
    archive: bytes,
    destination: Path,
    limits: ArchiveLimits,
    *,
    archive_format: str,
) -> ArchiveManifest:
    """Validate every member before atomically publishing an extracted snapshot."""
    if len(archive) > limits.max_compressed_bytes:
        raise ValueError("archive exceeds its compressed byte bound")
    if destination.exists():
        raise FileExistsError("archive destination already exists")
    entries = (
        _zip_entries(archive, limits)
        if archive_format == "zip"
        else _tar_entries(archive, limits)
        if archive_format in {"tar", "tar.gz"}
        else _unsupported_archive()
    )
    _validate_entry_set(entries, limits, compressed_bytes=len(archive))
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
    )
    try:
        for path, content in entries:
            target = staging.joinpath(*PurePosixPath(path).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(content)
            target.chmod(0o600)
        staging.replace(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    manifest_entries = tuple(
        ArchiveManifestEntry(path, len(content), sha256(content).hexdigest())
        for path, content in sorted(entries, key=lambda item: item[0])
    )
    encoded = "\n".join(
        f"{entry.path}\0{entry.size_bytes}\0{entry.digest}"
        for entry in manifest_entries
    ).encode()
    return ArchiveManifest(
        archive_digest=sha256(archive).hexdigest(),
        entries=manifest_entries,
        expanded_bytes=sum(entry.size_bytes for entry in manifest_entries),
        manifest_digest=sha256(encoded).hexdigest(),
    )


def _zip_entries(
    archive: bytes,
    limits: ArchiveLimits,
) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as container:
            for member in container.infolist():
                if member.is_dir():
                    continue
                path = _archive_path(member.filename)
                if member.flag_bits & 0x1:
                    raise ValueError("encrypted archive members are denied")
                mode = member.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    raise ValueError("archive symlinks are denied")
                _validate_next_entry(
                    entries,
                    path,
                    member.file_size,
                    limits,
                    compressed_bytes=len(archive),
                )
                with container.open(member, "r") as handle:
                    content = handle.read(limits.max_file_bytes + 1)
                if len(content) != member.file_size:
                    raise ValueError("archive member size is inconsistent")
                entries.append((path, content))
    except zipfile.BadZipFile as error:
        raise ValueError("zip archive is malformed") from error
    return entries


def _tar_entries(
    archive: bytes,
    limits: ArchiveLimits,
) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as container:
            for member in container:
                if member.isdir():
                    continue
                path = _archive_path(member.name)
                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                    or not member.isfile()
                ):
                    raise ValueError("archive links and special files are denied")
                _validate_next_entry(
                    entries,
                    path,
                    member.size,
                    limits,
                    compressed_bytes=len(archive),
                )
                extracted = container.extractfile(member)
                if extracted is None:
                    raise ValueError("archive member content is missing")
                content = extracted.read(limits.max_file_bytes + 1)
                if len(content) != member.size:
                    raise ValueError("archive member size is inconsistent")
                entries.append((path, content))
    except tarfile.TarError as error:
        raise ValueError("tar archive is malformed") from error
    return entries


def _archive_path(value: str) -> str:
    if "\\" in value or value.startswith(("/", "~")) or "\x00" in value:
        raise ValueError("archive member path is unsafe")
    path = PurePosixPath(value)
    if (
        value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
    ):
        raise ValueError("archive member path is unsafe")
    return value


def _validate_entry_set(
    entries: Sequence[tuple[str, bytes]],
    limits: ArchiveLimits,
    *,
    compressed_bytes: int,
) -> None:
    del limits, compressed_bytes
    if not entries:
        raise ValueError("archive file count is outside the hard bound")


def _validate_next_entry(
    entries: Sequence[tuple[str, bytes]],
    path: str,
    declared_size: int,
    limits: ArchiveLimits,
    *,
    compressed_bytes: int,
) -> None:
    if len(entries) >= limits.max_files:
        raise ValueError("archive file count is outside the hard bound")
    if declared_size > limits.max_file_bytes:
        raise ValueError("archive member exceeds the file byte bound")
    expanded = sum(len(content) for _path, content in entries) + declared_size
    if expanded > limits.max_expanded_bytes:
        raise ValueError("archive exceeds the expanded byte bound")
    if expanded > max(1, compressed_bytes) * limits.max_expansion_ratio:
        raise ValueError("archive expansion ratio exceeds the hard bound")
    for existing, _content in entries:
        if (
            path == existing
            or path.startswith(f"{existing}/")
            or existing.startswith(f"{path}/")
        ):
            raise ValueError("archive contains duplicate or conflicting paths")


def _unsupported_archive() -> list[tuple[str, bytes]]:
    raise ValueError("archive format is not supported")


__all__ = [
    "AllowlistScanner",
    "ArchiveLimits",
    "ArchiveManifest",
    "ArchiveManifestEntry",
    "ArtifactRedactor",
    "ArtifactScanner",
    "InMemoryArtifactStore",
    "ScanDecision",
    "ScanOutcome",
    "StoredArtifact",
    "extract_archive_atomically",
]
