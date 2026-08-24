"""Safe content-addressed workspace and artifact tests."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from aegis_agent_platform.sandbox.workspace import (
    AllowlistScanner,
    ArchiveLimits,
    InMemoryArtifactStore,
    ScanDecision,
    ScanOutcome,
    extract_archive_atomically,
)
from sandbox_helpers import CONTEXT, TENANT_ID

LIMITS = ArchiveLimits(
    max_files=10,
    max_compressed_bytes=128 * 1024,
    max_expanded_bytes=128 * 1024,
    max_file_bytes=64 * 1024,
)


def _zip(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, content in entries:
            archive.writestr(path, content)
    return output.getvalue()


def _tar(
    entries: tuple[tuple[str, bytes], ...],
    *,
    special: tarfile.TarInfo | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path, content in entries:
            info = tarfile.TarInfo(path)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        if special is not None:
            archive.addfile(special)
    return output.getvalue()


def test_zip_and_tar_extract_to_deterministic_atomic_manifests(
    tmp_path: Path,
) -> None:
    entries = (
        ("source/b.py", b"print('b')\n"),
        ("source/a.py", b"print('a')\n"),
    )
    zip_destination = tmp_path / "zip"
    tar_destination = tmp_path / "tar"
    zip_manifest = extract_archive_atomically(
        _zip(entries),
        zip_destination,
        LIMITS,
        archive_format="zip",
    )
    tar_manifest = extract_archive_atomically(
        _tar(entries),
        tar_destination,
        LIMITS,
        archive_format="tar",
    )
    assert tuple(entry.path for entry in zip_manifest.entries) == (
        "source/a.py",
        "source/b.py",
    )
    assert zip_manifest.manifest_digest == tar_manifest.manifest_digest
    assert (zip_destination / "source/a.py").read_bytes() == b"print('a')\n"
    assert stat.S_IMODE((zip_destination / "source/a.py").stat().st_mode) == 0o600

    with pytest.raises(FileExistsError):
        extract_archive_atomically(
            _zip(entries),
            zip_destination,
            LIMITS,
            archive_format="zip",
        )


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "source\\windows",
        "source/../escape",
        "C:/device",
    ],
)
def test_archive_paths_cannot_escape_staging(tmp_path: Path, path: str) -> None:
    destination = tmp_path / "unsafe"
    with pytest.raises(ValueError, match="path is unsafe"):
        extract_archive_atomically(
            _zip(((path, b"bad"),)),
            destination,
            LIMITS,
            archive_format="zip",
        )
    assert not destination.exists()


def test_archive_rejects_links_special_files_conflicts_and_bombs(
    tmp_path: Path,
) -> None:
    symlink_zip = io.BytesIO()
    with zipfile.ZipFile(symlink_zip, "w") as archive:
        member = zipfile.ZipInfo("source/link")
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "../outside")
    with pytest.raises(ValueError, match="symlinks"):
        extract_archive_atomically(
            symlink_zip.getvalue(),
            tmp_path / "zip-link",
            LIMITS,
            archive_format="zip",
        )

    symlink_tar = tarfile.TarInfo("source/link")
    symlink_tar.type = tarfile.SYMTYPE
    symlink_tar.linkname = "../outside"
    with pytest.raises(ValueError, match="special files"):
        extract_archive_atomically(
            _tar((), special=symlink_tar),
            tmp_path / "tar-link",
            LIMITS,
            archive_format="tar",
        )

    with pytest.raises(ValueError, match="conflicting paths"):
        extract_archive_atomically(
            _zip((("source/item", b"file"), ("source/item/child", b"child"))),
            tmp_path / "conflict",
            LIMITS,
            archive_format="zip",
        )

    compressed = io.BytesIO()
    with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", b"0" * 64_000)
    with pytest.raises(ValueError, match="expansion ratio"):
        extract_archive_atomically(
            compressed.getvalue(),
            tmp_path / "bomb",
            ArchiveLimits(2, 128_000, 128_000, 128_000, 2),
            archive_format="zip",
        )

    with pytest.raises(ValueError, match="not supported"):
        extract_archive_atomically(
            b"not-an-archive",
            tmp_path / "unsupported",
            LIMITS,
            archive_format="rar",
        )


@pytest.mark.parametrize(
    ("entries", "limits", "message"),
    [
        ((), ArchiveLimits(2, 128_000, 128_000, 128_000), "file count"),
        (
            (("a", b"a"), ("b", b"b")),
            ArchiveLimits(1, 128_000, 128_000, 128_000),
            "file count",
        ),
        (
            (("large", b"12345"),),
            ArchiveLimits(2, 128_000, 128_000, 4),
            "file byte bound",
        ),
        (
            (("a", b"1234"), ("b", b"5678")),
            ArchiveLimits(2, 128_000, 6, 8),
            "expanded byte bound",
        ),
    ],
)
def test_archive_enforces_streaming_bounds_before_staging(
    tmp_path: Path,
    entries: tuple[tuple[str, bytes], ...],
    limits: ArchiveLimits,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        extract_archive_atomically(
            _zip(entries),
            tmp_path / "bounded",
            limits,
            archive_format="zip",
        )


@pytest.mark.parametrize("archive_format", ["zip", "tar"])
def test_malformed_supported_archives_are_rejected(
    tmp_path: Path,
    archive_format: str,
) -> None:
    with pytest.raises(ValueError, match="archive is malformed"):
        extract_archive_atomically(
            b"not-an-archive",
            tmp_path / archive_format,
            LIMITS,
            archive_format=archive_format,
        )


@pytest.mark.parametrize("archive_format", ["zip", "tar"])
def test_directory_only_archives_are_rejected(
    tmp_path: Path,
    archive_format: str,
) -> None:
    if archive_format == "zip":
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("empty/", b"")
        content = output.getvalue()
    else:
        directory = tarfile.TarInfo("empty")
        directory.type = tarfile.DIRTYPE
        content = _tar((), special=directory)
    with pytest.raises(ValueError, match="file count"):
        extract_archive_atomically(
            content,
            tmp_path / archive_format,
            LIMITS,
            archive_format=archive_format,
        )


class _RedactingScanner:
    def scan(
        self,
        context: object,
        *,
        media_type: str,
        content: bytes,
    ) -> ScanDecision:
        del context, media_type, content
        return ScanDecision(ScanOutcome.REDACT, "secret_detected")


class _Redactor:
    def redact(self, *, media_type: str, content: bytes) -> bytes:
        del media_type
        return content.replace(b"secret", b"[REDACTED]")


def test_artifact_store_binds_tenants_redacts_and_quarantines() -> None:
    sandbox_id = uuid4()
    artifact_id = uuid4()
    redacting = InMemoryArtifactStore(
        _RedactingScanner(),
        redactor=_Redactor(),
    )
    record = redacting.put(
        CONTEXT,
        sandbox_id=sandbox_id,
        artifact_id=artifact_id,
        media_type="application/json",
        content=b'{"value":"secret"}',
        maximum_bytes=1_024,
        retention_seconds=300,
    )
    assert record.scan_outcome is ScanOutcome.REDACT
    assert record.reference.startswith(f"aegis-artifact://{TENANT_ID}/")
    assert redacting.get(CONTEXT, artifact_id) == (
        record,
        b'{"value":"[REDACTED]"}',
    )

    quarantining = InMemoryArtifactStore(
        AllowlistScanner(
            frozenset({"application/json"}),
            denied_markers=(b"malware",),
        )
    )
    quarantine = quarantining.put(
        CONTEXT,
        sandbox_id=sandbox_id,
        artifact_id=uuid4(),
        media_type="application/json",
        content=b"malware",
        maximum_bytes=1_024,
        retention_seconds=300,
    )
    assert quarantine.scan_outcome is ScanOutcome.QUARANTINE
    assert quarantine.reference.startswith(f"aegis-quarantine://{TENANT_ID}/")

    with pytest.raises(ValueError, match="output bound"):
        quarantining.put(
            CONTEXT,
            sandbox_id=sandbox_id,
            artifact_id=uuid4(),
            media_type="application/json",
            content=b"too large",
            maximum_bytes=1,
            retention_seconds=300,
        )


class _ExpandingRedactor:
    def redact(self, *, media_type: str, content: bytes) -> bytes:
        del media_type
        return content * 2


def test_scanner_store_and_archive_limits_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="bounded"):
        ScanDecision(ScanOutcome.ALLOW, "")
    scanner = AllowlistScanner(frozenset({"application/json"}))
    assert (
        scanner.scan(CONTEXT, media_type="text/plain", content=b"safe").outcome
        is ScanOutcome.QUARANTINE
    )
    assert (
        scanner.scan(CONTEXT, media_type="application/json", content=b"safe").outcome
        is ScanOutcome.ALLOW
    )
    sandbox_id = uuid4()
    with pytest.raises(ValueError, match="not configured"):
        InMemoryArtifactStore(_RedactingScanner()).put(
            CONTEXT,
            sandbox_id=sandbox_id,
            artifact_id=uuid4(),
            media_type="application/json",
            content=b"secret",
            maximum_bytes=100,
            retention_seconds=300,
        )
    with pytest.raises(ValueError, match="redacted artifact"):
        InMemoryArtifactStore(
            _RedactingScanner(),
            redactor=_ExpandingRedactor(),
        ).put(
            CONTEXT,
            sandbox_id=sandbox_id,
            artifact_id=uuid4(),
            media_type="application/json",
            content=b"secret",
            maximum_bytes=6,
            retention_seconds=300,
        )
    assert InMemoryArtifactStore(scanner).get(CONTEXT, uuid4()) is None
    with pytest.raises(ValueError, match="positive"):
        ArchiveLimits(0, 1, 1, 1)
    with pytest.raises(ValueError, match="compressed"):
        extract_archive_atomically(
            _zip((("a", b"a"),)),
            tmp_path / "compressed",
            ArchiveLimits(1, 1, 100, 100),
            archive_format="zip",
        )

    empty_zip = io.BytesIO()
    with zipfile.ZipFile(empty_zip, "w"):
        pass
    with pytest.raises(ValueError, match="file count"):
        extract_archive_atomically(
            empty_zip.getvalue(),
            tmp_path / "empty",
            LIMITS,
            archive_format="zip",
        )
    with pytest.raises(ValueError, match="file byte"):
        extract_archive_atomically(
            _zip((("large", b"ab"),)),
            tmp_path / "zip-member",
            ArchiveLimits(2, 10_000, 10_000, 1),
            archive_format="zip",
        )
    with pytest.raises(ValueError, match="malformed"):
        extract_archive_atomically(
            b"not-a-zip",
            tmp_path / "bad-zip",
            LIMITS,
            archive_format="zip",
        )
    with pytest.raises(ValueError, match="file count"):
        extract_archive_atomically(
            _zip((("one", b"1"), ("two", b"2"))),
            tmp_path / "file-count",
            ArchiveLimits(1, 10_000, 10_000, 10_000),
            archive_format="zip",
        )
    with pytest.raises(ValueError, match="expanded byte"):
        extract_archive_atomically(
            _zip((("large", b"ab"),)),
            tmp_path / "expanded",
            ArchiveLimits(2, 10_000, 1, 10_000),
            archive_format="zip",
        )

    directory = tarfile.TarInfo("directory")
    directory.type = tarfile.DIRTYPE
    with pytest.raises(ValueError, match="file count"):
        extract_archive_atomically(
            _tar((), special=directory),
            tmp_path / "tar-directory",
            LIMITS,
            archive_format="tar",
        )
    with pytest.raises(ValueError, match="file byte"):
        extract_archive_atomically(
            _tar((("large", b"ab"),)),
            tmp_path / "tar-member",
            ArchiveLimits(2, 20_000, 10_000, 1),
            archive_format="tar",
        )
    with pytest.raises(ValueError, match="malformed"):
        extract_archive_atomically(
            b"not-a-tar",
            tmp_path / "bad-tar",
            LIMITS,
            archive_format="tar",
        )
    with pytest.raises(ValueError, match="duplicate"):
        extract_archive_atomically(
            _tar((("same", b"1"), ("same", b"2"))),
            tmp_path / "duplicate",
            LIMITS,
            archive_format="tar",
        )
