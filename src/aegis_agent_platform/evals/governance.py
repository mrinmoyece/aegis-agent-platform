"""Synthetic dataset governance, tamper detection, and secret/PII scanning."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import cast

from aegis_agent_platform.evals.contracts import (
    DatasetManifest,
    FixtureClassification,
    FixtureDisposition,
    FixtureProvenance,
    canonical_data,
)

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|client_secret|password|token)\s*[\"']?\s*[=:]\s*"
        r"[\"']?[A-Za-z0-9._~+/=-]{12,}"
    ),
)
_EMAIL = re.compile(
    r"\b[A-Z0-9._%+-]+@(?!example\.invalid\b)[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
_PHONE = re.compile(r"(?<!\d)(?:\+?[1-9]\d{7,14})(?!\d)")


@dataclass(frozen=True, slots=True)
class GovernanceFinding:
    """One bounded machine-readable fixture-governance failure."""

    fixture_id: str
    reason_code: str
    detail: str

    def __post_init__(self) -> None:
        if not self.fixture_id or not self.reason_code or not self.detail:
            raise ValueError("governance findings require bounded identifiers")
        if len(self.detail) > 256:
            raise ValueError("governance finding detail exceeds supported bounds")


@dataclass(frozen=True, slots=True)
class GovernanceReport:
    """Deterministic integrity result for one dataset manifest."""

    dataset_id: str
    dataset_digest: str
    checked_fixtures: int
    findings: tuple[GovernanceFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


def verify_dataset(
    repository_root: Path,
    manifest: DatasetManifest,
    *,
    required_ci: bool = True,
) -> GovernanceReport:
    """Verify paths, hashes, JSON shape, provenance, classification, and content."""
    root = repository_root.resolve()
    findings: list[GovernanceFinding] = []
    for fixture in manifest.fixtures:
        candidate = root / fixture.path
        path = candidate.resolve()
        try:
            path.relative_to(root)
        except ValueError:
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_path_escape",
                    "fixture resolves outside repository root",
                )
            )
            continue
        if candidate.is_symlink():
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_symlink",
                    "fixture path must not be a symlink",
                )
            )
            continue
        if not path.is_file():
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_missing",
                    "fixture file is missing",
                )
            )
            continue
        if path.stat().st_size > 1_000_000:
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_oversized",
                    "fixture exceeds the one megabyte governance cap",
                )
            )
            continue
        payload = path.read_bytes()
        actual_digest = sha256(payload).hexdigest()
        if not hmac_digest_equal(actual_digest, fixture.content_digest):
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_digest_mismatch",
                    "fixture content does not match its reviewed digest",
                )
            )
        try:
            decoded = payload.decode("utf-8")
            document = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_invalid_json",
                    "fixtures must be UTF-8 JSON snapshots",
                )
            )
            continue
        if not isinstance(document, dict):
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_invalid_root",
                    "fixture root must be an object",
                )
            )
        if any(pattern.search(decoded) for pattern in _SECRET_PATTERNS):
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_secret_detected",
                    "fixture matches a disallowed credential pattern",
                )
            )
        if _EMAIL.search(decoded) or _PHONE.search(decoded):
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_pii_detected",
                    "fixture matches a disallowed PII pattern",
                )
            )
        if required_ci and (
            not fixture.synthetic
            or not fixture.redacted
            or fixture.classification
            not in {FixtureClassification.PUBLIC, FixtureClassification.INTERNAL}
        ):
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "fixture_not_ci_eligible",
                    "required CI accepts only synthetic redacted public/internal data",
                )
            )
        if fixture.disposition is FixtureDisposition.DELETED:
            findings.append(
                GovernanceFinding(
                    fixture.fixture_id,
                    "deleted_fixture_present",
                    "deleted fixture metadata must not reference checked-in content",
                )
            )
    return GovernanceReport(
        manifest.dataset_id,
        manifest.digest,
        len(manifest.fixtures),
        tuple(sorted(findings, key=lambda item: (item.fixture_id, item.reason_code))),
    )


def write_dataset_manifest(path: Path, manifest: DatasetManifest) -> None:
    """Explicit reviewed update path for the machine-readable dataset manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(canonical_data(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_fixture_documents(
    repository_root: Path,
    manifest: DatasetManifest,
) -> Mapping[str, Mapping[str, object]]:
    """Load exact verified JSON snapshots for bounded case execution."""
    report = verify_dataset(repository_root, manifest)
    if not report.passed:
        reasons = ",".join(item.reason_code for item in report.findings)
        raise ValueError(f"dataset fixtures failed verification: {reasons}")
    root = repository_root.resolve()
    documents: dict[str, Mapping[str, object]] = {}
    for fixture in manifest.fixtures:
        value = json.loads((root / fixture.path).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("verified fixture root must be an object")
        documents[fixture.fixture_id] = MappingProxyType(value)
    return MappingProxyType(dict(sorted(documents.items())))


def load_dataset_manifest(path: Path) -> DatasetManifest:
    """Strictly load the current additive dataset schema."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("dataset manifest root must be an object")
    version = raw.get("schema_version")
    if version != 1:
        raise ValueError("unsupported dataset manifest schema version")
    fixture_values = raw.get("fixtures")
    case_values = raw.get("case_ids")
    if not isinstance(fixture_values, list) or not isinstance(case_values, list):
        raise ValueError("dataset manifest fixtures and case_ids must be arrays")
    fixtures = tuple(_fixture_from_mapping(item) for item in fixture_values)
    return DatasetManifest(
        _string(raw, "dataset_id"),
        1,
        _string(raw, "version"),
        _string(raw, "description"),
        _datetime(raw, "created_at"),
        fixtures,
        tuple(_strings(case_values, "case_ids")),
        (
            _string(raw, "migration_from")
            if raw.get("migration_from") is not None
            else None
        ),
    )


def migrate_dataset_manifest(value: object) -> DatasetManifest:
    """Fail closed until an explicit additive migration is implemented."""
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("no migration exists for this dataset schema")
    fixture_values = value.get("fixtures")
    case_values = value.get("case_ids")
    if not isinstance(fixture_values, list) or not isinstance(case_values, list):
        raise ValueError("dataset manifest fixtures and case_ids must be arrays")
    return DatasetManifest(
        _string(value, "dataset_id"),
        1,
        _string(value, "version"),
        _string(value, "description"),
        _datetime(value, "created_at"),
        tuple(_fixture_from_mapping(item) for item in fixture_values),
        tuple(_strings(case_values, "case_ids")),
        (
            _string(value, "migration_from")
            if value.get("migration_from") is not None
            else None
        ),
    )


def hmac_digest_equal(left: str, right: str) -> bool:
    """Compare public content digests without early-exit differences."""
    import hmac

    return hmac.compare_digest(left, right)


def _fixture_from_mapping(value: object) -> FixtureProvenance:
    if not isinstance(value, dict):
        raise ValueError("fixture manifest entry must be an object")
    return FixtureProvenance(
        _string(value, "fixture_id"),
        _string(value, "path"),
        _string(value, "content_digest"),
        _string(value, "source"),
        _string(value, "license"),
        _string(value, "consent"),
        FixtureClassification(_string(value, "classification")),
        _integer(value, "retention_days"),
        _boolean(value, "synthetic"),
        _boolean(value, "redacted"),
        FixtureDisposition(_string(value, "disposition")),
        (
            _string(value, "deletion_reference")
            if value.get("deletion_reference") is not None
            else None
        ),
    )


def _string(value: dict[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"{key} must be a string")
    return result


def _datetime(value: dict[str, object], key: str) -> datetime:
    return datetime.fromisoformat(_string(value, key).replace("Z", "+00:00"))


def _integer(value: dict[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError(f"{key} must be an integer")
    return result


def _boolean(value: dict[str, object], key: str) -> bool:
    result = value.get(key)
    if not isinstance(result, bool):
        raise ValueError(f"{key} must be a boolean")
    return result


def _strings(value: list[object], key: str) -> list[str]:
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key} must contain strings")
    return cast(list[str], value)


__all__ = [
    "GovernanceFinding",
    "GovernanceReport",
    "load_dataset_manifest",
    "load_fixture_documents",
    "migrate_dataset_manifest",
    "verify_dataset",
    "write_dataset_manifest",
]
