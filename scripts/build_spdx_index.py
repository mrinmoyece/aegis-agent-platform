#!/usr/bin/env python3
"""Build an SPDX 2.3 index that binds platform manifests to platform SBOMs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_PLATFORM = re.compile(r"^linux/(amd64|arm64)=([^=]+)=(sha256:[0-9a-f]{64})$")


@dataclass(frozen=True, slots=True)
class Platform:
    architecture: str
    sbom_path: Path
    digest: str


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--platform", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _parse_platform(value: str) -> Platform:
    match = _PLATFORM.fullmatch(value)
    if match is None:
        raise ValueError("platform must be linux/{amd64|arm64}=SBOM=sha256:DIGEST")
    architecture, sbom_path, digest = match.groups()
    return Platform(architecture, Path(sbom_path), digest)


def _load_sbom(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    document: Any = json.loads(raw)
    if (
        not isinstance(document, dict)
        or document.get("spdxVersion") != "SPDX-2.3"
        or not isinstance(document.get("documentNamespace"), str)
    ):
        raise ValueError(f"{path} is not an SPDX 2.3 JSON document")
    return document["documentNamespace"], hashlib.sha256(raw).hexdigest()


def main() -> int:
    """Write one deterministic aggregate document for the OCI image index."""
    args = _arguments()
    index_match = _DIGEST.fullmatch(args.index_digest)
    if index_match is None:
        raise ValueError("index digest must be sha256")
    platforms = tuple(_parse_platform(value) for value in args.platform)
    if {platform.architecture for platform in platforms} != {"amd64", "arm64"}:
        raise ValueError(
            "exactly one linux/amd64 and one linux/arm64 SBOM are required"
        )

    external_documents: list[dict[str, object]] = []
    packages: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []
    for platform in sorted(platforms, key=lambda item: item.architecture):
        namespace, sbom_checksum = _load_sbom(platform.sbom_path)
        digest_match = _DIGEST.fullmatch(platform.digest)
        if digest_match is None:
            raise ValueError("platform digest must be sha256")
        identifier = f"linux-{platform.architecture}"
        package_id = f"SPDXRef-Package-{identifier}"
        document_id = f"DocumentRef-{identifier}"
        external_documents.append(
            {
                "externalDocumentId": document_id,
                "spdxDocument": namespace,
                "checksum": {
                    "algorithm": "SHA256",
                    "checksumValue": sbom_checksum,
                },
            }
        )
        packages.append(
            {
                "SPDXID": package_id,
                "name": f"{args.name}-{identifier}",
                "versionInfo": platform.digest,
                "downloadLocation": f"{args.image}@{platform.digest}",
                "filesAnalyzed": False,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": digest_match.group(1),
                    }
                ],
            }
        )
        relationships.extend(
            (
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": package_id,
                },
                {
                    "spdxElementId": package_id,
                    "relationshipType": "OTHER",
                    "relatedSpdxElement": f"{document_id}:SPDXRef-DOCUMENT",
                    "comment": "Platform package SBOM",
                },
            )
        )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{args.name}-multi-platform-index",
        "documentNamespace": (
            f"https://aegis.example.invalid/spdx/{args.name}/{index_match.group(1)}"
        ),
        "creationInfo": {
            "created": args.created,
            "creators": ["Tool: aegis-build-spdx-index"],
        },
        "externalDocumentRefs": external_documents,
        "packages": packages,
        "relationships": relationships,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
