"""Fail when installed distributions use explicitly prohibited licenses."""

from __future__ import annotations

from collections.abc import Sequence
from importlib import metadata

PROHIBITED_IDENTIFIERS = (
    "agpl-3.0",
    "sspl-1.0",
)
PROHIBITED_NAMES = (
    "gnu affero general public license",
    "server side public license",
)


def is_prohibited_license(
    *,
    expression: str | None,
    license_value: str | None,
    classifiers: Sequence[str],
) -> bool:
    """Classify declared licenses without matching references in bundled texts."""
    normalized_expression = (expression or "").casefold()
    if any(item in normalized_expression for item in PROHIBITED_IDENTIFIERS):
        return True
    if any(
        prohibited in classifier.casefold()
        for classifier in classifiers
        for prohibited in PROHIBITED_NAMES
    ):
        return True
    license_prefix = (license_value or "").strip().casefold()[:512]
    return any(
        prohibited in license_prefix
        for prohibited in (*PROHIBITED_IDENTIFIERS, *PROHIBITED_NAMES)
    )


def main() -> None:
    """Reject explicitly prohibited licenses in installed package metadata."""
    violations: list[str] = []
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name", "unknown")
        if is_prohibited_license(
            expression=distribution.metadata.get("License-Expression"),
            license_value=distribution.metadata.get("License"),
            classifiers=distribution.metadata.get_all("Classifier", []),
        ):
            violations.append(str(name))
    if violations:
        raise SystemExit(
            "prohibited dependency licenses: " + ", ".join(sorted(violations))
        )


if __name__ == "__main__":
    main()
