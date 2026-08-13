"""Authentication principal contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated subject before tenant authorization is applied."""

    subject: str
    issuer: str
    roles: frozenset[str]
