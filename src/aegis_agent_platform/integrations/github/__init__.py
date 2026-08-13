"""Read-only GitHub delivery-evidence contract for future adapters."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol


class ChangeKind(StrEnum):
    """Source and delivery changes relevant to incident correlation."""

    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    DEPLOYMENT = "deployment"


@dataclass(frozen=True, slots=True)
class ChangeEvidence:
    """Normalized GitHub evidence with a stable source reference."""

    reference: str
    repository: str
    revision: str
    kind: ChangeKind
    observed_at: datetime
    summary: str


class GitHubEvidenceReader(Protocol):
    """Tenant-scoped read port; implementations arrive in a later layer."""

    async def changes_between(
        self,
        *,
        tenant_id: str,
        repository: str,
        start: datetime,
        end: datetime,
    ) -> Sequence[ChangeEvidence]:
        """Read normalized delivery changes within an incident window."""
        ...
