"""Runtime policy-decision boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Decision(StrEnum):
    """Possible runtime policy outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Auditable policy result returned before an effect is attempted."""

    decision: Decision
    reason: str
    policy_version: str
