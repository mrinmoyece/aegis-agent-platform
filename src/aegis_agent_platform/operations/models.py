"""Pure models used by deployment, migration, restore, and failover gates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SchemaCompatibilityWindow:
    """Application schema range accepted during an expand/migrate/contract rollout."""

    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if not 1 <= self.minimum <= self.maximum:
            raise ValueError("schema compatibility window is invalid")

    def accepts(self, current: int) -> bool:
        """Return whether a database version is safe for this application build."""
        return self.minimum <= current <= self.maximum


@dataclass(frozen=True, slots=True)
class WriterFence:
    """Single-writer region generation recorded in durable control state."""

    home_region: str
    generation: int

    def __post_init__(self) -> None:
        if not self.home_region.strip():
            raise ValueError("home_region is required")
        if self.generation < 1:
            raise ValueError("writer generation must be positive")

    def permits(self, *, region: str, generation: int) -> bool:
        """Reject stale or non-home-region writers deterministically."""
        return region == self.home_region and generation == self.generation


@dataclass(frozen=True, slots=True)
class DeploymentPrerequisites:
    """Fail-closed readiness state for optional high-risk deployment surfaces."""

    authentication_ready: bool
    key_reference_ready: bool
    schema_compatible: bool
    protocol_trust_ready: bool = False
    sandbox_isolation_ready: bool = False

    @property
    def core_ready(self) -> bool:
        """Core serving requires identity, keys, and compatible ledger schema."""
        return (
            self.authentication_ready
            and self.key_reference_ready
            and self.schema_compatible
        )

    @property
    def protocol_enabled(self) -> bool:
        """Federation is disabled until both core and trust prerequisites pass."""
        return self.core_ready and self.protocol_trust_ready

    @property
    def sandbox_enabled(self) -> bool:
        """Sandbox execution is disabled until qualified isolation passes."""
        return self.core_ready and self.sandbox_isolation_ready


@dataclass(frozen=True, slots=True)
class RestoreEvidence:
    """Bounded integrity facts emitted by an isolated restore drill."""

    source_event_count: int
    restored_event_count: int
    source_max_position: int
    restored_max_position: int
    source_checksum: str
    restored_checksum: str
    projections_rebuilt: bool
    redis_recovered_from_ledger: bool

    def __post_init__(self) -> None:
        for value in (
            self.source_event_count,
            self.restored_event_count,
            self.source_max_position,
            self.restored_max_position,
        ):
            if value < 0:
                raise ValueError("restore evidence counts cannot be negative")
        for digest in (self.source_checksum, self.restored_checksum):
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError("restore checksums must be lowercase SHA-256")

    @property
    def valid(self) -> bool:
        """Require exact ledger integrity and rebuildable non-authoritative state."""
        return (
            self.source_event_count == self.restored_event_count
            and self.source_max_position == self.restored_max_position
            and self.source_checksum == self.restored_checksum
            and self.projections_rebuilt
            and self.redis_recovered_from_ledger
        )
