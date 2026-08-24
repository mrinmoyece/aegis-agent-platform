"""Canonical synthetic operator data behind production-shaped fake adapters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from aegis_agent_platform.identity import Principal
from aegis_agent_platform.operator.contracts import (
    ApprovalDecisionCommand,
    ApprovalDecisionResult,
    DataAuthority,
    OperatorEventPage,
    OperatorItem,
    OperatorSnapshot,
    PeerTrustCommand,
    PeerTrustResult,
)
from aegis_agent_platform.tenancy import TenantContext

DEMO_TENANT_ID = "tenant-alpha"
DEMO_PLAN_DIGEST = sha256(b"aegis-canonical-checkout-plan-v1").hexdigest()
DEMO_POLICY_DIGEST = sha256(b"aegis-canonical-checkout-policy-v1").hexdigest()
DEMO_MCP_PEER_DIGEST = sha256(b"aegis-canonical-mcp-peer-deterministic-v1").hexdigest()


def _item(
    item_id: str,
    kind: str,
    title: str,
    summary: str,
    status: str,
    authority: DataAuthority,
    occurred_at: datetime,
    *,
    severity: str = "info",
    stale: bool = False,
    citation: str | None = None,
    metadata: dict[str, str | int | float | bool | None] | None = None,
) -> OperatorItem:
    return OperatorItem(
        item_id,
        kind,
        title,
        summary,
        status,
        authority,
        occurred_at,
        severity,
        stale,
        citation,
        metadata or {},
    )


def canonical_operator_snapshot(*, at: datetime) -> OperatorSnapshot:
    """Return synthetic checkout data covering every Layer 13 operator surface."""
    base = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    sections = {
        "health": (
            _item(
                "health-control-plane",
                "service",
                "Control plane",
                "Readiness is healthy; checkout latency SLO is burning.",
                "degraded",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=42),
                severity="warning",
                metadata={"slo": "checkout-latency", "burn_rate": 4.2},
            ),
            _item(
                "health-ledger",
                "dependency",
                "Event ledger",
                "Append and replay probes are healthy.",
                "healthy",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=42),
            ),
        ),
        "incidents": (
            _item(
                "inc-checkout-001",
                "incident",
                "Checkout latency after synthetic deployment",
                "Connection-pool saturation overlaps a bounded test deployment.",
                "investigating",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=7),
                severity="critical",
                citation="evidence://synthetic-observability/checkout-latency",
                metadata={"service": "checkout", "environment": "test"},
            ),
        ),
        "timeline": (
            _item(
                "evt-deploy-001",
                "deployment",
                "Synthetic deployment recorded",
                "Change event committed before the first alert.",
                "recorded",
                DataAuthority.EVENT_FACT,
                base,
                citation="event://checkout/41",
            ),
            _item(
                "evt-alert-001",
                "alert",
                "Latency SLO alert fired",
                "Four-window burn rate crossed the warning threshold.",
                "recorded",
                DataAuthority.EVENT_FACT,
                base + timedelta(minutes=7),
                severity="warning",
                citation="event://checkout/42",
            ),
            _item(
                "claim-pool-001",
                "hypothesis",
                "Pool saturation is causal",
                "Specialist confidence is 0.78; conflicting evidence remains visible.",
                "contested",
                DataAuthority.MODEL_CLAIM,
                base + timedelta(minutes=19),
                severity="warning",
                citation="evidence://synthetic-observability/pool-saturation",
                metadata={"confidence": 0.78},
            ),
        ),
        "specialists": (
            _item(
                "task-metrics",
                "specialist-task",
                "Metrics specialist",
                "Correlated latency and pool saturation with immutable citations.",
                "completed",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=18),
                citation="artifact://investigation/task-metrics",
            ),
            _item(
                "task-critic",
                "critic-task",
                "Critic review",
                "Preserved a deployment-timing contradiction and requested abstention.",
                "abstained",
                DataAuthority.MODEL_CLAIM,
                base + timedelta(minutes=21),
                severity="warning",
                citation="artifact://investigation/task-critic",
            ),
        ),
        "usage": (
            _item(
                "usage-investigation",
                "budget",
                "Investigation budget",
                "18,420 of 40,000 tokens; USD 1.84 of USD 5.00.",
                "within-budget",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=22),
                metadata={"tokens": 18420, "token_limit": 40000, "cost_usd": 1.84},
            ),
        ),
        "approvals": (
            _item(
                "approval-checkout-001",
                "approval",
                "Restart checkout pool",
                "Two-person approval; one independent grant recorded, one required.",
                "pending",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=25),
                severity="critical",
                citation="event://remediation/approval-requested",
                metadata={
                    "plan_digest": DEMO_PLAN_DIGEST,
                    "policy_digest": DEMO_POLICY_DIGEST,
                    "target": "deployment/checkout",
                    "risk": "critical",
                    "blast_radius": "one test namespace",
                    "expires_at": (base + timedelta(hours=1)).isoformat(),
                    "quorum": "1/2",
                    "version": "approval-v3",
                    "requester": "svc-incident-coordinator",
                },
            ),
        ),
        "actions": (
            _item(
                "action-restart-001",
                "controlled-action",
                "Restart checkout pool",
                "Provider acknowledgement was ambiguous; reconciliation is required.",
                "ambiguous",
                DataAuthority.EVENT_FACT,
                base + timedelta(minutes=31),
                severity="critical",
                citation="event://remediation/action-ambiguous",
                metadata={"verification": "pending", "rollback": "available"},
            ),
        ),
        "sandboxes": (
            _item(
                "sandbox-analysis-001",
                "sandbox-job",
                "Heap dump analysis",
                "Job completed; one archive is quarantined pending review.",
                "quarantined",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=28),
                severity="warning",
                citation="event://sandbox/artifact-quarantined",
                metadata={"cleanup": "scheduled", "egress": "denied"},
            ),
        ),
        "memory": (
            _item(
                "memory-checkout-001",
                "memory",
                "Prior pool saturation incident",
                "Accepted episodic memory with event and evidence provenance.",
                "active",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=17),
                citation="memory://checkout-pool/7",
                metadata={"retention": "30 days", "tombstone": False},
            ),
        ),
        "evaluations": (
            _item(
                "eval-operator-001",
                "regression",
                "Operator safety invariant pack",
                "One accessibility baseline is unmeasured; hard safety gates pass.",
                "degraded",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=40),
                severity="warning",
                metadata={"baseline": "canonical-v1", "hard_safety_failures": 0},
            ),
        ),
        "audit": (
            _item(
                "audit-approval-read",
                "audit-event",
                "Approval detail viewed",
                "Privileged read recorded with tenant and correlation scope.",
                "recorded",
                DataAuthority.EVENT_FACT,
                base + timedelta(minutes=26),
                citation="audit://operator/read/1",
            ),
        ),
        "replay": (
            _item(
                "replay-checkout-001",
                "replay-event",
                "Replay chain verified",
                "Ledger sequence and content digest converge through action ambiguity.",
                "verified",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=41),
                citation="event://checkout/replay/46",
                metadata={"redacted": True, "support_bundle": "available"},
            ),
        ),
        "protocols": (
            _item(
                "peer-mcp-deterministic",
                "protocol-peer",
                "Deterministic MCP peer",
                "Canonical read-only MCP peer used for integration verification.",
                "active",
                DataAuthority.DERIVED_STATE,
                base + timedelta(minutes=5),
                metadata={
                    "peer_digest": DEMO_MCP_PEER_DIGEST,
                    "version": "peer-v1",
                    "trust_tier": "verified",
                    "transport": "https",
                },
            ),
        ),
    }
    return OperatorSnapshot(
        1,
        DEMO_TENANT_ID,
        at,
        "46",
        False,
        True,
        sections,
    )


class DemoOperatorViews:
    """Read-only synthetic adapter with no production network or credentials."""

    async def snapshot(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
    ) -> OperatorSnapshot:
        if (
            principal.tenant_id != context.tenant_id
            or str(context.tenant_id) != DEMO_TENANT_ID
        ):
            raise PermissionError("operator tenant mismatch")
        return canonical_operator_snapshot(at=at)

    async def events(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        after_cursor: str | None,
        at: datetime,
    ) -> OperatorEventPage:
        snapshot = await self.snapshot(principal, context, at=at)
        cursor = int(after_cursor or "0")
        if cursor < 0:
            raise ValueError("cursor cannot be negative")
        ordered = tuple(
            sorted(
                (item for items in snapshot.sections.values() for item in items),
                key=lambda item: (item.occurred_at, item.item_id),
            )
        )
        page = ordered[cursor : cursor + 100]
        next_cursor = (
            str(cursor + len(page)) if cursor + len(page) < len(ordered) else None
        )
        return OperatorEventPage(page, next_cursor, at)


class DemoOperatorCommands:
    """Deterministic command fake that never performs a production effect."""

    def __init__(self) -> None:
        self._results: dict[str, ApprovalDecisionResult] = {}
        self._fingerprints: dict[str, str] = {}
        # Track current approval version for optimistic concurrency checks.
        self._current_approval_version: str = "approval-v3"
        self._approval_terminal: bool = False
        # Track peer trust versions.
        self._peer_trust_results: dict[str, PeerTrustResult] = {}
        self._peer_trust_fingerprints: dict[str, str] = {}
        self._peer_versions: dict[str, str] = {"peer-mcp-deterministic": "peer-v1"}

    async def decide_approval(
        self,
        principal: Principal,
        context: TenantContext,
        command: ApprovalDecisionCommand,
        *,
        at: datetime,
    ) -> ApprovalDecisionResult:
        if (
            principal.tenant_id != context.tenant_id
            or str(context.tenant_id) != DEMO_TENANT_ID
        ):
            raise PermissionError("operator tenant mismatch")
        duplicate = self._results.get(command.idempotency_key)
        if duplicate is not None:
            # Verify the duplicate request is for the same command; a different
            # command reusing the same key is an idempotency conflict.
            fingerprint = sha256(
                f"{command.approval_id}:{command.plan_digest}:"
                f"{command.policy_digest}:{command.decision}:"
                f"{command.rationale_code}".encode()
            ).hexdigest()
            if fingerprint != self._fingerprints.get(command.idempotency_key):
                raise ValueError("idempotency_conflict: command fingerprint mismatch")
            return ApprovalDecisionResult(
                duplicate.approval_id,
                duplicate.status,
                duplicate.verification,
                duplicate.version,
                True,
                at,
            )
        if command.approval_id != "approval-checkout-001":
            raise LookupError("approval not found")
        if (
            command.plan_digest != DEMO_PLAN_DIGEST
            or command.policy_digest != DEMO_POLICY_DIGEST
        ):
            raise ValueError("approval scope digest is stale")
        if self._approval_terminal:
            raise RuntimeError("approval version conflict")
        if command.expected_version != self._current_approval_version:
            raise RuntimeError("approval version conflict")
        new_version = "approval-v4"
        result = ApprovalDecisionResult(
            command.approval_id,
            "decision_recorded",
            "pending",
            new_version,
            False,
            at,
        )
        fingerprint = sha256(
            f"{command.approval_id}:{command.plan_digest}:"
            f"{command.policy_digest}:{command.decision}:"
            f"{command.rationale_code}".encode()
        ).hexdigest()
        self._results[command.idempotency_key] = result
        self._fingerprints[command.idempotency_key] = fingerprint
        # Advance the version and mark the approval as terminal so no further
        # decisions with a stale version can be recorded.
        self._current_approval_version = new_version
        self._approval_terminal = True
        return result

    async def change_peer_trust(
        self,
        principal: Principal,
        context: TenantContext,
        command: PeerTrustCommand,
        *,
        at: datetime,
    ) -> PeerTrustResult:
        if (
            principal.tenant_id != context.tenant_id
            or str(context.tenant_id) != DEMO_TENANT_ID
        ):
            raise PermissionError("operator tenant mismatch")
        duplicate = self._peer_trust_results.get(command.idempotency_key)
        if duplicate is not None:
            fingerprint = sha256(
                f"{command.peer_id}:{command.peer_digest}:"
                f"{command.decision}:{command.rationale_code}".encode()
            ).hexdigest()
            if fingerprint != self._peer_trust_fingerprints.get(
                command.idempotency_key
            ):
                raise ValueError("idempotency_conflict: command fingerprint mismatch")
            return PeerTrustResult(
                duplicate.peer_id,
                duplicate.status,
                duplicate.version,
                True,
                at,
            )
        if command.peer_id not in self._peer_versions:
            raise LookupError("peer not found")
        if command.peer_digest != DEMO_MCP_PEER_DIGEST:
            raise ValueError("peer digest is stale")
        current_version = self._peer_versions[command.peer_id]
        if command.expected_version != current_version:
            raise RuntimeError("peer version conflict")
        # Increment version: "peer-v1" → "peer-v2"
        version_num = int(current_version.split("-v")[-1]) + 1
        new_version = f"peer-v{version_num}"
        decision_to_status = {
            "activate": "active",
            "quarantine": "quarantined",
            "revoke": "revoked",
        }
        result = PeerTrustResult(
            command.peer_id,
            decision_to_status[command.decision],
            new_version,
            False,
            at,
        )
        fingerprint = sha256(
            f"{command.peer_id}:{command.peer_digest}:"
            f"{command.decision}:{command.rationale_code}".encode()
        ).hexdigest()
        self._peer_trust_results[command.idempotency_key] = result
        self._peer_trust_fingerprints[command.idempotency_key] = fingerprint
        self._peer_versions[command.peer_id] = new_version
        return result


__all__ = [
    "DEMO_MCP_PEER_DIGEST",
    "DEMO_PLAN_DIGEST",
    "DEMO_POLICY_DIGEST",
    "DEMO_TENANT_ID",
    "DemoOperatorCommands",
    "DemoOperatorViews",
    "canonical_operator_snapshot",
]
