"""Approval-gated remediation and controlled external action boundaries."""

from aegis_agent_platform.remediation.approvals import (
    ApprovalDecision,
    ApprovalDeniedError,
    ProposalDecision,
    RemediationApprovalService,
)
from aegis_agent_platform.remediation.execution import (
    ActionAdapterResult,
    ActionErrorClass,
    ActionObservation,
    ApprovalAuthority,
    CancellationSignal,
    ControlledActionError,
    ControlledActionExecutor,
    ControlledActionPort,
    FakeControlledActionAdapter,
    StaticApprovalAuthority,
)
from aegis_agent_platform.remediation.operations import (
    ActionQuotaReader,
    InMemoryRemediationPolicyRepository,
    RemediationOperations,
    RemediationPolicyRepository,
)
from aegis_agent_platform.remediation.policy import (
    ActionQuotaUsage,
    RemediationPolicyEvaluator,
)
from aegis_agent_platform.remediation.postgres import PostgresRemediationRepository
from aegis_agent_platform.remediation.repository import (
    InMemoryRemediationRepository,
    ProposalResult,
    RemediationIdempotencyConflictError,
    RemediationRepository,
)
from aegis_agent_platform.remediation.telemetry import (
    RemediationMetrics,
    RemediationTracer,
)

__all__ = [
    "ActionAdapterResult",
    "ActionErrorClass",
    "ActionObservation",
    "ActionQuotaReader",
    "ActionQuotaUsage",
    "ApprovalAuthority",
    "ApprovalDecision",
    "ApprovalDeniedError",
    "CancellationSignal",
    "ControlledActionError",
    "ControlledActionExecutor",
    "ControlledActionPort",
    "FakeControlledActionAdapter",
    "InMemoryRemediationPolicyRepository",
    "InMemoryRemediationRepository",
    "PostgresRemediationRepository",
    "ProposalDecision",
    "ProposalResult",
    "RemediationApprovalService",
    "RemediationIdempotencyConflictError",
    "RemediationMetrics",
    "RemediationOperations",
    "RemediationPolicyEvaluator",
    "RemediationPolicyRepository",
    "RemediationRepository",
    "RemediationTracer",
    "StaticApprovalAuthority",
]
