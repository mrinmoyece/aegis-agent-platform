"""Secure operator BFF boundary and provider-neutral view contracts."""

from aegis_agent_platform.operator.api import OperatorBffApp
from aegis_agent_platform.operator.contracts import (
    ApprovalDecisionCommand,
    ApprovalDecisionResult,
    OperatorEventPage,
    OperatorSnapshot,
)
from aegis_agent_platform.operator.demo import (
    DemoOperatorCommands,
    DemoOperatorViews,
    canonical_operator_snapshot,
)
from aegis_agent_platform.operator.session import (
    InMemoryOperatorSessionStore,
    OidcAuthorizationState,
    OidcAuthorizationStateStore,
    OperatorSession,
    OperatorSessionHandle,
)

__all__ = [
    "ApprovalDecisionCommand",
    "ApprovalDecisionResult",
    "DemoOperatorCommands",
    "DemoOperatorViews",
    "InMemoryOperatorSessionStore",
    "OidcAuthorizationState",
    "OidcAuthorizationStateStore",
    "OperatorBffApp",
    "OperatorEventPage",
    "OperatorSession",
    "OperatorSessionHandle",
    "OperatorSnapshot",
    "canonical_operator_snapshot",
]
