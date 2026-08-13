"""Provider-neutral model gateway runtime."""

from aegis_agent_platform.gateway.catalog import (
    CatalogError,
    ModelCatalog,
    ModelCatalogEntry,
    ModelRouter,
    RouteDecision,
    RouteDeniedError,
    RoutePreference,
)
from aegis_agent_platform.gateway.operations import GatewayOperations, ModelUsageReader
from aegis_agent_platform.gateway.postgres import PostgresGatewayRepository
from aegis_agent_platform.gateway.repository import (
    BudgetDeniedError,
    BudgetReservation,
    DuplicateCallInProgressError,
    GatewayRepository,
    InMemoryGatewayRepository,
    estimate_cost,
)
from aegis_agent_platform.gateway.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    ProviderControls,
    RetryPolicy,
    TokenBucket,
)
from aegis_agent_platform.gateway.service import ModelGateway
from aegis_agent_platform.gateway.structured import validate_object, validate_schema
from aegis_agent_platform.gateway.telemetry import GatewayMetrics, GatewayTracer

__all__ = [
    "BudgetDeniedError",
    "BudgetReservation",
    "CatalogError",
    "CircuitBreaker",
    "CircuitOpenError",
    "CircuitState",
    "DuplicateCallInProgressError",
    "GatewayMetrics",
    "GatewayOperations",
    "GatewayRepository",
    "GatewayTracer",
    "InMemoryGatewayRepository",
    "ModelCatalog",
    "ModelCatalogEntry",
    "ModelGateway",
    "ModelRouter",
    "ModelUsageReader",
    "PostgresGatewayRepository",
    "ProviderControls",
    "RetryPolicy",
    "RouteDecision",
    "RouteDeniedError",
    "RoutePreference",
    "TokenBucket",
    "estimate_cost",
    "validate_object",
    "validate_schema",
]
