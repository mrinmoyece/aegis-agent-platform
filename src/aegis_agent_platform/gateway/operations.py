"""Authorized, bounded model catalog, usage, and provider-health views."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from aegis_agent_platform.config import Environment
from aegis_agent_platform.domain import JsonValue, ModelIdentity
from aegis_agent_platform.gateway.catalog import ModelCatalog, ModelRouter
from aegis_agent_platform.gateway.resilience import ProviderControls
from aegis_agent_platform.identity import (
    AuthorizationService,
    Permission,
    Principal,
)
from aegis_agent_platform.policy import TenantPolicy
from aegis_agent_platform.tenancy import TenantContext


class ModelUsageReader(Protocol):
    def usage_summary(self, context: TenantContext) -> Mapping[str, JsonValue]:
        """Return a bounded tenant-scoped usage projection."""
        ...


class GatewayOperations:
    def __init__(
        self,
        catalog: ModelCatalog,
        controls: ProviderControls,
        usage: ModelUsageReader,
        environment: Environment = Environment.PRODUCTION,
        authorization: AuthorizationService | None = None,
    ) -> None:
        self._catalog = catalog
        self._controls = controls
        self._usage = usage
        self._environment = environment
        self._authorization = authorization or AuthorizationService()

    def catalog(
        self,
        principal: Principal,
        context: TenantContext,
        policy: TenantPolicy,
        *,
        at: datetime,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        self._require(principal, context, at)
        if str(policy.tenant_id) != str(context.tenant_id):
            raise PermissionError("cross_tenant_policy")
        result: list[Mapping[str, JsonValue]] = []
        for entry in self._catalog.entries():
            if ModelRouter.policy_failures(entry, policy, self._environment):
                continue
            identity = entry.identity
            result.append(
                {
                    "provider": identity.provider,
                    "model": identity.model,
                    "pricing_version": entry.pricing.version,
                    "max_context_tokens": entry.capabilities.max_context_tokens,
                    "max_output_tokens": entry.capabilities.max_output_tokens,
                    "supports_tools": entry.capabilities.supports_tools,
                    "supports_vision": entry.capabilities.supports_vision,
                    "supports_structured_output": (
                        entry.capabilities.supports_structured_output
                    ),
                    "data_residencies": tuple(sorted(entry.data_residencies)),
                    "provider_retains_data": entry.provider_retains_data,
                }
            )
        return tuple(result)

    def usage(
        self,
        principal: Principal,
        context: TenantContext,
        *,
        at: datetime,
    ) -> Mapping[str, JsonValue]:
        self._require(principal, context, at)
        return self._usage.usage_summary(context)

    def health(
        self,
        principal: Principal,
        context: TenantContext,
        policy: TenantPolicy,
        *,
        at: datetime,
    ) -> tuple[Mapping[str, JsonValue], ...]:
        self._require(principal, context, at)
        allowed = self.catalog(principal, context, policy, at=at)
        return tuple(
            {
                "provider": str(entry["provider"]),
                "model": str(entry["model"]),
                "circuit_state": self._controls.circuit(
                    self._catalog_identity(
                        str(entry["provider"]),
                        str(entry["model"]),
                    )
                ).state.value,
            }
            for entry in allowed
        )

    def _catalog_identity(self, provider: str, model: str) -> ModelIdentity:
        return ModelIdentity(provider, model)

    def _require(
        self,
        principal: Principal,
        context: TenantContext,
        at: datetime,
    ) -> None:
        decision = self._authorization.decide(
            principal=principal,
            tenant_id=context.tenant_id,
            permission=Permission.MODEL_READ,
            at=at,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)


__all__ = ["GatewayOperations", "ModelUsageReader"]
