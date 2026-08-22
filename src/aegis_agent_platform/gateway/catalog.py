"""Versioned model catalog and deterministic tenant-aware routing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegis_agent_platform.config import Environment
from aegis_agent_platform.domain import (
    ModelCapabilities,
    ModelIdentity,
    ModelRequest,
    PricingVersion,
)
from aegis_agent_platform.policy import TenantPolicy


class RoutePreference(StrEnum):
    COST = "cost"
    LATENCY = "latency"


class CatalogError(LookupError):
    """Unknown or ambiguous catalog data must fail closed."""


class RouteDeniedError(PermissionError):
    def __init__(self, reasons: tuple[str, ...]) -> None:
        super().__init__(", ".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True, slots=True)
class ModelCatalogEntry:
    identity: ModelIdentity
    capabilities: ModelCapabilities
    pricing: PricingVersion
    environments: frozenset[Environment]
    data_residencies: frozenset[str]
    provider_retains_data: bool
    cost_rank: int
    latency_rank: int
    fallback_models: tuple[ModelIdentity, ...] = ()

    def __post_init__(self) -> None:
        if not self.environments or not self.data_residencies:
            raise ValueError("catalog environment and residency must be explicit")
        if self.cost_rank < 0 or self.latency_rank < 0:
            raise ValueError("catalog ranks cannot be negative")


class ModelCatalog:
    def __init__(self, entries: tuple[ModelCatalogEntry, ...]) -> None:
        self._entries = {entry.identity: entry for entry in entries}
        if len(self._entries) != len(entries):
            raise ValueError("duplicate catalog model identity")

    def get(self, identity: ModelIdentity) -> ModelCatalogEntry:
        try:
            return self._entries[identity]
        except KeyError as error:
            raise CatalogError(f"unknown model: {identity.catalog_key}") from error

    def entries(self) -> tuple[ModelCatalogEntry, ...]:
        return tuple(
            sorted(self._entries.values(), key=lambda item: item.identity.catalog_key)
        )


@dataclass(frozen=True, slots=True)
class RouteDecision:
    selected: ModelCatalogEntry
    candidates: tuple[ModelCatalogEntry, ...]
    rationale: tuple[str, ...]


class ModelRouter:
    """Pure deterministic selection; runtime health is supplied as bounded keys."""

    @staticmethod
    def policy_failures(
        entry: ModelCatalogEntry,
        policy: TenantPolicy,
        environment: Environment,
    ) -> tuple[str, ...]:
        identity = entry.identity
        allowed_model = (
            identity.catalog_key in policy.allowed_models
            or identity.model in policy.allowed_models
        )
        checks = {
            "model_not_allowed": not allowed_model,
            "provider_not_allowed": identity.provider not in policy.allowed_providers,
            "environment_not_allowed": environment not in entry.environments
            or environment.value not in policy.allowed_environments,
            "residency_not_allowed": not entry.data_residencies.intersection(
                policy.allowed_data_residencies
            ),
            "retention_not_allowed": entry.provider_retains_data
            and not policy.allow_provider_retention,
        }
        return tuple(name for name, failed in checks.items() if failed)

    def route(
        self,
        request: ModelRequest,
        *,
        catalog: ModelCatalog,
        policy: TenantPolicy,
        environment: Environment,
        unavailable: frozenset[ModelIdentity] = frozenset(),
        preference: RoutePreference = RoutePreference.COST,
    ) -> RouteDecision:
        reasons: list[str] = []
        if str(policy.tenant_id) != request.tenant_id:
            raise RouteDeniedError(("cross_tenant_policy",))
        entries = catalog.entries()
        if request.requested_model is not None:
            entries = (catalog.get(request.requested_model),)
            reasons.append("explicit_model")
        eligible: list[ModelCatalogEntry] = []
        denied: set[str] = set()
        for entry in entries:
            identity = entry.identity
            checks = {
                **dict.fromkeys(self.policy_failures(entry, policy, environment), True),
                "provider_unavailable": identity in unavailable,
                "context_limit_exceeded": (
                    request.prompt_token_estimate + request.max_output_tokens
                    > entry.capabilities.max_context_tokens
                ),
                "output_limit_exceeded": (
                    request.max_output_tokens > entry.capabilities.max_output_tokens
                ),
                "tools_unsupported": bool(request.tools)
                and not entry.capabilities.supports_tools,
                "vision_unsupported": _uses_vision(request)
                and not entry.capabilities.supports_vision,
                "structured_output_unsupported": request.response_schema is not None
                and not entry.capabilities.supports_structured_output,
            }
            failures = tuple(name for name, failed in checks.items() if failed)
            if failures:
                denied.update(failures)
            else:
                eligible.append(entry)
        if not eligible:
            raise RouteDeniedError(tuple(sorted(denied)) or ("no_catalog_candidates",))
        key = (
            (lambda entry: (entry.cost_rank, entry.latency_rank, entry.identity))
            if preference is RoutePreference.COST
            else (lambda entry: (entry.latency_rank, entry.cost_rank, entry.identity))
        )
        ordered = tuple(sorted(eligible, key=key))
        reasons.extend(
            (
                "tenant_policy_allowed",
                "capabilities_matched",
                f"{preference.value}_preference",
            )
        )
        return RouteDecision(ordered[0], ordered, tuple(reasons))


def _uses_vision(request: ModelRequest) -> bool:
    from aegis_agent_platform.domain import ImagePart

    return any(
        isinstance(part, ImagePart)
        for message in request.messages
        for part in message.content
    )


__all__ = [
    "CatalogError",
    "ModelCatalog",
    "ModelCatalogEntry",
    "ModelRouter",
    "RouteDecision",
    "RouteDeniedError",
    "RoutePreference",
]
