"""Secret references and explicit provider adapters."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.tenancy import TenantContext


class SecretError(RuntimeError):
    """Raised when a secret reference cannot be safely resolved."""


@dataclass(frozen=True, slots=True)
class SecretReference:
    """Serializable reference to secret material, never the material itself."""

    tenant_id: TenantId
    provider: str
    name: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not self.provider or not self.name:
            raise ValueError("secret provider and name are required")
        if any(character.isspace() for character in self.name):
            raise ValueError("secret names cannot contain whitespace")


class SecretValue:
    """Opaque secret bytes with redacted string and representation behavior."""

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if not value:
            raise ValueError("secret value cannot be empty")
        self.__value = value

    def reveal(self) -> bytes:
        """Explicitly reveal bytes at the adapter boundary that requires them."""
        return self.__value

    def __repr__(self) -> str:
        return "SecretValue([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"


class SecretProvider(Protocol):
    """Resolve a typed reference without exposing ambient tool credentials."""

    def resolve(
        self,
        context: TenantContext,
        reference: SecretReference,
    ) -> SecretValue:
        """Resolve one explicit secret reference."""
        ...


class EnvironmentSecretProvider:
    """Development provider over an explicit environment snapshot."""

    provider_name = "env"

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    @classmethod
    def from_process_environment(cls) -> EnvironmentSecretProvider:
        """Capture process environment only when explicitly requested."""
        return cls(os.environ)

    def resolve(
        self,
        context: TenantContext,
        reference: SecretReference,
    ) -> SecretValue:
        _require_tenant(context, reference)
        if reference.provider != self.provider_name:
            raise SecretError("secret reference targets a different provider")
        if reference.version is not None:
            raise SecretError("environment secrets do not support versions")
        if not reference.name.startswith("AEGIS_SECRET_"):
            raise SecretError("environment secret names require AEGIS_SECRET_ prefix")
        try:
            value = self._values[reference.name]
        except KeyError as error:
            raise SecretError("secret reference was not found") from error
        return SecretValue(value.encode())


class InMemorySecretProvider:
    """Deterministic test double keyed only by explicit references."""

    provider_name = "memory"

    def __init__(self, values: Mapping[SecretReference, bytes]) -> None:
        self._values = dict(values)

    def resolve(
        self,
        context: TenantContext,
        reference: SecretReference,
    ) -> SecretValue:
        _require_tenant(context, reference)
        if reference.provider != self.provider_name:
            raise SecretError("secret reference targets a different provider")
        try:
            return SecretValue(self._values[reference])
        except KeyError as error:
            raise SecretError("secret reference was not found") from error


def _require_tenant(
    context: TenantContext,
    reference: SecretReference,
) -> None:
    if context.tenant_id != reference.tenant_id:
        raise SecretError("secret reference tenant does not match trusted context")
