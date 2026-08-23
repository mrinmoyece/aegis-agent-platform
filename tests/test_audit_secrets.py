"""Audit immutability and secret-redaction tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aegis_agent_platform.audit import (
    REDACTED,
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    InMemoryAuditStore,
)
from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.secrets_boundary import (
    EnvironmentSecretProvider,
    InMemorySecretProvider,
    SecretError,
    SecretReference,
    SecretValue,
)
from aegis_agent_platform.tenancy import TenantContext
from security_helpers import TENANT_ID


def audit_event(
    tenant_id: TenantId = TENANT_ID,
    *,
    details: dict[str, JsonValue] | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=uuid4(),
        tenant_id=tenant_id,
        event_type=AuditEventType.AUTHORIZATION_DECISION,
        occurred_at=datetime.now(UTC),
        outcome=AuditOutcome.DENIED,
        actor_id="user-alice",
        action="policy:manage",
        resource="tenant/tenant-alpha/policy",
        correlation_id=uuid4(),
        details=details or {"reason": "permission_not_granted"},
    )


def test_audit_redacts_credentials_prompts_and_nested_bearer_values() -> None:
    event = audit_event(
        details={
            "access_token": "header.payload.signature",
            "full_prompt": "private incident text",
            "nested": {"message": "Authorization: Bearer abc.def"},
        }
    )

    assert event.details["access_token"] == REDACTED
    assert event.details["full_prompt"] == REDACTED
    assert REDACTED in str(event.details["nested"])
    assert "abc.def" not in repr(event.details)


def test_audit_store_is_append_only_and_tenant_scoped() -> None:
    store = InMemoryAuditStore()
    event = audit_event()
    context = TenantContext(TENANT_ID)
    store.append(context, event)

    assert store.query(context) == (event,)
    assert store.query(TenantContext(TenantId("tenant-beta"))) == ()
    with pytest.raises(ValueError, match="tenant"):
        store.append(TenantContext(TenantId("tenant-beta")), event)
    with pytest.raises(TypeError):
        event.details["later"] = True  # type: ignore[index]


def test_invalid_audit_event_contracts_are_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        AuditEvent(
            event_id=uuid4(),
            tenant_id=TENANT_ID,
            event_type=AuditEventType.ADMINISTRATIVE_CHANGE,
            occurred_at=datetime.now(),
            outcome=AuditOutcome.SUCCESS,
            actor_id="admin",
            action="policy:update",
            resource="policy",
            correlation_id=uuid4(),
            details={},
        )
    with pytest.raises(ValueError, match="additive"):
        AuditEvent(
            event_id=uuid4(),
            tenant_id=TENANT_ID,
            event_type=AuditEventType.ADMINISTRATIVE_CHANGE,
            occurred_at=datetime.now(UTC),
            outcome=AuditOutcome.SUCCESS,
            actor_id="admin",
            action="policy:update",
            resource="policy",
            correlation_id=uuid4(),
            details={},
            schema_version=2,
        )


def test_secret_values_never_render_or_serialize_raw_material() -> None:
    value = SecretValue(b"super-sensitive")

    assert repr(value) == "SecretValue([REDACTED])"
    assert str(value) == REDACTED
    assert "super-sensitive" not in repr(value)
    assert value.reveal() == b"super-sensitive"


def test_environment_provider_requires_explicit_prefixed_reference() -> None:
    provider = EnvironmentSecretProvider(
        {"AEGIS_SECRET_MODEL_API": "local-development-only"},
        tenant_id=TENANT_ID,
    )
    context = TenantContext(TENANT_ID)
    reference = SecretReference(TENANT_ID, "env", "AEGIS_SECRET_MODEL_API")

    assert provider.resolve(context, reference).reveal() == b"local-development-only"
    with pytest.raises(SecretError, match="prefix"):
        provider.resolve(context, SecretReference(TENANT_ID, "env", "MODEL_API"))
    with pytest.raises(SecretError, match="versions"):
        provider.resolve(
            context,
            SecretReference(TENANT_ID, "env", "AEGIS_SECRET_MODEL_API", "v1"),
        )
    with pytest.raises(SecretError, match="different provider"):
        provider.resolve(
            context,
            SecretReference(TENANT_ID, "vault", "AEGIS_SECRET_MODEL_API"),
        )
    with pytest.raises(SecretError, match="tenant"):
        provider.resolve(TenantContext(TenantId("tenant-beta")), reference)


def test_in_memory_secret_provider_requires_exact_reference() -> None:
    context = TenantContext(TENANT_ID)
    reference = SecretReference(TENANT_ID, "memory", "github-app", "1")
    provider = InMemorySecretProvider({reference: b"test-value"})

    assert provider.resolve(context, reference).reveal() == b"test-value"
    with pytest.raises(SecretError, match="not found"):
        provider.resolve(
            context,
            SecretReference(TENANT_ID, "memory", "missing"),
        )
    with pytest.raises(SecretError, match="different provider"):
        provider.resolve(
            context,
            SecretReference(TENANT_ID, "env", "missing"),
        )


def test_invalid_secret_contracts_are_rejected() -> None:
    with pytest.raises(ValueError, match="required"):
        SecretReference(TENANT_ID, "", "name")
    with pytest.raises(ValueError, match="whitespace"):
        SecretReference(TENANT_ID, "memory", "not valid")
    with pytest.raises(ValueError, match="empty"):
        SecretValue(b"")
