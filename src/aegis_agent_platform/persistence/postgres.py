"""PostgreSQL adapters for Layer 2 identity, tenancy, policy, and audit ports."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal
from threading import Lock, RLock
from typing import Any, cast
from weakref import WeakKeyDictionary

import psycopg
from psycopg.types.json import Jsonb

from aegis_agent_platform.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditStore,
)
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.event_store import PermanentStorageError
from aegis_agent_platform.event_store.postgres import classify_storage_error
from aegis_agent_platform.identity import (
    AuthenticationError,
    AuthenticationErrorCode,
    IdentityDirectory,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
    ServiceIdentity,
    TenantId,
    UserId,
    VerifiedClaims,
)
from aegis_agent_platform.policy import (
    PolicyRepository,
    QuotaLimits,
    RiskLevel,
    TenantPolicy,
)
from aegis_agent_platform.tenancy import (
    Tenant,
    TenantContext,
    TenantRepository,
)

_CONNECTION_LOCKS: WeakKeyDictionary[psycopg.Connection[Any], RLock] = (
    WeakKeyDictionary()
)
_CONNECTION_LOCKS_GUARD = Lock()


class PostgresTenantRepository(TenantRepository):
    """Read tenant records under transaction-local RLS context."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection
        self._lock = _connection_lock(connection)

    def get(self, context: TenantContext) -> Tenant | None:
        try:
            with _tenant_transaction(self._connection, self._lock, context):
                row = self._connection.execute(
                    """
                    SELECT tenant_id, display_name, enabled
                    FROM tenants
                    WHERE tenant_id = %s
                    """,
                    (str(context.tenant_id),),
                ).fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return (
            Tenant(tenant_id=TenantId(row[0]), display_name=row[1], enabled=row[2])
            if row
            else None
        )


class PostgresIdentityDirectory(IdentityDirectory):
    """Resolve signed tenant claims against RLS-protected identity records."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection
        self._lock = _connection_lock(connection)

    def resolve(self, claims: VerifiedClaims) -> Principal:
        try:
            with self._connection.transaction(), self._lock:
                # Use the SECURITY DEFINER function so aegis_runtime does not need
                # BYPASSRLS for the initial cross-tenant identity lookup.
                identity = self._connection.execute(
                    "SELECT * FROM lookup_identity_by_subject(%s, %s)",
                    (claims.issuer, claims.subject),
                ).fetchone()
                if identity is None:
                    raise AuthenticationError(
                        AuthenticationErrorCode.UNKNOWN_IDENTITY,
                        "verified subject is not registered",
                    )
                if not identity[5]:
                    raise AuthenticationError(
                        AuthenticationErrorCode.IDENTITY_DISABLED,
                        "identity is disabled",
                    )
                # Validate optional tenant claim against authoritative tenant_id.
                stored_tenant_id = TenantId(identity[1])
                if (
                    claims.asserted_tenant_id is not None
                    and claims.asserted_tenant_id != stored_tenant_id
                ):
                    raise AuthenticationError(
                        AuthenticationErrorCode.TENANT_MISMATCH,
                        "signed tenant claim does not match authoritative tenant",
                    )
                # Re-read role bindings with RLS enabled for the confirmed tenant.
                self._connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true)",
                    (str(stored_tenant_id),),
                )
                bindings = self._connection.execute(
                    """
                        SELECT role, assigned_by, assigned_by_kind, assigned_at,
                            expires_at, revoked_at
                        FROM role_bindings
                        WHERE tenant_id = %s AND identity_id = %s
                        ORDER BY assigned_at, role
                        """,
                    (str(stored_tenant_id), identity[0]),
                ).fetchall()
        except AuthenticationError:
            raise
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        kind = PrincipalKind(identity[2])
        return Principal(
            subject=claims.subject,
            issuer=claims.issuer,
            tenant_id=stored_tenant_id,
            kind=kind,
            role_bindings=tuple(
                _role_binding_from_row(stored_tenant_id, row) for row in bindings
            ),
            user_id=UserId(identity[3]) if identity[3] is not None else None,
            service_identity=(
                ServiceIdentity(identity[4]) if identity[4] is not None else None
            ),
        )


class PostgresPolicyRepository(PolicyRepository):
    """Load versioned policy and quotas within one tenant transaction."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection
        self._lock = _connection_lock(connection)

    def get(self, context: TenantContext) -> TenantPolicy | None:
        try:
            with _tenant_transaction(self._connection, self._lock, context):
                row = self._connection.execute(
                    """
                    SELECT p.policy_version, p.policy_document,
                        q.max_run_tokens, q.max_run_cost_usd,
                        q.max_tenant_tokens_per_period,
                        q.max_tenant_cost_usd_per_period,
                        q.max_concurrent_runs
                    FROM tenant_policies AS p
                    JOIN tenant_quotas AS q USING (tenant_id)
                    WHERE p.tenant_id = %s
                    """,
                    (str(context.tenant_id),),
                ).fetchone()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        if row is None:
            return None
        document = row[1]
        if not isinstance(document, dict):
            raise PermanentStorageError("policy document must be a JSON object")
        try:
            return TenantPolicy(
                tenant_id=context.tenant_id,
                version=row[0],
                allowed_models=_string_set(document, "allowed_models"),
                allowed_tools=_string_set(document, "allowed_tools"),
                allowed_connectors=_string_set(document, "allowed_connectors"),
                allowed_environments=_string_set(document, "allowed_environments"),
                max_risk=RiskLevel(_required_int(document, "max_risk")),
                approval_from_risk=RiskLevel(
                    _required_int(document, "approval_from_risk")
                ),
                tools_requiring_approval=_string_set(
                    document, "tools_requiring_approval"
                ),
                approver_roles=frozenset(
                    Role(value) for value in _string_set(document, "approver_roles")
                ),
                quotas=QuotaLimits(
                    max_run_tokens=int(row[2]),
                    max_run_cost_usd=Decimal(row[3]),
                    max_tenant_tokens_per_period=int(row[4]),
                    max_tenant_cost_usd_per_period=Decimal(row[5]),
                    max_concurrent_runs=int(row[6]),
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PermanentStorageError(
                "policy document has an invalid schema"
            ) from error


class PostgresAuditStore(AuditStore):
    """Append and query immutable redacted audit events under forced RLS."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection
        self._lock = _connection_lock(connection)

    def append(self, context: TenantContext, event: AuditEvent) -> None:
        if context.tenant_id != event.tenant_id:
            raise ValueError("audit event tenant does not match trusted context")
        try:
            with _tenant_transaction(self._connection, self._lock, context):
                self._connection.execute(
                    """
                    INSERT INTO security_audit_events (
                        event_id, tenant_id, event_type, schema_version,
                        occurred_at, outcome, actor_id, action, resource,
                        correlation_id, details
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event.event_id,
                        str(event.tenant_id),
                        event.event_type.value,
                        event.schema_version,
                        event.occurred_at,
                        event.outcome.value,
                        event.actor_id,
                        event.action,
                        event.resource,
                        event.correlation_id,
                        Jsonb(thaw_json(event.details)),
                    ),
                )
        except psycopg.Error as error:
            raise classify_storage_error(error) from error

    def query(
        self, context: TenantContext, *, limit: int = 100
    ) -> tuple[AuditEvent, ...]:
        if not 1 <= limit <= 1_000:
            raise ValueError("audit query limit must be between 1 and 1000")
        try:
            with _tenant_transaction(self._connection, self._lock, context):
                rows = self._connection.execute(
                    """
                    SELECT event_id, tenant_id, event_type, occurred_at,
                        outcome, actor_id, action, resource, correlation_id,
                        details, schema_version
                    FROM security_audit_events
                    WHERE tenant_id = %s
                    ORDER BY sequence_number DESC
                    LIMIT %s
                    """,
                    (str(context.tenant_id), limit),
                ).fetchall()
        except psycopg.Error as error:
            raise classify_storage_error(error) from error
        return tuple(
            AuditEvent(
                event_id=row[0],
                tenant_id=TenantId(row[1]),
                event_type=AuditEventType(row[2]),
                occurred_at=row[3],
                outcome=AuditOutcome(row[4]),
                actor_id=row[5],
                action=row[6],
                resource=row[7],
                correlation_id=row[8],
                details=row[9],
                schema_version=row[10],
            )
            for row in reversed(rows)
        )


def _connection_lock(connection: psycopg.Connection[Any]) -> RLock:
    with _CONNECTION_LOCKS_GUARD:
        lock = _CONNECTION_LOCKS.get(connection)
        if lock is None:
            lock = RLock()
            _CONNECTION_LOCKS[connection] = lock
        return lock


@contextmanager
def _tenant_transaction(
    connection: psycopg.Connection[Any],
    lock: RLock,
    context: TenantContext,
) -> Iterator[None]:
    with lock, connection.transaction():
        _set_tenant(connection, context)
        yield


def _set_tenant(connection: psycopg.Connection[Any], context: TenantContext) -> None:
    connection.execute(
        "SELECT set_config('aegis.tenant_id', %s, true)",
        (str(context.tenant_id),),
    )


def _role_binding_from_row(tenant_id: TenantId, row: tuple[object, ...]) -> RoleBinding:
    role = cast(str, row[0])
    assigned_by_raw = row[1]
    assigned_by_kind = row[2]
    if not isinstance(assigned_by_raw, str) or not isinstance(assigned_by_kind, str):
        raise PermanentStorageError("role binding assigned_by fields must be strings")
    assigned_by = (
        ServiceIdentity(assigned_by_raw)
        if assigned_by_kind == "service"
        else UserId(assigned_by_raw)
    )
    return RoleBinding(
        tenant_id=tenant_id,
        role=Role(role),
        assigned_by=assigned_by,
        assigned_at=cast("datetime", row[3]),
        expires_at=cast("datetime | None", row[4]),
        revoked_at=cast("datetime | None", row[5]),
    )


def _string_set(document: dict[str, object], key: str) -> frozenset[str]:
    value = document[key]
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{key} must be a list of strings")
    return frozenset(value)


def _required_int(document: dict[str, object], key: str) -> int:
    value = document[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    return value


__all__ = [
    "PostgresAuditStore",
    "PostgresIdentityDirectory",
    "PostgresPolicyRepository",
    "PostgresTenantRepository",
]
