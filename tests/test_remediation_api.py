"""Authenticated, tenant-scoped, redacted Layer 8 API tests."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from uuid import uuid4

from aegis_agent_platform.audit import InMemoryAuditStore
from aegis_agent_platform.control_plane.api import ControlPlaneApp
from aegis_agent_platform.domain import plan_to_payload
from aegis_agent_platform.identity import IdentityRecord, PrincipalKind, Role, UserId
from aegis_agent_platform.policy import InMemoryPolicyRepository
from aegis_agent_platform.remediation import (
    InMemoryRemediationPolicyRepository,
    InMemoryRemediationRepository,
    RemediationApprovalService,
    RemediationOperations,
)
from aegis_agent_platform.tenancy import InMemoryTenantRepository, Tenant
from remediation_helpers import CONTEXT, NOW, TENANT_ID, Clock, plan
from security_helpers import (
    ISSUER,
    authentication_service,
    binding,
    signing_fixture,
    tenant_policy,
    token,
)
from test_api import bearer, request


def secured_remediation_app(
    operations: RemediationOperations,
    *,
    actor_id: str,
    role: Role,
) -> tuple[ControlPlaneApp, str]:
    signing = signing_fixture()
    subject = f"subject-{actor_id}"
    record = IdentityRecord(
        issuer=ISSUER,
        subject=subject,
        tenant_id=TENANT_ID,
        kind=PrincipalKind.USER,
        role_bindings=(
            binding(
                role,
                tenant_id=TENANT_ID,
                assigned_at=NOW - timedelta(hours=1),
            ),
        ),
        enabled=True,
        user_id=UserId(actor_id),
    )
    app = ControlPlaneApp(
        authentication=authentication_service(signing, records=(record,)),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Remediation tenant"),)),
        policies=InMemoryPolicyRepository((tenant_policy(),)),
        audit=InMemoryAuditStore(),
        remediation_operations=operations,
    )
    return app, token(
        signing,
        subject=subject,
        tenant_id=str(TENANT_ID),
    )


def test_authenticated_api_propose_quorum_status_list_and_revoke() -> None:
    repository = InMemoryRemediationRepository()
    approval_service = RemediationApprovalService(repository, clock=Clock())
    selected = plan(requested_by="operator")
    operations = RemediationOperations(
        repository,
        approval_service,
        InMemoryRemediationPolicyRepository((selected.approval_policy,)),
    )
    operator_app, operator_token = secured_remediation_app(
        operations,
        actor_id="operator",
        role=Role.OPERATOR,
    )
    path = f"/v1/tenants/{TENANT_ID}/remediations"
    status, body, _headers = request(
        path,
        app=operator_app,
        method="POST",
        authorization=bearer(operator_token),
        body=json.dumps(
            {
                "plan": plan_to_payload(selected),
                "idempotency_key": "api-proposal-1",
            }
        ).encode(),
    )
    assert status == 202
    assert body["accepted"] is True
    assert body["redacted"] is True

    events = asyncio.run(repository.load(CONTEXT, selected.plan_id))
    approval_id = str(
        next(
            event.payload["approval_id"]
            for event in events
            if event.event_type == "remediation.approval_requested.v1"
        )
    )
    decision_path = f"{path}/{selected.plan_id}/approvals/{approval_id}/decisions"
    for index, actor_id in enumerate(("approver-one", "approver-two"), start=1):
        approver_app, approver_token = secured_remediation_app(
            operations,
            actor_id=actor_id,
            role=Role.APPROVER,
        )
        decision_status, decision, _ = request(
            decision_path,
            app=approver_app,
            method="POST",
            authorization=bearer(approver_token),
            body=json.dumps(
                {
                    "decision_id": str(uuid4()),
                    "decision": "grant",
                    "rationale_code": "reviewed",
                    "comment": "independent bounded review",
                }
            ).encode(),
        )
        assert decision_status == 200
        assert decision["approval_count"] == index
        assert decision["redacted"] is True

    status_code, detail, _ = request(
        f"{path}/{selected.plan_id}",
        app=operator_app,
        authorization=bearer(operator_token),
    )
    assert status_code == 200
    assert detail["approvals"][0]["status"] == "granted"
    assert detail["redacted"] is True
    list_status, listing, _ = request(
        path,
        app=operator_app,
        authorization=bearer(operator_token),
    )
    assert list_status == 200
    assert len(listing["remediations"]) == 1
    assert listing["remediations"][0]["redacted"] is True

    approver_app, approver_token = secured_remediation_app(
        operations,
        actor_id="approver-one",
        role=Role.APPROVER,
    )
    revoke_status, revoked, _ = request(
        f"{path}/{selected.plan_id}/approvals/{approval_id}/revocations",
        app=approver_app,
        method="POST",
        authorization=bearer(approver_token),
        body=json.dumps(
            {
                "revocation_id": str(uuid4()),
                "rationale_code": "scope_withdrawn",
            }
        ).encode(),
    )
    assert revoke_status == 200
    assert revoked["status"] == "revoked"


def test_api_rejects_unauthorized_stale_malformed_and_cross_tenant_requests() -> None:
    repository = InMemoryRemediationRepository()
    selected = plan(requested_by="operator")
    operations = RemediationOperations(
        repository,
        RemediationApprovalService(repository, clock=Clock()),
        InMemoryRemediationPolicyRepository((selected.approval_policy,)),
    )
    viewer_app, viewer_token = secured_remediation_app(
        operations,
        actor_id="viewer",
        role=Role.VIEWER,
    )
    path = f"/v1/tenants/{TENANT_ID}/remediations"
    denied_status, denied, _ = request(
        path,
        app=viewer_app,
        method="POST",
        authorization=bearer(viewer_token),
        body=json.dumps(
            {
                "plan": plan_to_payload(selected),
                "idempotency_key": "forged",
            }
        ).encode(),
    )
    assert denied_status == 403
    assert denied["error"]["code"] == "remediation_proposal_denied"
    malformed_status, malformed, _ = request(
        path,
        app=viewer_app,
        method="POST",
        authorization=bearer(viewer_token),
        body=b'{"plan":',
    )
    assert malformed_status == 400
    assert malformed["error"]["code"] == "invalid_remediation_plan"
    cursor_status, cursor, _ = request(
        path,
        app=viewer_app,
        authorization=bearer(viewer_token),
        query_string="after_plan_id=not-a-uuid",
    )
    assert cursor_status == 400
    assert cursor["error"]["code"] == "invalid_cursor"
    cross_status, cross, _ = request(
        "/v1/tenants/tenant-other/remediations",
        app=viewer_app,
        authorization=bearer(viewer_token),
    )
    assert cross_status == 403
    assert cross["error"]["code"] == "permission_denied"

    missing_policy_operations = RemediationOperations(
        repository,
        RemediationApprovalService(repository, clock=Clock()),
        InMemoryRemediationPolicyRepository(()),
    )
    operator_app, operator_token = secured_remediation_app(
        missing_policy_operations,
        actor_id="operator",
        role=Role.OPERATOR,
    )
    missing_status, missing, _ = request(
        path,
        app=operator_app,
        method="POST",
        authorization=bearer(operator_token),
        body=json.dumps(
            {
                "plan": plan_to_payload(selected),
                "idempotency_key": "missing-policy",
            }
        ).encode(),
    )
    assert missing_status == 403
    assert missing["error"]["code"] == "remediation_policy_not_configured"


def test_readiness_reports_remediation_capability_without_secrets() -> None:
    repository = InMemoryRemediationRepository()
    selected = plan(requested_by="operator")
    operations = RemediationOperations(
        repository,
        RemediationApprovalService(repository, clock=Clock()),
        InMemoryRemediationPolicyRepository((selected.approval_policy,)),
    )
    app, _encoded = secured_remediation_app(
        operations,
        actor_id="operator",
        role=Role.OPERATOR,
    )

    status, body, _ = request("/readyz", app=app)

    assert status == 200
    assert body["capabilities"]["remediation"] == "configured"
    assert "token" not in repr(body).lower()
