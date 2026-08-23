"""Authenticated tenant-scoped Layer 9 control-plane API tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

from aegis_agent_platform.control_plane.api import ControlPlaneApp
from aegis_agent_platform.domain import (
    ContentReference,
    SandboxLinkage,
    sandbox_request_to_payload,
)
from aegis_agent_platform.identity import Role
from aegis_agent_platform.sandbox import (
    InMemorySandboxPolicyRepository,
    InMemorySandboxRepository,
    SandboxOperations,
    SandboxRequestService,
    StaticSandboxApprovalAuthority,
)
from aegis_agent_platform.tenancy import InMemoryTenantRepository, Tenant
from sandbox_helpers import UUIDs
from sandbox_helpers import binding as sandbox_binding
from sandbox_helpers import policy as sandbox_policy
from sandbox_helpers import request as sandbox_request
from security_helpers import (
    TENANT_ID,
    authentication_service,
    binding,
    identity_record,
    signing_fixture,
    token,
)
from test_api import request as api_request


def _app() -> tuple[ControlPlaneApp, str, object, object]:
    uuids = UUIDs("api")
    base = sandbox_request(uuids)
    tenant_spec = replace(
        base.spec,
        input_snapshot=ContentReference(
            f"aegis-input://{TENANT_ID}/snapshot",
            base.spec.input_snapshot.digest,
            base.spec.input_snapshot.size_bytes,
            base.spec.input_snapshot.media_type,
        ),
    )
    tenant_request = replace(
        base,
        linkage=SandboxLinkage(
            tenant_id=str(TENANT_ID),
            run_id=base.linkage.run_id,
            task_id=base.linkage.task_id,
            remediation_plan_id=base.linkage.remediation_plan_id,
            remediation_action_id=base.linkage.remediation_action_id,
            approval_id=base.linkage.approval_id,
        ),
        spec=tenant_spec,
    )
    policy = sandbox_policy(tenant_request)
    approval = sandbox_binding(tenant_request, policy)
    repository = InMemorySandboxRepository(uuid_factory=uuids)
    authority = StaticSandboxApprovalAuthority(
        frozenset({"approver-one", "approver-two"})
    )
    operations = SandboxOperations(
        repository,
        SandboxRequestService(
            repository,
            authority,
            clock=lambda: tenant_request.requested_at,
            uuid_factory=uuids,
        ),
        InMemorySandboxPolicyRepository((policy,)),
    )
    signing = signing_fixture()
    app = ControlPlaneApp(
        authentication=authentication_service(
            signing,
            records=(
                identity_record(
                    (
                        binding(
                            Role.OPERATOR,
                            assigned_at=tenant_request.requested_at
                            - timedelta(minutes=1),
                        ),
                    ),
                ),
            ),
        ),
        tenants=InMemoryTenantRepository((Tenant(TENANT_ID, "Tenant Alpha"),)),
        sandbox_operations=operations,
    )
    return app, token(signing), tenant_request, approval


def _approval_payload(approval: object) -> dict[str, object]:
    from aegis_agent_platform.domain import SandboxApprovalBinding

    if not isinstance(approval, SandboxApprovalBinding):
        raise TypeError("approval fixture is invalid")
    return {
        "action_digest": approval.action_digest,
        "action_id": str(approval.action_id),
        "approval_id": str(approval.approval_id),
        "approver_ids": approval.approver_ids,
        "expires_at": approval.expires_at.isoformat(),
        "issued_at": approval.issued_at.isoformat(),
        "plan_digest": approval.plan_digest,
        "plan_id": str(approval.plan_id),
        "policy_digest": approval.policy_digest,
        "purpose": approval.purpose.value,
        "risk": int(approval.risk),
        "schema_version": approval.schema_version,
        "spec_digest": approval.spec_digest,
    }


def test_sandbox_request_status_page_artifact_and_cleanup_routes() -> None:
    app, access_token, sandbox, approval = _app()
    from aegis_agent_platform.domain import SandboxRequest

    assert isinstance(sandbox, SandboxRequest)
    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes",
        app=app,
        authorization=f"Bearer {access_token}",
        method="POST",
        body=json.dumps(
            {
                "approval": _approval_payload(approval),
                "request": sandbox_request_to_payload(sandbox),
            }
        ).encode(),
    )
    assert status == 202
    assert body["sandbox_id"] == str(sandbox.sandbox_id)
    assert body["redacted"] is True

    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes/{sandbox.sandbox_id}",
        app=app,
        authorization=f"Bearer {access_token}",
    )
    assert status == 200
    assert body["status"] == "approved"
    assert "argv" not in body
    assert "environment" not in body

    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes",
        app=app,
        authorization=f"Bearer {access_token}",
    )
    assert status == 200
    assert len(body["sandboxes"]) == 1
    assert body["sandboxes"][0]["redacted"] is True

    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes/{sandbox.sandbox_id}/artifacts",
        app=app,
        authorization=f"Bearer {access_token}",
    )
    assert status == 200
    assert body == {"artifacts": [], "next_cursor": None, "redacted": True}

    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes/cleanup",
        app=app,
        authorization=f"Bearer {access_token}",
    )
    assert status == 200
    assert body == {"cleanup": [], "next_cursor": None, "redacted": True}


def test_sandbox_routes_reject_malformed_and_unconfigured_requests() -> None:
    app, access_token, _sandbox, _approval = _app()
    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes",
        app=app,
        authorization=f"Bearer {access_token}",
        method="POST",
        body=b"{}",
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_sandbox_request"

    unconfigured_signing = signing_fixture()
    unconfigured = ControlPlaneApp(
        authentication=authentication_service(
            unconfigured_signing,
            records=(identity_record((binding(Role.OPERATOR),)),),
        )
    )
    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes",
        app=unconfigured,
        authorization=f"Bearer {token(unconfigured_signing)}",
        method="POST",
        body=b"{}",
    )
    assert status == 503
    assert body["error"]["code"] == "sandbox_not_configured"

    status, body, _headers = api_request(
        f"/v1/tenants/{TENANT_ID}/sandboxes",
        app=app,
        authorization=f"Bearer {access_token}",
        query_string="after_sandbox_id=not-a-uuid",
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_cursor"
