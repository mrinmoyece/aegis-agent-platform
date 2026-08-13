"""Fixed-shape official Kubernetes controlled-action adapter tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from typing import cast

import pytest

from aegis_agent_platform.domain import ReconciliationOutcome
from aegis_agent_platform.integrations.kubernetes import (
    OfficialKubernetesActionAdapter,
    OfficialKubernetesClient,
)
from aegis_agent_platform.remediation import ControlledActionError
from remediation_helpers import CONTEXT, NOW, Clock, action


class FakeOfficialClient:
    def __init__(self) -> None:
        self.applied = False
        self.calls: list[tuple[object, ...]] = []

    async def deployment(
        self,
        namespace: str,
        name: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int = 65_536,
    ) -> Mapping[str, object]:
        self.calls.append(("deployment", namespace, name, timeout_seconds))
        return {
            "metadata": {
                "generation": 4,
                "name": name,
                "namespace": namespace,
                "resourceVersion": "rv-4",
            },
            "spec": {
                "replicas": 3,
                "template": {
                    "metadata": {
                        "annotations": (
                            {"aegis.github.com/restart-id": (action().idempotency_key)}
                            if self.applied
                            else {}
                        )
                    }
                },
            },
            "status": {"availableReplicas": 3, "observedGeneration": 4},
        }

    async def restart_deployment(
        self,
        namespace: str,
        name: str,
        *,
        idempotency_key: str,
        dry_run: bool,
        timeout_seconds: float,
        max_response_bytes: int = 65_536,
    ) -> Mapping[str, object]:
        self.calls.append(
            (
                "restart",
                namespace,
                name,
                idempotency_key,
                dry_run,
                timeout_seconds,
            )
        )
        if not dry_run:
            self.applied = True
        return {
            "metadata": {
                "name": name,
                "namespace": namespace,
                "resourceVersion": "rv-5",
            }
        }


def test_official_adapter_observes_dry_runs_executes_and_reconciles() -> None:
    selected = action()
    client = FakeOfficialClient()
    adapter = OfficialKubernetesActionAdapter(
        cast(OfficialKubernetesClient, client),
        tenant_id=str(CONTEXT.tenant_id),
        environment=selected.target.environment,
        clock=Clock(),
    )

    before = asyncio.run(adapter.observe(CONTEXT, selected))
    dry_run = asyncio.run(adapter.dry_run(CONTEXT, selected))
    result = asyncio.run(adapter.execute(CONTEXT, selected))
    reconciliation, after = asyncio.run(adapter.reconcile(CONTEXT, selected))

    assert before.values["deployment.available"] is True
    assert before.values["deployment.restart_observed"] is False
    assert dry_run.provider_reference == "kubernetes-dry-run"
    assert result.provider_reference == "kubernetes-restart"
    assert reconciliation is ReconciliationOutcome.APPLIED
    assert after.values["deployment.restart_observed"] is True
    assert all(call[1:3] == ("checkout", "checkout-api") for call in client.calls)
    with pytest.raises(ControlledActionError, match="no_safe"):
        asyncio.run(adapter.rollback(CONTEXT, selected))
    with pytest.raises(ControlledActionError, match="no_safe"):
        asyncio.run(adapter.compensate(CONTEXT, selected))


def test_official_client_uses_fixed_patch_path_and_dry_run_query() -> None:
    client = object.__new__(OfficialKubernetesClient)
    calls: list[tuple[object, ...]] = []

    def request_sync(
        method: str,
        path: str,
        query: Sequence[tuple[str, str | None]],
        timeout_seconds: float,
        max_response_bytes: int,
        accept: str,
        body: bytes | None,
        content_type: str | None,
    ) -> bytes:
        calls.append(
            (
                method,
                path,
                query,
                timeout_seconds,
                max_response_bytes,
                accept,
                body,
                content_type,
            )
        )
        return b'{"metadata":{"resourceVersion":"rv-safe"}}'

    client._request_sync = request_sync  # type: ignore[method-assign]
    response = asyncio.run(
        client.restart_deployment(
            "checkout",
            "checkout-api",
            idempotency_key="tenant:checkout:restart:1",
            dry_run=True,
            timeout_seconds=3,
        )
    )

    assert response["metadata"] == {"resourceVersion": "rv-safe"}
    assert calls[0][0] == "PATCH"
    assert calls[0][1] == ("/apis/apps/v1/namespaces/checkout/deployments/checkout-api")
    assert calls[0][2] == (("dryRun", "All"),)
    assert calls[0][7] == "application/merge-patch+json"
    patch = json.loads(cast(bytes, calls[0][6]))
    assert patch == {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "aegis.github.com/restart-id": "tenant:checkout:restart:1"
                    }
                }
            }
        }
    }
    with pytest.raises(ValueError, match="bounded"):
        asyncio.run(
            client.restart_deployment(
                "checkout",
                "checkout-api",
                idempotency_key="x" * 129,
                dry_run=False,
                timeout_seconds=3,
            )
        )


def test_official_transport_encodes_body_query_without_urllib3_fields() -> None:
    client = object.__new__(OfficialKubernetesClient)
    captured: dict[str, object] = {}

    class Response:
        status = 200

        def read(self, amount: int) -> bytes:
            del amount
            return b'{"metadata":{"resourceVersion":"rv-safe"}}'

        def release_conn(self) -> None:
            return None

        def close(self) -> None:
            return None

    class Pool:
        def request(self, method: str, url: str, **kwargs: object) -> Response:
            captured.update(method=method, url=url, **kwargs)
            return Response()

    class Api:
        def __init__(self) -> None:
            self.rest_client = type("RestClient", (), {"pool_manager": Pool()})()

        def update_params_for_auth(
            self,
            headers: dict[str, str],
            query: list[tuple[str, str]],
            auth: list[str],
        ) -> None:
            del headers, query, auth

    client._host = "https://cluster.invalid"
    client._api = Api()

    response = asyncio.run(
        client.restart_deployment(
            "checkout",
            "checkout-api",
            idempotency_key="tenant:checkout:restart:1",
            dry_run=True,
            timeout_seconds=3,
        )
    )

    assert response["metadata"] == {"resourceVersion": "rv-safe"}
    assert captured["method"] == "PATCH"
    assert str(captured["url"]).endswith("/deployments/checkout-api?dryRun=All")
    assert captured["fields"] is None
    assert isinstance(captured["body"], bytes)


def test_official_adapter_rejects_wrong_tenant_and_malformed_provider_data() -> None:
    selected = action()
    client = FakeOfficialClient()
    adapter = OfficialKubernetesActionAdapter(
        cast(OfficialKubernetesClient, client),
        tenant_id=str(CONTEXT.tenant_id),
        environment=selected.target.environment,
        clock=lambda: NOW,
    )
    from aegis_agent_platform.identity import TenantId
    from aegis_agent_platform.tenancy import TenantContext

    with pytest.raises(PermissionError, match="tenant"):
        asyncio.run(
            adapter.execute(
                TenantContext(TenantId("tenant-other")),
                selected,
            )
        )
    client.deployment = malformed_deployment  # type: ignore[method-assign]
    with pytest.raises(ControlledActionError, match="malformed"):
        asyncio.run(adapter.observe(CONTEXT, selected))


async def malformed_deployment(
    namespace: str,
    name: str,
    *,
    timeout_seconds: float,
    max_response_bytes: int = 65_536,
) -> Mapping[str, object]:
    del namespace, name, timeout_seconds, max_response_bytes
    return {"metadata": "not-an-object"}
