"""Mocked connector security and normalization tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis_agent_platform.domain import (
    DeploymentReference,
    EnvironmentIdentity,
    EvidenceKind,
    EvidenceSourceKind,
    PaginationCursor,
    QueryWindow,
    SpanReference,
)
from aegis_agent_platform.evidence import (
    ConnectorError,
    ConnectorErrorClass,
    EvidenceQuery,
    HttpRequest,
    HttpResponse,
)
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.integrations.config import (
    ConnectorLimits,
    DynatraceConnectorConfig,
    GitHubConnectorConfig,
    KubernetesConnectorConfig,
    RunbookConnectorConfig,
)
from aegis_agent_platform.integrations.dynatrace import DynatraceAdapter
from aegis_agent_platform.integrations.github import GitHubAdapter
from aegis_agent_platform.integrations.kubernetes import KubernetesAdapter
from aegis_agent_platform.integrations.runbooks import (
    LocalRunbookSource,
    RunbookAdapter,
    RunbookDocument,
)
from aegis_agent_platform.secrets_boundary import (
    InMemorySecretProvider,
    SecretReference,
)
from aegis_agent_platform.tenancy import TenantContext

TENANT = TenantId("tenant-connectors")
CONTEXT = TenantContext(TENANT)
NOW = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
WINDOW = QueryWindow(NOW - timedelta(minutes=10), NOW)
CLIENT_ID = SecretReference(TENANT, "memory", "dynatrace-client", "1")
CLIENT_SECRET = SecretReference(TENANT, "memory", "dynatrace-secret", "1")
GITHUB_KEY = SecretReference(TENANT, "memory", "github-key", "1")


class MockTransport:
    def __init__(self, responses: Sequence[HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[HttpRequest] = []

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        return self.responses.pop(0)


def response(
    value: object, *, status: int = 200, headers: dict[str, str] | None = None
) -> HttpResponse:
    return HttpResponse(
        status,
        headers or {},
        json.dumps(value, separators=(",", ":")).encode(),
    )


def evidence_query(
    source: EvidenceSourceKind,
    kinds: tuple[EvidenceKind, ...],
    selectors: Mapping[str, str],
) -> EvidenceQuery:
    return EvidenceQuery(
        uuid4(),
        str(TENANT),
        source,
        EnvironmentIdentity("production"),
        WINDOW,
        kinds,
        selectors,
        50,
        f"{source.value}-query",
    )


def test_dynatrace_oauth_safe_dql_and_completed_grail_result() -> None:
    transport = MockTransport(
        (
            response({"access_token": "short-lived"}),
            response(
                {
                    "records": [
                        {
                            "timestamp": "2026-08-13T08:59:00Z",
                            "content": "checkout failed",
                            "service.name": "checkout",
                        }
                    ],
                    "requestToken": "next-page",
                }
            ),
        )
    )
    config = DynatraceConnectorConfig(
        TENANT,
        "production",
        "https://tenant.live.dynatrace.com",
        "https://sso.dynatrace.com",
        CLIENT_ID,
        CLIENT_SECRET,
        ("storage:logs:read",),
        enabled=True,
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        config,
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )

    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.DYNATRACE,
                (EvidenceKind.LOG,),
                {"service": "checkout"},
            )
        )
    )

    assert not page.result.partial
    assert page.next_cursor is None
    assert b"fetch logs" in (transport.requests[1].body or b"")
    assert b"checkout" in (transport.requests[1].body or b"")
    assert "short-lived" not in repr(page)
    assert asyncio.run(adapter.capability()).api_version == "environment-v2+grail-v1"


def test_dynatrace_grail_execution_polls_within_bounds() -> None:
    transport = MockTransport(
        (
            response({"access_token": "short-lived"}),
            response({"requestToken": "request-1", "state": "RUNNING"}),
            response(
                {
                    "state": "SUCCEEDED",
                    "records": [
                        {
                            "timestamp": "2026-08-13T08:59:00Z",
                            "content": "checkout failed",
                        }
                    ],
                }
            ),
        )
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("storage:logs:read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )

    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.DYNATRACE,
                (EvidenceKind.LOG,),
                {},
            )
        )
    )

    assert len(page.records) == 1
    assert "query:poll?" in transport.requests[2].url


def test_dynatrace_normalizes_documented_rest_collection_keys() -> None:
    transport = MockTransport(
        (
            response({"access_token": "short-lived"}),
            response(
                {
                    "entities": [
                        {
                            "entityId": "SERVICE-1",
                            "lastSeenTms": 1_786_611_540_000,
                            "displayName": "checkout",
                        }
                    ]
                }
            ),
            response({"access_token": "short-lived"}),
            response(
                {
                    "events": [
                        {
                            "eventId": "EVENT-1",
                            "startTime": "2026-08-13T08:59:00Z",
                            "title": "deployment",
                        }
                    ]
                }
            ),
            response({"access_token": "short-lived"}),
            response(
                {
                    "problems": [
                        {
                            "problemId": "PROBLEM-1",
                            "startTime": "2026-08-13T08:58:00Z",
                            "title": "checkout failures",
                        }
                    ]
                }
            ),
        )
    )
    config = DynatraceConnectorConfig(
        TENANT,
        "production",
        "https://tenant.live.dynatrace.com",
        "https://sso.dynatrace.com",
        CLIENT_ID,
        CLIENT_SECRET,
        ("environment-api:read",),
        enabled=True,
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        config,
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )

    pages = tuple(
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.DYNATRACE,
                    (kind,),
                    {},
                )
            )
        )
        for kind in (EvidenceKind.ENTITY, EvidenceKind.EVENT, EvidenceKind.PROBLEM)
    )

    assert {item.source_record_id for page in pages for item in page.records} == {
        "SERVICE-1",
        "EVENT-1",
        "PROBLEM-1",
    }


def test_dynatrace_rest_cursor_resumes_only_the_paginated_kind() -> None:
    transport = MockTransport(
        (
            response({"access_token": "token-one"}),
            response(
                {
                    "entities": [
                        {
                            "entityId": "SERVICE-1",
                            "lastSeenTms": 1_786_611_540_000,
                            "displayName": "checkout",
                        }
                    ],
                    "nextPageKey": "vendor-next",
                }
            ),
            response({"access_token": "token-two"}),
            response(
                {
                    "entities": [
                        {
                            "entityId": "SERVICE-2",
                            "lastSeenTms": 1_786_611_550_000,
                            "displayName": "checkout-2",
                        }
                    ]
                }
            ),
        )
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("environment-api:read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )
    query = evidence_query(
        EvidenceSourceKind.DYNATRACE,
        (EvidenceKind.ENTITY,),
        {},
    )

    first = asyncio.run(adapter.query(query))
    second = asyncio.run(adapter.query(replace(query, cursor=first.next_cursor)))

    assert first.next_cursor is not None
    assert second.next_cursor is None
    assert "nextPageKey=vendor-next" in transport.requests[3].url


def test_dynatrace_span_normalization_retains_time_and_identifiers() -> None:
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("storage:spans:read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        MockTransport(
            (
                response({"access_token": "short-lived"}),
                response(
                    {
                        "records": [
                            {
                                "start_time": "2026-08-13T08:59:00Z",
                                "trace.id": "trace-1",
                                "span.id": "span-1",
                                "service.name": "checkout",
                            }
                        ]
                    }
                ),
            )
        ),
    )

    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.DYNATRACE,
                (EvidenceKind.SPAN,),
                {"service": "checkout"},
            )
        )
    )

    assert page.records[0].source_record_id == "span-1"
    assert page.records[0].references == (SpanReference("trace-1", "span-1"),)


def test_dynatrace_trace_rows_aggregate_spans_without_identity_conflicts() -> None:
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("storage:spans:read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        MockTransport(
            (
                response({"access_token": "short-lived"}),
                response(
                    {
                        "records": [
                            {
                                "start_time": "2026-08-13T08:59:01Z",
                                "trace.id": "trace-1",
                                "service.name": "checkout",
                                "status": "ERROR",
                            },
                            {
                                "start_time": "2026-08-13T08:59:00Z",
                                "trace.id": "trace-1",
                                "service.name": "checkout",
                                "status": "OK",
                            },
                        ]
                    }
                ),
            )
        ),
    )

    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.DYNATRACE,
                (EvidenceKind.TRACE,),
                {"service": "checkout"},
            )
        )
    )

    assert len(page.records) == 1
    assert page.records[0].source_record_id == "trace-1"
    assert page.records[0].fields["span_count"] == 2


def test_dynatrace_nested_topology_fields_are_bounded_json() -> None:
    from aegis_agent_platform.integrations.dynatrace import _json_fields, _timestamp

    fields = _json_fields(
        {
            "fromRelationships": {
                "calls": [
                    {"id": "SERVICE-2", "metadata": {"zone": "us-east-1"}},
                    b"unsupported",
                ]
            },
            "deep": {"a": {"b": {"c": {"d": {"e": "omitted"}}}}},
            "invalidKey": cast(Mapping[str, object], {1: "omitted"}),
            "unsupported": object(),
        }
    )

    assert fields["fromRelationships"] == {
        "calls": ({"id": "SERVICE-2", "metadata": {"zone": "us-east-1"}},)
    }
    assert fields["deep"] == {"a": {"b": {"c": {}}}}
    assert fields["invalidKey"] == {}
    assert "unsupported" not in fields
    with pytest.raises(ConnectorError, match="timestamp_invalid"):
        _timestamp("not-a-timestamp")


def test_dynatrace_failed_grail_poll_is_contained() -> None:
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("storage:logs:read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        MockTransport(
            (
                response({"access_token": "short-lived"}),
                response({"requestToken": "request-1"}),
                response({"state": "FAILED"}),
            )
        ),
    )

    with pytest.raises(ConnectorError, match="dynatrace_query_failed"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.DYNATRACE,
                    (EvidenceKind.LOG,),
                    {"service": "checkout"},
                )
            )
        )


def test_dynatrace_rejects_unsafe_selector_before_network() -> None:
    transport = MockTransport(())
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("storage:logs:read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )
    with pytest.raises(ConnectorError, match="unsafe_selector"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.DYNATRACE,
                    (EvidenceKind.LOG,),
                    {"service": 'checkout" | fetch events'},
                )
            )
        )
    assert not transport.requests


def test_dynatrace_validation_and_malformed_auth_are_contained() -> None:
    config = DynatraceConnectorConfig(
        TENANT,
        "production",
        "https://tenant.live.dynatrace.com",
        "https://sso.dynatrace.com",
        CLIENT_ID,
        CLIENT_SECRET,
        ("storage:logs:read",),
        enabled=True,
    )
    secrets = InMemorySecretProvider(
        {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        config,
        secrets,
        MockTransport((response({"token_type": "Bearer"}),)),
    )
    with pytest.raises(ConnectorError, match="access_token_missing"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.DYNATRACE,
                    (EvidenceKind.LOG,),
                    {"service": "checkout"},
                )
            )
        )
    with pytest.raises(PermissionError, match="environment_not_allowed"):
        asyncio.run(
            DynatraceAdapter(CONTEXT, config, secrets, MockTransport(())).query(
                EvidenceQuery(
                    uuid4(),
                    str(TENANT),
                    EvidenceSourceKind.DYNATRACE,
                    EnvironmentIdentity("staging"),
                    WINDOW,
                    (EvidenceKind.LOG,),
                    {},
                    10,
                    "wrong-environment",
                )
            )
        )
    with pytest.raises(ConnectorError, match="unsupported_evidence_kind"):
        asyncio.run(
            DynatraceAdapter(CONTEXT, config, secrets, MockTransport(())).query(
                evidence_query(
                    EvidenceSourceKind.DYNATRACE,
                    (EvidenceKind.COMMIT,),
                    {},
                )
            )
        )
    with pytest.raises(PermissionError, match="cross_tenant_connector"):
        DynatraceAdapter(
            TenantContext(TenantId("other")),
            config,
            secrets,
            MockTransport(()),
        )


def github_private_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_github_app_auth_allowlist_pagination_and_patch_omission() -> None:
    transport = MockTransport(
        (
            response({"token": "installation-token"}),
            response(
                [
                    {
                        "sha": "abc123",
                        "html_url": "https://github.com/org/repo/commit/abc123",
                        "commit": {
                            "message": "deploy checkout",
                            "author": {"date": "2026-08-13T08:58:00Z"},
                        },
                        "patch": "secret=must-not-ingest",
                    }
                ],
                headers={
                    "link": '<https://api.github.com/page=2>; rel="next"',
                    "etag": '"commit-page"',
                },
            ),
        )
    )
    config = GitHubConnectorConfig(
        TENANT,
        "1234",
        99,
        GITHUB_KEY,
        frozenset({"org/repo"}),
        enabled=True,
    )
    adapter = GitHubAdapter(
        CONTEXT,
        config,
        InMemorySecretProvider({GITHUB_KEY: github_private_key()}),
        transport,
        clock=lambda: NOW,
    )

    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.GITHUB,
                (EvidenceKind.COMMIT,),
                {"repository": "org/repo"},
            )
        )
    )

    assert page.next_cursor is not None
    assert "patch" not in page.records[0].fields
    assert page.records[0].summary == "deploy checkout"
    assert transport.requests[1].headers["x-github-api-version"] == "2022-11-28"
    assert transport.requests[0].headers["authorization"].startswith("Bearer ey")
    with pytest.raises(PermissionError, match="repository_not_allowed"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.GITHUB,
                    (EvidenceKind.COMMIT,),
                    {"repository": "org/private"},
                )
            )
        )


def test_github_review_and_tag_metadata_use_source_timestamps() -> None:
    config = GitHubConnectorConfig(
        TENANT,
        "1234",
        99,
        GITHUB_KEY,
        frozenset({"org/repo"}),
        enabled=True,
    )
    secrets = InMemorySecretProvider({GITHUB_KEY: github_private_key()})
    review_transport = MockTransport(
        (
            response({"token": "installation-token"}),
            response(
                [
                    {
                        "id": 42,
                        "submitted_at": "2026-08-13T08:58:00Z",
                        "body": "approved",
                        "html_url": "https://github.com/org/repo/pull/7#review-42",
                    }
                ]
            ),
        )
    )
    review_adapter = GitHubAdapter(
        CONTEXT,
        config,
        secrets,
        review_transport,
        clock=lambda: NOW,
    )

    review_page = asyncio.run(
        review_adapter.query(
            evidence_query(
                EvidenceSourceKind.GITHUB,
                (EvidenceKind.REVIEW,),
                {"repository": "org/repo", "pull_request": "7"},
            )
        )
    )

    assert review_page.records[0].source_record_id == "42"
    assert "/pulls/7/reviews?" in review_transport.requests[1].url

    tag_transport = MockTransport(
        (
            response({"token": "installation-token"}),
            response(
                [
                    {
                        "name": "v1.2.3",
                        "commit": {
                            "sha": "abc123",
                            "url": "https://api.github.com/repos/org/repo/commits/abc123",
                        },
                    }
                ]
            ),
            response(
                {
                    "object": {
                        "type": "tag",
                        "url": "https://api.github.com/repos/org/repo/git/tags/tag-object",
                    }
                }
            ),
            response(
                {
                    "tagger": {"date": "2026-08-13T08:57:00Z"},
                    "object": {"type": "commit", "sha": "abc123"},
                }
            ),
        )
    )
    tag_adapter = GitHubAdapter(
        CONTEXT,
        config,
        secrets,
        tag_transport,
        clock=lambda: NOW,
    )

    tag_page = asyncio.run(
        tag_adapter.query(
            evidence_query(
                EvidenceSourceKind.GITHUB,
                (EvidenceKind.TAG,),
                {"repository": "org/repo"},
            )
        )
    )

    assert tag_page.records[0].summary == "v1.2.3"
    assert tag_page.records[0].observed_at == datetime(2026, 8, 13, 8, 57, tzinfo=UTC)


def test_github_validation_auth_and_malformed_records_fail_closed() -> None:
    config = GitHubConnectorConfig(
        TENANT,
        "1234",
        99,
        GITHUB_KEY,
        frozenset({"org/repo"}),
        enabled=True,
    )
    request = evidence_query(
        EvidenceSourceKind.GITHUB,
        (EvidenceKind.COMMIT,),
        {"repository": "org/repo"},
    )
    missing_token = GitHubAdapter(
        CONTEXT,
        config,
        InMemorySecretProvider({GITHUB_KEY: github_private_key()}),
        MockTransport((response({}),)),
        clock=lambda: NOW,
    )
    with pytest.raises(ConnectorError, match="installation_token_missing"):
        asyncio.run(missing_token.query(request))
    invalid_key = GitHubAdapter(
        CONTEXT,
        config,
        InMemorySecretProvider({GITHUB_KEY: b"not-a-private-key"}),
        MockTransport(()),
        clock=lambda: NOW,
    )
    with pytest.raises(ConnectorError, match="private_key_invalid"):
        asyncio.run(invalid_key.query(request))
    malformed = GitHubAdapter(
        CONTEXT,
        config,
        InMemorySecretProvider({GITHUB_KEY: github_private_key()}),
        MockTransport(
            (
                response({"token": "installation-token"}),
                response([{"commit": {"message": "missing identity"}}]),
            )
        ),
        clock=lambda: NOW,
    )
    with pytest.raises(ConnectorError, match="record_id_missing"):
        asyncio.run(malformed.query(request))
    assert asyncio.run(malformed.capability()).detail_code == "github_app_installation"
    with pytest.raises(PermissionError, match="cross_tenant_connector"):
        GitHubAdapter(
            TenantContext(TenantId("other")),
            config,
            InMemorySecretProvider({GITHUB_KEY: github_private_key()}),
            MockTransport(()),
        )


class FakeKubernetesClient:
    async def list_resources(
        self,
        kind: EvidenceKind,
        namespace: str,
        *,
        label_selector: str | None,
        name: str | None,
        limit: int,
        continue_token: str | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Sequence[Mapping[str, object]], str | None]:
        del kind, label_selector, name, limit, continue_token, timeout_seconds
        del max_response_bytes
        return (
            (
                {
                    "metadata": {
                        "name": "checkout",
                        "uid": "uid-1",
                        "creationTimestamp": "2026-08-13T08:55:00Z",
                        "labels": {"app": "checkout"},
                        "annotations": {"deployment.kubernetes.io/revision": "7"},
                    },
                    "spec": {
                        "replicas": 3,
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "image": (
                                            "registry.example/checkout@sha256:"
                                            + ("a" * 64)
                                        )
                                    }
                                ]
                            }
                        },
                    },
                    "status": {
                        "readyReplicas": 2,
                        "containerStatuses": [
                            {"state": {"terminated": {"reason": "CrashLoopBackOff"}}}
                        ],
                    },
                },
            ),
            "continue-token",
        )

    async def pod_logs(
        self,
        namespace: str,
        pod: str,
        *,
        since_seconds: int,
        tail_lines: int,
        limit_bytes: int,
        timeout_seconds: float,
    ) -> str:
        del namespace, pod, since_seconds, tail_lines, limit_bytes, timeout_seconds
        return "line one\nline two"


def test_kubernetes_namespace_rbac_shape_and_log_policy() -> None:
    adapter = KubernetesAdapter(
        CONTEXT,
        KubernetesConnectorConfig(
            TENANT,
            "cluster-a",
            frozenset({"checkout"}),
            enabled=True,
        ),
        FakeKubernetesClient(),
    )
    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.KUBERNETES,
                (EvidenceKind.WORKLOAD,),
                {"namespace": "checkout", "name": "checkout"},
            )
        )
    )
    assert page.next_cursor is not None
    assert page.records[0].resource is not None
    assert page.records[0].fields["readyReplicas"] == 2
    assert page.records[0].fields["terminationReasons"] == ("CrashLoopBackOff",)
    reference = page.records[0].references[0]
    assert isinstance(reference, DeploymentReference)
    assert reference.image_digest == "sha256:" + ("a" * 64)
    with pytest.raises(PermissionError, match="logs_not_allowed"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.KUBERNETES,
                    (EvidenceKind.LOG,),
                    {"namespace": "checkout", "pod": "checkout-1"},
                )
            )
        )
    with pytest.raises(PermissionError, match="namespace_not_allowed"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.KUBERNETES,
                    (EvidenceKind.POD,),
                    {"namespace": "kube-system"},
                )
            )
        )


def test_kubernetes_bounded_logs_are_explicitly_truncated() -> None:
    class LargeLogClient(FakeKubernetesClient):
        async def pod_logs(
            self,
            namespace: str,
            pod: str,
            *,
            since_seconds: int,
            tail_lines: int,
            limit_bytes: int,
            timeout_seconds: float,
        ) -> str:
            del namespace, pod, since_seconds, tail_lines, limit_bytes, timeout_seconds
            return "x" * 2_000

    adapter = KubernetesAdapter(
        CONTEXT,
        KubernetesConnectorConfig(
            TENANT,
            "cluster-a",
            frozenset({"checkout"}),
            allow_logs=True,
            max_log_bytes=1024,
            enabled=True,
        ),
        LargeLogClient(),
    )
    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.KUBERNETES,
                (EvidenceKind.LOG,),
                {
                    "namespace": "checkout",
                    "pod": "checkout-1",
                    "service": "checkout",
                },
            )
        )
    )
    assert page.result.truncated
    assert page.records[0].fields["truncated"] is True
    assert len(str(page.records[0].fields["content"]).encode()) == 1024


def test_kubernetes_validation_capabilities_and_malformed_resources() -> None:
    config = KubernetesConnectorConfig(
        TENANT,
        "cluster-a",
        frozenset({"checkout"}),
        enabled=True,
    )
    adapter = KubernetesAdapter(CONTEXT, config, FakeKubernetesClient())
    capability = asyncio.run(adapter.capability())
    assert EvidenceKind.LOG not in capability.kinds
    with pytest.raises(ConnectorError, match="unsafe_kubernetes_selector"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.KUBERNETES,
                    (EvidenceKind.POD,),
                    {"namespace": "checkout", "name": "../secret"},
                )
            )
        )
    with pytest.raises(PermissionError, match="cross_tenant_connector"):
        KubernetesAdapter(
            TenantContext(TenantId("other")),
            config,
            FakeKubernetesClient(),
        )

    class MalformedClient(FakeKubernetesClient):
        async def list_resources(
            self,
            kind: EvidenceKind,
            namespace: str,
            *,
            label_selector: str | None,
            name: str | None,
            limit: int,
            continue_token: str | None,
            timeout_seconds: float,
            max_response_bytes: int,
        ) -> tuple[Sequence[Mapping[str, object]], str | None]:
            del kind, namespace, label_selector, name
            del limit, continue_token, timeout_seconds, max_response_bytes
            return (({"metadata": {}},), None)

    with pytest.raises(ConnectorError, match="identity_missing"):
        asyncio.run(
            KubernetesAdapter(CONTEXT, config, MalformedClient()).query(
                evidence_query(
                    EvidenceSourceKind.KUBERNETES,
                    (EvidenceKind.POD,),
                    {"namespace": "checkout"},
                )
            )
        )


def test_kubernetes_cursor_resumes_one_collection_and_rejects_multi_kind() -> None:
    class CursorClient(FakeKubernetesClient):
        def __init__(self) -> None:
            self.calls: list[tuple[EvidenceKind, str | None]] = []

        async def list_resources(
            self,
            kind: EvidenceKind,
            namespace: str,
            *,
            label_selector: str | None,
            name: str | None,
            limit: int,
            continue_token: str | None,
            timeout_seconds: float,
            max_response_bytes: int,
        ) -> tuple[Sequence[Mapping[str, object]], str | None]:
            self.calls.append((kind, continue_token))
            records, _ = await super().list_resources(
                kind,
                namespace,
                label_selector=label_selector,
                name=name,
                limit=limit,
                continue_token=continue_token,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            token = None if continue_token is not None else f"{kind.value}-next"
            return records, token

    client = CursorClient()
    adapter = KubernetesAdapter(
        CONTEXT,
        KubernetesConnectorConfig(
            TENANT,
            "cluster-a",
            frozenset({"checkout"}),
            enabled=True,
        ),
        client,
    )
    query = evidence_query(
        EvidenceSourceKind.KUBERNETES,
        (EvidenceKind.POD,),
        {"namespace": "checkout"},
    )

    first = asyncio.run(adapter.query(query))
    assert first.next_cursor is not None
    asyncio.run(adapter.query(replace(query, cursor=first.next_cursor)))

    assert client.calls == [
        (EvidenceKind.POD, None),
        (EvidenceKind.POD, "pod-next"),
    ]
    with pytest.raises(ConnectorError, match="single_kind_required"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.KUBERNETES,
                    (EvidenceKind.EVENT, EvidenceKind.POD),
                    {"namespace": "checkout"},
                )
            )
        )
    with pytest.raises(ConnectorError, match="connector_cursor_invalid"):
        asyncio.run(
            adapter.query(replace(query, cursor=PaginationCursor("not-base64")))
        )


def test_dynatrace_environment_api_metric_normalization() -> None:
    transport = MockTransport(
        (
            response({"access_token": "short-lived"}),
            response(
                {
                    "result": [
                        {
                            "metricId": "builtin:service.errors.total",
                            "data": [
                                {
                                    "timestamps": [
                                        int(
                                            (NOW - timedelta(minutes=1)).timestamp()
                                            * 1000
                                        )
                                    ],
                                    "values": [7],
                                }
                            ],
                        }
                    ]
                }
            ),
        )
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("metrics.read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )
    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.DYNATRACE,
                (EvidenceKind.METRIC,),
                {"service": "checkout"},
            )
        )
    )
    assert page.records[0].kind is EvidenceKind.METRIC
    assert "metricSelector=" in transport.requests[1].url


def test_dynatrace_metric_cap_does_not_skip_with_upstream_cursor() -> None:
    timestamp = int((NOW - timedelta(minutes=1)).timestamp() * 1000)
    transport = MockTransport(
        (
            response({"access_token": "short-lived"}),
            response(
                {
                    "result": [
                        {
                            "metricId": "builtin:service.errors.total",
                            "data": [
                                {
                                    "timestamps": [timestamp, timestamp + 1000],
                                    "values": [7, 8],
                                }
                            ],
                        }
                    ],
                    "nextPageKey": "next-series-page",
                }
            ),
        )
    )
    adapter = DynatraceAdapter(
        CONTEXT,
        DynatraceConnectorConfig(
            TENANT,
            "production",
            "https://tenant.live.dynatrace.com",
            "https://sso.dynatrace.com",
            CLIENT_ID,
            CLIENT_SECRET,
            ("metrics.read",),
            enabled=True,
        ),
        InMemorySecretProvider(
            {CLIENT_ID: b"client-id", CLIENT_SECRET: b"client-secret"}
        ),
        transport,
    )
    query = replace(
        evidence_query(
            EvidenceSourceKind.DYNATRACE,
            (EvidenceKind.METRIC,),
            {"service": "checkout"},
        ),
        limit=1,
    )

    page = asyncio.run(adapter.query(query))

    assert len(page.records) == 1
    assert page.next_cursor is None
    assert page.result.truncated
    assert page.result.reasons == ("record_cap",)


def test_github_check_collection_and_unexpected_not_modified_is_partial() -> None:
    transport = MockTransport(
        (
            response({"token": "installation-token"}),
            response(
                {
                    "check_runs": [
                        {
                            "id": 5,
                            "name": "integration",
                            "status": "completed",
                            "conclusion": "failure",
                            "head_sha": "abc123",
                            "started_at": "2026-08-13T08:57:00Z",
                            "completed_at": "2026-08-13T08:58:00Z",
                            "html_url": "https://github.com/org/repo/runs/5",
                        }
                    ]
                },
                headers={"etag": '"check-page"'},
            ),
            response({"token": "installation-token"}),
            HttpResponse(304, {}, b""),
        )
    )
    adapter = GitHubAdapter(
        CONTEXT,
        GitHubConnectorConfig(
            TENANT,
            "1234",
            99,
            GITHUB_KEY,
            frozenset({"org/repo"}),
            enabled=True,
        ),
        InMemorySecretProvider({GITHUB_KEY: github_private_key()}),
        transport,
        clock=lambda: NOW,
    )
    request = evidence_query(
        EvidenceSourceKind.GITHUB,
        (EvidenceKind.CHECK,),
        {"repository": "org/repo", "ref": "abc123"},
    )
    first = asyncio.run(adapter.query(request))
    second = asyncio.run(adapter.query(request))
    assert first.records[0].fields["conclusion"] == "failure"
    assert second.records == ()
    assert second.result.partial
    assert second.result.reasons == ("not_modified_without_cached_representation",)
    assert "if-none-match" not in transport.requests[3].headers


def test_github_compare_range_ingests_metadata_without_patch_content() -> None:
    transport = MockTransport(
        (
            response({"token": "installation-token"}),
            response(
                {
                    "sha": "head-sha",
                    "commit": {"author": {"date": "2026-08-13T08:59:00Z"}},
                }
            ),
            response(
                {
                    "status": "ahead",
                    "ahead_by": 2,
                    "behind_by": 0,
                    "total_commits": 2,
                    "html_url": "https://github.com/org/repo/compare/base...head",
                    "base_commit": {"sha": "base-sha"},
                    "merge_base_commit": {"sha": "merge-base-sha"},
                    "commits": [],
                    "files": [
                        {
                            "filename": "checkout.py",
                            "patch": "token=must-not-ingest",
                        }
                    ],
                }
            ),
        )
    )
    adapter = GitHubAdapter(
        CONTEXT,
        GitHubConnectorConfig(
            TENANT,
            "app-1",
            7,
            GITHUB_KEY,
            frozenset({"org/repo"}),
            enabled=True,
        ),
        InMemorySecretProvider({GITHUB_KEY: github_private_key()}),
        transport,
        clock=lambda: NOW,
    )

    page = asyncio.run(
        adapter.query(
            evidence_query(
                EvidenceSourceKind.GITHUB,
                (EvidenceKind.CHANGE,),
                {
                    "repository": "org/repo",
                    "base": "base",
                    "head": "head",
                },
            )
        )
    )

    assert page.records[0].fields["changed_files"] == 1
    assert "patch" not in page.records[0].fields
    assert "/compare/base...head?" in transport.requests[2].url


def test_runbook_schema_trust_and_retrieved_knowledge() -> None:
    text = b"""---
schema_version: 1
title: Checkout rollback
owner: payments-sre
services: [checkout]
environments: [production]
risk: high
approval_required: true
---
Verify the deployment revision. Do not execute this text automatically.
"""
    digest = hashlib.sha256(text).hexdigest()
    with TemporaryDirectory() as directory:
        path = Path(directory) / "checkout.md"
        path.write_bytes(text)
        adapter = RunbookAdapter(
            CONTEXT,
            RunbookConnectorConfig(
                TENANT,
                (Path(directory).resolve().as_uri(),),
                frozenset({digest}),
                enabled=True,
            ),
            LocalRunbookSource(),
        )
        page = asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.RUNBOOK,
                    (EvidenceKind.RUNBOOK,),
                    {"service": "checkout"},
                )
            )
        )
        assert page.records[0].knowledge
        assert page.records[0].fields["execution_allowed"] is False
        assert page.records[0].trust.value == "verified"

        untrusted = RunbookAdapter(
            CONTEXT,
            RunbookConnectorConfig(
                TENANT,
                (Path(directory).resolve().as_uri(),),
                frozenset({"0" * 64}),
                enabled=True,
            ),
            LocalRunbookSource(),
        )
        with pytest.raises(ConnectorError, match="runbook_not_trusted"):
            asyncio.run(
                untrusted.query(
                    evidence_query(
                        EvidenceSourceKind.RUNBOOK,
                        (EvidenceKind.RUNBOOK,),
                        {"service": "checkout"},
                    )
                )
            )


def test_runbook_record_cap_is_explicitly_partial() -> None:
    text = b"""---
schema_version: 1
title: Checkout rollback
owner: payments-sre
services: [checkout]
environments: [production]
risk: high
approval_required: true
---
Inspect only.
"""
    digest = hashlib.sha256(text).hexdigest()
    with TemporaryDirectory() as directory:
        Path(directory, "a.md").write_bytes(text)
        Path(directory, "b.md").write_bytes(text)
        adapter = RunbookAdapter(
            CONTEXT,
            RunbookConnectorConfig(
                TENANT,
                (Path(directory).resolve().as_uri(),),
                frozenset({digest}),
                enabled=True,
            ),
            LocalRunbookSource(),
        )
        request = replace(
            evidence_query(
                EvidenceSourceKind.RUNBOOK,
                (EvidenceKind.RUNBOOK,),
                {"service": "checkout"},
            ),
            limit=1,
        )

        page = asyncio.run(adapter.query(request))
        second = asyncio.run(adapter.query(replace(request, cursor=page.next_cursor)))

    assert len(page.records) == 1
    assert page.result.partial
    assert page.result.truncated
    assert page.result.reasons == ("record_cap",)
    assert page.next_cursor is not None
    assert second.records[0].source_record_id.startswith("b.md@")
    assert second.next_cursor is None


def test_runbook_filtering_scans_past_unrelated_documents() -> None:
    unrelated = b"""---
schema_version: 1
title: Inventory
owner: platform-sre
services: [inventory]
environments: [production]
risk: low
approval_required: false
---
Inspect inventory.
"""
    applicable = unrelated.replace(b"Inventory", b"Checkout").replace(
        b"inventory",
        b"checkout",
    )
    with TemporaryDirectory() as directory:
        Path(directory, "a-unrelated.md").write_bytes(unrelated)
        Path(directory, "b-checkout.md").write_bytes(applicable)
        adapter = RunbookAdapter(
            CONTEXT,
            RunbookConnectorConfig(
                TENANT,
                (Path(directory).resolve().as_uri(),),
                frozenset(
                    {
                        hashlib.sha256(unrelated).hexdigest(),
                        hashlib.sha256(applicable).hexdigest(),
                    }
                ),
                enabled=True,
            ),
            LocalRunbookSource(),
        )

        page = asyncio.run(
            adapter.query(
                replace(
                    evidence_query(
                        EvidenceSourceKind.RUNBOOK,
                        (EvidenceKind.RUNBOOK,),
                        {"service": "checkout"},
                    ),
                    limit=1,
                )
            )
        )

    assert [record.summary for record in page.records] == ["Checkout"]
    assert page.next_cursor is None
    assert not page.result.partial


def test_runbook_rejects_missing_front_matter() -> None:
    text = b"# Unsafe unversioned instructions"
    digest = hashlib.sha256(text).hexdigest()
    with TemporaryDirectory() as directory:
        Path(directory, "unsafe.md").write_bytes(text)
        adapter = RunbookAdapter(
            CONTEXT,
            RunbookConnectorConfig(
                TENANT,
                (Path(directory).resolve().as_uri(),),
                frozenset({digest}),
                enabled=True,
            ),
            LocalRunbookSource(),
        )
        with pytest.raises(ConnectorError, match="front_matter_missing"):
            asyncio.run(
                adapter.query(
                    evidence_query(
                        EvidenceSourceKind.RUNBOOK,
                        (EvidenceKind.RUNBOOK,),
                        {"service": "checkout"},
                    )
                )
            )


def test_runbook_validation_cancellation_and_capability() -> None:
    content = b"""---
schema_version: 1
title: Checkout
owner: sre
services: [checkout]
environments: [production]
risk: low
approval_required: false
---
Observe only.
"""
    document = RunbookDocument(
        "git+https://github.com/org/runbooks",
        "checkout.md",
        "commit-1",
        content,
        NOW,
    )

    class StaticRunbooks:
        async def documents(
            self,
            *,
            roots: Sequence[str],
            limit: int,
            cursor: str | None,
            max_document_bytes: int,
        ) -> tuple[Sequence[RunbookDocument], str | None]:
            del roots, limit, cursor, max_document_bytes
            return (document,), None

    config = RunbookConnectorConfig(
        TENANT,
        ("git+https://github.com/org/runbooks",),
        frozenset({hashlib.sha256(content).hexdigest()}),
        enabled=True,
    )
    adapter = RunbookAdapter(CONTEXT, config, StaticRunbooks())
    assert asyncio.run(adapter.capability()).detail_code == "retrieval_only"
    remote_without_source = RunbookAdapter(
        CONTEXT,
        RunbookConnectorConfig(
            TENANT,
            ("git+https://github.com/org/runbooks",),
            frozenset(),
            enabled=True,
        ),
        LocalRunbookSource(),
    )
    with pytest.raises(ConnectorError, match="remote_source_not_configured"):
        asyncio.run(
            remote_without_source.query(
                evidence_query(
                    EvidenceSourceKind.RUNBOOK,
                    (EvidenceKind.RUNBOOK,),
                    {"service": "checkout"},
                )
            )
        )
    with pytest.raises(ConnectorError, match="runbook_kind_required"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.RUNBOOK,
                    (EvidenceKind.LOG,),
                    {},
                )
            )
        )

    class Cancelled:
        cancelled = True

    with pytest.raises(ConnectorError, match="query_cancelled"):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.RUNBOOK,
                    (EvidenceKind.RUNBOOK,),
                    {},
                ),
                cancellation=Cancelled(),
            )
        )
    with pytest.raises(PermissionError, match="cross_tenant_connector"):
        RunbookAdapter(
            TenantContext(TenantId("other")),
            config,
            StaticRunbooks(),
        )


@pytest.mark.parametrize(
    ("content", "error_code"),
    [
        (b"\xff\xfe", "runbook_not_utf8"),
        (
            b"""---
schema_version: [
---
body
""",
            "runbook_front_matter_invalid",
        ),
        (
            b"""---
schema_version: 2
title: Bad schema
owner: sre
services: [checkout]
environments: [production]
risk: low
approval_required: false
---
body
""",
            "runbook_schema_invalid",
        ),
        (
            b"""---
schema_version: 1
title: Empty body
owner: sre
services: [checkout]
environments: [production]
risk: low
approval_required: false
---
""",
            "runbook_body_empty",
        ),
        (
            b"""---
schema_version: 1
title: Bad services
owner: sre
services: []
environments: [production]
risk: low
approval_required: false
---
body
""",
            "runbook_services_invalid",
        ),
    ],
)
def test_runbook_malformed_content_is_contained(
    content: bytes,
    error_code: str,
) -> None:
    document = RunbookDocument(
        "git+https://github.com/org/runbooks",
        "bad.md",
        "commit-bad",
        content,
        NOW,
    )

    class StaticRunbooks:
        async def documents(
            self,
            *,
            roots: Sequence[str],
            limit: int,
            cursor: str | None,
            max_document_bytes: int,
        ) -> tuple[Sequence[RunbookDocument], str | None]:
            del roots, limit, cursor, max_document_bytes
            return (document,), None

    adapter = RunbookAdapter(
        CONTEXT,
        RunbookConnectorConfig(
            TENANT,
            ("git+https://github.com/org/runbooks",),
            frozenset({hashlib.sha256(content).hexdigest()}),
            enabled=True,
        ),
        StaticRunbooks(),
    )
    with pytest.raises(ConnectorError, match=error_code):
        asyncio.run(
            adapter.query(
                evidence_query(
                    EvidenceSourceKind.RUNBOOK,
                    (EvidenceKind.RUNBOOK,),
                    {"service": "checkout"},
                )
            )
        )


@pytest.mark.parametrize(
    ("response_status", "error_class"),
    [
        (401, ConnectorErrorClass.AUTHENTICATION),
        (403, ConnectorErrorClass.AUTHORIZATION),
        (429, ConnectorErrorClass.RATE_LIMIT),
        (504, ConnectorErrorClass.TIMEOUT),
        (503, ConnectorErrorClass.UNAVAILABLE),
    ],
)
def test_connector_http_failures_are_classified(
    response_status: int,
    error_class: ConnectorErrorClass,
) -> None:
    from aegis_agent_platform.integrations._http import classify_status

    with pytest.raises(ConnectorError) as failure:
        classify_status(HttpResponse(response_status, {}, b"{}"))
    assert failure.value.error_class is error_class


@pytest.mark.parametrize(
    ("parser", "body", "error_code"),
    [
        ("mapping", b"{", "connector_response_invalid_json"),
        ("mapping", b"[]", "connector_response_not_object"),
        ("sequence", b"[", "connector_response_invalid_json"),
        ("sequence", b"{}", "connector_response_not_array"),
    ],
)
def test_connector_json_shapes_fail_closed(
    parser: str,
    body: bytes,
    error_code: str,
) -> None:
    from aegis_agent_platform.integrations._http import json_mapping, json_sequence

    parse = json_mapping if parser == "mapping" else json_sequence
    with pytest.raises(ConnectorError, match=error_code):
        parse(HttpResponse(200, {}, body))


def test_github_primary_rate_limit_headers_are_retryable() -> None:
    from aegis_agent_platform.integrations._http import classify_status

    with pytest.raises(ConnectorError) as failure:
        classify_status(
            HttpResponse(
                403,
                {
                    "x-ratelimit-remaining": "0",
                    "x-ratelimit-reset": "9999999999",
                },
                b"{}",
            )
        )
    assert failure.value.error_class is ConnectorErrorClass.RATE_LIMIT
    assert failure.value.retryable


def test_connector_configs_are_disabled_by_default_and_require_https() -> None:
    limits = ConnectorLimits()
    assert limits.max_pages == 10
    with pytest.raises(ValueError, match="HTTPS"):
        GitHubConnectorConfig(
            TENANT,
            "app",
            1,
            GITHUB_KEY,
            frozenset({"org/repo"}),
            api_url="http://github.invalid",
        )
    with pytest.raises(ValueError, match="window cap"):
        ConnectorLimits(max_window_seconds=1)
    with pytest.raises(ValueError, match="namespace"):
        KubernetesConnectorConfig(TENANT, "cluster", frozenset())
    with pytest.raises(ValueError, match="roots"):
        RunbookConnectorConfig(TENANT, (), frozenset())
