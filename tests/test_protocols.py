"""Layer 14 neutral contracts, security, registry, and durable gateway tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import UUID

import pytest

from aegis_agent_platform.domain import (
    CapabilityPage,
    ProtocolArtifact,
    ProtocolAuthScheme,
    ProtocolCapability,
    ProtocolDataClassification,
    ProtocolErrorClass,
    ProtocolFamily,
    ProtocolOperationStatus,
    ProtocolPeer,
    ProtocolPeerStatus,
    ProtocolRequest,
    ProtocolResult,
    ProtocolRisk,
    ProtocolTrustTier,
    content_digest,
    normalize_untrusted_text,
    validate_json,
)
from aegis_agent_platform.event_store import FencingError
from aegis_agent_platform.identity import Role, TenantId
from aegis_agent_platform.protocols import (
    CapabilityDriftError,
    FakeExternalProtocolAdapter,
    InMemoryReplayCache,
    NetworkTargetPolicy,
    ProtocolAuthAssertion,
    ProtocolAuthenticator,
    ProtocolBoundary,
    ProtocolGateway,
    ProtocolMetrics,
    ProtocolPolicyDeniedError,
    ProtocolSchemaValidator,
    ProtocolSecurityError,
    ProtocolTracer,
    TransportResponse,
    canonical_protocol_capabilities,
    canonical_protocol_peer,
    canonical_protocol_policy,
)
from aegis_agent_platform.protocols.demo import NOW
from aegis_agent_platform.protocols.registry import peer_digest
from aegis_agent_platform.tenancy import TenantContext
from protocol_helpers import (
    CORRELATION_ID,
    protocol_lease,
    protocol_principal,
    protocol_request,
    protocol_stack,
)


class SendSecurityFailureAdapter(FakeExternalProtocolAdapter):
    async def send(
        self,
        peer: ProtocolPeer,
        capability: ProtocolCapability,
        request: ProtocolRequest,
    ) -> TransportResponse:
        raise ProtocolSecurityError("a2a_artifact_content_rejected")


class ObserveSecurityFailureAdapter(FakeExternalProtocolAdapter):
    async def observe(
        self,
        peer: ProtocolPeer,
        request: ProtocolRequest,
    ) -> TransportResponse | None:
        raise ProtocolSecurityError("a2a_dns_not_pinned")


class CancelSecurityFailureAdapter(FakeExternalProtocolAdapter):
    async def cancel(self, peer: ProtocolPeer, request: ProtocolRequest) -> bool:
        raise ProtocolSecurityError("a2a_dns_not_pinned")


class BoundaryTimeoutAdapter(FakeExternalProtocolAdapter):
    timeout_on = ""

    async def send(
        self,
        peer: ProtocolPeer,
        capability: ProtocolCapability,
        request: ProtocolRequest,
    ) -> TransportResponse:
        if self.timeout_on == "send":
            raise TimeoutError
        return await super().send(peer, capability, request)

    async def observe(
        self,
        peer: ProtocolPeer,
        request: ProtocolRequest,
    ) -> TransportResponse | None:
        if self.timeout_on == "observe":
            raise TimeoutError
        return await super().observe(peer, request)

    async def cancel(self, peer: ProtocolPeer, request: ProtocolRequest) -> bool:
        if self.timeout_on == "cancel":
            raise TimeoutError
        return await super().cancel(peer, request)


def test_protocol_json_canonicalization_is_stable_and_rejects_bombs() -> None:
    assert content_digest({"b": 2, "a": 1}) == content_digest({"a": 1, "b": 2})
    with pytest.raises(ValueError, match="maximum depth"):
        validate_json({"a": {"b": {"c": {"d": {"e": {}}}}}}, maximum_depth=3)
    with pytest.raises(ValueError, match="unsafe"):
        normalize_untrusted_text("trusted\u202eevil", name="external")
    with pytest.raises(ValueError, match="finite"):
        validate_json({"cost": float("inf")})
    with pytest.raises(ValueError, match="object exceeds"):
        validate_json({f"key-{index}": index for index in range(1_001)})
    with pytest.raises(ValueError, match="array exceeds"):
        validate_json(tuple(range(1_001)))


def test_protocol_capabilities_never_allow_direct_mutation() -> None:
    proposal = next(
        item
        for item in canonical_protocol_capabilities()
        if item.capability_id == "aegis.remediation.propose"
    )

    assert proposal.risk is ProtocolRisk.MUTATING
    assert proposal.proposal_only is True
    with pytest.raises(ValueError, match="cannot directly execute"):
        replace(proposal, proposal_only=False)


def test_protocol_contract_bounds_fail_closed() -> None:
    capability = canonical_protocol_capabilities()[0]
    peer = canonical_protocol_peer(ProtocolFamily.MCP)
    _, _, _, _, _, policy = protocol_stack(ProtocolFamily.MCP)
    request = protocol_request(ProtocolFamily.MCP, policy, peer)

    with pytest.raises(ValueError, match="maximum_input"):
        replace(capability, maximum_input_bytes=0)
    with pytest.raises(ValueError, match="maximum_output"):
        replace(capability, maximum_output_bytes=2_000_000)
    with pytest.raises(ValueError, match="content types"):
        replace(capability, content_types=())
    with pytest.raises(ValueError, match="opaque secret"):
        replace(peer, secret_reference="local-invalid-not-secret")  # noqa: S106
    with pytest.raises(ValueError, match="transport"):
        replace(peer, transports=())
    with pytest.raises(ValueError, match="capability allowlist"):
        replace(peer, allowed_capability_digests={})
    with pytest.raises(ValueError, match="classifications"):
        replace(peer, allowed_classifications=frozenset())
    with pytest.raises(ValueError, match="egress"):
        replace(peer, egress_destinations=())
    with pytest.raises(ValueError, match="timezone"):
        replace(peer, registered_at=peer.registered_at.replace(tzinfo=None))
    with pytest.raises(ValueError, match="ordering"):
        replace(peer, expires_at=peer.reviewed_at)
    with pytest.raises(ValueError, match="positive"):
        replace(peer, revision=0)
    with pytest.raises(ValueError, match="timezone-aware"):
        peer.available(NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="allowed peers"):
        replace(policy, allowed_peer_ids=frozenset())
    with pytest.raises(ValueError, match="request byte"):
        replace(policy, maximum_request_bytes=0)
    with pytest.raises(ValueError, match="response byte"):
        replace(policy, maximum_response_bytes=0)
    with pytest.raises(ValueError, match="timeout"):
        replace(policy, timeout_seconds=0)
    with pytest.raises(ValueError, match="attempts"):
        replace(policy, maximum_attempts=0)
    with pytest.raises(ValueError, match="concurrency"):
        replace(policy, maximum_concurrent=0)
    with pytest.raises(ValueError, match="quota"):
        replace(policy, maximum_daily_operations=0)
    with pytest.raises(ValueError, match="payload digest"):
        replace(request, payload_digest="0" * 64)
    with pytest.raises(ValueError, match="timestamps"):
        replace(request, requested_at=request.requested_at.replace(tzinfo=None))
    with pytest.raises(ValueError, match="deadline"):
        replace(request, deadline=request.requested_at)
    with pytest.raises(ValueError, match="capability page"):
        CapabilityPage((capability,) * 101, None)
    with pytest.raises(ValueError, match="at least one peer"):
        canonical_protocol_policy(())
    with pytest.raises(ValueError, match="span tenants"):
        canonical_protocol_policy(
            (
                peer,
                replace(
                    canonical_protocol_peer(ProtocolFamily.A2A),
                    tenant_id="tenant-beta",
                ),
            )
        )


def test_protocol_result_and_artifact_bounds_fail_closed() -> None:
    artifact = ProtocolArtifact(
        "artifact-1",
        "application/json",
        "1" * 64,
        "aegis-artifact://artifact-1",
        ProtocolDataClassification.INTERNAL,
        ProtocolTrustTier.UNTRUSTED,
        (),
        10,
    )
    with pytest.raises(ValueError, match="internal content reference"):
        replace(artifact, content_reference="https://attacker.invalid/exfiltrate")
    with pytest.raises(ValueError, match="byte count"):
        replace(artifact, byte_count=-1)
    with pytest.raises(ValueError, match="timezone-aware"):
        ProtocolResult(
            UUID(int=1),
            ProtocolOperationStatus.COMPLETED,
            "2" * 64,
            "provider",
            (),
            NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValueError, match="too many artifacts"):
        ProtocolResult(
            UUID(int=1),
            ProtocolOperationStatus.COMPLETED,
            "2" * 64,
            "provider",
            (artifact,) * 65,
            NOW,
        )
    with pytest.raises(ValueError, match="supplied together"):
        ProtocolResult(
            UUID(int=1),
            ProtocolOperationStatus.FAILED,
            "2" * 64,
            "provider",
            (),
            NOW,
            error_class=ProtocolErrorClass.PERMANENT,
        )


def test_schema_validation_rejects_smuggling_remote_refs_and_extra_fields() -> None:
    validator = ProtocolSchemaValidator()
    capability = canonical_protocol_capabilities()[0]

    with pytest.raises(ProtocolSecurityError, match="schema_rejected"):
        validator.validate(
            capability.input_schema,
            {"incident_id": "inc-1", "role": "admin"},
            maximum_bytes=1024,
        )
    with pytest.raises(ProtocolSecurityError, match="remote_schema"):
        validator.compile({"$ref": "https://attacker.invalid/schema.json"})


@pytest.mark.parametrize(
    ("url", "addresses", "code"),
    [
        ("http://partner.example/mcp", ("203.0.113.9",), "unsafe_protocol_url"),
        ("https://attacker.example/mcp", ("8.8.8.8",), "egress_host_denied"),
        ("https://partner.example/mcp", ("127.0.0.1",), "dns_address_denied"),
        ("https://partner.example/mcp", ("169.254.169.254",), "dns_address_denied"),
        ("https://user@partner.example/mcp", ("8.8.8.8",), "unsafe_protocol_url"),
    ],
)
def test_network_policy_blocks_ssrf_dns_ip_and_userinfo(
    url: str,
    addresses: tuple[str, ...],
    code: str,
) -> None:
    policy = NetworkTargetPolicy(frozenset({"partner.example"}))

    with pytest.raises(ProtocolSecurityError, match=code):
        policy.validate(url, resolved_addresses=addresses)


def test_network_policy_revalidates_redirects_and_accepts_public_pinned_ip() -> None:
    policy = NetworkTargetPolicy(
        frozenset({"partner.example"}),
        maximum_redirects=1,
    )

    assert policy.validate(
        "https://partner.example/mcp",
        resolved_addresses=("8.8.8.8",),
        redirect_count=1,
    ) == ("partner.example", 443)
    with pytest.raises(ProtocolSecurityError, match="redirect_denied"):
        policy.validate(
            "https://partner.example/mcp",
            resolved_addresses=("8.8.8.8",),
            redirect_count=2,
        )


def _assertion(
    *,
    tenant_id: str = "tenant-alpha",
    audiences: frozenset[str] = frozenset({"aegis-protocol"}),
    scopes: frozenset[str] = frozenset({"protocol.invoke"}),
    expires_at: datetime = NOW + timedelta(minutes=5),
    proof_thumbprint: str | None = sha256(b"dpop-key").hexdigest(),
) -> ProtocolAuthAssertion:
    return ProtocolAuthAssertion(
        "svc-external-agent",
        "https://issuer.example",
        tenant_id,
        audiences,
        scopes,
        "token-001",
        NOW - timedelta(seconds=5),
        expires_at,
        proof_thumbprint,
        "nonce-001",
        None,
    )


def _authenticator() -> ProtocolAuthenticator:
    return ProtocolAuthenticator(
        trusted_issuers={"https://issuer.example": frozenset({"aegis-protocol"})},
        replay_cache=InMemoryReplayCache(),
        production_boundary_ready=False,
    )


def test_protocol_auth_binds_audience_scope_tenant_proof_and_replay() -> None:
    peer = replace(
        canonical_protocol_peer(ProtocolFamily.MCP),
        auth_scheme=ProtocolAuthScheme.OAUTH2_DPOP,
    )
    authenticator = _authenticator()

    principal = authenticator.authenticate(
        _assertion(),
        peer,
        tenant_id="tenant-alpha",
        audience="aegis-protocol",
        required_scope="protocol.invoke",
        at=NOW,
    )

    assert principal.tenant_id == "tenant-alpha"
    assert authenticator.production_ready is False
    with pytest.raises(ProtocolSecurityError, match="replay_denied"):
        authenticator.authenticate(
            _assertion(),
            peer,
            tenant_id="tenant-alpha",
            audience="aegis-protocol",
            required_scope="protocol.invoke",
            at=NOW,
        )


def test_protocol_auth_denies_claim_confusion() -> None:
    peer = replace(
        canonical_protocol_peer(ProtocolFamily.MCP),
        auth_scheme=ProtocolAuthScheme.OAUTH2_DPOP,
    )
    cases = (
        (_assertion(tenant_id="tenant-beta"), "cross_tenant"),
        (_assertion(audiences=frozenset({"other"})), "audience"),
        (_assertion(scopes=frozenset({"protocol.read"})), "scope"),
        (_assertion(expires_at=NOW), "expired"),
        (_assertion(proof_thumbprint=None), "bound_token"),
    )
    for assertion, code in cases:
        with pytest.raises(ProtocolSecurityError, match=code):
            _authenticator().authenticate(
                assertion,
                peer,
                tenant_id="tenant-alpha",
                audience="aegis-protocol",
                required_scope="protocol.invoke",
                at=NOW,
            )


def test_registry_capability_or_card_drift_quarantines_peer() -> None:
    _, registry, _, _, peer, _ = protocol_stack(ProtocolFamily.MCP)
    context = TenantContext(TenantId("tenant-alpha"))
    drifted = tuple(
        replace(item, version="v2") for item in canonical_protocol_capabilities()
    )

    with pytest.raises(CapabilityDriftError):
        registry.record_capabilities(
            context,
            peer.peer_id,
            drifted,
            card_digest=peer.card_digest,
            schema_digest=peer.schema_digest,
            at=NOW,
        )

    quarantined = registry.get(context, peer.peer_id)
    assert quarantined is not None
    assert quarantined.status is ProtocolPeerStatus.QUARANTINED


def test_registry_trust_change_requires_exact_digest_and_expected_revision() -> None:
    _, registry, _, _, peer, _ = protocol_stack(ProtocolFamily.A2A)
    context = TenantContext(TenantId("tenant-alpha"))

    with pytest.raises(ValueError, match="stale"):
        registry.change_trust(
            context,
            peer.peer_id,
            next_status=ProtocolPeerStatus.REVOKED,
            actor_id="tenant-admin",
            rationale_code="emergency-disable",
            confirmation_peer_digest="0" * 64,
            expected_revision=1,
            at=NOW,
        )
    revoked = registry.change_trust(
        context,
        peer.peer_id,
        next_status=ProtocolPeerStatus.REVOKED,
        actor_id="tenant-admin",
        rationale_code="emergency-disable",
        confirmation_peer_digest=peer_digest(peer),
        expected_revision=1,
        at=NOW,
        emergency_disabled=True,
    )

    assert revoked.status is ProtocolPeerStatus.REVOKED
    assert registry.trust_history[-1].peer_digest == peer_digest(peer)


def test_registry_is_tenant_scoped_paginated_and_quarantinable() -> None:
    _, registry, _, _, peer, _ = protocol_stack(ProtocolFamily.MCP)
    context = TenantContext(TenantId("tenant-alpha"))
    second = replace(
        peer,
        peer_id="peer-mcp-second",
        server_identity="aegis-mcp-second",
    )
    registry.register(context, second)

    page, cursor = registry.page(context, limit=1)
    assert len(page) == 1
    assert cursor == page[0].peer_id
    remaining, final_cursor = registry.page(
        context,
        after_peer_id=cursor,
        limit=1,
    )
    assert remaining == (second,)
    assert final_cursor is None
    with pytest.raises(ValueError, match="page limit"):
        registry.page(context, limit=0)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(context, peer)
    with pytest.raises(PermissionError, match="cross_tenant"):
        registry.register(TenantContext(TenantId("tenant-beta")), peer)
    with pytest.raises(RuntimeError, match="revision conflict"):
        registry.change_trust(
            context,
            peer.peer_id,
            next_status=ProtocolPeerStatus.REVOKED,
            actor_id="tenant-admin",
            rationale_code="emergency",
            confirmation_peer_digest=peer_digest(peer),
            expected_revision=99,
            at=NOW,
        )
    assert (
        registry.quarantine(context, peer.peer_id, at=NOW).status
        is ProtocolPeerStatus.QUARANTINED
    )
    with pytest.raises(LookupError, match="not found"):
        registry.quarantine(context, "unknown-peer", at=NOW)


def test_gateway_records_intent_before_external_call_and_redacted_result() -> None:
    gateway, _, ledger, adapter, peer, policy = protocol_stack(ProtocolFamily.MCP)
    request = protocol_request(ProtocolFamily.MCP, policy, peer)

    result = asyncio.run(
        gateway.request(
            protocol_principal(),
            TenantContext(TenantId("tenant-alpha")),
            request,
            policy,
        )
    )

    event_types = [event.event_type for event in ledger.events]
    assert event_types[:3] == [
        "protocol.policy_decided.v1",
        "mcp.invocation_requested.v1",
        "mcp.invocation_started.v1",
    ]
    assert adapter.calls == ["send:protocol-request-001"]
    assert result.status is ProtocolOperationStatus.COMPLETED
    assert all("incident_id" not in str(event.payload) for event in ledger.events)


def test_gateway_records_untrusted_adapter_validation_as_durable_failure() -> None:
    _, registry, ledger, _, peer, policy = protocol_stack(ProtocolFamily.A2A)
    capabilities = canonical_protocol_capabilities()
    adapter = SendSecurityFailureAdapter(
        ProtocolFamily.A2A,
        capabilities,
        card_digest=peer.card_digest,
        schema_digest=peer.schema_digest,
    )
    gateway = ProtocolGateway(
        registry=registry,
        ledger=ledger,
        adapters={ProtocolFamily.A2A: adapter},
        capabilities={item.capability_id: item for item in capabilities},
    )

    result = asyncio.run(
        gateway.request(
            protocol_principal(),
            TenantContext(TenantId("tenant-alpha")),
            protocol_request(ProtocolFamily.A2A, policy, peer),
            policy,
        )
    )

    assert result.status is ProtocolOperationStatus.FAILED
    assert result.error_class is ProtocolErrorClass.SECURITY
    assert ledger.events[-1].event_type == "a2a.task_failed.v1"


def test_protocol_telemetry_uses_only_bounded_boundary_labels() -> None:
    (
        _gateway,
        registry,
        ledger,
        adapter,
        peer,
        policy,
    ) = protocol_stack(ProtocolFamily.MCP)
    boundary = ProtocolBoundary(
        peer.family,
        peer.protocol_versions[0],
        peer.transports[0],
    )
    metrics = ProtocolMetrics((boundary,))
    tracer = ProtocolTracer((boundary,))
    gateway = ProtocolGateway(
        registry=registry,
        ledger=ledger,
        adapters={ProtocolFamily.MCP: adapter},
        capabilities={
            capability.capability_id: capability
            for capability in canonical_protocol_capabilities()
        },
        metrics=metrics,
        tracer=tracer,
        monotonic=iter((1.0, 1.025)).__next__,
    )

    result = asyncio.run(
        gateway.request(
            protocol_principal(),
            TenantContext(TenantId("tenant-alpha")),
            protocol_request(ProtocolFamily.MCP, policy, peer),
            policy,
        )
    )

    assert result.status is ProtocolOperationStatus.COMPLETED
    snapshot = metrics.snapshot()
    assert (
        snapshot[
            (
                "operations",
                "mcp",
                peer.protocol_versions[0],
                peer.transports[0].value,
                "completed",
                "none",
            )
        ]
        == 1
    )
    assert all(
        peer.peer_id not in label and "https://" not in label
        for key in snapshot
        for label in key
    )
    with pytest.raises(ValueError, match="bounded catalog"):
        metrics.add(
            "operations",
            ProtocolBoundary(
                ProtocolFamily.MCP,
                "2099-01-01",
                peer.transports[0],
            ),
            "completed",
        )


def test_gateway_duplicate_suppression_never_repeats_network_effect() -> None:
    gateway, _, _, adapter, peer, policy = protocol_stack(ProtocolFamily.A2A)
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    context = TenantContext(TenantId("tenant-alpha"))

    first = asyncio.run(gateway.request(protocol_principal(), context, request, policy))
    duplicate = asyncio.run(
        gateway.request(protocol_principal(), context, request, policy)
    )

    assert first.status is duplicate.status is ProtocolOperationStatus.COMPLETED
    assert adapter.calls == ["send:protocol-request-001"]


def test_gateway_duplicate_payload_conflict_and_invalid_lifecycle_are_denied() -> None:
    gateway, _, _, adapter, peer, policy = protocol_stack(ProtocolFamily.MCP)
    request = protocol_request(ProtocolFamily.MCP, policy, peer)
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()
    asyncio.run(gateway.request(principal, context, request, policy))
    changed_payload = {"incident_id": "inc-different"}
    conflicting = replace(
        request,
        payload=changed_payload,
        payload_digest=content_digest(changed_payload),
    )

    with pytest.raises(ProtocolPolicyDeniedError, match="payload_conflict"):
        asyncio.run(gateway.request(principal, context, conflicting, policy))
    with pytest.raises(ProtocolPolicyDeniedError, match="only_ambiguous"):
        asyncio.run(gateway.reconcile(principal, context, request, at=NOW))

    missing = replace(
        request,
        operation_id=UUID("81306ec2-89d5-44dc-b99f-58d8ff3b7507"),
        idempotency_key="missing-operation",
    )
    with pytest.raises(LookupError, match="not found"):
        asyncio.run(gateway.reconcile(principal, context, missing, at=NOW))
    with pytest.raises(LookupError, match="not found"):
        asyncio.run(gateway.cancel(principal, context, missing, at=NOW))
    assert adapter.calls == ["send:protocol-request-001"]


def test_gateway_refreshes_exact_capabilities_and_quarantines_drift() -> None:
    gateway, registry, _, adapter, peer, _ = protocol_stack(ProtocolFamily.MCP)
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal(Role.TENANT_ADMIN)

    refreshed = asyncio.run(
        gateway.refresh_capabilities(
            principal,
            context,
            peer.peer_id,
            at=NOW,
        )
    )
    assert refreshed == peer
    adapter.card_digest = "0" * 64
    with pytest.raises(CapabilityDriftError):
        asyncio.run(
            gateway.refresh_capabilities(
                principal,
                context,
                peer.peer_id,
                at=NOW,
            )
        )
    quarantined = registry.get(context, peer.peer_id)
    assert quarantined is not None
    assert quarantined.status is ProtocolPeerStatus.QUARANTINED


def test_gateway_denies_policy_peer_family_and_unknown_capability_confusion() -> None:
    gateway, _, _, adapter, peer, policy = protocol_stack(ProtocolFamily.MCP)
    base = protocol_request(ProtocolFamily.MCP, policy, peer)
    denied_policy = replace(policy, allowed_peer_ids=frozenset({"other-peer"}))
    cases = (
        (
            replace(base, policy_digest="0" * 64),
            policy,
            "policy_binding",
        ),
        (replace(base, peer_digest="0" * 64), policy, "peer_digest"),
        (replace(base, family=ProtocolFamily.A2A), policy, "family_mismatch"),
        (
            replace(base, policy_digest=denied_policy.digest),
            denied_policy,
            "peer_not_allowed",
        ),
        (
            replace(base, capability_id="unknown-capability"),
            policy,
            "capability_unknown",
        ),
    )
    for request, selected_policy, error in cases:
        with pytest.raises(ProtocolPolicyDeniedError, match=error):
            asyncio.run(
                gateway.request(
                    protocol_principal(),
                    TenantContext(TenantId("tenant-alpha")),
                    request,
                    selected_policy,
                )
            )
    assert adapter.calls == []


def test_gateway_ambiguous_delivery_observes_before_reconciliation() -> None:
    gateway, _, ledger, adapter, peer, policy = protocol_stack(
        ProtocolFamily.A2A,
        responses=(ProtocolOperationStatus.AMBIGUOUS,),
    )
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()

    ambiguous = asyncio.run(gateway.request(principal, context, request, policy))
    reconciled = asyncio.run(
        gateway.reconcile(principal, context, request, at=NOW + timedelta(seconds=2))
    )

    assert ambiguous.status is ProtocolOperationStatus.AMBIGUOUS
    assert reconciled.status is ProtocolOperationStatus.COMPLETED
    assert adapter.calls == [
        "send:protocol-request-001",
        "observe:protocol-request-001",
    ]
    assert ledger.events[-1].event_type == "a2a.reconciled.v1"


def test_gateway_reconciliation_security_failure_remains_durably_ambiguous() -> None:
    _, registry, ledger, _, peer, policy = protocol_stack(ProtocolFamily.A2A)
    capabilities = canonical_protocol_capabilities()
    adapter = ObserveSecurityFailureAdapter(
        ProtocolFamily.A2A,
        capabilities,
        card_digest=peer.card_digest,
        schema_digest=peer.schema_digest,
        responses=(ProtocolOperationStatus.AMBIGUOUS,),
    )
    gateway = ProtocolGateway(
        registry=registry,
        ledger=ledger,
        adapters={ProtocolFamily.A2A: adapter},
        capabilities={item.capability_id: item for item in capabilities},
    )
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()
    asyncio.run(gateway.request(principal, context, request, policy))

    result = asyncio.run(gateway.reconcile(principal, context, request, at=NOW))

    assert result.status is ProtocolOperationStatus.AMBIGUOUS
    assert result.error_class is ProtocolErrorClass.SECURITY
    assert result.retryable is False
    assert ledger.events[-1].event_type == "a2a.task_ambiguous.v1"


def test_gateway_cancellation_is_durable_and_remote_confirmed() -> None:
    gateway, _, ledger, _, peer, policy = protocol_stack(ProtocolFamily.MCP)
    request = protocol_request(ProtocolFamily.MCP, policy, peer)
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()
    asyncio.run(gateway.request(principal, context, request, policy))

    result = asyncio.run(
        gateway.cancel(principal, context, request, at=NOW + timedelta(seconds=2))
    )

    assert result.status is ProtocolOperationStatus.CANCELLED
    assert ledger.events[-2].event_type == "mcp.invocation_cancel_requested.v1"
    assert ledger.events[-1].event_type == "mcp.invocation_cancelled.v1"


def test_gateway_cancellation_security_failure_is_durably_ambiguous() -> None:
    _, registry, ledger, _, peer, policy = protocol_stack(ProtocolFamily.A2A)
    capabilities = canonical_protocol_capabilities()
    adapter = CancelSecurityFailureAdapter(
        ProtocolFamily.A2A,
        capabilities,
        card_digest=peer.card_digest,
        schema_digest=peer.schema_digest,
    )
    gateway = ProtocolGateway(
        registry=registry,
        ledger=ledger,
        adapters={ProtocolFamily.A2A: adapter},
        capabilities={item.capability_id: item for item in capabilities},
    )
    request = protocol_request(ProtocolFamily.A2A, policy, peer)
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()
    asyncio.run(gateway.request(principal, context, request, policy))

    result = asyncio.run(gateway.cancel(principal, context, request, at=NOW))

    assert result.status is ProtocolOperationStatus.AMBIGUOUS
    assert result.error_class is ProtocolErrorClass.SECURITY
    assert result.retryable is False
    assert ledger.events[-2].event_type == "a2a.task_cancel_requested.v1"
    assert ledger.events[-1].event_type == "a2a.task_ambiguous.v1"


def test_gateway_boundary_timeouts_remain_durable_and_reconcilable() -> None:
    capabilities = canonical_protocol_capabilities()
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()

    _, send_registry, send_ledger, _, send_peer, send_policy = protocol_stack(
        ProtocolFamily.A2A
    )
    send_adapter = BoundaryTimeoutAdapter(
        ProtocolFamily.A2A,
        capabilities,
        card_digest=send_peer.card_digest,
        schema_digest=send_peer.schema_digest,
    )
    send_adapter.timeout_on = "send"
    send_gateway = ProtocolGateway(
        registry=send_registry,
        ledger=send_ledger,
        adapters={ProtocolFamily.A2A: send_adapter},
        capabilities={item.capability_id: item for item in capabilities},
    )
    send_result = asyncio.run(
        send_gateway.request(
            principal,
            context,
            protocol_request(ProtocolFamily.A2A, send_policy, send_peer),
            send_policy,
        )
    )
    assert send_result.status is ProtocolOperationStatus.AMBIGUOUS
    assert send_result.error_code == "protocol_timeout_ambiguous"

    _, observe_registry, observe_ledger, _, observe_peer, observe_policy = (
        protocol_stack(ProtocolFamily.A2A)
    )
    observe_adapter = BoundaryTimeoutAdapter(
        ProtocolFamily.A2A,
        capabilities,
        card_digest=observe_peer.card_digest,
        schema_digest=observe_peer.schema_digest,
        responses=(ProtocolOperationStatus.AMBIGUOUS,),
    )
    observe_gateway = ProtocolGateway(
        registry=observe_registry,
        ledger=observe_ledger,
        adapters={ProtocolFamily.A2A: observe_adapter},
        capabilities={item.capability_id: item for item in capabilities},
    )
    observe_request = protocol_request(
        ProtocolFamily.A2A,
        observe_policy,
        observe_peer,
    )
    asyncio.run(
        observe_gateway.request(
            principal,
            context,
            observe_request,
            observe_policy,
        )
    )
    observe_adapter.timeout_on = "observe"
    observe_result = asyncio.run(
        observe_gateway.reconcile(
            principal,
            context,
            observe_request,
            at=NOW,
        )
    )
    assert observe_result.status is ProtocolOperationStatus.AMBIGUOUS
    assert observe_result.error_code == "protocol_reconciliation_timeout"

    _, cancel_registry, cancel_ledger, _, cancel_peer, cancel_policy = protocol_stack(
        ProtocolFamily.A2A
    )
    cancel_adapter = BoundaryTimeoutAdapter(
        ProtocolFamily.A2A,
        capabilities,
        card_digest=cancel_peer.card_digest,
        schema_digest=cancel_peer.schema_digest,
    )
    cancel_gateway = ProtocolGateway(
        registry=cancel_registry,
        ledger=cancel_ledger,
        adapters={ProtocolFamily.A2A: cancel_adapter},
        capabilities={item.capability_id: item for item in capabilities},
    )
    cancel_request = protocol_request(
        ProtocolFamily.A2A,
        cancel_policy,
        cancel_peer,
    )
    asyncio.run(
        cancel_gateway.request(
            principal,
            context,
            cancel_request,
            cancel_policy,
        )
    )
    cancel_adapter.timeout_on = "cancel"
    cancel_result = asyncio.run(
        cancel_gateway.cancel(principal, context, cancel_request, at=NOW)
    )
    assert cancel_result.status is ProtocolOperationStatus.AMBIGUOUS
    assert cancel_result.error_code == "protocol_cancellation_timeout"


def test_gateway_stale_fence_is_denied_before_external_call() -> None:
    gateway, _, ledger, adapter, peer, policy = protocol_stack(ProtocolFamily.MCP)
    current = protocol_lease(generation=2)
    ledger.register_lease(current)
    stale = replace(current, generation=1)

    with pytest.raises(FencingError):
        asyncio.run(
            gateway.request(
                protocol_principal(),
                TenantContext(TenantId("tenant-alpha")),
                protocol_request(ProtocolFamily.MCP, policy, peer),
                policy,
                lease=stale,
            )
        )

    assert adapter.calls == []


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("tenant_id", "tenant-beta", "cross_tenant"),
        ("purpose", "policy_override", "purpose"),
        ("capability_digest", "0" * 64, "capability_digest"),
    ],
)
def test_gateway_denies_cross_tenant_purpose_and_digest_attacks(
    field: str,
    value: str,
    error: str,
) -> None:
    gateway, _, _, adapter, peer, policy = protocol_stack(ProtocolFamily.MCP)
    base = protocol_request(ProtocolFamily.MCP, policy, peer)
    request = (
        replace(base, tenant_id=value)
        if field == "tenant_id"
        else replace(base, purpose=value)
        if field == "purpose"
        else replace(base, capability_digest=value)
    )

    with pytest.raises(ProtocolPolicyDeniedError, match=error):
        asyncio.run(
            gateway.request(
                protocol_principal(),
                TenantContext(TenantId("tenant-alpha")),
                request,
                policy,
            )
        )

    assert adapter.calls == []


def test_revocation_blocks_new_calls_without_corrupting_prior_run() -> None:
    gateway, registry, ledger, adapter, peer, policy = protocol_stack(
        ProtocolFamily.A2A
    )
    context = TenantContext(TenantId("tenant-alpha"))
    principal = protocol_principal()
    first = protocol_request(ProtocolFamily.A2A, policy, peer)
    asyncio.run(gateway.request(principal, context, first, policy))
    registry.change_trust(
        context,
        peer.peer_id,
        next_status=ProtocolPeerStatus.REVOKED,
        actor_id="tenant-admin",
        rationale_code="peer-revoked",
        confirmation_peer_digest=peer_digest(peer),
        expected_revision=1,
        at=NOW + timedelta(seconds=2),
        emergency_disabled=True,
    )
    second = replace(
        first,
        operation_id=UUID("65de6d70-3991-416c-a28c-8d2acb754db0"),
        idempotency_key="protocol-request-002",
        correlation_id=CORRELATION_ID,
    )

    with pytest.raises(ProtocolPolicyDeniedError, match="peer_denied"):
        asyncio.run(gateway.request(principal, context, second, policy))

    assert len(adapter.calls) == 1
    assert ledger.events[-1].event_type == "a2a.task_completed.v1"


def test_protocol_permission_is_deny_by_default_for_viewer_invocation() -> None:
    gateway, _, _, adapter, peer, policy = protocol_stack(ProtocolFamily.MCP)

    with pytest.raises(ProtocolPolicyDeniedError, match="permission_not_granted"):
        asyncio.run(
            gateway.request(
                protocol_principal(Role.VIEWER),
                TenantContext(TenantId("tenant-alpha")),
                protocol_request(
                    ProtocolFamily.MCP,
                    policy,
                    peer,
                    capability_id="aegis.investigation.submit",
                    payload={"incident_id": "inc-1", "question": "Check evidence"},
                ),
                policy,
            )
        )

    assert adapter.calls == []


def test_protocol_classification_ceiling_is_enforced() -> None:
    gateway, _, _, _, peer, policy = protocol_stack(ProtocolFamily.MCP)
    request = replace(
        protocol_request(ProtocolFamily.MCP, policy, peer),
        classification=ProtocolDataClassification.RESTRICTED,
    )

    with pytest.raises(ProtocolPolicyDeniedError, match="classification"):
        asyncio.run(
            gateway.request(
                protocol_principal(),
                TenantContext(TenantId("tenant-alpha")),
                request,
                policy,
            )
        )
