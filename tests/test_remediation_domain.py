"""Pure Layer 8 contract, replay, and malformed-input tests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from types import MappingProxyType
from uuid import UUID, uuid4

import pytest

from aegis_agent_platform.domain import (
    ActionKind,
    ActionSpecification,
    ActionTarget,
    ApprovalPolicySnapshot,
    ApprovalScope,
    ApprovalState,
    ApprovalStatus,
    BlastRadius,
    Condition,
    ConditionOperator,
    DomainEventType,
    EffectOutcome,
    EventEnvelope,
    ExecutionRecord,
    JsonValue,
    MaintenanceWindow,
    PolicyEvaluationRecord,
    PolicyOutcome,
    ReconciliationOutcome,
    ReconciliationPolicy,
    ReconciliationRecord,
    RemediationEvidenceCitation,
    RemediationReplayError,
    RetryPolicy,
    RiskTier,
    VerificationOutcome,
    VerificationRecord,
    plan_from_payload,
    plan_to_payload,
    replay_remediation,
)
from remediation_helpers import NOW, TENANT_ID, action, plan, policy, target


def event(
    event_type: DomainEventType,
    payload: dict[str, object],
    *,
    plan_id: UUID,
    sequence: int,
    event_id: UUID | None = None,
    key: str | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id or uuid4(),
        str(TENANT_ID),
        str(plan_id),
        event_type,
        1,
        NOW,
        payload,  # type: ignore[arg-type]
        aggregate_sequence=sequence,
        idempotency_key=key or f"event:{sequence}",
    )


def proposal_events() -> tuple[EventEnvelope, ...]:
    selected = plan()
    item = selected.actions[0]
    approval_id = uuid4()
    return (
        event(
            DomainEventType.REMEDIATION_PROPOSED,
            {"plan": plan_to_payload(selected)},
            plan_id=selected.plan_id,
            sequence=1,
        ),
        event(
            DomainEventType.REMEDIATION_POLICY_EVALUATED,
            {
                "action_id": str(item.action_id),
                "action_digest": item.digest,
                "plan_digest": selected.digest,
                "policy_digest": selected.approval_policy.digest,
                "outcome": "require_approval",
                "reasons": ["exact_scope_approval_required"],
            },
            plan_id=selected.plan_id,
            sequence=2,
        ),
        event(
            DomainEventType.REMEDIATION_APPROVAL_REQUESTED,
            {
                "action_id": str(item.action_id),
                "action_digest": item.digest,
                "approval_id": str(approval_id),
                "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
                "plan_digest": selected.digest,
                "policy_digest": selected.approval_policy.digest,
                "requester_id": "operator",
                "required_quorum": 2,
                "risk": int(item.risk),
                "target_fingerprint": item.target.fingerprint,
            },
            plan_id=selected.plan_id,
            sequence=3,
        ),
    )


def test_plan_round_trip_digest_and_deep_immutability() -> None:
    selected = plan()

    decoded = plan_from_payload(plan_to_payload(selected))

    assert decoded == selected
    assert decoded.digest == selected.digest
    assert decoded.actions[0].digest == selected.actions[0].digest
    assert isinstance(decoded.actions[0].parameters, MappingProxyType)
    with pytest.raises(FrozenInstanceError):
        decoded.revision = 2  # type: ignore[misc]


def test_replay_grants_exact_quorum_and_rejects_replayed_actor() -> None:
    base = proposal_events()
    selected = plan_from_payload(base[0].payload["plan"])  # type: ignore[arg-type]
    approval_id = UUID(str(base[2].payload["approval_id"]))
    grants = (
        event(
            DomainEventType.REMEDIATION_APPROVAL_GRANTED,
            {
                "action_id": str(selected.actions[0].action_id),
                "approval_id": str(approval_id),
                "approver_id": "approver-one",
                "rationale_code": "reviewed",
            },
            plan_id=selected.plan_id,
            sequence=4,
        ),
        event(
            DomainEventType.REMEDIATION_APPROVAL_GRANTED,
            {
                "action_id": str(selected.actions[0].action_id),
                "approval_id": str(approval_id),
                "approver_id": "approver-two",
                "rationale_code": "reviewed",
            },
            plan_id=selected.plan_id,
            sequence=5,
        ),
    )

    state = replay_remediation((*base, *grants))

    assert state.approvals[approval_id].status is ApprovalStatus.GRANTED
    assert state.approvals[approval_id].approver_ids == (
        "approver-one",
        "approver-two",
    )
    replayed = replace(
        grants[1],
        event_id=uuid4(),
        aggregate_sequence=6,
        idempotency_key="event:6",
        payload={
            **grants[1].payload,
            "approver_id": "approver-one",
        },
    )
    with pytest.raises(RemediationReplayError, match="replayed"):
        replay_remediation((*base, *grants, replayed))


@pytest.mark.parametrize(
    "invalid",
    [
        lambda: ActionTarget("kubernetes", "staging", "deployment", "$(id)", "ns"),
        lambda: RetryPolicy(0),
        lambda: ReconciliationPolicy(max_attempts=11),
        lambda: Condition("signal", ConditionOperator.EXISTS, False),
        lambda: MaintenanceWindow(NOW, NOW),
        lambda: ApprovalPolicySnapshot(
            str(TENANT_ID),
            "v1",
            frozenset(),
            frozenset(),
            frozenset(),
            (),
            RiskTier.HIGH,
            BlastRadius.SINGLE_RESOURCE,
            RiskTier.LOW,
            0,
            True,
            True,
            True,
            1,
            1,
            1,
            60,
        ),
        lambda: ActionSpecification(
            uuid4(),
            ActionKind.KUBERNETES_ROLLOUT_RESTART,
            target(),
            RiskTier.HIGH,
            BlastRadius.SINGLE_RESOURCE,
            (Condition("a", ConditionOperator.EQUALS, True),),
            (Condition("b", ConditionOperator.EQUALS, True),),
            (),
            "safe-key",
            10,
            RetryPolicy(),
            ReconciliationPolicy(),
            True,
            {"command": "rm -rf /"},
        ),
    ],
)
def test_untrusted_and_prompt_injected_contracts_fail_closed(
    invalid: Callable[[], object],
) -> None:
    with pytest.raises(ValueError, match=r".+"):
        invalid()


def test_plan_rejects_missing_evidence_and_stale_policy_tenant() -> None:
    item = action()
    with pytest.raises(ValueError, match="evidence"):
        replace(plan(item), evidence=())
    other = replace(policy(item.target), tenant_id="other-tenant")
    with pytest.raises(ValueError, match="tenants"):
        plan(item, other)


def test_replay_rejects_sequence_duplicates_and_stale_scope() -> None:
    base = proposal_events()
    with pytest.raises(RemediationReplayError, match="sequence"):
        replay_remediation((replace(base[0], aggregate_sequence=2),))
    with pytest.raises(RemediationReplayError, match="duplicate"):
        replay_remediation((base[0], replace(base[0], aggregate_sequence=2)))
    stale = replace(
        base[1],
        payload={**base[1].payload, "policy_digest": "0" * 64},
    )
    with pytest.raises(RemediationReplayError, match="stale"):
        replay_remediation((base[0], stale))


@pytest.mark.parametrize(
    ("event_type", "payload", "message"),
    [
        (
            DomainEventType.ACTION_EXECUTION_REQUESTED,
            {"attempt": 1},
            "intent lacks dry run",
        ),
        (
            DomainEventType.ACTION_EXECUTION_SUCCEEDED,
            {"attempt": 1},
            "outcome lacks started intent",
        ),
        (
            DomainEventType.ACTION_RECONCILIATION_COMPLETED,
            {"attempt": 1},
            "reconciliation lacks request",
        ),
        (
            DomainEventType.ACTION_VERIFICATION_REQUESTED,
            {"attempt": 1},
            "verification lacks applied effect",
        ),
        (
            DomainEventType.ACTION_ROLLBACK_COMPLETED,
            {},
            "rollback outcome lacks request",
        ),
    ],
)
def test_replay_rejects_corrupt_action_lifecycle_histories(
    event_type: DomainEventType,
    payload: dict[str, object],
    message: str,
) -> None:
    base = proposal_events()
    selected = plan_from_payload(base[0].payload["plan"])  # type: ignore[arg-type]
    approval_id = UUID(str(base[2].payload["approval_id"]))
    grants = tuple(
        event(
            DomainEventType.REMEDIATION_APPROVAL_GRANTED,
            {
                "action_id": str(selected.actions[0].action_id),
                "approval_id": str(approval_id),
                "approver_id": actor,
                "rationale_code": "reviewed",
            },
            plan_id=selected.plan_id,
            sequence=index,
        )
        for index, actor in enumerate(
            ("approver-one", "approver-two"),
            start=4,
        )
    )
    corrupt = event(
        event_type,
        {
            "action_id": str(selected.actions[0].action_id),
            **payload,
        },
        plan_id=selected.plan_id,
        sequence=6,
    )

    with pytest.raises(RemediationReplayError, match=message):
        replay_remediation((*base, *grants, corrupt))


def test_replay_requires_exact_approval_before_dispatch() -> None:
    base = proposal_events()
    selected = plan_from_payload(base[0].payload["plan"])  # type: ignore[arg-type]
    dispatch = event(
        DomainEventType.ACTION_DISPATCH_CLAIMED,
        {
            "action_id": str(selected.actions[0].action_id),
            "attempt": 1,
        },
        plan_id=selected.plan_id,
        sequence=4,
    )

    with pytest.raises(RemediationReplayError, match="dispatch lacks exact approval"):
        replay_remediation((*base, dispatch))


def test_existing_event_envelope_fixture_remains_readable() -> None:
    fixture = {
        "event_id": str(uuid4()),
        "tenant_id": "tenant-old",
        "aggregate_id": "run-old",
        "event_type": "run.started.v1",
        "schema_version": 1,
        "occurred_at": NOW.isoformat(),
        "payload": {"legacy": True},
    }

    decoded = EventEnvelope.from_mapping(fixture)

    assert decoded.payload["legacy"] is True
    assert decoded.aggregate_sequence == 0


@pytest.mark.parametrize(
    "invalid",
    [
        lambda: RemediationEvidenceCitation(
            "evidence",
            "https://untrusted.invalid",
            "a" * 64,
            NOW,
            0.5,
        ),
        lambda: RemediationEvidenceCitation(
            "evidence",
            "aegis-evidence://safe",
            "a" * 64,
            NOW,
            1.1,
        ),
        lambda: RetryPolicy(1, 61, 61),
        lambda: RetryPolicy(1, 20, 10),
        lambda: ReconciliationPolicy(max_attempts=0),
        lambda: ReconciliationPolicy(interval_seconds=3_601),
        lambda: MaintenanceWindow(NOW, NOW + timedelta(days=2)),
        lambda: policy(quorum=6),
        lambda: replace(policy(), max_actions_per_plan=0),
        lambda: replace(policy(), max_actions_per_period=0),
        lambda: replace(policy(), max_concurrent_actions=0),
        lambda: replace(policy(), approval_ttl_seconds=59),
        lambda: replace(policy(), schema_version=2),
        lambda: replace(action(), action_id=UUID(int=0)),
        lambda: replace(action(), preconditions=()),
        lambda: replace(action(), timeout_seconds=301),
        lambda: replace(action(), dry_run_supported=False),
        lambda: replace(
            action(),
            target=ActionTarget(
                "github",
                "staging",
                "deployment",
                "checkout-api",
                "checkout",
            ),
        ),
        lambda: replace(
            action(),
            target=ActionTarget(
                "kubernetes",
                "staging",
                "pod",
                "checkout-api",
                "checkout",
            ),
        ),
        lambda: replace(action(), rollback_reference="https://unsafe.invalid"),
        lambda: replace(action(), schema_version=2),
        lambda: replace(plan(), plan_id=UUID(int=0)),
        lambda: replace(plan(), revision=0),
        lambda: replace(plan(), actions=()),
        lambda: replace(
            plan(),
            verification_artifact_reference="https://unsafe.invalid",
        ),
        lambda: replace(plan(), schema_version=2),
    ],
)
def test_additional_contract_bounds_fail_closed(
    invalid: Callable[[], object],
) -> None:
    with pytest.raises(ValueError, match=r".+"):
        invalid()


def test_record_contracts_validate_bounds_and_exact_scope() -> None:
    selected = plan()
    selected_action = selected.actions[0]
    scope = ApprovalScope(
        uuid4(),
        selected_action.action_id,
        selected.digest,
        selected_action.digest,
        selected.approval_policy.digest,
        selected_action.target.fingerprint,
        selected_action.risk,
        selected.requested_by,
        2,
        NOW,
        NOW + timedelta(minutes=5),
    )
    pending = ApprovalState(scope, ApprovalStatus.PENDING)

    assert not pending.valid_for(
        plan=selected,
        action=selected_action,
        policy_digest=selected.approval_policy.digest,
        at=NOW,
    )
    with pytest.raises(ValueError, match="distinct"):
        ApprovalState(
            scope,
            ApprovalStatus.GRANTED,
            ("same", "same"),
            (uuid4(), uuid4()),
        )
    with pytest.raises(ValueError, match="align"):
        ApprovalState(scope, ApprovalStatus.GRANTED, ("one",), ())
    with pytest.raises(ValueError, match="attempt"):
        ExecutionRecord(
            selected_action.action_id,
            0,
            EffectOutcome.SUCCEEDED,
            NOW,
        )
    with pytest.raises(ValueError, match="attempt"):
        ReconciliationRecord(
            selected_action.action_id,
            11,
            ReconciliationOutcome.UNKNOWN,
            selected_action.target.fingerprint,
            NOW,
        )
    with pytest.raises(ValueError, match="postconditions"):
        VerificationRecord(
            selected_action.action_id,
            VerificationOutcome.UNKNOWN,
            (),
            (),
            NOW,
        )
    with pytest.raises(ValueError, match="reasons"):
        PolicyEvaluationRecord(
            selected_action.action_id,
            selected.digest,
            selected_action.digest,
            selected.approval_policy.digest,
            PolicyOutcome.DENY,
            (),
            NOW,
        )
    with pytest.raises(ValueError, match="nil"):
        replace(scope, approval_id=UUID(int=0))
    with pytest.raises(ValueError, match="quorum"):
        replace(scope, required_quorum=0)
    with pytest.raises(ValueError, match="follow"):
        replace(scope, expires_at=NOW)


def test_replay_rejects_malformed_proposals_actions_and_decisions() -> None:
    base = proposal_events()
    selected = plan_from_payload(base[0].payload["plan"])  # type: ignore[arg-type]
    with pytest.raises(RemediationReplayError, match="empty"):
        replay_remediation(())
    with pytest.raises(RemediationReplayError, match="no proposal"):
        replay_remediation(
            (
                event(
                    DomainEventType.RUN_STARTED,
                    {},
                    plan_id=selected.plan_id,
                    sequence=1,
                ),
            )
        )
    with pytest.raises(RemediationReplayError, match="proposed twice"):
        replay_remediation(
            (
                base[0],
                replace(
                    base[0],
                    event_id=uuid4(),
                    aggregate_sequence=2,
                    idempotency_key="second-proposal",
                ),
            )
        )
    with pytest.raises(RemediationReplayError, match="typed plan"):
        replay_remediation((replace(base[0], payload={"plan": "untrusted"}),))
    with pytest.raises(RemediationReplayError, match="linkage"):
        replay_remediation((replace(base[0], tenant_id="other-tenant"),))
    with pytest.raises(RemediationReplayError, match="tenant changed"):
        replay_remediation(
            (
                base[0],
                replace(base[1], tenant_id="other-tenant"),
            )
        )
    with pytest.raises(RemediationReplayError, match="unknown action"):
        replay_remediation(
            (
                base[0],
                replace(
                    base[1],
                    payload={
                        **base[1].payload,
                        "action_id": str(uuid4()),
                    },
                ),
            )
        )
    with pytest.raises(RemediationReplayError, match="must be a string"):
        replay_remediation(
            (
                base[0],
                replace(base[1], payload={**base[1].payload, "action_id": 1}),
            )
        )
    with pytest.raises(RemediationReplayError, match="malformed"):
        replay_remediation(
            (
                base[0],
                replace(
                    base[1],
                    payload={**base[1].payload, "action_id": "not-a-uuid"},
                ),
            )
        )
    orphan_decision = event(
        DomainEventType.REMEDIATION_APPROVAL_DENIED,
        {
            "action_id": str(selected.actions[0].action_id),
            "approval_id": str(uuid4()),
            "rationale_code": "unsafe",
        },
        plan_id=selected.plan_id,
        sequence=2,
    )
    with pytest.raises(RemediationReplayError, match="no request"):
        replay_remediation((base[0], orphan_decision))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("outcome", "", "string"),
        ("reasons", "not-an-array", "array"),
        ("reasons", [1], "invalid strings"),
    ],
)
def test_replay_rejects_malformed_policy_payload_fields(
    field: str,
    value: JsonValue,
    message: str,
) -> None:
    base = proposal_events()
    malformed = replace(base[1], payload={**base[1].payload, field: value})
    with pytest.raises((RemediationReplayError, ValueError), match=message):
        replay_remediation((base[0], malformed))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("approval_policy", [], "object"),
        ("actions", "not-an-array", "array"),
        ("requested_by", 1, "string"),
        ("revision", True, "integer"),
        ("critic_approved", "yes", "boolean"),
    ],
)
def test_plan_payload_parser_rejects_wrong_json_types(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = dict(plan_to_payload(plan()))
    payload[field] = value  # type: ignore[assignment]
    with pytest.raises(ValueError, match=message):
        plan_from_payload(payload)
