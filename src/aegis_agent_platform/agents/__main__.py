"""Safe deterministic checkout investigation demo with fake inputs only."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from aegis_agent_platform.agents.artifacts import EvidenceCitation
from aegis_agent_platform.agents.engines import (
    CanonicalCheckoutEngine,
    CanonicalScenario,
    canonical_checkout_citations,
    canonical_checkout_plan,
)
from aegis_agent_platform.agents.repository import InMemoryAgentRepository
from aegis_agent_platform.agents.service import DurableCoordinator
from aegis_agent_platform.domain import EventEnvelope, JsonValue, WorkLease
from aegis_agent_platform.identity import TenantId
from aegis_agent_platform.tenancy import TenantContext

DEMO_NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
DEMO_RUN_ID = UUID("70000000-0000-4000-8000-000000000007")
DEMO_LEASE_TOKEN = UUID("70000000-0000-4000-8000-000000000008")


async def run_canonical_demo(
    scenario: CanonicalScenario = CanonicalScenario.SUCCESS,
    *,
    tenant_id: str = "tenant-demo",
    incident_id: str = "checkout-failure-demo",
    run_id: UUID = DEMO_RUN_ID,
    evidence: Mapping[str, EvidenceCitation] | None = None,
    event_sink: Callable[[tuple[EventEnvelope, ...]], None] | None = None,
) -> Mapping[str, JsonValue]:
    context = TenantContext(TenantId(tenant_id))
    repository = InMemoryAgentRepository()
    coordinator = DurableCoordinator(
        repository,
        CanonicalCheckoutEngine(scenario, clock=lambda: DEMO_NOW),
        clock=lambda: DEMO_NOW,
    )
    plan = canonical_checkout_plan(
        tenant_id=tenant_id,
        incident_id=incident_id,
        run_id=run_id,
        created_at=DEMO_NOW,
    )
    request = await coordinator.request(
        context,
        plan,
        actor_id="local-demo-operator",
        idempotency_key=f"checkout-demo:{scenario.value}",
    )
    lease = WorkLease(
        work_id=run_id,
        tenant_id=tenant_id,
        token=DEMO_LEASE_TOKEN,
        generation=1,
        owner="local-fake-worker",
        attempt=1,
        acquired_at=DEMO_NOW,
        heartbeat_at=DEMO_NOW,
        expires_at=DEMO_NOW + timedelta(hours=1),
    )
    repository.register_lease(lease)
    state = await coordinator.execute(
        context,
        run_id,
        lease,
        evidence or canonical_checkout_citations(),
    )
    status = await repository.status(context, run_id)
    artifacts, _cursor = await repository.artifact_page(
        context,
        run_id,
        limit=100,
    )
    events = await repository.load(context, run_id)
    before_rebuild = cast(Mapping[str, JsonValue], status or {})
    repository.clear_projections()
    await repository.rebuild_projection(context, run_id)
    after_rebuild = cast(
        Mapping[str, JsonValue], await repository.status(context, run_id) or {}
    )
    if event_sink is not None:
        event_sink(events)
    return {
        "demo_only": True,
        "uses_live_network": False,
        "executes_remediation": False,
        "scenario": scenario.value,
        "request_created": request.created,
        "status": state.status.value,
        "run": before_rebuild,
        "artifacts": artifacts,
        "event_count": len(events),
        "projection_rebuild_identical": before_rebuild == after_rebuild,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the fake-only Aegis checkout investigation.",
    )
    parser.add_argument(
        "--scenario",
        choices=tuple(item.value for item in CanonicalScenario),
        default=CanonicalScenario.SUCCESS.value,
    )
    arguments = parser.parse_args()
    result = asyncio.run(run_canonical_demo(CanonicalScenario(arguments.scenario)))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
