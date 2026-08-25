"""Bounded local chaos and capacity smoke profiles for release evidence."""

from __future__ import annotations

import asyncio
import math
import sys
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from time import perf_counter
from typing import cast
from uuid import NAMESPACE_URL, uuid5

from aegis_agent_platform.agents.__main__ import run_canonical_demo
from aegis_agent_platform.agents.engines import CanonicalScenario
from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.gateway.__main__ import run_mock_diagnostic
from aegis_agent_platform.memory.demo import run_demo as run_memory_demo
from aegis_agent_platform.operator.demo import canonical_operator_snapshot
from aegis_agent_platform.protocols.__main__ import (
    ProtocolDemoScenario,
    run_protocol_demo,
)
from aegis_agent_platform.qualification.demo import (
    QUALIFICATION_NOW,
    QUALIFICATION_TENANT_ID,
    run_evidence_qualification_stage,
    run_qualification_demo,
)
from aegis_agent_platform.remediation.__main__ import (
    RemediationScenario,
    run_remediation_demo,
)
from aegis_agent_platform.sandbox.__main__ import (
    SandboxScenario,
    run_sandbox_demo,
)

type AsyncProfile = Callable[[int], Awaitable[object]]


async def run_chaos_smoke() -> Mapping[str, JsonValue]:
    """Execute deterministic recovery/denial branches without external systems."""
    scenarios: list[tuple[str, bool]] = []
    for agent_scenario, expected in (
        (CanonicalScenario.RECOVERY, "succeeded"),
        (CanonicalScenario.AMBIGUITY, "abstained"),
        (CanonicalScenario.BUDGET_EXHAUSTION, "budget_exhausted"),
    ):
        agent_result = await run_canonical_demo(agent_scenario)
        scenarios.append(
            (f"agent.{agent_scenario.value}", agent_result["status"] == expected)
        )
    for remediation_scenario, expected in (
        (RemediationScenario.AMBIGUOUS_RECONCILED, "verified"),
        (RemediationScenario.CRASH_RECOVERY, "verified"),
        (RemediationScenario.POLICY_ATTACK, "policy_denied"),
        (RemediationScenario.VERIFICATION_FAILURE, "verification_failed"),
    ):
        remediation_result = await run_remediation_demo(remediation_scenario)
        scenarios.append(
            (
                f"remediation.{remediation_scenario.value}",
                remediation_result["status"] == expected,
            )
        )
    for sandbox_scenario, expected in (
        (SandboxScenario.AMBIGUOUS_PROVISIONING, "cleaned"),
        (SandboxScenario.CLEANUP_RECOVERY, "cleaned"),
        (SandboxScenario.TIMEOUT, "cleaned"),
        (SandboxScenario.OUTPUT_QUARANTINE, "cleaned"),
        (SandboxScenario.MALICIOUS_ARCHIVE, "rejected"),
    ):
        sandbox_result = await run_sandbox_demo(sandbox_scenario)
        scenarios.append(
            (
                f"sandbox.{sandbox_scenario.value}",
                sandbox_result["status"] == expected,
            )
        )
    for protocol_scenario, expected in (
        (ProtocolDemoScenario.AMBIGUOUS_RECONCILIATION, "completed"),
        (ProtocolDemoScenario.CAPABILITY_DRIFT, "quarantined"),
        (ProtocolDemoScenario.REVOCATION, "denied"),
        (ProtocolDemoScenario.TENANT_ATTACK, "denied"),
    ):
        protocol_result = await run_protocol_demo(protocol_scenario)
        scenarios.append(
            (
                f"protocol.{protocol_scenario.value}",
                protocol_result["status"] == expected,
            )
        )
    memory = await run_memory_demo()
    scenarios.append(
        (
            "memory.index-cache-rebuild",
            bool(
                cast(Mapping[str, object], memory["purge"])["immutable_ledger_retained"]
            ),
        )
    )
    failures = tuple(name for name, passed in scenarios if not passed)
    if failures:
        raise RuntimeError(
            "qualification chaos scenario failed: " + ", ".join(failures)
        )
    return {
        "schema_version": 1,
        "profile": "ci-safe-deterministic-chaos",
        "scenario_count": len(scenarios),
        "passed": len(scenarios),
        "failed": 0,
        "scenarios": tuple(name for name, _passed in scenarios),
        "ledger_convergence_required": True,
        "production_chaos_claimed": False,
    }


async def run_load_smoke(
    *,
    samples: int = 3,
    p95_budget_ms: float = 5_000.0,
) -> Mapping[str, JsonValue]:
    """Measure bounded local profiles; results never extrapolate to production."""
    if not 3 <= samples <= 20:
        raise ValueError("load smoke samples must be between 3 and 20")
    if not 100 <= p95_budget_ms <= 60_000:
        raise ValueError("load smoke p95 budget is outside the CI-safe range")
    profiles: tuple[tuple[str, AsyncProfile], ...] = (
        ("api_event_append_read_replay", _full_profile),
        ("outbox_worker_throughput_queue_lag", _agent_profile),
        ("provider_gateway_concurrency_budgets", _gateway_profile),
        ("connector_pagination_correlation", _evidence_profile),
        ("dag_fanout_fanin", _agent_profile),
        ("approval_effect_flow", _remediation_profile),
        ("sandbox_scheduling_model", _sandbox_profile),
        ("pgvector_retrieval_model", _memory_profile),
        ("eval_runner", _eval_profile),
        ("protocol_boundary_exchange", _protocol_profile),
        ("ui_bundle_large_timeline", _operator_profile),
        ("restore_rebuild", _full_profile),
    )
    results: list[Mapping[str, JsonValue]] = []
    blocking: list[str] = []
    for name, profile in profiles:
        await profile(-1)

        async def _timed_sample(
            idx: int, _p: AsyncProfile = profile
        ) -> tuple[float, bool]:
            t0 = perf_counter()
            try:
                await _p(idx)
                return (perf_counter() - t0) * 1_000, False
            except (RuntimeError, ValueError, PermissionError):
                return (perf_counter() - t0) * 1_000, True

        started = perf_counter()
        # Run all samples concurrently so that concurrent reservation and
        # budget enforcement paths are exercised; serial execution can mask
        # races that only surface under load.
        sample_outcomes = await asyncio.gather(
            *[_timed_sample(i) for i in range(samples)]
        )
        elapsed = perf_counter() - started
        durations = [dur for dur, _ in sample_outcomes]
        errors = sum(1 for _, failed in sample_outcomes if failed)
        ordered = sorted(durations)
        p50 = _percentile(ordered, 0.50)
        p95 = _percentile(ordered, 0.95)
        p99 = _percentile(ordered, 0.99)
        error_rate = errors / samples
        throughput = samples / elapsed if elapsed > 0 else 0.0
        passed = error_rate == 0 and p95 <= p95_budget_ms
        if not passed:
            blocking.append(name)
        results.append(
            {
                "name": name,
                "samples": samples,
                "p50_ms": round(p50, 3),
                "p95_ms": round(p95, 3),
                "p99_ms": round(p99, 3),
                "throughput_per_second": round(throughput, 3),
                "error_rate": error_rate,
                "p95_budget_ms": p95_budget_ms,
                "passed": passed,
            }
        )
    result: Mapping[str, JsonValue] = {
        "schema_version": 1,
        "profile": "bounded-local-deterministic",
        "environment": "developer-or-ci-host; not normalized production hardware",
        "samples_per_profile": samples,
        "profiles": tuple(results),
        "profile_count": len(results),
        "blocking_profiles": tuple(blocking),
        "production_capacity_claimed": False,
    }
    return result


async def _gateway_profile(index: int) -> object:
    run_id = uuid5(NAMESPACE_URL, f"qualification-load-gateway:{index}")
    return await run_mock_diagnostic(
        "Bounded gateway load probe.",
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=run_id,
    )


async def _agent_profile(index: int) -> object:
    return await run_canonical_demo(
        CanonicalScenario.SUCCESS,
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=uuid5(NAMESPACE_URL, f"qualification-load-agent:{index}"),
    )


async def _evidence_profile(index: int) -> object:
    del index
    return await run_evidence_qualification_stage([])


async def _remediation_profile(index: int) -> object:
    return await run_remediation_demo(
        RemediationScenario.AMBIGUOUS_RECONCILED,
        tenant_id=QUALIFICATION_TENANT_ID,
        investigation_run_id=uuid5(
            NAMESPACE_URL,
            f"qualification-load-remediation:{index}",
        ),
    )


async def _sandbox_profile(index: int) -> object:
    return await run_sandbox_demo(
        SandboxScenario.APPROVED_ANALYSIS,
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=uuid5(NAMESPACE_URL, f"qualification-load-sandbox:{index}"),
    )


async def _memory_profile(index: int) -> object:
    del index
    return await run_memory_demo()


async def _protocol_profile(index: int) -> object:
    return await run_protocol_demo(
        ProtocolDemoScenario.ARTIFACT_EXCHANGE,
        tenant_id=QUALIFICATION_TENANT_ID,
        run_id=uuid5(NAMESPACE_URL, f"qualification-load-protocol:{index}"),
    )


async def _eval_profile(index: int) -> object:
    del index
    with tempfile.TemporaryDirectory(prefix="aegis-qualification-eval-") as directory:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "aegis_agent_platform.evals",
            "run",
            "--case",
            "ledger.additive-replay",
            "--output",
            directory,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                "bounded evaluation profile failed: "
                + stderr.decode(errors="replace")[:512]
            )
        return process.returncode


async def _operator_profile(index: int) -> object:
    snapshot = canonical_operator_snapshot(
        at=QUALIFICATION_NOW + timedelta(seconds=max(index, 0))
    )
    return tuple(
        sorted(
            (
                item.occurred_at.isoformat(),
                item.item_id,
                item.status,
            )
            for _ in range(100)
            for items in snapshot.sections.values()
            for item in items
        )
    )


async def _full_profile(index: int) -> object:
    del index
    with tempfile.TemporaryDirectory(prefix="aegis-qualification-load-") as directory:
        return await run_qualification_demo(Path(directory))


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        raise ValueError("percentile requires samples")
    index = max(0, math.ceil(fraction * len(values)) - 1)
    return values[index]


__all__ = ["run_chaos_smoke", "run_load_smoke"]
