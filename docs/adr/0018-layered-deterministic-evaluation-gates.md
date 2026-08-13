# ADR 0018: Layer deterministic evaluation and release gates

- Status: Accepted/Implemented
- Date: 2026-08-13
- Supersedes and extends: [ADR 0007](0007-evaluation-strategy.md)

## Context

[ADR 0007](0007-evaluation-strategy.md) established versioned evaluation as
release evidence, deterministic security assertions, calibrated semantic
grading, and bounded post-release evaluation. Layer 11 needs a sharper boundary
between reproducible release gates, deployment-specific qualification,
probabilistic experiments, and observations from production.

Evaluation output can inform a release decision, but it cannot authorize work,
repair run state, or weaken production controls. Required CI also cannot depend
on live credentials, networks, providers, or production effects.

## Decision

1. Evaluator artifacts and results are immutable, versioned **release evidence**,
   never runtime or production truth. The append-only event ledger remains the
   source of run state, and authorization, policy, budgets, sandboxing, approval,
   intent-before-effect, reconciliation, and safety limits remain code-enforced.
2. Evaluation has four explicit classes:
   - **Hermetic deterministic CI:** required, offline, fixed clocks/IDs/seeds and
     provider-neutral fakes; no live secrets, network, or production effects.
   - **Environment-gated integration:** dedicated disposable services and
     non-production identities; opt-in and separately reported.
   - **Live/statistical evaluation:** opt-in qualification against dedicated
     non-production providers/connectors, with repeated samples and uncertainty.
   - **Production evidence:** bounded redacted operational observations used for
     review and corpus proposals, not replay inputs or authoritative state.
3. Provider-neutral dataset, scenario, grader, result, baseline, comparison, and
   waiver contracts are additive, immutable, schema-versioned, content-digested,
   and attributable to code, policy, prompt, provider/model, fixture, and grader
   versions. Vendor SDK objects stop at adapters.
4. Governed synthetic datasets cover the checkout scenario, adversarial inputs,
   and crash/recovery paths. They retain provenance, classification, ownership,
   review, retention, and expected deterministic assertions. Production content
   is not copied into required CI.
5. Hard safety assertions are individual baseline gates; quality improvements
   cannot offset a safety regression and safety failures are non-waivable. A
   non-safety release exception requires a reviewed waiver bound to exact
   case/metric scope, reason, owner, and expiry. Expired or mismatched waivers
   fail closed and remain in the release report.
6. Fault injection uses named deterministic cut points around durable intents,
   external-call boundaries, result appends, projection checkpoints, approval
   rechecks, verification, and deletion. Timing sleeps and random process failure
   are not acceptance evidence.
7. A model-as-judge is optional, isolated, redacted, versioned, and calibrated.
   It is disabled in required CI, has no tool or production authority, and is
   never the sole safety, authorization, tenancy, or effect gate.
8. Telemetry and reports contain bounded identifiers, digests, versions, counts,
   classifications, and aggregate statistics only. Raw prompts, evidence,
   credentials, tenant content, model transcripts, and unrestricted outputs are
   excluded.
9. Dataset lifecycle is explicit. Suspected leakage, poisoning, provenance loss,
   schema failure, or digest mismatch quarantines the version and blocks its use.
   Tamper is a security/release incident. Approved deletion records a tombstone,
   purges source and derived evaluation data subject to legal hold, and leaves
   minimal non-sensitive audit evidence; published results are never silently
   rewritten.

The implementation boundary is `aegis_agent_platform.evals`. Immutable
contracts, catalog, probes, fault injection, runner, scoring, baselines,
governance, reporting, telemetry, optional-live boundaries, and CLI are isolated
there. Governed fixtures, the dataset manifest, canonical baseline, and waiver
registry live under `evals/`. The CLI lists cases; runs all or `--case`/`--tag`
selections; replays reports; compares the checked-in baseline; explicitly
updates a baseline; and checks or writes a dataset manifest. `make evals` runs
the required fake-only gates. `make eval-deterministic`, `eval-adversarial`,
`eval-recovery`, `eval-baseline`, `eval-fixtures`, and `eval-meta` expose focused
paths; `eval-integration` remains environment-gated. See
[Evaluation and release evidence](../evaluation.md).

The required catalog contains 91 deterministic cases: 12 adversarial cases,
all 22 named fault cut points, and cross-layer core scenarios. The 22 evaluator
meta-tests cover contracts, repeatability, selection/sharding, scoring, hard
gates, baseline/waiver handling, fixture governance, reporting, telemetry, and
the fail-closed live/model-judge boundary.

## Consequences

- Required CI remains reproducible and safe to run on untrusted changes.
- Live compatibility, statistical quality, and production behavior cannot be
  collapsed into one score or one release badge.
- Baseline updates are reviewed changes, not automatic acceptance of current
  output; comparisons preserve regressions, segments, uncertainty, and waivers.
- Evaluation improves release confidence but does not certify production model
  or connector behavior, penetration resistance, human-label quality,
  observability/SLOs, HA/DR, multi-region operation, or final load/chaos limits.

## Explicit deferrals

Full production model/connector qualification, independent penetration testing,
large-scale human labeling, operator UI, MCP/A2A, the observability/SLO layer,
HA/DR and multi-region operation, and final load/chaos certification remain
separate acceptance work.
