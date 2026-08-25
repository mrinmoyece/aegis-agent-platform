# Evaluation and release evidence

## Status and boundary

Layer 11 is **implemented** under `aegis_agent_platform.evals` and governed by
[ADR 0018](adr/0018-layered-deterministic-evaluation-gates.md). Its immutable
contracts, catalog, probes, 22-point deterministic fault injector, runner,
scoring, baseline/waiver enforcement, fixture governance, bounded reports,
telemetry, optional-live boundary, and CLI are executable. Governed artifacts
live in `evals/fixtures`, `evals/datasets/checkout-layer11-v1.json`,
`evals/baselines/canonical-v1.json`, and `evals/waivers.json`.

The required suite contains 91 deterministic cases: 12 adversarial cases, all
22 named fault cut points, and cross-layer core scenarios. The evaluator
meta-suite in `tests/test_evaluation_platform.py` contains 22 tests. Existing
Layers 7–10 behavioral matrices remain additional fake-only regression checks.

Evaluator artifacts/results are release evidence, never runtime or production
truth. They cannot authorize a tenant action, reconstruct a run, satisfy an
approval, or substitute for the append-only event ledger. Production safety is
enforced in code: authentication and authorization, tenant policy, budgets,
schema checks, fencing, sandbox boundaries, durable intent, idempotency or
reconciliation, exact approval, and verification all fail closed independently
of an evaluation score.

## Evaluation classes

| Class | Purpose | Execution and release use |
| --- | --- | --- |
| Hermetic deterministic CI | Required safety and behavioral regression gates | Offline fixed fixtures, clocks, IDs, seeds, fakes, and named fault cut points; no live secrets, network, or production effects |
| Environment-gated integration | Adapter/database/runtime compatibility | Dedicated disposable or non-production services and scoped identities; opt-in, isolated, and separately reported |
| Opt-in live/statistical | Model/connector qualification and semantic drift | Dedicated non-production accounts, repeated samples, segments, confidence ranges, cost/latency bounds, and explicit human approval |
| Production evidence | Detect operational drift and propose future cases | Bounded redacted telemetry/reports only; never a replay source, release baseline by itself, or authoritative run state |

Required CI must remain hermetic. Network availability, a provider account, live
credential, model judge, production dataset, or mutating external target may not
be a prerequisite.

The hermetic class and its release artifacts are implemented. The code also
implements fail-closed configuration, caps, confidence intervals, and a
registered-adapter boundary for optional non-CI live/statistical runs, but no
adapter is registered by default and no live production qualification is
claimed. Environment-specific integration evidence remains separately gated.
Production evidence here means bounded reporting/telemetry contracts, not a
claim that production observations have been collected.

## Versioned provider-neutral contracts

The `aegis_agent_platform.evals` boundary defines immutable additive
contracts for dataset manifests, cases, scenarios, graders, fault plans, runs,
case results, baselines, comparisons, waivers, and reports. Every artifact carries
stable identity, schema version, content digest, provenance, classification,
owner/reviewer, creation input, retention state, and applicable code, policy,
prompt, fixture, adapter, provider/model, and grader versions. Vendor SDK types
remain inside optional live adapters.

Results distinguish pass, fail, error, skipped-by-class, quarantined, and waived;
they preserve each assertion and segment rather than reducing everything to one
score. Replay uses the recorded immutable inputs and versions. If an unavailable
external dependency prevents exact replay, the result says so rather than
inventing equivalence.

## Governed corpus

Initial datasets are synthetic and reviewed; no production record is required.
The versioned corpus covers:

- checkout success, missing evidence, ambiguous timing, conflicting telemetry,
  stale topology, and alternative-cause scenarios;
- prompt-injected runbooks, poisoned memory, forged citations, tenant confusion,
  role/capability escalation, unsafe action proposals, and false recovery;
- duplicate delivery, timeout, cancellation, budget exhaustion, stale fences,
  partial providers/connectors, crashes around intent/result boundaries,
  reconciliation, projection rebuild, quarantine, and deletion.

Cases declare required/prohibited evidence, claims, transitions, actions, and
recovery criteria. Synthetic generators, source fixtures, transformations,
licenses, sensitivity, and reviewer decisions are versioned and digested.

## Deterministic gates, faults, and waivers

Hard baseline gates include tenant isolation, authorization, immutable citation
reachability, transition legality, budget bounds, approval binding, no
effect-before-intent, sandbox/tool denial, ambiguity handling, and fresh recovery
verification. A quality aggregate cannot compensate for any failed hard gate.

Faults are injected at named cut points such as before/after intent commit,
external invocation, outcome append, lease reclaim, projection checkpoint,
approval/policy recheck, verification observation, and deletion purge. A run
records the cut-point identifier and explicit clock/ID/seed; sleep-based races and
unrecorded randomness do not establish a gate.

Hard safety findings are non-waivable. A non-safety waiver is an immutable
release artifact bound to exact case/metric scope, owner, reason, and expiry. It
neither changes the baseline nor weakens runtime enforcement. Missing, expired,
or mismatched waivers block comparison; baseline suite/dataset/case digests are
validated independently.

## Semantic grading

Deterministic graders own all implemented safety and contract assertions.
`ModelJudgeConfig` enforces disabled-by-default, versioned-rubric,
injection-delimited, never-sole-safety-gate configuration. No model judge
execution is implemented or run in required CI. Any future judge must receive
only minimized/redacted inputs, have no tools or production access, report
sampling uncertainty, use opt-in non-production credentials, and be calibrated
against reviewed labels. Large-scale human labeling remains deferred.

## Reports and production evidence

Reports expose bounded case IDs/digests, contract and baseline versions,
pass/fail/error/waiver counts, segmented deltas, confidence ranges, duration,
cost class, and classified failure codes. They exclude raw tenant content,
credentials, prompts, evidence, model transcripts, unrestricted tool output, and
high-cardinality tenant/run labels. Production observations may propose a
redacted synthetic case through review; they cannot be copied directly into CI
or used to rewrite historical results.

## Dataset lifecycle and incident handling

1. Quarantine a dataset version on suspected poisoning, leakage, provenance loss,
   malformed schema, license/retention violation, or digest mismatch. Exclude it
   from all gates and preserve bounded incident metadata.
2. Treat digest mismatch or unauthorized baseline/result modification as a
   tamper incident: stop promotion, preserve hashes and audit evidence, determine
   scope, and create a reviewed replacement version rather than editing history.
3. For deletion, check legal hold, record approval and tombstone, purge source,
   caches, judge inputs, exports, and derived reports where policy permits, then
   record completion. Historical reports mark data unavailable/deleted and retain
   only approved non-sensitive identity/digest evidence.

## Developer workflow

The current CLI is `python -m aegis_agent_platform.evals`:

```bash
python -m aegis_agent_platform.evals list
python -m aegis_agent_platform.evals check-fixtures
python -m aegis_agent_platform.evals run
python -m aegis_agent_platform.evals run --case identity.cross-tenant
python -m aegis_agent_platform.evals run --tag adversarial
python -m aegis_agent_platform.evals compare
python -m aegis_agent_platform.evals replay .aegis-evals/report.json
python -m aegis_agent_platform.evals update-baseline \
  --review-reference REVIEW-ID --yes
python -m aegis_agent_platform.evals write-manifest --yes
make evals
make eval-deterministic
make eval-adversarial
make eval-recovery
make eval-baseline
make eval-fixtures
make eval-meta
```

`run` accepts repeatable `--case` and `--tag` filters plus bounded shard,
concurrency, timeout, output, baseline, and waiver options. `compare` enforces
the checked-in canonical baseline. `replay` reruns exactly the case IDs in a
bounded prior JSON report. Baseline and manifest updates require explicit
confirmation; baseline updates additionally require a review reference and a
complete passing run. Outputs are bounded, content-checked JSON, Markdown, and
JUnit under `.aegis-evals` by default.

`make evals` combines the existing Layers 5 and 7–10 behavioral matrices with
the required Layer 11 deterministic, fixture, and baseline gates. The focused
targets above are hermetic. `make eval-integration` is separate,
environment-gated, and requires disposable PostgreSQL/Redis services; it is not
part of the no-service required path.

## Deferred qualification

Layer 11 does not complete full production model/connector qualification,
independent penetration testing, large-scale human labeling, operator UI,
MCP/A2A, observability/SLOs, HA/DR or multi-region readiness, or final load/chaos
certification. Track those gaps in [limitations](limitations.md), the
[roadmap](roadmap.md), and the
[enterprise implementation plan](enterprise-implementation-plan.md).

Layer 12 extends the catalog to 97 deterministic cases. Six observability cases
assert causal coverage, retry outcome deduplication, injected-secret absence,
telemetry-outage containment, replay convergence, and bounded safety alert
registration. They remain synthetic CI evidence and do not qualify a live
production telemetry or SLO path.

Layer 16 extends the catalog to 127 cases with eight final-qualification cases:
canonical archive/replay convergence, ambiguous-action recovery, protocol drift
and revocation, readiness, residual risk, chaos matrix, and performance budget
contracts. These remain hermetic release probes. The bounded load runner is a
separate regression gate and is not a model-quality baseline or production
capacity claim.
