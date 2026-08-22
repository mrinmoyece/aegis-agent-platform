# Staff-level interview question bank

> **Current status:** these outlines assess design reasoning. References to
> runtime behavior are roadmap targets unless linked to current contracts or
> tests.

## Product and architecture

### Why is Aegis multi-agent instead of one large prompt?

**Answer outline:** telemetry, changes, runtime, and knowledge require distinct
least-privilege capabilities and can be investigated in parallel. A fixed
coordinator DAG gives budgets and deadlines. Typed ledger artifacts replace peer
chat. A critic challenges evidence. Deterministic aggregation avoids
completion-order races. More agents are not inherently better.

### What is authoritative state?

**Answer outline:** the append-only event log, not queue messages, traces,
caches, projections, model transcripts, or specialist memory. State is a
deterministic fold; projections are rebuildable.

### Why not use an agent framework?

**Answer outline:** the project teaches durability and safety mechanics
directly. Framework abstractions can hide state, retries, prompts, and tool
authority. Reconsider only when a framework can honor the same ports,
determinism, event semantics, and enforcement evidence.

## Reliability

### Can the platform guarantee exactly-once remediation?

**Answer outline:** no general exactly-once guarantee crosses external systems.
Use intent-before-effect, idempotency keys, fenced ownership, at-least-once
delivery, durable outcomes, and reconciliation for ambiguous completion.

### Why does a lease need a fencing token?

**Answer outline:** an expired worker may continue after a new worker acquires
the task. Time alone does not revoke authority. Authoritative writes reject the
older monotonic fence.

### What happens if the worker crashes after rollback succeeds?

**Answer outline:** replay finds a committed intent without a completion.
Reconcile using the idempotency key and target state; do not blindly infer
failure or issue an unkeyed second rollback.

## Security and tenancy

### Why separate identity from tenant authorization?

**Answer outline:** authentication proves a subject and issuer, not authority in
a selected tenant. Bind principal, tenant, action, and resource explicitly and
enforce again at persistence and tool boundaries.

### How do you stop prompt injection from executing rollback?

**Answer outline:** treat all content as untrusted. The model cannot grant
capabilities. A typed proposal passes runtime policy, exact scoped approval,
intent persistence, controlled tool validation, and sandbox/egress controls.

### How can specialists communicate safely?

**Answer outline:** only through typed tenant/incident-scoped artifacts committed
to the ledger. No direct chat, recursive spawning, hidden scratchpad authority,
or capability transfer.

## Evidence and evaluation

### How do you avoid blaming the nearest deployment?

**Answer outline:** correlate time, topology, rollout reach, trace path, logs,
metrics, and counter-evidence. Cite immutable references, expose confidence,
require critique, and preserve unresolved conflict.

### How do you know recovery is real?

**Answer outline:** predeclare a verification window and baseline, inspect
multiple checkout signals and downstream traces, account for traffic changes,
and persist evidence. Tool success is not service recovery.

### What should be deterministic in evaluation?

**Answer outline:** schemas, authorization, tenant isolation, citations,
budgets, transition legality, approval binding, and effect guards. Use
statistical or model grading only for semantic quality, calibrated against human
labels and never as the sole security assertion.

## Scale and operations

### How would you partition the event store?

**Answer outline:** start with tenant plus aggregate ordering requirements;
measure hot tenants and event size. Preserve per-aggregate concurrency, avoid a
global order claim, plan projection lag and tenant migration, and test restore.

### Which SLO matters first?

**Answer outline:** distinguish investigation latency from correctness and safe
remediation. Start with accepted-to-first-evidence latency, durable progress,
and recovery verification availability; pair each SLI with user impact and an
error-budget action.

### What makes the system production-ready?

**Answer outline:** not a feature checklist alone. Require isolation evidence,
failure and restore drills, SLOs, capacity tests, key rotation, privacy
workflows, signed artifacts, runbooks, audit review, and explicit residual risk.
