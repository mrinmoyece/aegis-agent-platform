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

### What happens if the worker crashes after a controlled action succeeds?

**Answer outline:** replay finds a committed intent without a completion.
Reconcile using the idempotency key and target state; do not blindly infer
failure or issue an unkeyed second action. Layer 8 redelivery detects the
in-flight attempt and reconciles before retry.

## Security and tenancy

### Why separate identity from tenant authorization?

**Answer outline:** authentication proves a subject and issuer, not authority in
a selected tenant. Bind principal, tenant, action, and resource explicitly and
enforce again at persistence and tool boundaries.

### How do you stop prompt injection from executing remediation?

**Answer outline:** treat all content as untrusted. The model cannot grant
capabilities. A typed immutable proposal passes deny-by-default runtime policy,
exact human approval, current-fence checks, intent persistence, fixed-shape
adapter validation, reconciliation, and explicit verification. Layer 8 exposes
no arbitrary production command or model-selected credential. Layer 9 analysis
uses a separate exact-approval sandbox boundary and cannot mutate production.

### Why is a Kubernetes Job manifest not proof of sandbox isolation?

**Answer outline:** workload security context is only one layer. Admission must
reject weakening mutations; the runtime class/node boundary must isolate the
kernel; PID and resource controllers must enforce limits; network policy and an
egress/DNS boundary must prevent metadata/private-network/rebinding attacks; and
content/artifact drivers must preserve tenant scope. Layer 9 therefore generates
a locked-down suspended Job but reports readiness false until those environment
controls are independently verified.

### How does sandbox redelivery avoid duplicate or orphaned workloads?

**Answer outline:** it does not claim exactly once. A stable tenant/sandbox name
and spec digest form the provider identity. The current fenced worker commits
provision/cleanup intent, observes before create/delete retry, records explicit
reconciliation, and continues only for a matching scope. Unknown or conflicting
state remains ambiguous or quarantined. Redis acknowledgement is irrelevant to
the authoritative decision.

### Why reject shell strings even when execution is isolated?

**Answer outline:** isolation reduces impact but does not make command
construction safe. Provider-neutral contracts preserve argv token boundaries;
canonical validation rejects shell families, interpolation/control operators,
control characters, and policy-escaping Unicode. No adapter may use
`shell=True`, `eval`, or a host subprocess fallback.

### Why is pgvector not the memory source of truth?

**Answer outline:** authoritative event/artifact references are distinct from
derived search acceleration. Replay, lifecycle intent, forced RLS, tenant-first
filtering, checkpoints/rebuild, and cache invalidation keep correctness outside
the ANN index. pgvector cannot decide acceptance, retention, legal hold, or
deletion.

### How does compaction avoid turning a model summary into false memory?

**Answer outline:** record summary intent and exact source references, validate
every claim citation and coverage, preserve contradiction, bound recursive
depth, reject unsupported output, use deterministic extractive fallback, and
keep raw references. Summaries are derived, and retrieved text cannot grant
tools, roles, policy, or approvals.

### How can specialists communicate safely?

**Answer outline:** only through typed tenant/incident-scoped artifacts committed
to the ledger. No direct chat, recursive spawning, hidden scratchpad authority,
or capability transfer.

### How does Layer 7 prevent parallel completion order from changing the answer?

**Answer outline:** the coordinator alone declares the immutable acyclic graph.
Readiness is a pure function of ledger-folded task states. Ready nodes sort by
declared ordinal and ID; completed task results sort again by ordinal and
artifact kind/ID before one fenced append. No specialist writes shared state or
talks to peers. Replay rejects premature dispatch, duplicate identity, and
unreachable provenance, so wall-clock completion cannot become authority.

### When must the coordinator abstain instead of finalizing?

**Answer outline:** finalization requires a durable selected hypothesis with
valid immutable citations, confidence at or above the plan threshold, and at
least one accepted critique with no unsupported claims or unresolved
contradictions. Missing evidence, contradictory evidence, critic rejection, or
low confidence produces an explicit abstain/escalate artifact retaining
unresolved questions. A fluent model response cannot override this runtime gate.

### Why is a remediation recommendation not permission to remediate?

**Answer outline:** Layer 7's artifact constructor requires `proposal_only=true`
and binds the recommendation to an upstream hypothesis. Layer 8 is a separate
boundary: authenticated humans authorize the exact tenant, immutable
plan/action/policy digests, target, risk, quorum, and expiry. The executor
rechecks that scope and its PostgreSQL fence before intent, invokes only a
controlled idempotent adapter, reconciles ambiguity, and records fresh
verification. Agents cannot approve their own proposals.

## Identity and tenancy deep dive

> Layer 2 implements a real vertical slice for these questions
> (`identity/authentication.py`, `identity/authorization.py`, `policy/`,
> `audit.py`, `secrets_boundary.py`, `migrations/0001_identity_governance.sql`),
> proven by a committed automated negative-test suite
> (`tests/test_identity_security.py`, `tests/test_policy_security.py`,
> `tests/test_audit_secrets.py`, `tests/test_migrations.py`). Durable Postgres
> wiring, live-Keycloak drills, and quota usage accounting remain planned —
> see `limitations.md` and `roadmap.md` before claiming the full gate is met.

### Why does `AuthorizationService.decide` check tenant match before checking permission?

**Answer outline:** deny-by-default means the cheapest, least-ambiguous check
runs first. A caller from tenant A must never learn *anything* about tenant
B's roles or permissions — not even "the permission would have been denied
anyway." Checking tenant identity first and returning
`cross_tenant_access_denied` collapses the entire cross-tenant surface to a
single reason code, so no permission-specific detail leaks across a tenant
boundary. It also means a bug in `ROLE_PERMISSIONS` can never accidentally
grant cross-tenant access, because the tenant check is unconditional and
runs in code the permission table cannot influence.

### Why verify JWTs against a deterministic `StaticJwksProvider` fixture instead of a live Keycloak realm in tests and the tutorial?

**Answer outline:** correctness of signature/issuer/audience/expiry
verification is a property of the verifier and the key material, not of the
network. A deterministic fixture (a fixed RSA keypair, fixed `kid`, fixed
claims) makes tests reproducible, offline, and fast, and lets negative cases
(wrong `kid`, wrong issuer, expired token) be constructed exactly rather than
raced against a live IdP's clock and rotation schedule. `RemoteJwksProvider`
exists specifically so the *same* `JwtVerifier` code path also works against a
real Keycloak-compatible JWKS endpoint — the fixture proves the verifier
logic; a deployment-time integration check proves reachability. Conflating
the two would make unit tests flaky for reasons that have nothing to do with
the code under test.

### Why does `AuthenticationService` resolve identity through `IdentityDirectory` instead of trusting claims already inside the verified JWT?

**Answer outline:** a verified signature only proves the issuer signed those
claims at issuance time — it does not prove the subject is still enabled,
still belongs to the tenant it claims, or still holds the roles a client
might embed in a custom claim. Treating the JWT as authoritative for
authorization would let a valid-but-stale or attacker-influenced claim (e.g.
a role claim from an over-broad IdP mapping) bypass this system's own
tenant/role source of truth. The directory is the single place authority is
looked up, so revoking a user or changing tenant membership takes effect
immediately without waiting for token expiry.

### Why is `PolicyEvaluator.evaluate` a pure function over a caller-supplied `QuotaUsage` instead of querying live usage itself?

**Answer outline:** keeping the evaluator pure — no I/O, no wall clock, no
hidden lookups — makes every policy decision a deterministic, unit-testable
fold over its inputs, consistent with the domain-purity invariant. It also
makes the *boundary* between "what counts as usage" (a runtime/accounting
concern, planned for later layers) and "what a limit means" (a governance
concern, implemented now) explicit and independently testable. If the
evaluator queried usage itself, testing policy edge cases would require
faking a stateful usage store instead of just constructing a `QuotaUsage`
value.

### Why are secrets modeled as `SecretReference`/`SecretValue` instead of plain strings?

**Answer outline:** a plain string secret can be logged, serialized into an
audit event, or captured in a stack trace by accident — there is no type
system to stop it. `SecretReference` carries only provider, name, and version
metadata, so a component can request a secret without ever holding it.
`SecretValue` wraps the revealed material in a slotted object whose `repr`
and `str` are redacted by construction, and `.reveal()` is the single
explicit call site where material becomes visible — making every accidental
leak path (logging, string interpolation, equality against a log line) fail
safe instead of fail open.

### Why does `AuditEvent.__post_init__` redact `details` unconditionally instead of trusting the caller to redact first?

**Answer outline:** an append-only, tamper-evident audit log is only useful if
it can never be revoked from bad callers — but caller discipline is exactly
the kind of invariant that erodes over time as new call sites are added.
Redacting inside the frozen dataclass's constructor means there is no way to
construct an `AuditEvent` instance carrying an unredacted secret, regardless
of which route, specialist, or future caller creates it. This is the same
"fail closed by construction" pattern as `SecretValue`: the safety property
lives in the type, not in caller convention.

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
