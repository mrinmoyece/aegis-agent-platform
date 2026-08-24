# Threat model

## Scope and assumptions

This model covers the intended platform and marks control status honestly.
Layer 1 established contracts; Layers 2–3 added governance and the ledger.
Layer 4 adds Redis delivery plus PostgreSQL leases/fencing and live race evidence.
Layer 5 adds the provider-neutral model gateway and fenced cost governance.
Layer 6 adds read-only evidence adapters, bounded immutable ingestion, and
deterministic correlation. Layer 7 adds the fixed specialist DAG, durable typed
reasoning artifacts, and deterministic critic/finalization gates. Layer 8 adds
immutable remediation scope, deny-by-default policy, authenticated
separation-of-duties approval, fenced controlled effects, reconciliation, and
explicit postcondition verification. Layer 9 adds strict untrusted execution
contracts, approval-bound sandbox policy, fenced provider lifecycle intents,
safe artifacts, default-deny egress, and cleanup reconciliation.
Layer 10 adds event-grounded memory and derived retrieval. Layer 11 currently
implements hermetic release gates, governed synthetic datasets, deterministic
fault injection, baseline/waiver controls, bounded reports, and fail-closed
optional-live/model-judge configuration.
The system assumes model output, tool output, retrieved
content, and tenant input can be hostile. Cloud, identity provider, model
provider, and operator accounts can be compromised. Prompt instructions are
never trusted as controls.

## Assets

- tenant data, prompts, memory, tool inputs, and outputs
- credentials, provider tokens, signing material, and sandbox capabilities
- event-log integrity and audit evidence
- authorization policy and tenant membership
- model budgets, infrastructure capacity, and service availability
- evaluation datasets and release decisions
- incident evidence, hypotheses, approvals, remediation plans, and records
- Dynatrace, GitHub, Kubernetes, and incident-system integration authority

## Trust boundaries

1. User or client to control plane.
2. Control plane to identity provider.
3. Control plane and workers to durable storage and queue.
4. Runtime to external model providers.
5. Runtime to tools and isolated sandboxes.
6. Runtime to memory and retrieval sources.
7. Services to telemetry backends and operators.
8. Build system to registries and deployment environments.
9. Evidence sources and runbooks to the investigation context.
10. Approval channel to controlled remediation tools.
11. Dataset producers, evaluators, optional judges, and release decision makers.

## Principal threats and required controls

| Threat | Example impact | Required control | Current status |
| --- | --- | --- | --- |
| Tenant confusion | Cross-tenant reads or work claims | Explicit tenant context, database policy, negative tests | PostgreSQL repositories use transaction-local context; forced RLS and confused-deputy denial are proven against PostgreSQL 16 |
| Identity spoofing | Attacker acts as an operator | OIDC validation, key rotation, audience checks | Standards-correct JWT signature/issuer/audience/expiry/algorithm verification implemented against deterministic fixtures and a Keycloak-compatible JWKS config, with a committed negative-test suite for malformed/expired/wrong-issuer/wrong-audience/unsupported-algorithm tokens; live-IdP key-rotation drills against a running Keycloak remain a deployment-time check |
| Prompt injection | Evidence/model content changes authority or bypasses review | Treat content as untrusted data, strict schemas, code-enforced roles/citations, exact human approval | Layer 8 policy and action parsing fail closed; content cannot approve or widen an action |
| Confused deputy | Action uses broader platform privilege | Exact tenant/action/target policy and fixed-shape adapter | Implemented for rollout restart; short-lived capability credential brokering remains planned |
| Duplicate delivery | Repeated work or external effect | Intent event, deterministic message identity, inbox, idempotency, target reconciliation | Redis/inbox deduplication plus Layer 8 tenant effect claims and reconciliation implemented |
| Stale lease holder | Old worker overwrites a reclaimed result | PostgreSQL token/generation fence on every write | Implemented and live-tested |
| Queue tenant spoofing | Work executes under another tenant | Tenant-bound envelope plus trusted context and RLS | Implemented; malformed/mismatched envelopes fail closed |
| Poison queue payload | Parser exploit or supervisor crash | Size/schema bounds and quarantine | Safe decoder and supervisor containment implemented |
| Event tampering | False state or missing audit evidence | Append controls, hashes/retention, restricted roles | Event/audit update-delete rejected by grants and live-tested triggers; retention and access review remain planned |
| Sandbox escape | Host or network compromise | Non-root isolated runtime, immutable image, dropped capabilities, seccomp/AppArmor, no host namespaces/socket, deny-by-default network, quotas | Layer 9 contracts, manifest, validation, and fail-closed readiness implemented; production admission/runtime/network enforcement is unverified |
| Shell/path injection | Prompt-generated command escapes intended operation | argv tokens only, canonical Unicode/path validation, no shell/eval, immutable workspace | Implemented and adversarially tested |
| Malicious archive/artifact | Traversal, symlink/device escape, decompression bomb, malware or secret exfiltration | validate all members, atomic staging, size/count/ratio bounds, scanning/redaction/quarantine | Implemented with pluggable production scanner boundary |
| Sandbox approval drift | Changed image/spec/policy/risk reuses stale authority | dedicated Layer 8 sandbox action digest contains exact spec, policy, purpose, and risk; current approval is rechecked | Implemented; PostgreSQL authority compares the reviewed action scope under RLS |
| Ambiguous sandbox create/delete | Duplicate orphan or leaked workload | stable name, observe-before-create, intent event, reconciliation-before-retry, cleanup redrive | Implemented without exactly-once claim |
| DNS/private-network bypass | Metadata, loopback, private/link-local, rebinding, or Unix socket access | network none default, exact canonical DNS allowlist, broker/admission enforcement | Contract denial implemented; production proxy and DNS-rebinding enforcement remain unverified |
| Secret exfiltration | Credentials in prompts or telemetry | Brokered secrets, redaction, content policy | Secret-reference abstraction, redacted `SecretValue`, and audit-detail redaction implemented; only a local environment-variable provider exists, no vault-backed broker |
| Provider data leakage | Sensitive content retained externally | Provider policy, classification, regional routing | Retention/residency policy and routing implemented; provider account verification and encrypted content artifacts remain planned |
| Resource exhaustion | Runaway work or noisy tenant | Deadlines, queue backpressure, global and tenant quotas | Worker and provider concurrency, timeouts, request/token limits, circuits, and fenced model budgets implemented |
| Supply-chain compromise | Malicious build dependency/action | Pinned actions, review, scanning, attestations | Partial |
| Telemetry leakage | Tenant data in labels or traces | Redaction and bounded-cardinality conventions | Runtime/model instruments use fixed names and catalog-bounded provider/model labels without tenant/run/request IDs; backend review remains planned |
| Evaluation poisoning | Unsafe release passes gates | Synthetic governed datasets, provenance/digests, quarantine, immutable results | Implemented fixture manifest, digest/shape/sensitive-content checks, and quarantine disposition |
| Baseline or waiver abuse | Regression is normalized or exception silently broadened | Reviewed immutable baseline changes; hard safety non-waivable; exact non-safety case/metric, owner, reason, and expiry | Implemented with complete-passing-run baseline updates and fail-closed expiry |
| Model-judge manipulation | Prompt injection or judge drift marks unsafe behavior acceptable | Disabled-by-default versioned isolated configuration and deterministic safety gates | Configuration guard implemented; no judge execution or live qualification claimed |
| Evaluation side effect | CI leaks a credential, reaches production, or mutates a target | Hermetic required suite; no live secret/network/effect; optional live boundary prohibited in CI and separately capped | Implemented and covered by evaluator meta-tests; no live adapter registered by default |
| Evidence spoofing | Forged logs or change metadata drives a false hypothesis | Authenticated adapters, immutable references, timestamps, source labeling | Bounded authenticated adapters, digests, trust status, and quarantine implemented; live source assurance remains deployment evidence |
| Stale correlation | Unrelated deployment is blamed for checkout failures | Explicit time windows, topology, counter-evidence, confidence | Deterministic clock-skew bounds, rationale, ambiguity, and conflicts implemented; no causal inference |
| Runbook injection | Hostile text asks the agent to bypass policy | Treat runbooks as untrusted evidence; runtime authorization | Runtime approval and action policy implemented; injected arguments fail validation |
| Approval confusion | Approval for one incident authorizes another action | Bind approval to tenant, plan/action/policy digests, exact target/risk/quorum/expiry | Implemented with stale/replay/forgery/cross-tenant negative tests |
| Approval race or compromised approver | Revoked, expired, self-approved, or stale authority executes | Current role/policy/scope recheck, SoD, distinct quorum, optimistic concurrency, immutable audit | Implemented |
| Remediation escalation | Action mutates unrelated services | Exact target fingerprint, allowlist, fixed-shape port, preflight recheck | Implemented for rollout restart; destructive/broad actions disabled |
| Ambiguous or duplicate effect | Blind retry repeats provider mutation | Stable tenant idempotency key, durable intent, check-before-retry reconciliation, conflict escalation | Implemented without an exactly-once claim |
| Stale remediation worker | Old lease applies or records an action | PostgreSQL token/generation check before intent and fenced outcome append | Implemented and negative-tested |
| False recovery | Incident closes after action API acceptance or transient signal | Explicit postconditions and fresh evidence with success/failure/partial/unknown | Implemented; live external verification remains deployment evidence |
| Connector token theft | Dynatrace or GitHub authority is exfiltrated | Brokered read-only credentials, rotation, redaction | Typed secret references and redaction implemented; vault brokering/rotation drills planned |
| Agent authority creep | Specialist spawns workers or obtains broader tools | Fixed roles, coordinator-owned DAG, deny-by-default capability/output policy | Implemented and negative-tested |
| Opaque collusion | Peer chat creates uncited consensus | No peer channel; ledger-only typed artifacts and independent critic | Implemented |
| Runaway swarm | Recursive agents exhaust tokens or capacity | No specialist spawning; hard depth/fan-out/iteration/token/time bounds | Implemented |
| Aggregation race | Completion order changes the chosen hypothesis | Plan ordinal/ID ordering and deterministic artifact append/fold | Implemented |
| Critic bypass | Unsupported hypothesis reaches remediation | Required critic dependency, citations, confidence threshold, contradiction gate | Implemented for proposal/final assessment |
| Memory poisoning | Hostile or stale knowledge biases incident response | Acceptance, provenance, scanning, source quality, recency, critique, deletion | Implemented with deterministic scanner hooks; external DLP/malware service unverified |
| Compaction loss | Summary drops conflict, approval, or safety limits | Citation-preserving validation, rejection, deterministic fallback, and tests | Implemented |
| Cross-tenant embedding leak | Semantic search returns another tenant's data | Tenant/ACL filtering, forced RLS, tenant cache keys, adversarial retrieval tests | Implemented |
| A2A peer spoofing/replay | External agent injects or repeats tasks/artifacts | Authenticated peers, task binding, idempotency, replay protection | Planned |
| Protocol authority bypass | MCP/A2A message invokes tools outside policy | Treat as untrusted adapter input; enforce internal runtime controls | Planned |

## Abuse cases

- A tenant embeds instructions in a document to retrieve another tenant's data.
- A compromised provider response fabricates a tool result or approval.
- A worker crashes after a provider accepted a request but before completion was
  recorded.
- A lease expires while the original worker is still running.
- An operator uses a valid identity but exceeds tenant-scoped authority.
- Sensitive prompt content becomes a high-cardinality metric label.
- A malicious runbook embeds instructions to approve or execute a rollback.
- A valid approval is replayed against a different deployment or tenant.
- A short checkout recovery masks continuing trace errors downstream.
- Parallel specialists disagree about whether the deployment caused the failure.
- A compromised specialist attempts to request a write-capable tool or spawn a
  helper outside the coordinator's plan.
- A poisoned dataset or unauthorized baseline update hides a tenant-isolation
  regression.
- A model judge follows injected evidence or a waiver is replayed for a broader
  release.

## Multi-agent failure controls

The coordinator is a control-plane role, not a privileged general-purpose
agent. It owns a predeclared dependency DAG, incident state, aggregate budget,
and deterministic merge policy. Each specialist receives only its fixed
capability set and bounded step, token, and time budget. Read-only branches can
run in parallel, but completion order cannot determine the authoritative result.

There is no peer messaging channel and no recursive spawning. A specialist
commits a typed artifact to the event ledger; downstream roles read that durable
record. Findings and hypotheses cite evidence identifiers and confidence, while
the reviewer records counter-evidence and conflicts. Unresolved conflict is
shown to the operator rather than averaged into false certainty. Remediation is
a separate typed proposal and cannot grant tool authority. Human approval is
bound to the exact proposal, and verification is performed by a distinct role.

Layer 7 implements scheduling, capability/output enforcement, budgets,
deterministic aggregation, critique, and safe abstention. Layer 8 consumes the
immutable proposal through policy, human approval, controlled execution,
reconciliation, and fresh-evidence verification. An agent cannot approve its
own proposal or treat provider acceptance as recovery.

## Canonical scenario security questions

For checkout failures after a deployment, Aegis must prove which Dynatrace
problem, logs, traces, metrics, topology edges, and events support each claim;
which GitHub deployment, commit, and pull request are temporally and causally
relevant; and which Kubernetes/runtime change actually reached the affected
service. Missing evidence lowers confidence rather than being invented.

The proposal must identify the exact rollback target and expected effect.
Approval is durable, scoped, versioned, expiring, and separate from model output.
The runtime records intent before the controlled tool receives authority.
Recovery requires an explicit observation window and multiple relevant signals
before the incident record is updated.

Deterministic Layer 8 acceptance tests exercise approval success, denial,
staleness/expiry, policy and tenant attacks, ambiguous-effect reconciliation,
verification failure/rollback, and crash recovery. Live targets remain
deployment evidence.

## Layer 1 residual risk

Most agent-runtime controls are still unimplemented. Dynatrace and GitHub
contracts do not authenticate or call vendor APIs. The health endpoints are
unauthenticated by design and carry no sensitive data. The Compose stack uses
local-only credentials and exposes ports on loopback, but a developer
workstation remains outside the production threat model. Do not use this
repository for real tenant or provider data.

## Layer 2 residual risk

Authentication, deny-by-default authorization, tenant-scoped policy/quota
evaluation, and redacted audit events are implemented and proven by a
committed automated test suite (`tests/test_identity_security.py`,
`tests/test_policy_security.py`, `tests/test_audit_secrets.py`,
`tests/test_migrations.py`, and cross-tenant/authentication cases in
`tests/test_api.py`) covering cross-tenant denial,
malformed/expired/wrong-issuer/wrong-audience/unsupported-algorithm tokens,
expired and revoked role bindings, quota/policy allow-deny-require-approval
boundaries, and audit redaction/append-only behavior at the application
layer — all against deterministic fixtures. Layer 3 adds PostgreSQL equivalents
and live RLS evidence. `RemoteJwksProvider` is tested against a mocked
HTTPS transport, not a live Keycloak realm — whether that realm is reachable,
populated with users, and rotated correctly is a deployment concern not
verified by these tests. Quota *limits* are evaluated deterministically;
quota *usage* accounting has no authoritative source until the durable
runtime lands. Secrets remain local-environment-variable only; there is no
vault-backed broker, rotation, or leak-scanning pipeline.

## Layer 3 residual risk

The ledger, inbox/outbox mechanics, projections, durable Layer 2 repositories,
and database isolation are implemented and live-tested. This does not prove
exactly-once effects: no effect adapter exists, and a future crash after target
acceptance will require idempotency or reconciliation. Layer 4 supplies the
publisher and Redis notifier. Projection handlers cover representative typed
events; the incident state machine and agent scheduler remain absent. The
maintenance role requires deployment-time credential brokering and approval.
Backup, restore, retention, partitioning, HA, and regional recovery remain
Layer 8.

## Layer 4 residual risk

Redis is transport and can lose availability without losing PostgreSQL truth, but
continuous publisher/reconciler deployment is an operational requirement. Shared
stream fairness is approximate across worker processes. TLS/auth are validated
for production configuration but managed Redis failover, PostgreSQL HA, backup,
restore, and multi-region behavior are untested. No external target is called, so
the intent/result ambiguity protocol is represented but target idempotency and
reconciliation are not yet proven. Cooperative cancellation does not isolate
hostile code; sandboxing remains Layer 6.

## Layer 5 residual risk

Provider SDK calls now require tenant policy, catalog capability, health, and a
fenced durable reservation. Raw content and API keys are excluded from model
events, logs, metrics, and spans. This does not prove a provider honors retention
or residency claims, and the environment secret provider is not a vault. There
is no encrypted durable prompt/response store. A timeout can follow provider
acceptance and billing; Aegis records ambiguity but cannot automatically
reconcile a provider invoice. Provider egress, proxy, TLS trust roots, account
rotation, and live regional failure drills remain deployment evidence.

## Layer 6 residual risk

Connector transports are verified with mocks and deterministic Kubernetes/
runbook fixtures, not this repository's external accounts or clusters. A
deployment must verify least-privilege scopes/RBAC, tenant endpoint and
repository/namespace allowlists, private egress, proxy behavior, certificate
trust, credential rotation, API versions, quotas, and residency. GitHub and
Dynatrace webhook ingestion is absent; no endpoint should be exposed as one.

Evidence remains hostile after authenticated retrieval. Redaction hooks reduce
known credential/PII patterns but are not a complete DLP system. Full raw
payload storage is absent; only bounded redacted ledger content or an encrypted
external object reference is valid. Correlation preserves uncertainty and makes
no diagnosis. Specialist reasoning, approval, remediation, sandboxing,
memory/RAG, deletion/legal hold, and production alerting remain outside this
layer.

## Layer 7 residual risk

The checkout workflow is proven with deterministic fake providers/connectors and
bounded committed evidence, not a live model or external incident. Strict
structured output, citations, role transitions, critic review, and supervisor
containment reduce model risk but cannot prove semantic correctness. The
coordinator may abstain or escalate; it must not invent missing evidence.

The PostgreSQL event stream remains authoritative and specialist projections are
rebuildable. Live PostgreSQL tests prove RLS, fencing, pagination, and rebuild in
a disposable database, not backup/restore, HA, regional failover, or production
capacity. Layer 7 remediation remains proposal-only; Layer 8 provides the
separate approval and execution boundary.

## Layer 8 residual risk

The checkout remediation workflow is proven with deterministic fake evidence and
actions. The official Kubernetes adapter is unit-tested against a fake official
client and is not connected to a production cluster. A deployment must verify
least-privilege workload identity, namespace/deployment allowlists, API
compatibility, private egress, timeouts, target read-after-write semantics,
credential rotation, and operator escalation.

At-least-once delivery means a provider effect may remain ambiguous after a
network partition or crash. Stable idempotency and reconciliation reduce blind
duplicates but cannot prove exactly once. Unrestricted interactive sandboxing,
arbitrary production commands, production-qualified operator UI, MCP/A2A, broad
autonomous remediation, live external verification, production deployment, HA/DR, and
multi-region operation remain absent.

## Layer 9 residual risk

The sandbox contracts, policy, validation, event lifecycle, fake backend,
workspace/artifact handling, RLS schema, APIs, and Kubernetes workload generator
are executable. The fake never runs untrusted code, and official-client tests do
not establish cluster isolation.

A production deployment must independently prove admission policy, isolated
runtime class and node posture, PID/cgroup limits, default-deny network policy,
egress proxy and DNS-rebinding defense, metadata/private-address blocking,
trusted content/artifact drivers, scanner behavior, retention/cleanup, and
operator quarantine response. Secrets and writable seeded inputs fail closed
because their broker/copy-on-write boundaries are not implemented. Image
signature/SBOM policy and remote attestation remain planned. Provider create/
delete can still be ambiguous; stable naming and reconciliation do not make it
exactly once.

## Layer 10 residual risk

Retrieved text, runbooks, historical summaries, and model output remain untrusted.
Layer 10 marks injection/poisoning, requires curated acceptance, applies tenant/
ACL/purpose/retention filters before ranking, renders snippets inside explicit
data delimiters, and prevents memory from granting tools, roles, approvals, or
policy. These controls reduce authority escalation but do not prove that accepted
knowledge is true; citations, conflicts, confidence, critic review, and
abstention remain mandatory.

Forced RLS, tenant-first keys, tenant-digested caches, finite eight-dimensional
vectors, quotas, fencing, and rebuild tests provide executable isolation and
recovery evidence. They do not certify live embedding providers, external
DLP/malware scanning, production encrypted/erasable blobs, key destruction,
backup expiry, global cache invalidation, HA/DR, multi-region operation, or
production-scale resistance to approximate-nearest-neighbor abuse.

## Layer 11 residual risk

[ADR 0018](adr/0018-layered-deterministic-evaluation-gates.md) and
[evaluation.md](evaluation.md) define the implemented
`aegis_agent_platform.evals` contracts, 91-case governed corpus, CLI, reports,
hard gates, baseline/waiver handling, fixture governance, telemetry, and
fail-closed optional-live boundary. The deterministic suite and existing fake
behavioral matrices do not qualify live models/connectors or production
behavior. No model judge or live adapter executes by default.

Layer 12 addresses telemetry injection, hostile trace context/baggage, metric
cardinality exhaustion, secret/PII leakage, support-bundle exfiltration,
cross-tenant timeline enumeration, and debugger mutation with validation,
allowlists, redaction, bounds, purpose/RBAC checks, immutable access audit, and
read-only adapters. Residual risks include hash-key compromise, backend access
policy, collector spoofing without production mTLS/auth, and incomplete
production telemetry qualification.

Layer 13 addresses browser token theft, CSRF, cross-tenant cache bleed,
client-authority confusion, response/schema smuggling, XSS/unsafe URLs, CSV formula
injection, unsafe downloads/clipboard, mutation replay, stale scope, framing,
support-mode disclosure, and telemetry payload leakage. Controls include HttpOnly
server sessions, PKCE/state/nonce, origin-bound CSRF, server authorization,
anti-enumeration, tenant/purpose cache teardown, runtime schemas, React text
rendering, allowlists/bounds, idempotency/concurrency, CSP/frame denial, redaction,
and immutable audit. Residual risks include a compromised BFF/session store,
reverse-proxy header mistakes, malicious browser extensions, and unqualified
production identity/browser behavior.

Full production model/connector and telemetry qualification, independent
penetration/accessibility testing, large-scale human labeling, live production
identity/browser qualification, MCP/A2A, external managed backends, 24/7 on-call
evidence, HA/DR, multi-region operation, final load/chaos certification, and
compliance certification remain deferred.
