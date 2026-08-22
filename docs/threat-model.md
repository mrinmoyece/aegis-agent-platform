# Threat model

## Scope and assumptions

This model covers the intended platform and marks control status honestly.
Layer 1 established contracts and guardrails; Layer 2 adds a real identity,
tenancy, and governance vertical slice described below and in
`architecture.md`. The system assumes model output, tool output, retrieved
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

## Principal threats and required controls

| Threat | Example impact | Required control | Current status |
| --- | --- | --- | --- |
| Tenant confusion | Cross-tenant reads or work claims | Explicit tenant context, database policy, negative tests | Deny-by-default authorization and tenant-scoped repositories implemented (in-memory) with a committed cross-tenant negative-test suite (`tests/test_identity_security.py`, `tests/test_api.py`); Postgres row-level security defined in migration and asserted statically (`tests/test_migrations.py`), but not yet exercised against a live database |
| Identity spoofing | Attacker acts as an operator | OIDC validation, key rotation, audience checks | Standards-correct JWT signature/issuer/audience/expiry/algorithm verification implemented against deterministic fixtures and a Keycloak-compatible JWKS config, with a committed negative-test suite for malformed/expired/wrong-issuer/wrong-audience/unsupported-algorithm tokens; live-IdP key-rotation drills against a running Keycloak remain a deployment-time check |
| Prompt injection | Model invokes unauthorized tool | Typed tool allowlist, runtime policy, approval | Boundary only |
| Confused deputy | Tool uses broader platform privilege | Scoped capability token per invocation | Planned |
| Duplicate delivery | Repeated financial or external effect | Intent event, idempotency key, reconciliation | Invariant only |
| Event tampering | False state or missing audit evidence | Append controls, hashes/retention, restricted roles | Redacted, additive-schema audit events implemented (in-memory) with a committed test suite proving redaction and append-only behavior at the application layer (`tests/test_audit_secrets.py`); append-only database trigger and row-level security defined in migration and asserted statically, but durable wiring, retention, and access review remain planned |
| Sandbox escape | Host or network compromise | Strong isolation, deny-by-default egress, quotas | Boundary only |
| Secret exfiltration | Credentials in prompts or telemetry | Brokered secrets, redaction, content policy | Secret-reference abstraction, redacted `SecretValue`, and audit-detail redaction implemented; only a local environment-variable provider exists, no vault-backed broker |
| Provider data leakage | Sensitive content retained externally | Provider policy, classification, regional routing | Planned |
| Resource exhaustion | Runaway token/tool loop | Budgets, deadlines, queue backpressure, quotas | Pure tenant quota/risk policy evaluator implemented; authoritative usage accounting and runtime enforcement planned with the durable runtime |
| Supply-chain compromise | Malicious build dependency/action | Pinned actions, review, scanning, attestations | Partial |
| Telemetry leakage | Tenant data in labels or traces | Redaction and bounded-cardinality conventions | Planned |
| Evaluation poisoning | Unsafe release passes gates | Dataset provenance, immutable results, approvals | Planned |
| Evidence spoofing | Forged logs or change metadata drives a false hypothesis | Authenticated adapters, immutable references, timestamps, source labeling | Contracts only |
| Stale correlation | Unrelated deployment is blamed for checkout failures | Explicit time windows, topology, counter-evidence, confidence | Planned |
| Runbook injection | Hostile text asks the agent to bypass policy | Treat runbooks as untrusted evidence; runtime authorization | Planned |
| Approval confusion | Approval for one incident authorizes another action | Bind approval to tenant, incident, exact action, version, and expiry | Planned |
| Remediation escalation | Rollback tool mutates unrelated services | Capability-scoped tool input and target allowlist | Planned |
| False recovery | Incident closes after a transient metric dip | Defined verification window and multi-signal checks | Planned |
| Connector token theft | Dynatrace or GitHub authority is exfiltrated | Brokered read-only credentials, rotation, redaction | Planned |
| Agent authority creep | Specialist spawns workers or obtains broader tools | Fixed roles, coordinator-owned DAG, capability allowlist | Contracts only |
| Opaque collusion | Peer chat creates uncited consensus | Ledger-only typed artifacts and independent critic | Contracts only |
| Runaway swarm | Recursive agents exhaust tokens or capacity | No specialist spawning, hard budgets, deadlines, global quota | Contracts only |
| Aggregation race | Completion order changes the chosen hypothesis | Stable ledger order and deterministic conflict policy | Planned |
| Critic bypass | Unsupported hypothesis reaches remediation | Required reviewer dependency and cited confidence gate | Planned |
| Memory poisoning | Hostile or stale knowledge biases incident response | Provenance, source quality, recency, critique, deletion | Planned |
| Compaction loss | Summary drops conflict, approval, or safety limits | Citation-preserving compaction invariants and tests | Planned |
| Cross-tenant embedding leak | Semantic search returns another tenant's data | Tenant partitioning, authorization, adversarial retrieval tests | Planned |
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

Layer 1 encodes only types and interfaces for these controls. Scheduling,
capability enforcement, budgets, deterministic aggregation, approval, and
verification are planned and must not be inferred from the skeleton.

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

Later acceptance tests must exercise these cases rather than relying on design
claims.

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
layer — all against deterministic fixtures. What remains open: the default
repositories (`InMemoryIdentityDirectory`, `InMemoryTenantRepository`,
`InMemoryPolicyRepository`, `InMemoryAuditStore`) are deterministic in-process
fixtures; the Postgres migration defines the durable, row-level-secured
equivalents and its schema is asserted statically
(`tests/test_migrations.py`), but no adapter connects them yet, so restart
loses all state and the row-level-security policies have not been exercised
against a running database. `RemoteJwksProvider` is tested against a mocked
HTTPS transport, not a live Keycloak realm — whether that realm is reachable,
populated with users, and rotated correctly is a deployment concern not
verified by these tests. Quota *limits* are evaluated deterministically;
quota *usage* accounting has no authoritative source until the durable
runtime lands. Secrets remain local-environment-variable only; there is no
vault-backed broker, rotation, or leak-scanning pipeline.
