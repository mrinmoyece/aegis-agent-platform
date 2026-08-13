# Threat model

## Scope and assumptions

This model covers the intended platform and marks control status honestly.
Layer 1 established contracts; Layers 2–3 added governance and the ledger.
Layer 4 adds Redis delivery plus PostgreSQL leases/fencing and live race evidence.
Layer 5 adds the provider-neutral model gateway and fenced cost governance.
Layer 6 adds read-only evidence adapters, bounded immutable ingestion, and
deterministic correlation.
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

## Principal threats and required controls

| Threat | Example impact | Required control | Current status |
| --- | --- | --- | --- |
| Tenant confusion | Cross-tenant reads or work claims | Explicit tenant context, database policy, negative tests | PostgreSQL repositories use transaction-local context; forced RLS and confused-deputy denial are proven against PostgreSQL 16 |
| Identity spoofing | Attacker acts as an operator | OIDC validation, key rotation, audience checks | Standards-correct JWT signature/issuer/audience/expiry/algorithm verification implemented against deterministic fixtures and a Keycloak-compatible JWKS config, with a committed negative-test suite for malformed/expired/wrong-issuer/wrong-audience/unsupported-algorithm tokens; live-IdP key-rotation drills against a running Keycloak remain a deployment-time check |
| Prompt injection | Model invokes unauthorized tool | Typed tool allowlist, runtime policy, approval | Boundary only |
| Confused deputy | Tool uses broader platform privilege | Scoped capability token per invocation | Planned |
| Duplicate delivery | Repeated work or external effect | Intent event, deterministic message identity, inbox, reconciliation | Redis publication and inbox deduplication implemented; future target reconciliation remains required |
| Stale lease holder | Old worker overwrites a reclaimed result | PostgreSQL token/generation fence on every write | Implemented and live-tested |
| Queue tenant spoofing | Work executes under another tenant | Tenant-bound envelope plus trusted context and RLS | Implemented; malformed/mismatched envelopes fail closed |
| Poison queue payload | Parser exploit or supervisor crash | Size/schema bounds and quarantine | Safe decoder and supervisor containment implemented |
| Event tampering | False state or missing audit evidence | Append controls, hashes/retention, restricted roles | Event/audit update-delete rejected by grants and live-tested triggers; retention and access review remain planned |
| Sandbox escape | Host or network compromise | Strong isolation, deny-by-default egress, quotas | Boundary only |
| Secret exfiltration | Credentials in prompts or telemetry | Brokered secrets, redaction, content policy | Secret-reference abstraction, redacted `SecretValue`, and audit-detail redaction implemented; only a local environment-variable provider exists, no vault-backed broker |
| Provider data leakage | Sensitive content retained externally | Provider policy, classification, regional routing | Retention/residency policy and routing implemented; provider account verification and encrypted content artifacts remain planned |
| Resource exhaustion | Runaway work or noisy tenant | Deadlines, queue backpressure, global and tenant quotas | Worker and provider concurrency, timeouts, request/token limits, circuits, and fenced model budgets implemented |
| Supply-chain compromise | Malicious build dependency/action | Pinned actions, review, scanning, attestations | Partial |
| Telemetry leakage | Tenant data in labels or traces | Redaction and bounded-cardinality conventions | Runtime/model instruments use fixed names and catalog-bounded provider/model labels without tenant/run/request IDs; backend review remains planned |
| Evaluation poisoning | Unsafe release passes gates | Dataset provenance, immutable results, approvals | Planned |
| Evidence spoofing | Forged logs or change metadata drives a false hypothesis | Authenticated adapters, immutable references, timestamps, source labeling | Bounded authenticated adapters, digests, trust status, and quarantine implemented; live source assurance remains deployment evidence |
| Stale correlation | Unrelated deployment is blamed for checkout failures | Explicit time windows, topology, counter-evidence, confidence | Deterministic clock-skew bounds, rationale, ambiguity, and conflicts implemented; no causal inference |
| Runbook injection | Hostile text asks the agent to bypass policy | Treat runbooks as untrusted evidence; runtime authorization | Trust/schema validation and retrieval-only knowledge implemented; execution remains absent |
| Approval confusion | Approval for one incident authorizes another action | Bind approval to tenant, incident, exact action, version, and expiry | Planned |
| Remediation escalation | Rollback tool mutates unrelated services | Capability-scoped tool input and target allowlist | Planned |
| False recovery | Incident closes after a transient metric dip | Defined verification window and multi-signal checks | Planned |
| Connector token theft | Dynatrace or GitHub authority is exfiltrated | Brokered read-only credentials, rotation, redaction | Typed secret references and redaction implemented; vault brokering/rotation drills planned |
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
