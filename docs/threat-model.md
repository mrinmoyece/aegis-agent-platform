# Threat model

## Scope and assumptions

This model covers the intended platform and marks Layer 1 controls honestly.
The system assumes model output, tool output, retrieved content, and tenant
input can be hostile. Cloud, identity provider, model provider, and operator
accounts can be compromised. Prompt instructions are never trusted as controls.

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

| Threat | Example impact | Required control | Layer 1 status |
| --- | --- | --- | --- |
| Tenant confusion | Cross-tenant reads or work claims | Explicit tenant context, database policy, negative tests | Contract only |
| Identity spoofing | Attacker acts as an operator | OIDC validation, key rotation, audience checks | Local IdP scaffold |
| Prompt injection | Model invokes unauthorized tool | Typed tool allowlist, runtime policy, approval | Boundary only |
| Confused deputy | Tool uses broader platform privilege | Scoped capability token per invocation | Planned |
| Duplicate delivery | Repeated financial or external effect | Intent event, idempotency key, reconciliation | Invariant only |
| Event tampering | False state or missing audit evidence | Append controls, hashes/retention, restricted roles | Planned |
| Sandbox escape | Host or network compromise | Strong isolation, deny-by-default egress, quotas | Boundary only |
| Secret exfiltration | Credentials in prompts or telemetry | Brokered secrets, redaction, content policy | `.gitignore` only |
| Provider data leakage | Sensitive content retained externally | Provider policy, classification, regional routing | Planned |
| Resource exhaustion | Runaway token/tool loop | Budgets, deadlines, queue backpressure, quotas | Planned |
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

Nearly all runtime controls are unimplemented. Dynatrace and GitHub contracts do
not authenticate or call vendor APIs. The health endpoint is
unauthenticated by design and carries no sensitive data. The Compose stack uses
local-only credentials and exposes ports on loopback, but a developer workstation
remains outside the production threat model. Do not use Layer 1 for real tenant
or provider data.
