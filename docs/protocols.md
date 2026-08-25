# MCP and A2A interoperability

## Status and authority boundary

Layer 14 implements deterministic/local MCP and A2A interoperability. Internal
specialist orchestration does **not** use either protocol: the Incident
Coordinator still exclusively owns the plan, DAG, lifecycle, global budget, and
deterministic aggregation. Typed artifacts committed to the append-only event
ledger remain the only authoritative specialist channel.

Protocol messages, descriptions, prompts, Agent Cards, task updates, resources,
and artifacts are untrusted provider input. They cannot establish tenant
context, grant a role, change policy, approve a proposal, execute remediation,
or become ledger facts without a validated application command and additive
event. See [ADR 0022](adr/0022-ledger-mediated-mcp-a2a-boundaries.md).

## Compatibility matrix

The implementation pins exact SDK releases while keeping SDK types inside
adapters.

| Boundary | Implemented version | SDK pin | Implemented transport/binding | Compatibility behavior |
| --- | --- | --- | --- | --- |
| MCP | `2026-07-28` | `mcp==2.0.0` | authenticated Streamable HTTP; fixed-command stdio for isolated local development | exact current negotiation; documented legacy-version negotiation only; obsolete standalone HTTP+SSE is rejected |
| A2A | protocol `1.0`, specification tag `v1.0.1` | `a2a-sdk==1.1.2` | JSON-RPC over authenticated HTTP | signed Agent Card digest pinning; unsupported versions, bindings, content types, signatures, and card drift fail closed |

The MCP adapter implements initialize/version and capability negotiation,
bounded pagination, session/origin checks, progress/cancellation identifiers,
keepalive/backpressure bounds, and graceful shutdown contracts. Model input can
never select an executable or arbitrary stdio command. Network MCP requires
HTTPS, exact host/port allowlists, caller-pinned DNS results, public addresses,
redirect revalidation, authentication, and bounded request/response schemas.

The A2A adapter signs versioned Agent Cards with compact Ed25519 JWS and
advertises only evidence-backed incident investigation, status/artifact
exchange, and proposal submission. The card states authentication, content
types, limits, and local-only readiness. Internal roles and DAG authority are
not advertised as peer capabilities.

## Provider-neutral contracts

`domain.protocols` contains immutable, versioned contracts for:

- principals, peers, trust tiers, transports, authentication schemes, and
  exact capability digests
- resources, prompt templates, tools, skills, JSON Schemas, purpose, risk,
  idempotency, size limits, and proposal-only mutation
- requests, correlation/idempotency keys, policy snapshots, results, errors,
  tasks, messages, artifacts, citations, provenance/trust labels, and audit
- canonical JSON, Unicode/control rejection, collection/depth/byte bounds,
  digest validation, and pure deterministic operation replay

MCP JSON-RPC and A2A wire objects stay in `integrations.mcp` and
`integrations.a2a`. Vendor SDK types never enter domain, policy, ledger, or
operator contracts.

## Curated MCP server and client

The server surface is least privilege and calls existing Aegis application
services. It supports redacted incident/timeline/evidence/memory retrieval,
runbook resources, safe investigation submission/status, authorized approval
status, and exact-policy sandbox analysis requests. A remediation capability can
only submit a digest-bound Layer 8 proposal. Direct approval and execution are
structurally absent; mutating capabilities must be `proposal_only`.

External MCP servers require an explicit tenant registry entry with owner,
environment, identity, trust tier, exact transport/version, capability and
schema allowlists, data classifications, risk ceiling, quota/timeout/content
bounds, secret reference, certificate/key/card digests, expiry/review, and
egress destinations. Descriptions and returned content remain data, never system
instructions.

## A2A server and client

Inbound discovery is authenticated and returns a signed, versioned, bounded
Agent Card. Inbound tasks map only to application commands for investigation,
status, artifact exchange, or remediation proposal submission. A remote agent
cannot approve, run tools directly, access another tenant, alter policy, or
write authoritative facts.

Outbound agents require explicit registration and card/key/certificate/schema
digest pins. The gateway handles task/message/artifact lifecycle,
streaming/polling cursor contracts, cancellation, deadlines, idempotency,
bounded retry, ambiguous status reconciliation, citations, and provenance.
Capability/card/schema drift, unknown MIME types, forged progress, bad
signatures, and revocation quarantine or deny the peer.

## Durable lifecycle and persistence

`ProtocolGateway` records policy and request intent before adapter I/O. MCP
invocation and A2A task events represent request, start/acceptance, progress,
artifact, completion, failure, ambiguity, cancellation, reconciliation, drift,
and quarantine. Events contain bounded identifiers and digests, not raw
credentials, prompts, or returned content.

`PostgresProtocolLedger` atomically appends event truth and updates forced-RLS
operation, claim, artifact, cursor, quota, and audit projections from migration
`0010_mcp_a2a_interoperability.sql`. Expected versions and PostgreSQL lease
token/generation fences reject stale writers. Idempotency suppresses identical
duplicates; conflicting payload reuse fails. Ambiguous delivery is explicit and
must be observed before retry. Projections are rebuildable; Redis is transport
only. Exactly-once network effects are not claimed.

## Authentication and readiness

The neutral authentication boundary binds a cryptographically verified issuer,
audience, tenant, scopes, short lifetime, token ID, proof key, and certificate
digest, and rejects replay. Production deployments require OIDC/service
identity, short-lived secret references, DPoP or mTLS-equivalent proof,
rotation/revocation, and boundary TLS. Bearer tokens are prohibited from URLs,
logs, browser storage, events, and telemetry.

This repository does not configure distributed token brokerage, production PKI,
or live mTLS. `ProtocolAuthenticator.production_ready` and Agent Card readiness
therefore fail closed. The implemented endpoints and demos are deterministic
local interoperability evidence, not public federation.

## Operator, telemetry, tests, and demos

The tenant-admin operator view exposes bounded peer health, pinned digest/version,
capability counts, task/invocation ambiguity, quarantine, and exact typed trust
confirmation. It exposes no raw credential or unrestricted protocol console.

Metrics and spans use finite protocol-family/version/transport/outcome/byte
buckets. They exclude peer URLs, tenant IDs, capability names, prompts, tokens,
and content.

Run deterministic demos with:

```bash
python -m aegis_agent_platform.protocols safe-retrieval
python -m aegis_agent_platform.protocols artifact-exchange
python -m aegis_agent_platform.protocols remediation-proposal
python -m aegis_agent_platform.protocols ambiguous-reconciliation
python -m aegis_agent_platform.protocols capability-drift
python -m aegis_agent_platform.protocols malicious-content
python -m aegis_agent_platform.protocols tenant-attack
python -m aegis_agent_platform.protocols revocation
```

Required tests use fakes only and cover negotiation, initialization, signatures,
schemas/bounds, auth/replay, RBAC/purpose, SSRF/DNS/IP/redirect defenses,
poisoning/smuggling/Unicode/MIME attacks, tenant confusion, fencing,
duplicates/ambiguity/reconciliation, cancellation, quotas/backpressure, RLS,
projection rebuild, operator trust UX, redaction, and eight Layer 14 evaluation
invariants.

## Explicit deferrals

Broad public federation, production PKI/mTLS and token brokerage, independent
MCP/A2A conformance certification, external partner qualification,
Kubernetes/HA/DR/multi-region deployment, final load/chaos evidence, and
compliance certification remain deferred. See
[protocol security](mcp-a2a-security.md),
[protocol operations](protocol-operations.md), and
[limitations](limitations.md).
