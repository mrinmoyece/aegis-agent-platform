# Engineering invariants

These rules bind human and automated contributors. A change that violates one
requires an accepted ADR before merge.

## Durable execution

1. The append-only event log is the source of truth for run state.
2. Record a durable intent event before attempting any external side effect.
3. Treat delivery as at-least-once. Effects require idempotency keys or an
   explicit reconciliation strategy.
4. Make event schema changes additive. Existing events must remain readable.
5. Do not reconstruct authoritative state from logs, traces, caches, or model
   transcripts when an event stream exists.

## Boundaries

1. `domain` remains deterministic and pure: no frameworks, I/O, wall clocks,
   environment reads, random generation, or infrastructure imports.
2. Vendor SDK types stop at adapters. Core contracts use provider-neutral types.
3. Tenant context is required for data access, work claims, policy decisions,
   telemetry, and audit records. Never infer a tenant from mutable payload data.
4. Authentication establishes a principal; authorization separately binds that
   principal to a tenant and action.
5. Tools and untrusted code run behind policy and sandbox boundaries. Prompts
   are not security controls.
6. Safety limits are runtime-enforced and fail closed.
7. Do not add agent frameworks such as LangChain, CrewAI, or AutoGen.

## Multi-agent coordination

1. The Incident Coordinator exclusively owns the investigation plan, dependency
   DAG, lifecycle state, global budget, and final deterministic aggregation.
2. Specialists have fixed roles, capabilities, budgets, and timeouts. They
   cannot spawn agents or expand their own authority.
3. Specialists communicate only through typed artifacts committed to the event
   ledger. No free-form peer chat or hidden shared scratchpad is authoritative.
4. Evidence-backed claims carry immutable source citations and calibrated
   confidence. Conflicts remain visible until the coordinator resolves them by
   deterministic policy or explicit human input.
5. Parallel work is read-only. Remediation requires a durable proposal, scoped
   human approval, intent event, controlled tool, and post-action verification.
6. A2A is an external interoperability adapter and MCP is a tool/context adapter.
   Neither may replace internal typed artifacts, event truth, coordinator
   control, authorization, policy, approval, or durable effect handling.

## Engineering quality

1. Keep Python fully typed and pass `make check`.
2. Add deterministic tests for changed contracts and architectural rules.
3. Never commit secrets. Example credentials must be conspicuously local-only.
4. Avoid claims unsupported by executable evidence. Mark planned capabilities
   as planned.
5. Pin CI actions to immutable commit SHAs and keep workflow permissions minimal.
6. Prefer small, reversible layers with explicit acceptance gates.
