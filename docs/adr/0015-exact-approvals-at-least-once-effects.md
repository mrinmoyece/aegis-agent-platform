# ADR 0015: Bind approvals exactly and treat controlled effects as at-least-once

- Status: Accepted
- Date: 2026-08-13

## Context

A remediation recommendation is untrusted analysis, not authority. Operators
must be able to approve one immutable action without granting future or broader
power. Workers, networks, and providers fail in the window between recording an
intent, applying an effect, and recording the outcome. Redis delivery,
PostgreSQL transactions, or provider idempotency cannot prove exactly-once
external effects.

## Decision

Represent each plan revision, action, target, policy snapshot, and approval scope
with immutable provider-neutral versioned contracts and canonical SHA-256
digests. Approval binds the tenant, plan/action/policy digests, exact target
fingerprint, risk, requester, quorum, and expiry. Authenticate and authorize
every decision, require distinct human approvers, enforce configured separation
of duties, and invalidate approval after policy change, plan revision,
expiration, denial, or revocation.

The event ledger is the only remediation state truth. Append action intent under
the active PostgreSQL lease token/generation before calling an adapter. Recheck
identity, tenant, policy, approval, target, cancellation, and preconditions
immediately before intent. Effects are at-least-once: use one stable
tenant-scoped idempotency key and target fingerprint, classify ambiguous
outcomes, reconcile target state before retry, and escalate when correctness
cannot be established. Append outcome, reconciliation, and fresh-evidence
verification events under the same fence. API acceptance is not recovery.

Layer 8 exposes only the fixed-shape Kubernetes deployment rollout-restart
adapter and a deterministic fake. The official adapter accepts no arbitrary
patch, command, shell input, or model-selected credential. Destructive or broad
actions remain disabled by default. PostgreSQL forced-RLS projections and effect
claims are rebuildable read models, never truth.

## Consequences

Plan edits and policy changes require new approvals. Two-person approval adds
latency for high-risk actions but prevents self-authorization and broad replay.
A crash after an effect can remain ambiguous; read-after-write reconciliation
prevents blind retries but may require operator escalation. The platform does
not claim exactly-once effects.

General sandbox/code execution, arbitrary commands, broad autonomous
remediation, live external verification, memory/RAG, operator UI, MCP/A2A,
production credentials, Kubernetes production deployment, HA/DR, and
multi-region operation remain deferred.
