# Operational acceptance package

This package links signals, commands, safety checks, escalation, and rollback.
Deployment-specific account, cluster, tenant, contact, paging, and credential
references must be filled in an approved private operational system; never
commit them here.

## Launch checklist

1. Verify every hard gate in `qualification/release-readiness.json`; unresolved
   live gates block launch.
2. Promote only immutable signed/attested/scanned digests through the protected
   branch workflow. Verify SBOM, provenance, mirror, admission, and bundle
   checksum.
3. Prove schema compatibility, one migration runner, forced RLS, tenant writer
   fences, non-superuser runtime roles, and additive roll-forward.
4. Prove OIDC/JWKS/session/logout/revocation, secret/key rotation, workload
   identity, PKI/token brokerage where enabled, and deny-by-default egress.
5. Run restore/failover, capacity/soak, paging, tenant isolation, controlled
   action ambiguity, sandbox cleanup/quarantine, and protocol revocation drills.
6. Record owners, escalation paths, change approval, rollback digest, evidence
   location, and accepted residual risks. Do not declare certification.

## Day 0, day 1, and day 2

| Phase | Signals and commands | Safety and escalation/rollback |
| --- | --- | --- |
| Day 0: deploy | `make qualification`, promotion verification, migration preflight, Kustomize diff, Terraform approved plan | Halt on unsigned digest, schema/RLS/fence mismatch, missing identity/egress prerequisite, or failed canary; roll back compatible app only |
| Day 1: stabilize | SLO/burn, queue/outbox/DLQ, database/cache pools, model budget/circuit, connector/memory lag, sandbox cleanup, protocol drift | Freeze new risky work on fast burn, ambiguity, tenant denial spike, fence spike, or cleanup backlog; preserve ledger and reconcile |
| Day 2: accept | review 24-hour audit/support evidence, capacity headroom, alerts/pages, backups, access and change records | Reject acceptance on no-data, unowned alert, unmeasured recovery, unresolved risk, or projection/ledger difference |

## Operational matrix

| Operation | Signals | Commands/evidence | Safety check | Escalation and rollback |
| --- | --- | --- | --- | --- |
| Incident response | burn, error, latency, queue, fence, ambiguity | `docs/on-call-observability.md`, `aegis-replay` | Ledger facts only; no dashboard-as-truth | Incident Commander; stop claims/effects, preserve evidence |
| On-call handoff | open incidents, risks, pages, changes, capacity | bounded support report and shift record | No secrets/tenant payload in handoff | Escalate unowned critical signal before handoff |
| Backup/restore | backup/key/object status, RPO/RTO timer | `make restore-drill`, managed restore procedure | Count/hash/sequence/fence/rebuild/redrive all match | Remain isolated/unavailable; select another recovery point |
| Regional failover | writer health, generation, replication point | `docs/runbooks/regional-failover.md` | Old writer fenced before traffic moves | Disaster Commander; abort shift if fence proof is absent |
| Key/token rotation | expiry, auth errors, stale sessions/peers | `docs/runbooks/secrets-break-glass.md` | New version works and old authority is revoked | Disable affected integration; never plaintext-fallback |
| CVE/dependency response | scan, advisory, waiver expiry | `make dependency-audit`, vulnerability policy | Fixable HIGH/CRITICAL blocks; exact waiver only | Security owner; rollback digest or disable exposed surface |
| Capacity expansion | saturation, lag, connections, token/cost | `make qualification-load`, environment load plan | Ledger/fencing/policy remain correct under load | Shed before acceptance; do not bypass quota/circuit |
| Tenant onboarding | IdP binding, policy, RLS, quotas, retention | tenant isolation and access tests | Tenant derives only from verified principal/context | Disable tenant access on any confused-deputy evidence |
| Tenant offboarding/deletion | legal hold, jobs, blobs, cache, backups | memory lifecycle and privacy runbook | Hold first; intent, derived purge, blob erasure, completion | Privacy/security; mark backup expiry honestly |
| Protocol partner onboarding | peer identity, PKI, card/capability digests | `docs/protocol-operations.md` | Proposal-only mutation; exact tenant/purpose/risk | Quarantine/revoke on drift or auth failure |
| Sandbox quarantine | cleanup backlog, artifact scan, isolation health | sandbox section of `docs/runbook.md` | Never open raw bytes or enable unverified runtime | Scale to zero; security incident on isolation drift |
| Model/provider outage | circuit, timeout, budget, ambiguity | model section of `docs/runbook.md` | Bounded fallback; no permanent-error retry | Disable provider; preserve billing ambiguity |
| Audit/support evidence | replay validity, report size/digest/signature | `make qualification-demo`, replay debugger | Read-only, redacted, tenant-authorized, bounded | Stop export and rotate material on leakage |
| Disaster declaration | database/key/region integrity and elapsed objectives | DR decision record and recovery runbooks | Named authority; generation/fence proof | Remain unavailable rather than permit split brain |

## Capacity and SLO acceptance

Use `qualification/performance-budgets.json` for local regression and a separate
approved live plan for production. Measure representative p50/p95/p99,
throughput, errors, saturation, queue age, connections, provider cost/tokens,
and restore time/point. Roll back on fast burn, capacity exhaustion, ledger
divergence, stale effect, or unsafe load-shedding behavior.

## Evidence collection

Support bundles contain hashed tenant/aggregate references, event types,
sequence facts, validation, causal links, and content digest/signature. Raw
prompts, evidence, credentials, tenant payloads, provider bodies, sandbox bytes,
and model transcripts do not belong in tickets or handoff records.
