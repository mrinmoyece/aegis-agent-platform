# SLO catalog

These are **configured objectives**, locally syntax-tested against synthetic
signals. They are not claims of production attainment. A production claim
requires a representative deployment, qualified telemetry path, observation
window, ownership rotation, and retained measurement evidence.

| Objective | SLI numerator / denominator | Window / target | Exclusions | Owner / dependencies | Rationale and current gap |
|---|---|---|---|---|---|
| API availability | successful authenticated requests / eligible authenticated requests | 30d / 99.9% | client validation, explicit policy denials, health probes | Control plane / DB, identity | Leaves 43.2 min/month; no production traffic evidence |
| Safe correctness | verified correct terminal outcomes / terminal outcomes | 30d / 99.99% | cancelled work | Safety / ledger, policy, fencing | Safety violations page independently and are never traded for availability |
| Durable work freshness | work terminal within 60s / accepted work | 30d / 99% | explicit scheduled delay and tenant pause | Runtime / DB, outbox, Redis | Measures accepted-to-terminal ledger timestamps; no fleet history yet |
| Evidence freshness | accepted evidence no older than 15m / eligible connector polls | 7d / 99% | source-declared maintenance | Evidence / connectors | Source timestamps and cursor lag required; connector qualification pending |
| Provider gateway | successful or policy-safe outcomes / admitted calls | 30d / 99% | budget/policy denials | Gateway / provider, catalog | Provider errors count; no live provider qualification |
| Approval/action completion | verified terminal actions / approved dispatches | 30d / 99.9% | revoked/expired approvals before dispatch | Remediation / approval, adapter | Ambiguous effects remain failures until reconciled |
| Sandbox cleanup | cleanup completed within 5m / provisioned sandboxes | 30d / 99.99% | none | Sandbox / backend enforcement | Cleanup failure pages; production backend evidence absent |
| Memory retrieval | authorized successful retrievals under 1s / eligible retrievals | 30d / 99% | policy denial, empty corpus | Memory / Postgres, pgvector | Index lag is a dependency; representative corpus evidence absent |
| Evaluation gate health | required cases passing / required cases | per revision / 100% | approved non-safety waivers only | Evaluation / CI fixtures | Hard safety has no waiver or error budget |

Availability burn alerts use the standard 14.4x 5m/1h fast-burn pair and 6x
6h/3d slow-burn pair for a 99.9% 30-day objective. Recording rules also expose
the 30-day ratio. Missing series are shown as no data rather than success.

Hard safety violations, ledger corruption, stale fencing writes, unverifiable
effects, cleanup failures, and cross-tenant access are invariants or direct
alerts. They do not consume an availability error budget. During budget
exhaustion, freeze risky releases, prioritize reliability, and require explicit
leadership acceptance for unrelated changes.

## Layer 15 recovery and deployment objectives

These are future production objectives, not attained SLOs:

| Objective/SLI | Initial objective | Evidence gate |
| --- | --- | --- |
| Ledger recovery point | <= 5 minutes | managed PITR and restore point |
| Artifact/config recovery point | <= 24 hours | encrypted versioned object/config |
| Isolated tenant restore time | <= 4 hours | integrity, rebuild, redrive, rotation |
| Regional writer failover time | <= 2 hours | old-writer fence, generation, traffic/reconcile |
| Normal API rollout | zero unavailable replicas | PDB/rolling/readiness plus live observation |
| Migration safety | zero incompatible-ready pods/destructive statements | schema window, lock/checksum, canary |
| Supply-chain trust | 100% admitted Aegis images signed/attested | live admission audit |

Backup success alone does not satisfy recovery. Availability is never traded for
split-brain risk or tenant isolation.
