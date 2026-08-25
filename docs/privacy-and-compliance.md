# Privacy, governance, and compliance-ready evidence

## No certification claim

Layer 15 maps controls and produces local/CI evidence. It does not certify SOC 2, ISO
27001, GDPR, HIPAA, PCI DSS, or any other framework. Scope, legal basis, contracts,
organizational controls, production operation, independent audit, and jurisdictional
review remain required.

## Asset and data-flow inventory

| Asset/flow | Classification and authority | Primary controls |
| --- | --- | --- |
| Tenant identities, roles, policies | restricted authoritative PostgreSQL | OIDC, separate authorization, forced RLS, audit |
| Event ledger and approvals | restricted sole runtime truth | append-only, encryption, backup, retention policy, replay |
| Evidence/artifacts/memory | tenant-classified authoritative references plus derived indexes | provenance, redaction, quarantine, object KMS, legal hold |
| Redis work transport | ephemeral non-authoritative | TLS/network boundary, idempotency, inbox/outbox, reconciliation |
| Logs/metrics/traces | derived, redacted, never truth | semantic allowlist, cardinality bounds, retention/access |
| SBOM/provenance/signatures | release evidence | immutable digest, OIDC identity, bounded artifact retention |
| Backups/archives | sealed copy of authority | KMS, access audit, immutability, manifest/hash, isolated restore |
| Protocol/provider traffic | external untrusted boundary | tenant policy, egress gateway, scoped credentials, intent/reconcile |

Tenant residency policy covers home/backup/replica regions, providers, transfer purpose,
keys, and retention. Data minimization, deletion, legal hold, archive retrieval, and
derived-data rebuild follow existing event-grounded lifecycle controls. No telemetry,
cache, transcript, or archive becomes a second live source of truth.

## Control evidence mapping

| Control family | Code/config evidence | Operational evidence still required |
| --- | --- | --- |
| Access and separation of duties | RBAC, Pod Identity, RLS, exact approvals, environment gates | production access review, reviewer settings, joiner/mover/leaver records |
| Change management | signed digest promotion, migration lock/checksum, Git history | approved plans, GitOps reconciliation, emergency-change review |
| Backup/DR | locked-vault Terraform, local restore report, runbook | managed backup success, isolated full-volume restore, measured RPO/RTO |
| Audit and retention | append-only audit/events/archive manifests, policies | production retention jobs, legal review, archive access review |
| Vulnerability/supply chain | SBOM, scans, license/secret gates, signatures, attestations | registry/admission enforcement, waiver review cadence, response records |
| Incident response | alerts, failure modes, runbooks, reconciliation | exercised paging/on-call, postmortems, 24/7 coverage evidence |
| Sandbox/protocol | disabled readiness, restricted policy, trust registry | qualified runtime/CNI/admission, PKI/token broker, partner certification |

Platform security owns monthly access and vulnerability review; data governance owns
quarterly retention/residency review; service owners run restore drills at least
quarterly and regional exercises at least annually after live deployment. Evidence
bundles record owner, reviewer, period, immutable source, result, exceptions, expiry,
and follow-up. Cadence statements are objectives until production records exist.
