# Production-readiness evidence bundle

## Evidence classes

- **Implemented code/config:** typed operations contracts, migration `0011`, Kustomize
  resources, Kyverno policies, AWS Terraform, pinned workflows, Docker/Compose digests.
- **Local deterministic evidence:** unit/static checks, 119-case eval catalog, Kustomize
  renders, Terraform mock plans, Trivy scans, container restore/rebuild/redrive drill.
- **Unverified production control:** cloud apply, managed failover/PITR, cluster/CNI/
  admission/runtime class, egress, identity/session/keys, partner federation, paging,
  measured SLO/load/chaos, penetration/accessibility/compliance review.

Do not collapse these classes into a generic "production ready" statement.

## Bundle manifest

Every release/deployment evidence bundle should contain:

1. source/base/head commits and reviewed change reference;
2. promotion metadata, private-ECR digest equality, environment bundle `SHA256SUMS`,
   and the controller-prerequisite report;
3. application/operator image digests and multi-arch manifests;
4. SPDX SBOMs, provenance, cosign verification, vulnerability/license/secret results,
   and exact waivers;
5. Kustomize overlay/render hash, schema/policy/RBAC/network/security scan output;
6. Terraform version/provider lock, format/validate/lint/security/mock or approved live
   plan hash, cost review, apply identity, and state reference without state contents;
7. migration files/checksums, advisory-lock runner result, schema compatibility and RLS
   evidence;
8. backup identifiers, restore report hash, ledger integrity/rebuild/redrive result,
   credential rotation, and RPO/RTO observation when live;
9. canary/synthetic/SLO/error-budget results, rollback digest, reconciliations, and
   change/approval audit;
10. owner/reviewer, scope/environment/region, evidence class, timestamp, retention,
   exceptions, and next review.

Bundle artifacts must be bounded and redacted. Never retain backup contents, secret
values, raw tenant evidence, tokens, plans containing secrets, or unrestricted logs.

## Layer 15 acceptance evidence

The repository gate is `make check` plus frontend/protocol/integration/container,
Kubernetes, Terraform, restore, Compose, secret, and diff checks. GitHub checks must
pass on the stacked PR. That establishes repository evidence only. A production
readiness review remains false until the unverified controls above have independent,
environment-specific evidence.
