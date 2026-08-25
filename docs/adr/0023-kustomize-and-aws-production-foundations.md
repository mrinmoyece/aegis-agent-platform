# ADR 0023: Kustomize and AWS production foundations

## Status

Accepted

## Context

Aegis needs reviewable production deployment foundations without pretending that a
checked-in template proves a live cluster. The repository already uses plain YAML,
small validation scripts, and provider-neutral runtime contracts. A chart templating
language would add another execution surface before reusable packaging is needed.
Cloud-neutral diagrams alone would not prove credible network, identity, data, backup,
or cost tradeoffs.

## Decision

Use Kustomize `v5` conventions for Kubernetes packaging and an AWS reference rooted at
`infra/terraform/aws`. Kustomize keeps manifests visible, supports immutable
environment-specific digest promotion, and minimizes template logic. The AWS module
uses Terraform `1.11.4` and AWS provider `5.100.0`, private EKS endpoints, private
subnets/endpoints, managed PostgreSQL 16, encrypted Redis transport, immutable ECR,
S3/KMS, AWS Backup vault lock, Pod Identity, Secrets Manager references, Route53/ACM,
and CloudWatch. Paid resources are disabled by default and CI uses mocked plans.

Production environments use separate accounts, clusters, state keys, namespaces, and
workload identities. Tenant isolation remains application authorization plus forced
PostgreSQL RLS; Kubernetes namespaces do not become a tenant authority boundary.

## Consequences

- Operators can render and review every workload and policy without cloud credentials.
- Standard NetworkPolicy cannot enforce external FQDN intent; production requires a
  qualified egress gateway or CNI policy and generated private endpoint CIDR patches.
- The reference is AWS-specific rather than falsely portable.
- Placeholder application digests and disabled BFF/protocol replicas prove packaging
  shape only. Promotion and missing runtime bootstrap prerequisites must be resolved
  before apply.
- Terraform state bootstrap, live apply, addon installation, CNI behavior, and managed
  service qualification remain external evidence.

## Alternatives rejected

- Helm was rejected for this layer because values/template behavior would obscure the
  security review surface without a demonstrated reuse need.
- A cloud-neutral pseudo-module was rejected because it would hide material provider
  choices and produce no credible plan.
- In-cluster PostgreSQL/Redis were rejected as the production reference because managed
  backups, encryption, failover, and operational ownership are required.
