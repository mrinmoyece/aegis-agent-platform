# Terraform AWS reference

## Contract

The reference in `infra/terraform/aws` is deliberately AWS-specific and uses Terraform
`1.11.4` with `hashicorp/aws` `5.100.0`. It creates nothing unless
`enable_reference_environment=true`. CI runs format, initialize-without-backend,
validate, TFLint, Trivy, and three mocked plans without credentials or paid resources.
Blocking resource preconditions reject an enabled environment without a reviewed EKS
administrator and reject production without explicit DNS inputs; warning-only `check`
blocks are not used for apply safety.
No live apply has been performed or claimed.

## Included foundations

- Two-AZ VPC with public ingress subnets, private application/data subnets, no default
  private internet route, and private ECR/EC2/EKS Auth/S3/KMS/Logs/Secrets Manager/STS
  endpoints.
- Private-endpoint EKS, encrypted secrets, audit/control-plane logs, three-node trusted
  pool, a zero-to-ten dedicated tainted sandbox pool, a dedicated CloudWatch Logs KMS
  policy, and an explicit reviewed administrator access entry. CoreDNS
  `v1.11.4-eksbuild.2`, kube-proxy `v1.32.0-eksbuild.2`, VPC CNI
  `v1.19.2-eksbuild.1`, and Pod Identity Agent `v1.3.4-eksbuild.1` are pinned; VPC CNI
  NetworkPolicy enforcement is enabled.
- PostgreSQL 16 Multi-AZ with TLS forced, KMS encryption, managed master password,
  backups, logs, deletion protection in production, and pgvector compatibility. The
  extension and non-superuser forced-RLS roles remain migration responsibilities.
- Encrypted Multi-AZ Redis 7 transport with one replica. Redis remains
  non-authoritative and loss is handled by outbox redelivery/reconciliation.
- Immutable KMS-encrypted ECR repositories for application, UI, OTel, Envoy Gateway,
  External Secrets, Kyverno, and Prometheus Operator mirrors; private versioned
  encrypted S3 artifacts
  whose bucket policy requires `aws:kms` with the exact platform key on every upload,
  KMS keys, AWS Backup vault lock/plan, CloudWatch logs, optional Route53/ACM, and EKS
  Pod Identity with separate External Secrets and runtime object/KMS roles. API/worker
  roles cannot retrieve the RDS master secret; the migrator has no AWS role. AWS Backup
  includes the S3 service policy plus source/vault KMS use.

## State and environment separation

Create the S3 state bucket and KMS key through a separately reviewed bootstrap process.
Copy `backend.hcl.example`, set a dedicated account/environment/region key, enable
encryption and S3 lockfiles, then initialize with `-backend-config`. State access needs
separate plan/apply roles, MFA or equivalent strong authentication, audit logging,
versioning, retention, and break-glass review. Do not store database URLs, passwords,
tokens, private keys, or secret values in variables, state, plans, outputs, CI logs, or
artifacts. RDS owns its generated secret; outputs expose only its ARN.
The separately approved secret-population process must construct runtime `url` and
maintenance `maintenance_url` values with `sslmode=verify-full` and
`sslrootcert=/opt/aegis/trust/rds-global-bundle.pem`; Terraform deliberately does not
materialize those credentials into state.

Production uses a separate AWS account and remote state from staging. Workspace names
alone are not sufficient isolation.

## Apply gates

Before setting the paid-resource flag:

1. Replace placeholder DNS, CIDRs, image digests, secret/KMS ARNs, ownership tags, and
   set `eks_admin_principal_arn` to a reviewed IAM role.
2. Review the saved plan under separation of duties and a cost estimate.
3. Verify service quotas, pinned EKS add-ons/CNI, ingress/egress gateway, External
   Secrets, Kyverno, metrics stack, runtime class, pgvector support, database parameter
   behavior, Redis authentication, private controller mirrors, and workload bootstrap.
   Retain `verify_cluster_prerequisites.py` evidence.
4. Test backup, isolated restore, key dependency recovery, writer fencing, node/zone
   disruption, and credential rotation.
5. Record the approved plan digest and apply identity in the change evidence bundle.

## Known unproven boundaries

The module does not bootstrap remote state, configure organizational guardrails, install
Envoy Gateway/External Secrets/Kyverno/monitoring charts, mirror their OCI graphs, create
a NAT/egress appliance, issue partner PKI, configure Redis application authentication,
qualify instance types, or prove live HA/RPO/RTO/SLO/cost. Those remain environment work,
not hidden portability claims.
