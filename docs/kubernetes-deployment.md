# Kubernetes production foundation

## Scope and packaging

`deploy/kubernetes` is a Kustomize production-shape reference selected by
[ADR 0023](adr/0023-kustomize-and-aws-production-foundations.md). CI renders
development, staging, and production overlays, validates schemas, scans
misconfiguration, and runs repository policy checks. Repeated digest characters in the
checked-in application image transforms are deliberate non-secret placeholders. The
promotion workflow mirrors both verified OCI graphs into private ECR and replaces the
placeholders and endpoint/network templates in a checksummed bundle for one approved
environment at a time; do not apply the checked-in overlays.

Schema validation uses kubeconform's digest-pinned container, Kubernetes 1.32.0
schemas, a fixed `kubernetes-json-schema` commit, and a fixed CRD catalog commit for
Gateway API, Envoy Gateway, External Secrets, Kyverno, and monitoring resources. The
validator needs outbound HTTPS to retrieve those public schemas; it receives no repository/cloud
credentials and the rendered manifests contain references rather than secrets.

The manifests are executable configuration evidence, not proof of a qualified cluster.
The shared image dispatches process roles explicitly. API, outbox-publisher, and
reconciler roles assemble PostgreSQL/Redis/OIDC adapters; all other background roles
fail closed and remain at zero replicas until their production handler/adapters exist.
API startup/readiness fails closed when PostgreSQL, schema history, tenant writer fences,
or OIDC signing keys are unavailable. Redis is an optional API health dependency but a
required publisher startup dependency; it never becomes correctness authority.
The schema probe also fails closed when migration history is unavailable, gapped, older,
or newer than the build's compatibility window.
Writer credentials are reloaded from the atomically mounted External Secret on every
append, and readiness compares every mounted tenant region/generation with its
PostgreSQL-authoritative active fence row. Rotation order may briefly remove readiness;
it cannot preserve stale writer authority.

## Workload topology

| Workload | Desired shape | Coordination and authority |
| --- | --- | --- |
| API | 3–12 replicas | Stateless request handling; PostgreSQL ledger/RLS authoritative |
| Operator UI | 2 replicas | Static, no session authority, no sticky ingress |
| Operator BFF | zero until shared encrypted sessions and OIDC exchange exist | Separate service and ingress path; server authorization remains authoritative |
| General/evidence workers | zero until provider/evidence handler registries exist | Intended tenant-fair bounded concurrency remains tested at the library boundary; manifests cannot activate the API entrypoint as a worker |
| Outbox publisher | 2 replicas | Active-active `SKIP LOCKED` claims and deterministic message IDs |
| Reconciler | 2 replicas | Durable leases/generations; never Redis leadership |
| Migration Job | suspended, one admitted run | PostgreSQL-only network path, advisory lock, atomic checksum history, deadline, no rollback SQL |
| Protocol gateway | zero until PKI/token broker/trust ready | Separate service, exact peer policy, egress gateway |
| OTel collectors | 2 replicas | Bounded memory/batch; telemetry loss cannot alter correctness |

## Kubernetes identity and RBAC matrix

API, workers, migration, UI, protocol, OTel, and sandbox-runner service accounts
have no Kubernetes RBAC and do not mount API tokens. Only
`system:serviceaccount:aegis-sandbox:aegis-sandbox-cleanup` mounts a token:

| Resource in `aegis-sandbox` | get | list | watch | delete | create/update/patch |
| --- | --- | --- | --- | --- | --- |
| batch Jobs | yes | yes | yes | yes | no |
| Pods | yes | yes | yes | yes | no |

The dependency-free production check enforces this expected `can-i` matrix. A
live cluster must repeat it with `kubectl auth can-i --as` and retain the output;
no live authorization evidence is claimed here.

Active rolling workloads use startup/readiness/liveness probes, preStop drains, explicit
grace periods, resources, priority classes, topology spread, and PDBs. API HPA scale-up
and scale-down are deliberately slow. Worker HPA/KEDA is absent while workers are gated;
queue-lag scaling remains deferred until retries, tenant skew, and provider limits can be
represented without a retry storm.

## Security boundary

All workloads run non-root with a read-only root filesystem, all Linux capabilities
dropped, no privilege escalation, RuntimeDefault seccomp, bounded `emptyDir`, and no
host namespace/path/socket. Service-account token automount is false except the sandbox
cleanup controller, whose namespace Role can only inspect/delete Jobs and Pods.
Namespaces enforce the restricted Pod Security profile.

External Secrets references AWS Secrets Manager keys; no secret value is committed.
The External Secrets controller and application runtime use separate EKS Pod Identity
roles. API/worker identities cannot read the RDS master secret, and the migrator has no
AWS identity. Tenant-scoped writer fence credentials are mounted read-only from the
separate `aegis-writer-fences` ExternalSecret; no global writer generation is accepted.
Rotation updates the provider version, refreshes the ExternalSecret, rolls and drains
affected processes, and verifies readiness before database enforcement changes.
Revocation removes the IAM
association and secret policy before workload termination. See
[the secrets runbook](runbooks/secrets-break-glass.md).

Both the runtime `url` and maintenance `maintenance_url` database properties must use
`sslmode=verify-full&sslrootcert=/opt/aegis/trust/rds-global-bundle.pem`. The image
downloads the AWS global RDS CA bundle only when its pinned SHA-256 matches; runtime
configuration and the migration runner reject protected-environment URLs that omit or
replace that path. Bundle rotation therefore requires a reviewed image rebuild and
digest promotion before Secrets Manager connection URLs change.

## Namespace, tenant, and environment separation

- Use separate AWS accounts, clusters, state keys, DNS zones, keys, and approval
  environments for development, staging, and production.
- `aegis-system`, `aegis-data`, `aegis-egress`, and `aegis-sandbox` separate trust
  zones. They are not tenant authorities.
- Tenant context is established by authentication plus authorization and re-enforced by
  forced PostgreSQL RLS. A mutable payload or namespace label cannot select a tenant.

## Network intent and its limit

Every workload namespace is default deny. Explicit policies allow Kubernetes DNS,
PostgreSQL `5432` (including a separate migration-only rule), Redis TLS `6379`, OTLP
`4317/4318`, qualified Envoy Gateway data-plane traffic, and
one TLS egress-gateway port. OIDC, model providers, connectors, and protocol peers are
allowed only through an operator-supplied egress gateway's separately reviewed
FQDN/SNI/DNS/IP policy. The repository declares ingress, DNS, public-TLS, and
private/link-local deny intent for that gateway but deliberately does not deploy a
vendor proxy; external calls remain blocked until one is qualified.

For the reference `10.42.0.0/16` VPC, native NetworkPolicy admits only PostgreSQL and
Redis ports into the aggregate data-subnet range `10.42.128.0/17`; AWS security groups
then admit those ports only from the EKS cluster security group. If `vpc_cidr` changes,
the environment bundle must patch this CIDR and retain the Terraform/Kubernetes
cross-check. The in-cluster selectors are optional compatibility paths, not claims that
RDS or ElastiCache are pods.

Standard NetworkPolicy cannot prove FQDN identity or reliably deny metadata,
link-local, private, redirect, and DNS-rebinding targets after broad external egress.
Production requires a qualified CNI plus egress proxy/gateway that denies
`169.254.0.0/16`, loopback, RFC1918 except named private endpoints, IPv6 link-local,
node/control-plane networks, redirects, and unapproved DNS answers.

## Gateway and serving

The app uses Kubernetes Gateway API rather than the retired community ingress-nginx
controller. `controller-lock.json` pins Envoy Gateway `v1.8.3`, External Secrets
`helm-chart-2.9.0` using its served `external-secrets.io/v1` API, Kyverno `v1.18.2`,
and Prometheus Operator `v0.83.0`.
`scripts/verify_cluster_prerequisites.py` rejects missing CRDs/API versions, unavailable
controller generations, an unmaterialized ECR account/region, or a repository/digest
mismatch. Installation and qualification of those controllers, data-plane images,
load-balancer annotations, and their mirrored OCI graphs remain a separately approved
bootstrap. `Gateway`,
`HTTPRoute`, and `BackendTrafficPolicy` resources require HTTP-to-HTTPS redirect,
1 MiB bodies, bounded request/backend timeouts, local rate limits, circuit breaking,
CSP, HSTS, frame denial, no MIME sniffing, referrer, and permissions headers. API,
BFF, and UI routes have separate policies so the API can default-deny all content while
the UI permits only same-origin scripts/styles/assets/API. No stickiness is configured;
a future BFF
requires a distributed encrypted session store. SSE/WebSocket is not configured and
must add connection/duration/message limits before use. Static assets remain immutable;
HTML is no-store and production source maps are excluded.

## Sandbox

`aegis-sandbox` uses a dedicated RuntimeClass, tainted node pool, quota/limits,
default-deny network, no service token, non-root/read-only pods, ephemeral storage, and
a suspended conformance template. Production execution remains disabled until the
runtime handler, admission policies, CNI/egress, cleanup/quarantine, image policy, and
node isolation are independently qualified.

Promotion rewrites the suspended migration and sandbox conformance Job names with a
release identifier derived from the environment, immutable digests, change reference,
and trusted manifest commit. This creates a new immutable Job template per release;
checked-in fixed-name templates must never be applied directly.

## Commands

```bash
make production-check
make kubernetes-check
kubectl kustomize deploy/kubernetes/overlays/production
trivy config --severity HIGH,CRITICAL deploy/kubernetes
python scripts/verify_cluster_prerequisites.py \
  --output .aegis-evidence/cluster-prerequisites.json
```

Never use rendered placeholder digests as a deployment artifact.
