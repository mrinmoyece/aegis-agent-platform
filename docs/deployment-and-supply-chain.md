# Deployment safety and supply chain

## Artifact policy

Both application images pin base images by digest. Python runtime and development
graphs, including the Hatchling build backend, use Python 3.12-generated hash-checked
lockfiles and disable build isolation; the frontend uses its frozen
pnpm lock. Pull requests build one architecture, generate SPDX SBOMs, scan
HIGH/CRITICAL vulnerabilities, enforce backend and frontend license policies, and scan
secrets without registry credentials. Protected `master` builds publish locked
`linux/amd64` and `linux/arm64` images, resolve and scan each published platform digest,
generate an SPDX 2.3 SBOM for each platform, bind both SBOM checksums and manifest
digests into an aggregate index SPDX document, keyless-sign exact index digests with
cosign/GitHub OIDC, and attach versioned SPDX attestations to every platform and index
plus provenance to the index. Promotion resolves, verifies, and rescans both platforms.
Actions are commit-SHA pinned and permissions are job-minimal.

The runtime stages apply current Debian/Alpine security updates during the build
because pinned upstream digests can lag published fixes. The resulting digest is still
the only promoted identity, but byte-for-byte rebuild reproducibility is not claimed
until those fixed packages are available in newly pinned base digests.

Fixed HIGH/CRITICAL findings block builds and promotion. Findings with no
available vendor fix are reported but do not block; a newly available fix
immediately makes the finding blocking. `security/vulnerability-waivers.yaml` is
executable policy. Layer 16 reclassifies the temporary Python 3.14.7 record as an
exact scanner false positive after the upstream affected-range correction
confirmed 3.14.7 as patched. Grype 0.117.0 still reports only 3.15.0 as fixed;
the application has no `html.parser` import or HTML parsing entrypoint. Exact
amd64 and arm64 dispositions bind the scanner/version and upstream evidence and
expire after 14 days. Any future fixable HIGH/CRITICAL finding blocks until the dependency is
updated or an exact, reviewed, unexpired exception is added.
A waiver needs exact report/image-platform, vulnerability, package/version, owner,
rationale, disposition/evidence, compensating control, `change-ref://` approval,
issue/expiry dates, and
expiry <= 30 days; expired, duplicate, broad, or unscoped entries fail. It cannot waive
exposure of sensitive material, provenance/signature failure, or a hard safety invariant. Artifact and
attestation retention must cover rollback, investigation, and policy windows.

## Promotion and GitOps

The manual promotion workflow accepts the signed control-plane and operator-UI
multi-platform digests plus a `change-ref://` approval. It verifies both indexes,
platform SBOMs, provenance, keyless identity/issuer, and vulnerability policy. After the
approval it assumes that environment's short-lived OIDC role, copies each signed OCI
graph from GHCR into that environment's private ECR without changing its digest, and
creates one checksummed Kustomize bundle. Staging verifies the development bundle before
creating its independently configured mirror and bundle; production does the same with
the staging bundle. Each GitHub environment must provide its own ECR/role, public-domain,
OIDC, AWS-region, private-data-CIDR, qualified egress-proxy, and OTLP server-name
variables plus explicit platform/database alert routes. Promotion is accepted only from
`refs/heads/master`. Cosign `2.5.3` stores its keyless signature as an OCI 1.1
referrer, and ORAS `1.2.2` recursively copies the signed subject, child manifests,
signature, provenance, and SPDX referrers. Promotion then verifies the destination
cosign signature and loads every GitHub attestation bundle from ECR rather than the
GitHub API. Each workflow attempt uses a unique immutable transport tag
while every bundle and admission decision uses the unchanged digest, making partial-run
retries safe. Required reviewers and separation of duties are
repository settings and must be independently evidenced. The workflow does not apply
infrastructure or mutate clusters; GitOps consumes the reviewed bundle.

Promotion reuses one digest across environments. Never rebuild for production. Record
source commit, image/index digest, SBOM/provenance/signature verification, scanner and
waiver policy, Kustomize render digest, Terraform plan digest when relevant, migration
set/checksums, approvers, smoke results, and rollback digest.

## Deployment ordering

1. Check SLO/error-budget and incident/change freeze.
2. Verify artifact and render; preflight secrets, identity, keys, schema window,
   database capacity, backups, and old-writer fence.
3. Apply additive expand migration with the suspended one-runner Job.
4. Deploy publishers/reconcilers, then API and UI. Keep workers, BFF, protocol gateway,
   and sandbox execution at zero until their explicit readiness prerequisites pass.
5. Canary by tenant-safe traffic percentage or blue/green isolated service; never split
   one authoritative writer generation.
6. Run liveness/readiness, authentication, tenant denial, ledger append/replay,
   intent/effect/reconciliation, static headers/body/rate limits, telemetry, sandbox
   disabled, and protocol disabled synthetics.
7. Continue bounded backfill; contract only in a later change.

Automatic halt triggers include signature/policy failure, schema mismatch, readiness or
auth/key failure, writer-fence rejection, error-budget burn, tenant isolation alert,
ledger integrity alert, sustained error/latency regression, retry storm, or
reconciliation backlog. Roll back an application digest only when its schema window is
compatible. Never automatically reverse irreversible schema or delete ledger facts.

Maintenance mode stops new durable work, drains workers, preserves publisher/
reconciler operation where safe, and keeps explicit read-only status. Feature/config
versions are immutable inputs included in evidence. See
[deployment runbook](runbooks/deployment.md).

## Admission

Kyverno policy enforces restricted workload properties and declares separate keyless
Cosign signature and `SigstoreBundle` provenance/versioned-SPDX verification with
OCI 1.1 signature discovery, `Enforce`, `required`, digest verification, and fail-closed
webhook behavior. Do not install this example until the controller version,
trust roots, registry/transparency reachability, failure behavior, break glass, and
rollback are qualified: premature installation intentionally blocks workloads rather
than silently auditing them. Unsigned or untrusted images are rejected by the checked
policy and deterministic eval, but no live admission enforcement is claimed.
The controller versions and required CRDs/workloads are locked in
`deploy/kubernetes/bootstrap/controller-lock.json`; run
`scripts/verify_cluster_prerequisites.py` against the target before any GitOps apply.
