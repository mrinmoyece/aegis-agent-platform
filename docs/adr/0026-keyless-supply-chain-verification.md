# ADR 0026: Keyless supply-chain verification

## Status

Accepted

## Context

Tags and successful builds do not identify immutable code. Production promotion needs
dependency integrity, multi-architecture artifacts, SBOMs, vulnerability/license
policy, provenance, signatures, admission verification, retention, and rollback
traceability without long-lived signing keys in CI.

## Decision

Build pinned-base OCI images for `linux/amd64` and `linux/arm64` on protected `master`
pushes. Resolve and scan both exact platform manifests before signing the index. Generate
SPDX 2.3 JSON SBOMs per platform and a checksum-bound aggregate index document, attach
versioned SPDX attestations to both platforms and the index, reject fixable HIGH/CRITICAL vulnerabilities unless an exact
image-platform/vulnerability/package-version/owner/reason/control/approval/expiry waiver
is reviewed, report vendor-unfixed findings, reject prohibited licenses, scan repository
secrets, publish by digest, emit GitHub build provenance and SBOM attestations, and sign
with cosign keyless OIDC. Fork pull requests build and scan without publish credentials.

Promotion verifies the exact digest, workflow identity, OIDC issuer, attestation, and
current vulnerability policy before development, staging, then approval-protected
production. GitOps owns deployment; promotion does not mutate clusters directly.
The checked Kyverno admission policy is fail-closed and enforcing; it must not be
installed until the controller, trust roots, registry reachability, and emergency
procedure are qualified. Images roll back only by a previously verified digest with its
evidence.

## Consequences

- No repository signing secret is required.
- GitHub OIDC, transparency/registry availability, and admission-controller health are
  operational dependencies.
- The checked-in policy example and CI attestations are code/config evidence, not proof
  that a production admission controller enforces them.
- Emergency bypass requires break-glass approval, time bound, audit, and immediate
  reconciliation; unsigned images never become implicitly trusted.

## Alternatives rejected

- Mutable tags were rejected because they cannot prove artifact identity.
- Long-lived private signing keys in GitHub Secrets were rejected because rotation and
  theft risk are avoidable.
- Scan-only supply chains were rejected because scanners do not prove provenance.
