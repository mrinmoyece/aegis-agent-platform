# Repository governance and release process

## Current repository evidence

The repository contains issue forms, a pull-request template, CODEOWNERS,
security reporting, contribution guidance, Dependabot, pinned Actions, minimal
workflow permissions, CI/evaluation/infrastructure/restore/supply-chain gates,
ADRs, changelog, and release evidence manifests.

On 2026-08-14, GitHub returned `404 Branch not protected` for `master` and no
repository rulesets. Therefore required reviews/checks, linear history,
conversation resolution, signed commits, and protected-branch-only promotion
are **not proven or enforced by repository settings**. This is a hard live gate,
not something code can paper over.

## Required GitHub settings

Before a deployable release, maintainers must configure and retain evidence for:

- pull requests only; no force push or deletion;
- at least one independent approving review, CODEOWNER review for security,
  domain, workflow, deployment, and qualification changes, and dismissal of
  stale approvals;
- resolved conversations and linear history;
- required successful CI, deterministic evaluation, frontend, integration,
  infrastructure, restore, CodeQL, and supply-chain checks;
- environment approval for development, staging, and production promotion;
- protected-branch-only publish/sign/attest and immutable release tags;
- secret scanning/push protection, Dependabot/security updates, private
  vulnerability reporting, and dependency graph where supported;
- least-privilege GitHub Apps/tokens and periodic access review.

Use the GitHub API as evidence; screenshots alone are insufficient.

## Change, version, release, and deprecation

1. One roadmap layer or bounded fix per PR; update affected contracts, tests,
   ADRs, risks, runbooks, docs, and changelog.
2. Public events and APIs evolve additively. Breaking behavior requires an ADR,
   parallel version, migration/read window, deprecation notice, and rollback
   plan. Historical events remain readable.
3. Pre-1.0 versions use semantic versioning intent: patch for compatible fixes,
   minor for additive capabilities, and explicit migration notes for any
   compatibility boundary.
4. A release candidate records base/head SHAs, checks, eval counts, integration
   environment, image/index digests, SBOM/provenance/signature, migrations,
   readiness manifest, accepted risks, rollback digest, and live gates.
5. Promotion verifies immutable artifacts; it never rebuilds from an unreviewed
   source or mutable tag. Protected-branch signing evidence is required.
6. Deprecation names owner, replacement, affected tenants/integrations, telemetry
   signal, notice window, final version/date, data/event compatibility, and
   rollback. Safety controls cannot be deprecated into a permissive fallback.

## Dependency and vulnerability policy

Python and frontend locks are committed; CI enforces hashes/frozen install,
licenses, audits, SBOM, image scans, secret scans, and pinned Actions/images.
Dependabot runs weekly for pip, root/frontend Docker, frontend npm, and Actions.
Fixable HIGH/CRITICAL
findings block. Any temporary exception is exact, owned, change-approved,
compensated, and at most 30 days. Layer 16 carries only two 14-day,
per-architecture scanner false-positive dispositions for the same upstream-
fixed Python CVE.

## Ownership

CODEOWNERS is routing, not proof of review. Teams/people, backups, on-call,
security response, data protection, protocol partner, sandbox, and release
authority must be established organizationally before go-live.
