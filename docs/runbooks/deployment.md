# Deployment and rollback runbook

1. Confirm exact environment/tenant/region scope, change approval, no freeze, SLO/error
   budget, backup freshness, and old-writer generation.
2. Verify cosign identity, provenance/SBOM, vulnerability/license policy, immutable
   digest, private-ECR mirror equality, bundle checksums, Kustomize render, secret
   references, and Terraform/GitOps plan. Run `verify_cluster_prerequisites.py` and
   retain its output before apply.
3. Run migration preflight. Admit the suspended Job once; require advisory lock,
   checksum history, forced-RLS/non-superuser checks, and compatible schema window.
4. Deploy canary/green workloads with no external effects, then publisher/reconciler,
   API, and UI. Workers, BFF, protocol, and sandbox stay at zero until their explicit
   adapters and prerequisites pass. Drain before termination.
5. Run tenant denial, ledger append/replay, Redis-loss, auth/key readiness, headers/
   limits, telemetry, and reconciliation synthetics.
6. Halt on signature/schema/fence/isolation/integrity failures, error-budget burn,
   retry storm, or unresolved ambiguity.
7. Roll back only to a verified digest compatible with the current schema. Do not undo
   an irreversible migration. Enter maintenance mode and roll forward or restore.
8. Record GitOps state, observations, reconciliations, approvers, and evidence hashes.
