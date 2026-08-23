# ADR 0016: Hardened ephemeral sandbox boundary

- **Status:** Accepted
- **Date:** 2026-08-13

## Context

Layer 7 specialists can produce analysis and Layer 8 can authorize a fixed
controlled action, but some investigations need bounded code/config analysis,
tests, patch preparation, or evidence generation. Running agent-generated input
inside a worker process, through a shell, on a Docker socket, or with production
credentials would collapse tenancy, policy, approval, and host trust boundaries.
Queue deduplication also cannot make an external sandbox lifecycle exactly once.

## Decision

Create a separate event-sourced sandbox aggregate with immutable
provider-neutral contracts and a replaceable `SandboxBackend` port.

1. Bind tenant, Layer 7 run/task, Layer 8 plan/action/approval, approved purpose,
   canonical policy/spec digests, immutable image digest, content-addressed input,
   limits, output contract, and cleanup policy.
   Layer 8 uses a dedicated sandbox-change-preparation action whose digest includes
   the reviewed Layer 9 policy digest, purpose, risk, and spec digest.
2. Accept argv tokens only. Reject shells, interpolation/control operators,
   unsafe Unicode, paths, mounts, namespaces, sockets, privilege, mutable images,
   secret literals, unsafe archives, and special-network targets before work.
3. Persist request and every provision/start/terminate/cleanup intent before the
   external call. Fence all execution events and backend calls with PostgreSQL.
4. Treat provisioning/deletion as at-least-once with stable identity,
   observe-before-create/retry, explicit ambiguity, reconciliation, bounded
   retries, cleanup redrive, and quarantine.
5. Default network to none. Brokered egress requires an exact allowlist and an
   independently verified enforcement boundary.
6. Treat output as untrusted; capture only bounded redacted stream metadata and
   content-addressed scanned artifacts with provenance/attestation.
7. Provide a deterministic fake and an official-client Kubernetes suspended Job
   adapter. Fail readiness closed unless admission, authoritative fence
   validation, runtime, PID, artifact, and network controls are
   deployment-verified.
8. Keep production mutation behind Layer 8 controlled action ports. The sandbox
   cannot approve or execute production remediation.

## Consequences

The ledger remains authoritative and projections remain rebuildable. Backend
vendor shapes do not enter core contracts. Crashes leave explicit intent that a
new fenced worker can reconcile. Exact approval and policy changes invalidate
queued work. The Kubernetes manifest has strong workload defaults, but the code
does not overclaim cluster-level isolation or egress enforcement.

The design adds lifecycle, reconciliation, artifact, quota, and cleanup
complexity. Production requires an isolated runtime class, admission policy,
default-deny network, egress/DNS enforcement, trusted content/artifact drivers,
scanner, and operational evidence. Writable seeded inputs and secrets deny
until dedicated copy-on-write and broker boundaries exist.

## Rejected alternatives

- **Host subprocess or `shell=True`:** shares worker identity/host and enables
  command construction attacks.
- **Docker socket backend:** grants host-equivalent authority and creates an
  escape hatch.
- **Prompt-only command safety:** untrusted text cannot enforce runtime policy.
- **Kubernetes manifest alone as proof:** admission, runtime, network, and node
  controls are outside the manifest.
- **Redis lifecycle authority:** transport delivery cannot decide state,
  fencing, quotas, or reconciliation.
- **Exactly-once create/delete claim:** external acceptance can be ambiguous.
- **Reuse remediation action port:** analysis execution must not gain production
  mutation authority.
