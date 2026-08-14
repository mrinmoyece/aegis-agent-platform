# Hardened ephemeral sandbox execution

Layer 9 runs only bounded code/config analysis, tests, patch preparation, and
evidence production. It is not an interactive shell, a production remediation
path, or a way around Layer 8 approval. Raw sandbox output is untrusted data.

## Contract and authority

`domain.sandbox` defines immutable versioned provider-neutral contracts. A
request binds:

- tenant, Layer 7 run/task, Layer 8 remediation plan/action/approval, purpose,
  risk, requester, timestamp, and idempotency key;
- an OCI image pinned as `registry/repository@sha256:<digest>`;
- argv tokens, never a shell string, and a relative workspace directory;
- a tenant-bound immutable content-addressed input snapshot and declared mounts;
- literal environment allowlist and opaque tenant-bound secret references;
- network-none or exact encrypted brokered egress rules;
- CPU, memory, PID, ephemeral-storage, lifetime, output, file-count, and artifact
  limits;
- non-root user/group, dropped capabilities, no-new-privileges, read-only root,
  RuntimeDefault seccomp, AppArmor profile, and no host/service-account authority;
- exact output paths/media types/size bounds, bounded retry, and fail-closed
  cleanup/retention policy.

Canonical JSON and SHA-256 produce separate request and spec digests. A Layer 8
`sandbox.change_preparation.v1` action carries the reviewed Layer 9 policy digest,
purpose, risk, and spec digest inside its immutable action digest. Any policy,
purpose, risk, or spec change therefore invalidates that approval. PostgreSQL stores those
reviewed fields on the Layer 8 action projection, and
`PostgresSandboxApprovalAuthority` rechecks them with the granted, unexpired
plan/action approval and every approver's current enabled identity plus active
`approver`/`tenant_admin` role binding under tenant RLS.

## Validation boundary

Construction rejects mutable image tags, shell families/interpolation/control
operators, policy-escaping Unicode, control characters, absolute/traversal/device
paths, host paths/sockets/namespaces, weakened isolation, unknown capabilities,
oversized argv/environment/files/archives, literal secret-like values,
duplicate/conflicting paths, unsafe output paths, and special egress targets.
There is no `eval`, `exec`, `shell=True`, host subprocess backend, or Docker
socket backend.

ZIP/TAR validation reads every member before publication. It rejects traversal,
backslashes, absolute/drive paths, symlinks, hard links, devices, FIFOs,
duplicates, parent/child conflicts, encrypted ZIP members, file/count/byte
limits, and excessive expansion ratio. Extraction uses a private staging
directory, mode `0600`, and atomic rename.

## Durable lifecycle

The event ledger is the only run-state authority. Additive events cover request,
policy decision, approval binding, dispatch claim, provisioning intent,
provisioned identity, start intent, start, bounded output/artifact capture,
completion/failure/timeout/OOM/policy violation/cancellation, attestation,
cleanup intent/completion/failure, quarantine, and reconciliation. The pure fold
rejects sequence gaps, duplicates, corrupt linkage, stale approval/attestation,
and illegal transitions. Projections are rebuildable only.

The orchestrator rechecks authorization, tenant, policy, quota, exact approval,
input snapshot, fence, backend readiness, and egress enforcement before durable
execution intent or a backend lifecycle call. Every backend call after intent is
preceded by a current PostgreSQL lease check and receives the provider-neutral
lease fence. The fake backend enforces monotonic generations. Kubernetes readiness
additionally requires a verified admission boundary that validates fence
annotations against PostgreSQL authority; without it production readiness is
false. A stale worker cannot provision, start, terminate, clean, or append a result.
Approval or policy revocation denies new execution. After a lifecycle intent is
durable, revocation routes provisioned/starting/running work to fenced termination
and still permits terminal cleanup, so safety recovery cannot be stranded by
authority expiry.

Provision and delete are at-least-once:

1. Persist provisioning or cleanup intent.
2. Observe the stable backend name before create/delete retry.
3. Compare the observed spec digest.
4. Record explicit reconciliation.
5. Retry only within the request bound, or preserve ambiguity/quarantine.

Exactly-once execution is not claimed.

## Policy and egress

Tenant policy defaults deny and exactly allowlists image digest/registry,
command family, purpose, mount prefixes, output media types, egress rules, and
secret references. It also caps risk, lifetime, resources, period runs,
concurrency, CPU-time budget, and artifact bytes. Runtime isolation, admission,
and egress verification are required policy facts rather than prompt claims.

Network mode defaults to `none`. Exact egress rules accept only canonical DNS
names with encrypted protocols. Loopback, `.local`, `.localhost`, `.internal`,
metadata names, IP literals that are private/link-local/loopback/multicast/
reserved/unspecified, Unix sockets, and duplicate rules deny. `EgressBroker` is
an enforcement port; the repository contains only a deny-all implementation.
No full production proxy or DNS-rebinding control is delivered, so brokered
production readiness must remain false until an environment supplies and
verifies that boundary.

## Backends

`FakeSandboxBackend` is deterministic and never starts a process or network
connection. It exercises success, policy denial, injection, archive attack,
timeout, OOM, cancellation, ambiguous provision, artifact quarantine, and
ambiguous cleanup recovery.

`OfficialKubernetesSandboxBackend` contains official-client shapes at the
adapter. It creates a stable, suspended Job and starts it only after the start
intent commits. The manifest enforces a digest-pinned image, non-root identity,
read-only root filesystem, no privilege escalation, dropped capabilities,
RuntimeDefault seccomp, disabled service-account token/service links, no host
network/PID/IPC/shared-process namespace, one container, zero Job retries,
deadline/resources, ephemeral workspace/output volumes, and a read-only
content-addressed input CSI mount.

The adapter does **not** prove cluster isolation. `KubernetesSandboxControls`
must report verified admission policy, runtime class, PID enforcement, artifact
collector, authoritative fencing admission, and default-deny networking or
readiness fails closed. Start and cleanup carry hashed fence metadata; cleanup
uses a resource-version delete precondition and completes only after absence is
observed. Brokered egress, secret injection, and copy-on-write input staging are
rejected unless their deployment boundary exists; they are not simulated with an
unsafe fallback.

## Artifacts and attestation

Artifact content is content-addressed and tenant-bound. Scanner decisions are
allow, redact, or quarantine. A redaction requirement without a configured
redactor fails. Quarantined references use a separate scheme. Events/APIs expose
only bounded media type, size, digest, quarantine flag, and redaction marker;
they never expose command content, paths, artifact bytes, raw stdout/stderr, or
secret values.

Successful execution records an attestation over spec, image, input, result,
policy, exact approval, and backend identity. This is provenance metadata, not a
supply-chain signature. Image signing, SBOM verification, malware engine
certification, and remote attestation remain planned.

## Storage and API

Migration `0008_hardened_sandbox_execution.sql` adds forced-RLS sandbox,
artifact, execution-claim, quota, cleanup, and append-only attestation tables.
Atomic event/projection/claim updates use PostgreSQL locks and fences. Redis
continues to carry delivery only.

Authenticated routes are:

- `POST /v1/tenants/{tenant}/sandboxes`
- `GET /v1/tenants/{tenant}/sandboxes`
- `GET /v1/tenants/{tenant}/sandboxes/{sandbox_id}`
- `GET /v1/tenants/{tenant}/sandboxes/{sandbox_id}/artifacts`
- `GET /v1/tenants/{tenant}/sandboxes/cleanup`

Reads are bounded, cursor-based, tenant-authorized, and redacted. There is no
interactive exec, attach, log-stream, arbitrary command, or raw artifact API.

## Operator runbook

For a provisioning/start/result gap, first inspect the tenant-scoped event
stream and current fence. Never infer state from pod logs or Redis. If an intent
has no outcome, observe the stable backend name and spec digest, append
reconciliation under the current fence, then continue or quarantine.

For timeout, OOM, cancellation, or output limit, confirm the explicit terminal
event precedes cleanup intent. For cleanup failure, inspect bounded attempt,
backend reference, error code, and reconciliation outcome. Redrive only within
policy; exhausted attempts quarantine and require operator escalation. Never
delete ledger history or edit a projection.

For artifact quarantine, inspect digest, media type, size, scanner reason, and
provenance only. Do not open untrusted bytes on an operator workstation. Correct
scanner/policy configuration and submit new immutable work rather than clearing
the quarantine flag.

Treat an unexpected backend call by a stale fence, missing intent, cross-tenant
row, mutable event/attestation, host mount/socket, privileged workload, or
verified-control readiness false-positive as a security incident. Stop new
claims and preserve database and cluster audit evidence.

## Tutorial and deterministic demo

Run the complete fake scenario matrix:

```bash
python -m aegis_agent_platform.sandbox --scenario approved-analysis
python -m aegis_agent_platform.sandbox --scenario policy-denied
python -m aegis_agent_platform.sandbox --scenario prompt-injection
python -m aegis_agent_platform.sandbox --scenario malicious-archive
python -m aegis_agent_platform.sandbox --scenario timeout
python -m aegis_agent_platform.sandbox --scenario oom
python -m aegis_agent_platform.sandbox --scenario cancellation
python -m aegis_agent_platform.sandbox --scenario ambiguous-provisioning
python -m aegis_agent_platform.sandbox --scenario output-quarantine
python -m aegis_agent_platform.sandbox --scenario cleanup-recovery
make evals
```

Each JSON result states that it uses no live network and performs no production
mutation. In the successful case, trace request/policy/approval, provisioning
intent, start intent, bounded captures, result/attestation, and cleanup. Then run
the injection and ambiguity cases and verify denial/reconciliation rather than a
success-shaped fallback.

## Implemented versus environment-enforced

| Control | Repository status |
| --- | --- |
| Contracts, canonicalization, policy, replay, fencing, fake backend, artifacts, APIs, telemetry, RLS schema | Implemented and deterministic |
| Kubernetes locked-down Job generation and official-client translation | Implemented and mocked |
| Admission policy, isolated runtime class, PID controller, default-deny network policy, egress proxy/DNS defense, trusted artifact CSI/collector | Required environment controls; not deployed or certified |
| Secret broker, copy-on-write seeded writable mounts, malware engine, image signing/SBOM enforcement, remote attestation | Planned |
| Memory/RAG | Implemented separately in Layer 10; it grants no sandbox authority |
| Production-qualified operator UI, public MCP/A2A federation and PKI, HA/DR/multi-region, broad autonomous production mutation | Explicitly deferred |
