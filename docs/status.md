# Implementation status

The repository currently implements **Layer 9: hardened ephemeral sandbox
execution** on top of the Layer 7 specialist DAG and Layer 8 exact approval/effect
boundary.

Implemented repository evidence includes immutable provider-neutral contracts,
strict untrusted-input validation, additive sandbox events and deterministic
replay, deny-by-default policy and egress ports, PostgreSQL-authoritative fencing,
at-least-once reconciliation and cleanup, safe content-addressed workspace and
artifact hooks, forced-RLS projections, authenticated redacted APIs, bounded
telemetry, deterministic fake scenarios/evals, and a locked-down official-client
Kubernetes suspended Job adapter with externally verified fencing admission as a
mandatory readiness fact.

The implementation does not certify a production Kubernetes cluster. Admission
policy, isolated runtime class, PID enforcement, default-deny network policy,
egress proxy/DNS defense, trusted CSI/artifact collector, scanner, secret broker,
and image signing/SBOM enforcement require deployment evidence. Memory/RAG,
operator UI, MCP/A2A, HA/DR/multi-region, and broad autonomous production
mutation remain deferred. See [limitations](limitations.md) and
[sandbox execution](sandbox-execution.md).
