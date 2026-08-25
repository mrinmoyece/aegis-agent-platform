# Layer 16 security assessment

## Scope and conclusion

The final audit covered identity/JWT/JWKS, tenant/RLS/cache/UI/protocol
isolation, policy/role/approval revocation, evidence and memory poisoning,
prompt/indirect injection, schema/tool smuggling, SSRF/DNS/redirect behavior,
path/archive/symlink/shell handling, ambiguous/duplicate effects, sandbox
resources and cleanup, telemetry/support/backup leakage, dependencies,
containers, CI, Kubernetes, and Terraform.

No high-confidence exploitable in-repository vulnerability remained after the
audit. This is a source/configuration conclusion, not an independent penetration
test or a statement about a deployed environment. The open security gates are
tracked in [the residual-risk register](../qualification/residual-risks.json).

## Executable adversarial coverage

| Attack class | Enforcement surface | Evidence |
| --- | --- | --- |
| JWT algorithm/key/issuer/audience/time attacks | verifier allowlist, key binding, required claims, authoritative directory | `tests/test_identity_security.py` |
| Cross-tenant confused deputy | authorization before permission, explicit context, forced RLS | `tests/test_api.py`, `tests/integration/test_postgres_storage.py` |
| Prompt and indirect injection | untrusted-data delimiting, strict artifacts, fixed roles, runtime policy | `make eval-adversarial`, `tests/test_specialist_orchestration.py` |
| Evidence/memory poisoning | trust, digest, scanner, quarantine, acceptance, citations, conflict | `tests/test_evidence.py`, `tests/test_memory_recovery_edges.py` |
| Tool/schema smuggling | closed schemas, bounded JSON, unknown-tool denial, proposal-only mutation | `tests/test_model_gateway.py`, `tests/test_protocol_adapters.py` |
| SSRF/DNS/redirect/rebinding | HTTPS and host allowlists, IP rejection, DNS pinning, no redirects | `tests/test_evidence_adapters.py`, `tests/test_protocol_adapters.py` |
| Path/archive/symlink/shell | canonical argv/path validation, link/device denial, extraction limits | `tests/test_sandbox_workspace.py`, `tests/test_sandbox_domain.py` |
| Approval forgery/replay/stale scope | tenant/plan/action/policy digests, version, expiry, role, SoD, quorum | `tests/test_remediation_approvals.py`, `tests/test_operator_api.py` |
| Duplicate/ambiguous effects | stable idempotency, fenced intent, observe-before-retry, verification | `tests/test_remediation_execution.py`, `make qualification-demo` |
| Sandbox escape/resource bomb | immutable image/spec, no shell/host/token/network, resource bounds, cleanup | `tests/test_sandbox_execution.py`, `make qualification-chaos` |
| Protocol escalation/card drift | exact peer/capability/card/schema digest, quarantine, revocation | `make protocol-check`, `tests/test_protocols.py` |
| UI XSS/CSRF/cache leakage | text rendering, runtime schemas, CSP, Origin/CSRF, tenant teardown, no-store | `make frontend-check`, `make frontend-e2e` |
| Telemetry/support/backup leakage | central redaction, bounded cardinality, hashed support references | `tests/test_observability.py`, `tests/test_audit_secrets.py` |
| Supply chain/IaC/Kubernetes | hashes/digests, pinned actions, SBOM/provenance, non-root, RBAC/network policy | `make production-check`, `make terraform-check`, `make kubernetes-check` |

The deterministic adversarial pack remains non-waivable for hard safety. It
does not prove unknown-vulnerability absence, live proxy/controller behavior,
kernel isolation, operator process, or partner/provider security.

## CVE and base-image decision

Layer 15 temporarily treated Grype's report of `CVE-2026-15308` against Python
3.14.7 as accepted risk because the scanner listed only 3.15.0 as fixed. On
2026-08-12 the Python Software Foundation corrected the affected ranges:
3.12.14, 3.13.15, and 3.14.7 are patched stable releases. Layer 16 keeps the
digest-pinned 3.14.7 base because Grype reports only this one mismatch there;
moving to fixed 3.12.14 made Grype misclassify ten maintenance-branch fixes.

The two exact amd64/arm64 records are now `false_positive` scanner
dispositions—not vulnerability-risk acceptance. They bind Grype 0.117.0, the
image/package/version, upstream advisory, verification evidence, owner, approved
change, and a 14-day expiry. Aegis has no `html.parser` import or HTML-parsing
entrypoint. Missing, broadened, expired, or incompletely evidenced dispositions
fail closed; a fixable unwaived HIGH/CRITICAL blocks.

Trivy reports two fixable Python-package findings from an earlier upstream base
layer (`msgpack` and `setuptools`). Neither distribution exists in the final
runtime filesystem or import metadata, and Grype does not report them. They are
recorded as scanner/package-inventory disagreement rather than silently called
clean; the protected workflow's exact Grype policy remains the release gate.

## Fail-closed live gates

Do not enable real data, users, effects, sandbox jobs, protocol peers, or
promotion until the corresponding identity, egress, key, cluster, recovery,
capacity, on-call, and protected-branch gates in
`qualification/release-readiness.json` carry reviewed live evidence.
