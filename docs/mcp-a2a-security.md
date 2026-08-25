# MCP and A2A security

## Trust model

MCP servers and A2A agents are untrusted providers, including after
authentication. Authentication identifies a peer; tenant authorization, purpose,
policy, capability digest, risk, classification, budget, approval, and fence
checks independently decide each operation. Prompts and protocol descriptions
are never security controls.

## Mandatory controls

| Threat | Enforced response |
| --- | --- |
| Prompt/tool poisoning | NFC/control validation, strict schemas, untrusted provenance labels, no instruction promotion |
| Confused deputy or cross-tenant route | trusted tenant context, principal binding, RBAC/purpose checks, forced RLS |
| Capability escalation or schema smuggling | exact capability/schema/card digests, closed schemas, drift quarantine |
| JSON/Unicode/size denial | byte/depth/item/text bounds, non-finite rejection, dangerous control rejection |
| SSRF, DNS rebinding, redirects | HTTPS, exact host/port and DNS pins, public IP validation, every redirect revalidated |
| Replay or duplicate effect | short token lifetime, proof/certificate binding, one-use token ID, stable idempotency, reconciliation |
| Forged progress/artifact or MIME confusion | task/peer binding, signature and content-type allowlists, internal artifact references |
| Artifact URL exfiltration | only `aegis-artifact://` references; no remote artifact fetch from protocol content |
| Secret leakage | opaque `secret-ref://` values; no raw token/content in events, logs, metrics, URLs, or UI |
| Denial of wallet | tenant quotas, request/response bounds, deadlines, bounded retry, circuit and concurrency limits |
| Self-approval or remediation bypass | proposal-only capability; Layer 8 human approval and controlled execution remain local |

Signature, card, certificate, key, schema, or capability drift fails closed and
quarantines the peer. Emergency disable and revocation stop new calls.
Previously ambiguous work remains visible for reconciliation; revocation never
rewrites event history.

Production network use requires deployment-qualified TLS, OIDC/service identity,
audience/scope/tenant checks, short-lived tokens, DPoP or mTLS-equivalent proof,
key/certificate rotation and revocation, egress enforcement, and private secret
brokering. Those distributed controls are not configured here, so production
readiness is false.
