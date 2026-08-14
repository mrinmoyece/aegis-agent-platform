# MCP and A2A operations runbook

## Register and activate a peer

1. Verify tenant owner, environment, business purpose, data classifications,
   risk ceiling, and egress destinations.
2. Retrieve the authenticated Agent Card or MCP capability snapshot through the
   controlled adapter; never paste credentials into configuration or UI.
3. Review exact protocol/version/transport, card/schema/certificate/key and
   capability digests, expiry, quotas, timeouts, and secret reference.
4. Activate only by typing the exact peer ID in the tenant-admin trust view.
   The BFF binds peer digest, expected revision, CSRF, origin, permission, and
   idempotency key.
5. Run a redacted read-only canary. Production readiness remains false unless
   live identity, TLS/proof, rotation, egress, and observability dependencies
   report ready.

## Capability drift or signature failure

1. Quarantine immediately; do not accept the new card or schema automatically.
2. Preserve event IDs, old/new digests, bounded reason, and peer identity. Never
   persist the raw card, token, prompt, or returned content in an incident note.
3. Determine whether the change was expected, review supply-chain and ownership
   evidence, and register a new reviewed revision rather than editing history.
4. Revoke on compromise. Rotate referenced secrets/certificates outside the
   protocol message channel.

## Ambiguous invocation or task

1. Do not mark success and do not blindly resend.
2. Locate the durable request intent, peer/capability/request/policy digests,
   idempotency key, lease generation, and last status.
3. Observe remote status through the exact peer and task identity.
4. Append reconciliation intent/result. Retry only when policy permits and
   observation proves absence; otherwise quarantine and escalate.

## Cancellation and outage

Cancellation is durable request/acknowledgement state, not a process signal.
Unconfirmed cancellation remains `cancel_requested`. During protocol outage,
local incident runs and event truth continue; new external work fails closed,
bounded circuits open, and operators use ledger-derived status. Never infer
health from missing telemetry.

## Emergency revocation

Use exact tenant-admin confirmation to revoke and emergency-disable the peer.
Verify new requests deny before adapter I/O, active ambiguous work remains
reconcilable, and credentials/certificates are rotated. Re-enablement requires a
new digest/version review; never decrement the registry revision.

## Evidence collection

Collect bounded event/audit identifiers, outcome classes, latency/byte buckets,
drift/quarantine counters, and projection versions. Exclude tenant IDs and peer
URLs from metric labels and exclude prompts, resources, artifacts, credentials,
and tokens from logs/support exports.
