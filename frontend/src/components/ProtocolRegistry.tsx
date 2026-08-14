import { useState } from 'react';

import type { OperatorItem, PeerTrustRequest, PeerTrustResponse } from '../api/schema';
import { OperatorItemView } from './OperatorItemView';

export function ProtocolRegistry({
  items,
  canManageTrust,
  supportMode,
  onChangeTrust,
}: {
  readonly items: readonly OperatorItem[];
  readonly canManageTrust: boolean;
  readonly supportMode: boolean;
  readonly onChangeTrust: (
    request: PeerTrustRequest,
    expectedVersion: string,
    idempotencyKey: string,
  ) => Promise<PeerTrustResponse>;
}) {
  const [selected, setSelected] = useState<OperatorItem | null>(null);
  const [confirmation, setConfirmation] = useState('');
  const [decision, setDecision] = useState<'activate' | 'quarantine' | 'revoke'>(
    'quarantine',
  );
  const [result, setResult] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const peers = items.filter((item) => item.kind === 'protocol-peer');
  const operations = items.filter((item) => item.kind !== 'protocol-peer');

  async function submit(): Promise<void> {
    const peer = selected;
    if (confirmation !== peer?.id) {
      return;
    }
    const digest = peer.metadata.peer_digest;
    const version = peer.metadata.version;
    if (typeof digest !== 'string' || typeof version !== 'string') {
      setResult('Trust scope is incomplete; no change was submitted.');
      return;
    }
    setSubmitting(true);
    setResult(null);
    try {
      const response = await onChangeTrust(
        {
          peer_id: peer.id,
          peer_digest: digest,
          decision,
          rationale_code: 'operator-trust-review',
        },
        version,
        `peer-${peer.id}-${decision}-${version}`,
      );
      setResult(
        `${peer.title} is ${response.status}. Network effects remain independently verified.`,
      );
      setSelected(null);
      setConfirmation('');
    } catch {
      setResult('The exact peer scope changed or the trust decision was rejected.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Deny-by-default boundary</p>
            <h2>Protocol peer registry</h2>
          </div>
          <span className="demo-badge">Local deterministic interoperability</span>
        </div>
        <p>
          MCP servers and A2A agents are digest-pinned untrusted providers. Capability
          drift, signature failure, or revocation stops new work and requires review.
        </p>
        {result === null ? null : (
          <p className="alert alert--warning" role="status">
            {result}
          </p>
        )}
        <div className="card-grid">
          {peers.map((peer) => (
            <article className="item-card" key={peer.id}>
              <OperatorItemView item={peer} supportMode={supportMode} />
              <dl className="fact-list">
                <div>
                  <dt>Protocol</dt>
                  <dd>
                    {String(peer.metadata.family)}{' '}
                    {String(peer.metadata.protocol_version)}
                  </dd>
                </div>
                <div>
                  <dt>Transport</dt>
                  <dd>{String(peer.metadata.transport)}</dd>
                </div>
                <div>
                  <dt>Peer digest</dt>
                  <dd>
                    <code>{String(peer.metadata.peer_digest).slice(0, 16)}...</code>
                  </dd>
                </div>
                <div>
                  <dt>Readiness</dt>
                  <dd>
                    {peer.metadata.production_ready === true
                      ? 'Production ready'
                      : 'Fails closed outside local demo'}
                  </dd>
                </div>
              </dl>
              {canManageTrust ? (
                <button
                  type="button"
                  className="button-secondary"
                  onClick={() => {
                    setDecision(peer.status === 'active' ? 'quarantine' : 'activate');
                    setSelected(peer);
                    setConfirmation('');
                    setResult(null);
                  }}
                >
                  Review trust
                </button>
              ) : (
                <p>Tenant administrator permission is required to change trust.</p>
              )}
            </article>
          ))}
        </div>
      </section>
      <section className="card-grid" aria-label="Protocol task and invocation status">
        {operations.map((operation) => (
          <OperatorItemView
            key={operation.id}
            item={operation}
            supportMode={supportMode}
          />
        ))}
      </section>
      {selected === null ? null : (
        <div className="modal-backdrop">
          <section
            className="approval-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="peer-trust-title"
          >
            <p className="eyebrow">Exact scope confirmation</p>
            <h2 id="peer-trust-title">Review {selected.title}</h2>
            <p>
              This records a local trust decision for the displayed digest and version.
              It cannot grant the peer roles, approvals, or direct remediation
              authority.
            </p>
            <label>
              Decision
              <select
                value={decision}
                onChange={(event) =>
                  setDecision(
                    event.target.value as 'activate' | 'quarantine' | 'revoke',
                  )
                }
              >
                <option value="activate">Activate pinned peer</option>
                <option value="quarantine">Quarantine peer</option>
                <option value="revoke">Revoke peer</option>
              </select>
            </label>
            <label>
              Type <code>{selected.id}</code> to confirm
              <input
                autoComplete="off"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </label>
            <div className="dialog-actions">
              <button
                type="button"
                className="button-secondary"
                onClick={() => setSelected(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="button-danger"
                disabled={submitting || confirmation !== selected.id}
                onClick={() => void submit()}
              >
                {submitting ? 'Recording...' : `Record ${decision}`}
              </button>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
