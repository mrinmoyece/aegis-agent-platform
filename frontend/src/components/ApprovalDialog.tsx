import { useEffect, useId, useRef, useState, type SyntheticEvent } from 'react';

import type {
  ApprovalDecisionRequest,
  ApprovalDecisionResponse,
  OperatorItem,
} from '../api/schema';
import { copyBoundedText } from '../security/safe-content';

interface ApprovalDialogProps {
  readonly approval: OperatorItem;
  readonly serverTime: string;
  readonly onClose: () => void;
  readonly onSubmit: (
    request: ApprovalDecisionRequest,
    expectedVersion: string,
    idempotencyKey: string,
  ) => Promise<ApprovalDecisionResponse>;
}

export function ApprovalDialog({
  approval,
  serverTime,
  onClose,
  onSubmit,
}: ApprovalDialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const mountClientTimeRef = useRef<number>(Date.now());
  const [decision, setDecision] = useState<'grant' | 'deny'>('grant');
  const [confirmation, setConfirmation] = useState('');
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<ApprovalDecisionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const metadata = approval.metadata;
  const planDigest = String(metadata.plan_digest ?? '');
  const policyDigest = String(metadata.policy_digest ?? '');
  const expectedVersion = String(metadata.version ?? '');
  const expectedPhrase = decision === 'grant' ? 'APPROVE' : 'DENY';
  const expiresAt = String(metadata.expires_at ?? '');
  const expiresAtMs = Date.parse(expiresAt);
  const serverTimeMs = Date.parse(serverTime);
  const computeRemaining = () => {
    if (!Number.isFinite(expiresAtMs) || !Number.isFinite(serverTimeMs)) return 0;
    const elapsed = Date.now() - mountClientTimeRef.current;
    return Math.max(0, expiresAtMs - (serverTimeMs + elapsed));
  };
  const [remaining, setRemaining] = useState(computeRemaining);

  useEffect(() => {
    if (
      !Number.isFinite(expiresAtMs) ||
      !Number.isFinite(serverTimeMs) ||
      remaining <= 0
    )
      return;
    const id = window.setInterval(() => {
      setRemaining(computeRemaining());
    }, 1_000);
    return () => window.clearInterval(id);
  }, [expiresAtMs, serverTimeMs, remaining]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog !== null && !dialog.open) {
      dialog.showModal();
      closeRef.current?.focus();
    }
    return () => dialog?.close();
  }, []);

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (confirmation !== expectedPhrase || submitting || remaining === 0) {
      return;
    }
    setSubmitting(true);
    setError(null);
    const request: ApprovalDecisionRequest = {
      approval_id: approval.id,
      plan_digest: planDigest,
      policy_digest: policyDigest,
      decision,
      rationale_code: decision === 'grant' ? 'scope_reviewed' : 'scope_not_acceptable',
      comment,
    };
    try {
      const response = await onSubmit(request, expectedVersion, crypto.randomUUID());
      setResult(response);
    } catch (reason) {
      const code = reason instanceof Error ? reason.message : 'request_failed';
      setError(
        code === 'concurrency_conflict'
          ? 'The approval changed. Close this review and load the current scope.'
          : 'The decision was not recorded. No action has been reported successful.',
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <dialog
      ref={dialogRef}
      className="approval-dialog"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      onCancel={(event) => {
        event.preventDefault();
        if (!submitting) onClose();
      }}
    >
      <div className="dialog-header">
        <div>
          <p className="eyebrow">Exact-scope operator decision</p>
          <h2 id={titleId}>Review {approval.title}</h2>
        </div>
        <button
          ref={closeRef}
          type="button"
          className="icon-button"
          aria-label="Close approval review"
          disabled={submitting}
          onClick={onClose}
        >
          ×
        </button>
      </div>
      {result === null ? (
        <form onSubmit={(event) => void submit(event)}>
          <p id={descriptionId}>
            This records a decision only. The controlled action remains separately gated
            and cannot appear successful until post-action verification.
          </p>
          <dl className="review-grid">
            <div>
              <dt>Target</dt>
              <dd>{String(metadata.target ?? 'Unknown')}</dd>
            </div>
            <div>
              <dt>Risk</dt>
              <dd>{String(metadata.risk ?? 'Unknown')}</dd>
            </div>
            <div>
              <dt>Blast radius</dt>
              <dd>{String(metadata.blast_radius ?? 'Unknown')}</dd>
            </div>
            <div>
              <dt>Quorum / separation of duties</dt>
              <dd>{String(metadata.quorum ?? 'Unknown')} · requester differs</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>
                <time dateTime={expiresAt}>{expiresAt}</time>
                {' · '}
                {Math.ceil(remaining / 60_000)} minutes by server time
              </dd>
            </div>
          </dl>
          <Digest label="Plan digest" value={planDigest} />
          <Digest label="Policy snapshot digest" value={policyDigest} />
          <fieldset className="decision-choice">
            <legend>Decision</legend>
            <label>
              <input
                type="radio"
                name="decision"
                value="grant"
                checked={decision === 'grant'}
                onChange={() => {
                  setDecision('grant');
                  setConfirmation('');
                }}
              />
              Grant exact scope
            </label>
            <label>
              <input
                type="radio"
                name="decision"
                value="deny"
                checked={decision === 'deny'}
                onChange={() => {
                  setDecision('deny');
                  setConfirmation('');
                }}
              />
              Deny exact scope
            </label>
          </fieldset>
          <label className="field">
            Rationale (optional, 1,000 characters maximum)
            <textarea
              maxLength={1_000}
              value={comment}
              onChange={(event) => setComment(event.target.value)}
            />
          </label>
          <label className="field">
            Type <strong>{expectedPhrase}</strong> to confirm
            <input
              autoComplete="off"
              spellCheck={false}
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </label>
          {remaining === 0 ? (
            <p role="alert" className="alert alert--critical">
              This approval is expired. Reload the current policy and scope.
            </p>
          ) : null}
          {error === null ? null : (
            <p role="alert" className="alert alert--critical">
              {error}
            </p>
          )}
          <div className="dialog-actions">
            <button type="button" className="button-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={
                confirmation !== expectedPhrase || submitting || remaining === 0
              }
            >
              {submitting ? 'Recording…' : `Record ${decision}`}
            </button>
          </div>
        </form>
      ) : (
        <div role="status" className="decision-result">
          <h3>Decision recorded</h3>
          <p>
            Verification is <strong>{result.verification}</strong>. This is not an
            action-success signal.
          </p>
          <p>
            Current version: <code>{result.version}</code>
          </p>
          <button type="button" onClick={onClose}>
            Return to approval inbox
          </button>
        </div>
      )}
    </dialog>
  );
}

function Digest({ label, value }: { readonly label: string; readonly value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="digest">
      <span>{label}</span>
      <code>{value}</code>
      <button
        type="button"
        className="button-secondary"
        onClick={() => {
          void copyBoundedText(value).then(() => setCopied(true));
        }}
      >
        {copied ? 'Copied' : 'Copy digest'}
      </button>
    </div>
  );
}
