import type { OperatorItem } from '../api/schema';
import { safeCitation } from '../security/safe-content';

const authorityLabels: Record<OperatorItem['authority'], string> = {
  event_fact: 'Event fact',
  derived_state: 'Derived state',
  model_claim: 'Model claim',
  operator_decision: 'Operator decision',
  unknown: 'Unknown',
};

const dateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'long',
});

interface OperatorItemViewProps {
  readonly item: OperatorItem;
  readonly supportMode: boolean;
}

export function StatusBadge({
  status,
  severity,
}: {
  readonly status: string;
  readonly severity: OperatorItem['severity'];
}) {
  return (
    <span className={`status status--${severity}`}>
      <span aria-hidden="true">{severity === 'critical' ? '!' : '●'}</span>{' '}
      {status.replaceAll('-', ' ')}
    </span>
  );
}

export function OperatorItemView({ item, supportMode }: OperatorItemViewProps) {
  const citation = item.citation === null ? null : safeCitation(item.citation);
  return (
    <article className="item-card">
      <header className="item-card__header">
        <div>
          <p className="eyebrow">{item.kind.replaceAll('-', ' ')}</p>
          <h3>{item.title}</h3>
        </div>
        <StatusBadge status={item.status} severity={item.severity} />
      </header>
      <p>{supportMode ? supportSummary(item.summary) : item.summary}</p>
      <dl className="item-facts">
        <div>
          <dt>Authority</dt>
          <dd>{authorityLabels[item.authority]}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>
            <time dateTime={item.occurred_at}>
              {dateTime.format(new Date(item.occurred_at))}
            </time>
          </dd>
        </div>
        <div>
          <dt>Freshness</dt>
          <dd>
            {item.stale ? 'Stale — refresh required' : 'Current at source cursor'}
          </dd>
        </div>
      </dl>
      {citation === null ? null : (
        <p className="citation">
          <span aria-hidden="true">↳</span> Source: <code>{citation}</code>
        </p>
      )}
      {Object.keys(item.metadata).length === 0 ? null : (
        <details>
          <summary>Bounded metadata</summary>
          <dl className="metadata">
            {Object.entries(item.metadata).map(([key, value]) => (
              <div key={key}>
                <dt>{key.replaceAll('_', ' ')}</dt>
                <dd>{supportMode ? 'Hidden in support mode' : String(value)}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </article>
  );
}

function supportSummary(summary: string): string {
  return summary.replace(
    /(checkout|deployment|namespace|operator|coordinator)/gi,
    '[redacted]',
  );
}
