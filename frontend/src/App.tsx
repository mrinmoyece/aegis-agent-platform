import { useEffect, useRef, useState, type ReactNode } from 'react';

import type {
  ApprovalDecisionRequest,
  ApprovalDecisionResponse,
  OperatorItem,
  OperatorSnapshot,
  SessionBootstrap,
} from './api/schema';
import { ApprovalDialog } from './components/ApprovalDialog';
import { OperatorItemView, StatusBadge } from './components/OperatorItemView';
import { DemoOperatorDataSource, type OperatorDataSource } from './demo/api';
import { recordTelemetry } from './telemetry';
import { TenantEventPoller } from './updates/poller';

const views = [
  ['health', 'Health & SLOs'],
  ['incidents', 'Incident queue'],
  ['timeline', 'Incident overview'],
  ['specialists', 'Specialist DAG'],
  ['usage', 'Usage & budgets'],
  ['approvals', 'Approval inbox'],
  ['actions', 'Controlled actions'],
  ['sandboxes', 'Sandbox jobs'],
  ['memory', 'Memory'],
  ['evaluations', 'Evaluations'],
  ['audit', 'Audit timeline'],
  ['replay', 'Replay & support'],
] as const;

type ViewKey = (typeof views)[number][0];
type Theme = 'light' | 'dark' | 'contrast';

interface AppProps {
  readonly source?: OperatorDataSource;
}

export function App({ source = new DemoOperatorDataSource() }: AppProps) {
  const [session, setSession] = useState<SessionBootstrap | null>(null);
  const [snapshot, setSnapshot] = useState<OperatorSnapshot | null>(null);
  const [view, setView] = useState<ViewKey>(() => routeFromHash());
  const [theme, setTheme] = useState<Theme>('light');
  const [supportMode, setSupportMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approval, setApproval] = useState<OperatorItem | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const [online, setOnline] = useState(navigator.onLine);
  const mainRef = useRef<HTMLElement>(null);
  const pollerRef = useRef<TenantEventPoller | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    const updateOnline = () => setOnline(navigator.onLine);
    window.addEventListener('online', updateOnline);
    window.addEventListener('offline', updateOnline);
    return () => {
      window.removeEventListener('online', updateOnline);
      window.removeEventListener('offline', updateOnline);
    };
  }, []);

  useEffect(() => {
    const updateRoute = () => setView(routeFromHash());
    window.addEventListener('hashchange', updateRoute);
    return () => window.removeEventListener('hashchange', updateRoute);
  }, []);

  async function signIn(): Promise<void> {
    setLoading(true);
    setError(null);
    const controller = new AbortController();
    try {
      const nextSession = await source.signIn(controller.signal);
      setSession(nextSession);
      const nextSnapshot = await source.loadSnapshot(
        nextSession.tenant_id,
        controller.signal,
      );
      if (nextSnapshot.tenant_id !== nextSession.tenant_id) {
        throw new Error('tenant_mismatch');
      }
      setSnapshot(nextSnapshot);
      // Start bounded event polling so the workspace stays live.
      const poller = new TenantEventPoller(
        (tenantId, cursor, signal) => source.loadEvents(tenantId, cursor, signal),
        (events) => {
          setSnapshot((prev) => {
            if (prev === null) return prev;
            const incoming = new Map(events.map((e) => [e.id, e]));
            const updated: OperatorSnapshot = {
              ...prev,
              sections: {},
            };
            for (const [section, items] of Object.entries(prev.sections)) {
              (updated.sections as Record<string, readonly OperatorItem[]>)[section] =
                items.map((item) => incoming.get(item.id) ?? item);
            }
            return updated;
          });
        },
        () => undefined,
      );
      pollerRef.current?.stop();
      pollerRef.current = poller;
      poller.start(nextSession.tenant_id, nextSnapshot.source_cursor);
      setAnnouncement('Synthetic operator session started.');
    } catch {
      setSession(null);
      setSnapshot(null);
      setError('The operator session could not be started.');
    } finally {
      setLoading(false);
    }
  }

  function navigate(nextView: ViewKey): void {
    window.history.replaceState(null, '', `#${nextView}`);
    setView(nextView);
    setAnnouncement(`Showing ${labelFor(nextView)}.`);
    recordTelemetry('navigation_changed', { route: nextView });
    window.setTimeout(() => mainRef.current?.focus(), 0);
  }

  function clearTenantSession(): void {
    pollerRef.current?.stop();
    pollerRef.current = null;
    setSnapshot(null);
    setSession(null);
    setApproval(null);
    setAnnouncement('Tenant session cleared. Prior tenant data removed.');
    recordTelemetry('tenant_changed', { status: 'session_cleared' });
  }

  async function decideApproval(
    request: ApprovalDecisionRequest,
    expectedVersion: string,
    idempotencyKey: string,
  ): Promise<ApprovalDecisionResponse> {
    if (session === null) {
      throw new Error('session_expired');
    }
    return source.decideApproval(
      session.tenant_id,
      request,
      expectedVersion,
      idempotencyKey,
    );
  }

  if (session === null || snapshot === null) {
    return <SignIn loading={loading} error={error} onSignIn={() => void signIn()} />;
  }

  const currentItems = snapshot.sections[view] ?? [];
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            A
          </span>
          <div>
            <strong>Aegis Operator</strong>
            <span>Incident command surface</span>
          </div>
        </div>
        <div className="topbar__status">
          <span className="demo-badge">Synthetic demo · no production network</span>
          <span className={online ? 'online' : 'offline'}>
            {online ? '● Connected' : '○ Offline'}
          </span>
        </div>
        <div className="topbar__controls">
          <label>
            Theme
            <select
              value={theme}
              onChange={(event) => setTheme(event.target.value as Theme)}
            >
              <option value="light">Light</option>
              <option value="dark">Dark</option>
              <option value="contrast">High contrast</option>
            </select>
          </label>
          <button
            type="button"
            className="button-secondary"
            aria-pressed={supportMode}
            onClick={() => setSupportMode((active) => !active)}
          >
            Support mode {supportMode ? 'on' : 'off'}
          </button>
          {supportMode ? (
            <span className="support-mode-label" role="status">
              [redacted] Support-safe view
            </span>
          ) : null}
        </div>
      </header>
      <aside className="sidebar">
        <div className="tenant-card">
          <span className="eyebrow">Trusted tenant context</span>
          <strong>Tenant Alpha</strong>
          <code>{session.tenant_id}</code>
          <button type="button" className="button-link" onClick={clearTenantSession}>
            Change tenant / re-authenticate
          </button>
        </div>
        <nav aria-label="Operator sections">
          <ul>
            {views.map(([key, label]) => (
              <li key={key}>
                <a
                  href={`#${key}`}
                  aria-current={view === key ? 'page' : undefined}
                  onClick={(event) => {
                    event.preventDefault();
                    navigate(key);
                  }}
                >
                  <span aria-hidden="true">{navIcon(key)}</span>
                  {label}
                  {key === 'approvals' ? (
                    <span className="nav-count" aria-label="1 pending">
                      1
                    </span>
                  ) : null}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <main ref={mainRef} id="main-content" className="main" tabIndex={-1}>
        <PageHeader
          view={view}
          generatedAt={snapshot.generated_at}
          stale={snapshot.stale}
        />
        {!online ? (
          <p role="status" className="alert alert--warning">
            Offline. Displayed data is cached for this in-memory session and cannot
            authorize any operation.
          </p>
        ) : null}
        {snapshot.demo ? (
          <p className="demo-notice">
            <strong>Demo data:</strong> canonical synthetic checkout incident. No
            production credentials, identity exchange, or external services are used.
          </p>
        ) : null}
        <Screen
          view={view}
          items={currentItems}
          snapshot={snapshot}
          supportMode={supportMode}
          onReviewApproval={setApproval}
        />
      </main>
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {announcement}
      </div>
      {approval === null ? null : (
        <ApprovalDialog
          approval={approval}
          serverTime={session.server_time}
          onClose={() => setApproval(null)}
          onSubmit={decideApproval}
        />
      )}
    </div>
  );
}

function SignIn({
  loading,
  error,
  onSignIn,
}: {
  readonly loading: boolean;
  readonly error: string | null;
  readonly onSignIn: () => void;
}) {
  return (
    <main className="sign-in">
      <section className="sign-in__panel" aria-labelledby="sign-in-title">
        <div className="brand brand--large">
          <span className="brand-mark" aria-hidden="true">
            A
          </span>
          <div>
            <strong>Aegis Operator</strong>
            <span>Secure incident operations</span>
          </div>
        </div>
        <p className="eyebrow">Layer 13 deterministic demonstration</p>
        <h1 id="sign-in-title">Operate from facts, not browser state</h1>
        <p>
          Production sessions use an OIDC BFF boundary with authorization code, PKCE,
          state, nonce, and Secure HttpOnly cookies. This checkout starts only a clearly
          labeled synthetic session; live token exchange is not configured.
        </p>
        <ul className="trust-list">
          <li>No bearer token is stored in browser storage.</li>
          <li>Tenant authorization and policy remain server authoritative.</li>
          <li>Every effect still requires exact approval and verification.</li>
        </ul>
        {error === null ? null : (
          <p role="alert" className="alert alert--critical">
            {error}
          </p>
        )}
        <button type="button" disabled={loading} onClick={onSignIn}>
          {loading ? 'Starting synthetic session…' : 'Start synthetic demo'}
        </button>
        <p className="fine-print">
          Production readiness: <strong>false</strong> · identity/browser qualification
          remains explicit deployment evidence.
        </p>
      </section>
      <aside className="sign-in__context" aria-label="Operational principles">
        <p className="eyebrow">Operator contract</p>
        <h2>Facts stay distinguishable</h2>
        <AuthorityLegend />
      </aside>
    </main>
  );
}

function PageHeader({
  view,
  generatedAt,
  stale,
}: {
  readonly view: ViewKey;
  readonly generatedAt: string;
  readonly stale: boolean;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">Operator workspace</p>
        <h1>{labelFor(view)}</h1>
        <p>{descriptionFor(view)}</p>
      </div>
      <div className="freshness" data-stale={String(stale)}>
        <strong>{stale ? 'Stale' : 'Current'}</strong>
        <span>
          Server snapshot{' '}
          <time dateTime={generatedAt}>
            {new Intl.DateTimeFormat(undefined, {
              dateStyle: 'medium',
              timeStyle: 'short',
            }).format(new Date(generatedAt))}
          </time>
        </span>
      </div>
    </header>
  );
}

function Screen({
  view,
  items,
  snapshot,
  supportMode,
  onReviewApproval,
}: {
  readonly view: ViewKey;
  readonly items: readonly OperatorItem[];
  readonly snapshot: OperatorSnapshot;
  readonly supportMode: boolean;
  readonly onReviewApproval: (approval: OperatorItem) => void;
}) {
  if (items.length === 0) {
    return (
      <section className="empty-state">
        <h2>No items in this bounded page</h2>
        <p>Absence is not treated as evidence of health or completion.</p>
      </section>
    );
  }
  if (view === 'health') {
    return <HealthScreen items={items} />;
  }
  if (view === 'incidents') {
    return <IncidentQueue items={items} />;
  }
  if (view === 'timeline') {
    return <Timeline items={items} supportMode={supportMode} />;
  }
  if (view === 'usage') {
    return <UsageScreen items={items} />;
  }
  if (view === 'approvals') {
    return (
      <ApprovalInbox
        items={items}
        supportMode={supportMode}
        onReview={onReviewApproval}
      />
    );
  }
  if (view === 'actions') {
    return <ActionScreen items={items} supportMode={supportMode} />;
  }
  if (view === 'replay') {
    return (
      <ReplayScreen
        items={items}
        eventCount={snapshot.sections.timeline?.length ?? 0}
        supportMode={supportMode}
      />
    );
  }
  return (
    <section className="card-grid" aria-label={`${labelFor(view)} items`}>
      {items.map((item) => (
        <OperatorItemView key={item.id} item={item} supportMode={supportMode} />
      ))}
    </section>
  );
}

function HealthScreen({ items }: { readonly items: readonly OperatorItem[] }) {
  return (
    <>
      <section className="metric-grid" aria-label="Platform health summary">
        <Metric
          label="Services ready"
          value="7 / 7"
          detail="Ledger correctness gated"
        />
        <Metric label="Checkout burn rate" value="4.2×" detail="Warning · 1 hour" />
        <Metric label="Unverified actions" value="1" detail="Reconciliation required" />
        <Metric label="Eval safety failures" value="0" detail="Canonical baseline" />
      </section>
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Service level objective</p>
            <h2>Checkout latency error budget</h2>
          </div>
          <StatusBadge status="burning" severity="warning" />
        </div>
        <progress
          className="budget-bar"
          aria-label="Checkout latency has consumed 68 percent of its error budget"
          max={100}
          value={68}
        />
        <p>68% consumed · derived SLI window · not authoritative run state</p>
      </section>
      <section className="card-grid">
        {items.map((item) => (
          <OperatorItemView key={item.id} item={item} supportMode={false} />
        ))}
      </section>
    </>
  );
}

function IncidentQueue({ items }: { readonly items: readonly OperatorItem[] }) {
  return (
    <section className="panel table-scroll">
      <table>
        <caption>Bounded incident queue, one result</caption>
        <thead>
          <tr>
            <th scope="col">Incident</th>
            <th scope="col">Service</th>
            <th scope="col">Status</th>
            <th scope="col">Authority</th>
            <th scope="col">Observed</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <th scope="row">{item.title}</th>
              <td>{String(item.metadata.service ?? 'Unknown')}</td>
              <td>
                <StatusBadge status={item.status} severity={item.severity} />
              </td>
              <td>Derived queue state</td>
              <td>
                <time dateTime={item.occurred_at}>{item.occurred_at}</time>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Timeline({
  items,
  supportMode,
}: {
  readonly items: readonly OperatorItem[];
  readonly supportMode: boolean;
}) {
  return (
    <>
      <AuthorityLegend />
      <ol className="timeline">
        {items.map((item) => (
          <li key={item.id}>
            <OperatorItemView item={item} supportMode={supportMode} />
          </li>
        ))}
      </ol>
    </>
  );
}

function UsageScreen({ items }: { readonly items: readonly OperatorItem[] }) {
  const usage = items[0];
  const tokens = Number(usage?.metadata.tokens ?? 0);
  const limit = Number(usage?.metadata.token_limit ?? 1);
  const percentage = Math.min(100, Math.round((tokens / limit) * 100));
  return (
    <>
      <section className="metric-grid">
        <Metric
          label="Tokens"
          value={tokens.toLocaleString()}
          detail={`${String(percentage)}% of run limit`}
        />
        <Metric label="Cost" value="$1.84" detail="$5.00 incident ceiling" />
        <Metric label="Model calls" value="24" detail="Provider-neutral accounting" />
        <Metric label="Budget state" value="Open" detail="Server enforced" />
      </section>
      <section className="panel">
        <h2>Token budget consumption</h2>
        <progress
          className="budget-bar"
          aria-label={`${String(percentage)} percent of the token budget consumed`}
          max={100}
          value={percentage}
        />
        <p>Browser values are explanatory; the gateway enforces the real fence.</p>
      </section>
    </>
  );
}

function ApprovalInbox({
  items,
  supportMode,
  onReview,
}: {
  readonly items: readonly OperatorItem[];
  readonly supportMode: boolean;
  readonly onReview: (approval: OperatorItem) => void;
}) {
  return (
    <>
      <p className="alert alert--warning">
        Approval decisions are neutral choices. Grant and deny receive equal prominence;
        agents and this UI cannot self-approve or widen scope.
      </p>
      <section className="card-grid">
        {items.map((item) => (
          <article className="item-card approval-card" key={item.id}>
            <OperatorItemView item={item} supportMode={supportMode} />
            <button type="button" onClick={() => onReview(item)}>
              Review exact scope
            </button>
          </article>
        ))}
      </section>
    </>
  );
}

function ActionScreen({
  items,
  supportMode,
}: {
  readonly items: readonly OperatorItem[];
  readonly supportMode: boolean;
}) {
  return (
    <>
      <p role="alert" className="alert alert--critical">
        Ambiguous provider acknowledgement is not success. Reconciliation and
        independent verification remain required before any terminal outcome.
      </p>
      <section className="card-grid">
        {items.map((item) => (
          <OperatorItemView key={item.id} item={item} supportMode={supportMode} />
        ))}
      </section>
      <section className="panel">
        <h2>Controlled lifecycle</h2>
        <ol className="stepper">
          <li data-complete="true">Intent committed</li>
          <li data-complete="true">Effect attempted</li>
          <li data-current="true">Outcome ambiguous</li>
          <li>Reconciliation pending</li>
          <li>Verification not started</li>
          <li>Rollback available</li>
        </ol>
      </section>
    </>
  );
}

function ReplayScreen({
  items,
  eventCount,
  supportMode,
}: {
  readonly items: readonly OperatorItem[];
  readonly eventCount: number;
  readonly supportMode: boolean;
}) {
  return (
    <>
      <section className="metric-grid">
        <Metric
          label="Validated events"
          value={String(eventCount)}
          detail="Bounded demo page"
        />
        <Metric label="Sequence" value="Valid" detail="No gaps detected" />
        <Metric label="Redaction" value="Applied" detail="No raw prompt or evidence" />
        <Metric
          label="Support bundle"
          value="Ready"
          detail="Download allowlist enforced"
        />
      </section>
      <section className="card-grid">
        {items.map((item) => (
          <OperatorItemView key={item.id} item={item} supportMode={supportMode} />
        ))}
      </section>
    </>
  );
}

function Metric({
  label,
  value,
  detail,
}: {
  readonly label: string;
  readonly value: string;
  readonly detail: string;
}) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function AuthorityLegend() {
  return (
    <section className="legend" aria-labelledby="legend-title">
      <h2 id="legend-title">Information authority</h2>
      <ul>
        <li>
          <span className="legend-dot legend-dot--fact" /> Event fact
        </li>
        <li>
          <span className="legend-dot legend-dot--derived" /> Derived state
        </li>
        <li>
          <span className="legend-dot legend-dot--claim" /> Model claim
        </li>
        <li>
          <span className="legend-dot legend-dot--decision" /> Operator decision
        </li>
        <li>
          <span className="legend-dot legend-dot--unknown" /> Unknown
        </li>
      </ul>
    </section>
  );
}

function routeFromHash(): ViewKey {
  const candidate = window.location.hash.slice(1);
  return views.some(([key]) => key === candidate) ? (candidate as ViewKey) : 'health';
}

function labelFor(view: ViewKey): string {
  return views.find(([key]) => key === view)?.[1] ?? 'Operator';
}

function descriptionFor(view: ViewKey): string {
  const descriptions: Record<ViewKey, string> = {
    health: 'Service readiness, dependency health, and honest SLO windows.',
    incidents: 'Tenant-scoped incidents ordered from bounded derived state.',
    timeline: 'Cited event facts, model claims, contradictions, and operator context.',
    specialists:
      'Coordinator-owned task DAG, hypotheses, critic review, and abstention.',
    usage: 'Provider-neutral usage, costs, and server-enforced budget ceilings.',
    approvals:
      'Immutable scope, policy snapshot, quorum, expiry, and separation of duties.',
    actions: 'Intent, effect, ambiguity, reconciliation, verification, and rollback.',
    sandboxes: 'Ephemeral jobs, artifacts, quarantine decisions, and cleanup state.',
    memory: 'Provenance, retrieval purpose, retention, contradiction, and tombstones.',
    evaluations:
      'Regression baselines and hard safety invariants without aggregate hiding.',
    audit: 'Immutable privileged-read and operator-decision records.',
    replay: 'Redacted ledger chain and bounded support evidence.',
  };
  return descriptions[view];
}

function navIcon(view: ViewKey): ReactNode {
  const icons: Record<ViewKey, string> = {
    health: '◫',
    incidents: '◎',
    timeline: '≋',
    specialists: '⌘',
    usage: '◔',
    approvals: '◇',
    actions: '↻',
    sandboxes: '□',
    memory: '▤',
    evaluations: '✓',
    audit: '≡',
    replay: '◁',
  };
  return icons[view];
}
