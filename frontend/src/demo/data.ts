import {
  operatorSnapshotSchema,
  sessionBootstrapSchema,
  type OperatorItem,
  type OperatorSnapshot,
  type SessionBootstrap,
} from '../api/schema';

export const DEMO_TENANT = 'tenant-alpha';
export const DEMO_PLAN_DIGEST =
  '06963b1167bba0f8407b4d4825dbc97348ea5ffb45c7a015615678295f825c00';
export const DEMO_POLICY_DIGEST =
  'b3212707424f5a54994856f5f1840c8ff58ac37f0e0499093bc2a7c42987c59e';

const base = Date.parse('2026-08-13T08:00:00.000Z');

function item(
  id: string,
  kind: string,
  title: string,
  summary: string,
  status: string,
  authority: OperatorItem['authority'],
  minute: number,
  options: Partial<
    Pick<OperatorItem, 'citation' | 'metadata' | 'severity' | 'stale'>
  > = {},
): OperatorItem {
  return {
    id,
    kind,
    title,
    summary,
    status,
    authority,
    occurred_at: new Date(base + minute * 60_000).toISOString(),
    severity: options.severity ?? 'info',
    stale: options.stale ?? false,
    citation: options.citation ?? null,
    metadata: options.metadata ?? {},
  };
}

export const demoSession: SessionBootstrap = sessionBootstrapSchema.parse({
  schema_version: 1,
  actor_id: 'operator-alice',
  tenant_id: DEMO_TENANT,
  roles: ['approver', 'operator'],
  permissions: [
    'tenant:read',
    'resource:read',
    'investigation:read',
    'remediation:read',
    'approval:decide',
    'sandbox:read',
    'memory:read',
    'observability:read',
    'observability:replay',
  ],
  csrf_token: 'demo-csrf-token-is-not-a-production-secret',
  server_time: '2026-08-13T08:42:00.000Z',
  production_ready: false,
  demo: true,
  stale: false,
});

export const demoSnapshot: OperatorSnapshot = operatorSnapshotSchema.parse({
  schema_version: 1,
  tenant_id: DEMO_TENANT,
  generated_at: '2026-08-13T08:42:00.000Z',
  source_cursor: '46',
  stale: false,
  demo: true,
  sections: {
    health: [
      item(
        'health-control-plane',
        'service',
        'Control plane',
        'Readiness is healthy; checkout latency SLO is burning.',
        'degraded',
        'derived_state',
        42,
        {
          severity: 'warning',
          metadata: { slo: 'checkout-latency', burn_rate: 4.2 },
        },
      ),
      item(
        'health-ledger',
        'dependency',
        'Event ledger',
        'Append and replay probes are healthy.',
        'healthy',
        'derived_state',
        42,
      ),
    ],
    incidents: [
      item(
        'inc-checkout-001',
        'incident',
        'Checkout latency after synthetic deployment',
        'Connection-pool saturation overlaps a bounded test deployment.',
        'investigating',
        'derived_state',
        7,
        {
          severity: 'critical',
          citation: 'evidence://synthetic-observability/checkout-latency',
          metadata: { service: 'checkout', environment: 'test' },
        },
      ),
    ],
    timeline: [
      item(
        'evt-deploy-001',
        'deployment',
        'Synthetic deployment recorded',
        'Change event committed before the first alert.',
        'recorded',
        'event_fact',
        0,
        { citation: 'event://checkout/41' },
      ),
      item(
        'evt-alert-001',
        'alert',
        'Latency SLO alert fired',
        'Four-window burn rate crossed the warning threshold.',
        'recorded',
        'event_fact',
        7,
        {
          severity: 'warning',
          citation: 'event://checkout/42',
        },
      ),
      item(
        'claim-pool-001',
        'hypothesis',
        'Pool saturation is causal',
        'Specialist confidence is 0.78; conflicting evidence remains visible.',
        'contested',
        'model_claim',
        19,
        {
          severity: 'warning',
          citation: 'evidence://synthetic-observability/pool-saturation',
          metadata: { confidence: 0.78 },
        },
      ),
    ],
    specialists: [
      item(
        'task-metrics',
        'specialist-task',
        'Metrics specialist',
        'Correlated latency and pool saturation with immutable citations.',
        'completed',
        'derived_state',
        18,
        { citation: 'artifact://investigation/task-metrics' },
      ),
      item(
        'task-critic',
        'critic-task',
        'Critic review',
        'Preserved a deployment-timing contradiction and requested abstention.',
        'abstained',
        'model_claim',
        21,
        {
          severity: 'warning',
          citation: 'artifact://investigation/task-critic',
        },
      ),
    ],
    usage: [
      item(
        'usage-investigation',
        'budget',
        'Investigation budget',
        '18,420 of 40,000 tokens; USD 1.84 of USD 5.00.',
        'within-budget',
        'derived_state',
        22,
        {
          metadata: {
            tokens: 18_420,
            token_limit: 40_000,
            cost_usd: 1.84,
            cost_limit_usd: 5,
          },
        },
      ),
    ],
    approvals: [
      item(
        'approval-checkout-001',
        'approval',
        'Restart checkout pool',
        'Two-person approval; one independent grant recorded, one required.',
        'pending',
        'derived_state',
        25,
        {
          severity: 'critical',
          citation: 'event://remediation/approval-requested',
          metadata: {
            plan_digest: DEMO_PLAN_DIGEST,
            policy_digest: DEMO_POLICY_DIGEST,
            target: 'deployment/checkout',
            risk: 'critical',
            blast_radius: 'one test namespace',
            expires_at: '2026-08-13T09:00:00.000Z',
            quorum: '1/2',
            version: 'approval-v3',
            requester: 'svc-incident-coordinator',
          },
        },
      ),
    ],
    actions: [
      item(
        'action-restart-001',
        'controlled-action',
        'Restart checkout pool',
        'Provider acknowledgement was ambiguous; reconciliation is required.',
        'ambiguous',
        'event_fact',
        31,
        {
          severity: 'critical',
          citation: 'event://remediation/action-ambiguous',
          metadata: { verification: 'pending', rollback: 'available' },
        },
      ),
    ],
    sandboxes: [
      item(
        'sandbox-analysis-001',
        'sandbox-job',
        'Heap dump analysis',
        'Job completed; one archive is quarantined pending review.',
        'quarantined',
        'derived_state',
        28,
        {
          severity: 'warning',
          citation: 'event://sandbox/artifact-quarantined',
          metadata: { cleanup: 'scheduled', egress: 'denied' },
        },
      ),
    ],
    memory: [
      item(
        'memory-checkout-001',
        'memory',
        'Prior pool saturation incident',
        'Accepted episodic memory with event and evidence provenance.',
        'active',
        'derived_state',
        17,
        {
          citation: 'memory://checkout-pool/7',
          metadata: { retention: '30 days', tombstone: false },
        },
      ),
    ],
    evaluations: [
      item(
        'eval-operator-001',
        'regression',
        'Operator safety invariant pack',
        'One accessibility baseline is unmeasured; hard safety gates pass.',
        'degraded',
        'derived_state',
        40,
        {
          severity: 'warning',
          metadata: { baseline: 'canonical-v1', hard_safety_failures: 0 },
        },
      ),
    ],
    audit: [
      item(
        'audit-approval-read',
        'audit-event',
        'Approval detail viewed',
        'Privileged read recorded with tenant and correlation scope.',
        'recorded',
        'event_fact',
        26,
        { citation: 'audit://operator/read/1' },
      ),
    ],
    replay: [
      item(
        'replay-checkout-001',
        'replay-event',
        'Replay chain verified',
        'Ledger sequence and content digest converge through action ambiguity.',
        'verified',
        'derived_state',
        41,
        {
          citation: 'event://checkout/replay/46',
          metadata: { redacted: true, support_bundle: 'available' },
        },
      ),
    ],
  },
});
