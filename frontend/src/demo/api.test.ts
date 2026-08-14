import { describe, expect, it } from 'vitest';

import { DEMO_PLAN_DIGEST, DEMO_POLICY_DIGEST, demoSession } from './data';
import { DemoOperatorDataSource, orderedDemoEvents } from './api';

const request = {
  approval_id: 'approval-checkout-001',
  plan_digest: DEMO_PLAN_DIGEST,
  policy_digest: DEMO_POLICY_DIGEST,
  decision: 'grant' as const,
  rationale_code: 'scope_reviewed',
  comment: 'Reviewed.',
};

describe('deterministic demo adapter', () => {
  it('is tenant scoped and contains no live dependency', async () => {
    const source = new DemoOperatorDataSource();
    await expect(source.loadSnapshot(demoSession.tenant_id)).resolves.toMatchObject({
      demo: true,
      tenant_id: demoSession.tenant_id,
    });
    await expect(source.loadSnapshot('tenant-beta')).rejects.toThrow('not_found');
  });

  it('deduplicates approval decisions by idempotency key', async () => {
    const source = new DemoOperatorDataSource();
    const first = await source.decideApproval(
      demoSession.tenant_id,
      request,
      'approval-v3',
      'decision-1',
    );
    const duplicate = await source.decideApproval(
      demoSession.tenant_id,
      request,
      'approval-v3',
      'decision-1',
    );
    expect(first.duplicate).toBe(false);
    expect(duplicate.duplicate).toBe(true);
    expect(duplicate.verification).toBe('pending');
  });

  it('rejects stale digest and optimistic concurrency conflicts', async () => {
    const source = new DemoOperatorDataSource();
    await expect(
      source.decideApproval(
        demoSession.tenant_id,
        { ...request, plan_digest: '0'.repeat(64) },
        'approval-v3',
        'decision-stale',
      ),
    ).rejects.toThrow('stale_scope');
    await expect(
      source.decideApproval(
        demoSession.tenant_id,
        request,
        'approval-v2',
        'decision-conflict',
      ),
    ).rejects.toThrow('concurrency_conflict');
  });

  it('orders the bounded event stream deterministically', () => {
    const events = orderedDemoEvents();
    expect(events.length).toBeGreaterThan(10);
    expect(
      events.every(
        (event, index) =>
          index === 0 ||
          Date.parse(event.occurred_at) >=
            Date.parse(events[index - 1]?.occurred_at ?? ''),
      ),
    ).toBe(true);
  });
});
