import { describe, expect, it } from 'vitest';

import {
  DEMO_MCP_PEER_DIGEST,
  DEMO_PLAN_DIGEST,
  DEMO_POLICY_DIGEST,
  demoSession,
} from './data';
import { DemoOperatorDataSource, orderedDemoEvents } from './api';

const request = {
  approval_id: 'approval-checkout-001',
  plan_digest: DEMO_PLAN_DIGEST,
  policy_digest: DEMO_POLICY_DIGEST,
  decision: 'grant' as const,
  rationale_code: 'scope_reviewed',
  comment: 'Reviewed.',
};

const trustRequest = {
  peer_id: 'peer-mcp-deterministic',
  peer_digest: DEMO_MCP_PEER_DIGEST,
  decision: 'activate' as const,
  rationale_code: 'reviewed',
};

describe('deterministic demo adapter', () => {
  it('is tenant scoped and contains no live dependency', async () => {
    const source = new DemoOperatorDataSource();
    await expect(source.loadSnapshot(demoSession.tenant_id)).resolves.toMatchObject({
      demo: true,
      tenant_id: demoSession.tenant_id,
    });
    await expect(source.loadSnapshot('tenant-beta')).rejects.toThrow('not_found');
    // loadEvents and decideApproval are also tenant-scoped
    const sig = new AbortController().signal;
    await expect(source.loadEvents('tenant-other', null, sig)).rejects.toThrow(
      'not_found',
    );
    await expect(
      source.decideApproval('tenant-other', request, 'approval-v3', 'k'),
    ).rejects.toThrow('not_found');
  });

  it('respects AbortSignal and supports paginated event loading', async () => {
    const source = new DemoOperatorDataSource();
    // Aborted signal throws immediately.
    const controller = new AbortController();
    controller.abort(new Error('aborted'));
    await expect(
      source.loadEvents(demoSession.tenant_id, null, controller.signal),
    ).rejects.toThrow('aborted');
    // Cursor-based pagination: offset 0 returns events and a next_cursor.
    const fresh = new AbortController();
    const page = await source.loadEvents(demoSession.tenant_id, '0', fresh.signal);
    expect(page.events.length).toBeGreaterThan(0);
    // Null cursor also works (first page)
    const page2 = await source.loadEvents(
      demoSession.tenant_id,
      null,
      new AbortController().signal,
    );
    expect(page2.events.length).toBe(page.events.length);
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
    // Same idempotency key, different fingerprint → idempotency_conflict
    await expect(
      source.decideApproval(
        demoSession.tenant_id,
        { ...request, decision: 'deny' as const },
        'approval-v3',
        'decision-1',
      ),
    ).rejects.toThrow('idempotency_conflict');
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

  it('records peer trust changes and deduplicates by idempotency key', async () => {
    const source = new DemoOperatorDataSource();
    const first = await source.changePeerTrust(
      demoSession.tenant_id,
      trustRequest,
      'peer-v1',
      'trust-key-1',
    );
    expect(first.peer_id).toBe('peer-mcp-deterministic');
    expect(first.status).toBe('active');
    expect(first.duplicate).toBe(false);

    const dup = await source.changePeerTrust(
      demoSession.tenant_id,
      trustRequest,
      first.version,
      'trust-key-1',
    );
    expect(dup.duplicate).toBe(true);
    expect(dup.status).toBe('active');
  });

  it('rejects changePeerTrust with wrong tenant, bad version, or idempotency conflict', async () => {
    const source = new DemoOperatorDataSource();
    await expect(
      source.changePeerTrust('tenant-other', trustRequest, 'peer-v1', 'trust-x'),
    ).rejects.toThrow('not_found');

    await expect(
      source.changePeerTrust(demoSession.tenant_id, trustRequest, 'peer-v0', 'trust-y'),
    ).rejects.toThrow('concurrency_conflict');

    // Register a key under one fingerprint, then try a different fingerprint.
    await source.changePeerTrust(
      demoSession.tenant_id,
      trustRequest,
      'peer-v1',
      'trust-z',
    );
    await expect(
      source.changePeerTrust(
        demoSession.tenant_id,
        { ...trustRequest, decision: 'quarantine' },
        'peer-v1',
        'trust-z',
      ),
    ).rejects.toThrow('idempotency_conflict');
  });
});
