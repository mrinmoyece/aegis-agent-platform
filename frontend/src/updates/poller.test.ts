import { afterEach, describe, expect, it, vi } from 'vitest';

import { demoSnapshot } from '../demo/data';
import { TenantEventPoller } from './poller';

const event = demoSnapshot.sections.timeline?.[0];

describe('tenant event poller', () => {
  afterEach(() => vi.useRealTimers());

  it('deduplicates and orders events across resumed pages', async () => {
    vi.useFakeTimers();
    if (event === undefined) throw new Error('fixture missing');
    const source = vi
      .fn()
      .mockResolvedValueOnce({
        events: [
          { ...event, id: 'event-b' },
          { ...event, id: 'event-a' },
        ],
        next_cursor: '2',
        server_time: demoSnapshot.generated_at,
        stale: false,
      })
      .mockResolvedValueOnce({
        events: [{ ...event, id: 'event-a' }],
        next_cursor: null,
        server_time: demoSnapshot.generated_at,
        stale: false,
      });
    const received: string[] = [];
    const poller = new TenantEventPoller(
      source,
      (events) => received.push(...events.map((item) => item.id)),
      vi.fn(),
      { minDelayMs: 1, maxDelayMs: 10 },
    );
    poller.start('tenant-alpha');
    await vi.runOnlyPendingTimersAsync();
    await vi.runOnlyPendingTimersAsync();
    poller.stop();
    expect(received).toEqual(['event-a', 'event-b']);
    expect(source.mock.calls[1]?.[1]).toBe('2');
  });

  it('tears down the prior tenant request on switch', async () => {
    vi.useFakeTimers();
    const signals: AbortSignal[] = [];
    const source = vi.fn(
      async (_tenant: string, _cursor: string | null, signal: AbortSignal) => {
        signals.push(signal);
        await new Promise(() => undefined);
        throw new Error('unreachable');
      },
    );
    const poller = new TenantEventPoller(source, vi.fn(), vi.fn());
    poller.start('tenant-alpha');
    await Promise.resolve();
    poller.start('tenant-beta');
    expect(signals[0]?.aborted).toBe(true);
    poller.stop();
    expect(signals[1]?.aborted).toBe(true);
  });

  it('stops after a bounded number of reconnect failures', async () => {
    vi.useFakeTimers();
    const state = vi.fn();
    const source = vi.fn().mockRejectedValue(new Error('offline'));
    const poller = new TenantEventPoller(source, vi.fn(), state, {
      minDelayMs: 1,
      maxDelayMs: 2,
      maxFailures: 2,
    });
    poller.start('tenant-alpha');
    await vi.runAllTimersAsync();
    expect(state).toHaveBeenCalledWith('expired');
  });
});
