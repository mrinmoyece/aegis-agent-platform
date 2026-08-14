import type { OperatorEventPage, OperatorItem } from '../api/schema';

export type EventPageSource = (
  tenantId: string,
  cursor: string | null,
  signal: AbortSignal,
) => Promise<OperatorEventPage>;

export interface PollerOptions {
  readonly minDelayMs?: number;
  readonly maxDelayMs?: number;
  readonly maxFailures?: number;
}

export class TenantEventPoller {
  private controller: AbortController | null = null;
  private cursor: string | null = null;
  private tenantId: string | null = null;
  private readonly seen = new Map<string, number>();
  private failures = 0;
  private timer: number | null = null;

  public constructor(
    private readonly source: EventPageSource,
    private readonly onEvents: (events: readonly OperatorItem[]) => void,
    private readonly onState: (
      state: 'connected' | 'degraded' | 'expired' | 'stopped',
    ) => void,
    private readonly options: PollerOptions = {},
  ) {}

  public start(tenantId: string): void {
    this.stop();
    this.tenantId = tenantId;
    this.cursor = null;
    this.seen.clear();
    this.failures = 0;
    this.controller = new AbortController();
    void this.poll();
  }

  public stop(): void {
    this.controller?.abort();
    this.controller = null;
    if (this.timer !== null) {
      window.clearTimeout(this.timer);
      this.timer = null;
    }
    this.cursor = null;
    this.tenantId = null;
    this.seen.clear();
    this.onState('stopped');
  }

  private async poll(): Promise<void> {
    if (this.controller === null || this.tenantId === null) {
      return;
    }
    if (document.visibilityState === 'hidden') {
      this.schedule(this.options.maxDelayMs ?? 30_000);
      return;
    }
    const controller = this.controller;
    const tenantId = this.tenantId;
    try {
      const page = await this.source(tenantId, this.cursor, controller.signal);
      if (controller !== this.controller || tenantId !== this.tenantId) {
        return;
      }
      const ordered = [...page.events].sort(
        (left, right) =>
          Date.parse(left.occurred_at) - Date.parse(right.occurred_at) ||
          left.id.localeCompare(right.id),
      );
      const fresh = ordered.filter((event) => {
        if (this.seen.has(event.id)) {
          return false;
        }
        this.seen.set(event.id, Date.parse(event.occurred_at));
        return true;
      });
      this.trimSeen();
      this.cursor = page.next_cursor ?? this.cursor;
      this.failures = 0;
      this.onState(page.stale ? 'degraded' : 'connected');
      if (fresh.length > 0) {
        this.onEvents(fresh);
      }
      this.schedule(this.options.minDelayMs ?? 2_000);
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      this.failures += 1;
      const maxFailures = this.options.maxFailures ?? 5;
      this.onState(this.failures >= maxFailures ? 'expired' : 'degraded');
      if (this.failures < maxFailures) {
        this.schedule(
          Math.min(
            (this.options.minDelayMs ?? 2_000) * 2 ** this.failures,
            this.options.maxDelayMs ?? 30_000,
          ),
        );
      }
      void error;
    }
  }

  private schedule(milliseconds: number): void {
    this.timer = window.setTimeout(() => {
      void this.poll();
    }, milliseconds);
  }

  private trimSeen(): void {
    if (this.seen.size <= 500) {
      return;
    }
    const oldest = [...this.seen.entries()]
      .sort((left, right) => left[1] - right[1])
      .slice(0, this.seen.size - 500);
    for (const [eventId] of oldest) {
      this.seen.delete(eventId);
    }
  }
}
