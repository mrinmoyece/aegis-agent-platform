import type {
  ApprovalDecisionRequest,
  ApprovalDecisionResponse,
  OperatorEventPage,
  OperatorItem,
  OperatorSnapshot,
  SessionBootstrap,
} from '../api/schema';
import {
  DEMO_PLAN_DIGEST,
  DEMO_POLICY_DIGEST,
  demoSession,
  demoSnapshot,
} from './data';

export interface OperatorDataSource {
  signIn(signal?: AbortSignal): Promise<SessionBootstrap>;
  loadSnapshot(tenantId: string, signal?: AbortSignal): Promise<OperatorSnapshot>;
  loadEvents(
    tenantId: string,
    cursor: string | null,
    signal: AbortSignal,
  ): Promise<OperatorEventPage>;
  decideApproval(
    tenantId: string,
    request: ApprovalDecisionRequest,
    expectedVersion: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<ApprovalDecisionResponse>;
}

export class DemoOperatorDataSource implements OperatorDataSource {
  private readonly decisions = new Map<string, ApprovalDecisionResponse>();
  private readonly fingerprints = new Map<string, string>();
  // Optimistic concurrency: track the current version and terminal status.
  private currentApprovalVersion = 'approval-v3';
  private approvalTerminal = false;

  public async signIn(signal?: AbortSignal): Promise<SessionBootstrap> {
    await Promise.resolve();
    assertNotAborted(signal);
    return structuredClone(demoSession);
  }

  public async loadSnapshot(
    tenantId: string,
    signal?: AbortSignal,
  ): Promise<OperatorSnapshot> {
    await Promise.resolve();
    assertNotAborted(signal);
    if (tenantId !== demoSession.tenant_id) {
      throw new Error('not_found');
    }
    return structuredClone(demoSnapshot);
  }

  public async loadEvents(
    tenantId: string,
    cursor: string | null,
    signal: AbortSignal,
  ): Promise<OperatorEventPage> {
    await Promise.resolve();
    assertNotAborted(signal);
    if (tenantId !== demoSession.tenant_id) {
      throw new Error('not_found');
    }
    const items = orderedDemoEvents();
    const offset = cursor !== null ? parseInt(cursor, 10) : 0;
    const page = items.slice(offset, offset + 100);
    const nextCursor =
      offset + page.length < items.length ? String(offset + page.length) : null;
    return {
      events: page,
      next_cursor: nextCursor,
      server_time: demoSession.server_time,
      stale: false,
    };
  }

  public async decideApproval(
    tenantId: string,
    request: ApprovalDecisionRequest,
    expectedVersion: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<ApprovalDecisionResponse> {
    await Promise.resolve();
    assertNotAborted(signal);
    if (tenantId !== demoSession.tenant_id) {
      throw new Error('not_found');
    }
    const duplicate = this.decisions.get(idempotencyKey);
    if (duplicate !== undefined) {
      // Reject re-use of the same key for a different command.
      const fp = `${request.approval_id}:${request.plan_digest}:${request.policy_digest}:${request.decision}`;
      if (fp !== this.fingerprints.get(idempotencyKey)) {
        throw new Error('idempotency_conflict');
      }
      return { ...duplicate, duplicate: true };
    }
    if (
      request.approval_id !== 'approval-checkout-001' ||
      request.plan_digest !== DEMO_PLAN_DIGEST ||
      request.policy_digest !== DEMO_POLICY_DIGEST
    ) {
      throw new Error('stale_scope');
    }
    // Optimistic concurrency: reject stale or repeat decisions.
    if (this.approvalTerminal || expectedVersion !== this.currentApprovalVersion) {
      throw new Error('concurrency_conflict');
    }
    const newVersion = 'approval-v4';
    const response: ApprovalDecisionResponse = {
      approval_id: request.approval_id,
      status: 'decision_recorded',
      verification: 'pending',
      version: newVersion,
      duplicate: false,
      server_time: demoSession.server_time,
    };
    const fp = `${request.approval_id}:${request.plan_digest}:${request.policy_digest}:${request.decision}`;
    this.decisions.set(idempotencyKey, response);
    this.fingerprints.set(idempotencyKey, fp);
    this.currentApprovalVersion = newVersion;
    this.approvalTerminal = true;
    return response;
  }
}

export function orderedDemoEvents(): readonly OperatorItem[] {
  return Object.values(demoSnapshot.sections)
    .flat()
    .sort(
      (left, right) =>
        Date.parse(left.occurred_at) - Date.parse(right.occurred_at) ||
        left.id.localeCompare(right.id),
    );
}

function assertNotAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw signal.reason;
  }
}
