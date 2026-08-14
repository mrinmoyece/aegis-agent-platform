import type {
  ApprovalDecisionRequest,
  ApprovalDecisionResponse,
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
      return { ...duplicate, duplicate: true };
    }
    if (
      request.approval_id !== 'approval-checkout-001' ||
      request.plan_digest !== DEMO_PLAN_DIGEST ||
      request.policy_digest !== DEMO_POLICY_DIGEST
    ) {
      throw new Error('stale_scope');
    }
    if (expectedVersion !== 'approval-v3') {
      throw new Error('concurrency_conflict');
    }
    const response: ApprovalDecisionResponse = {
      approval_id: request.approval_id,
      status: 'decision_recorded',
      verification: 'pending',
      version: 'approval-v4',
      duplicate: false,
      server_time: demoSession.server_time,
    };
    this.decisions.set(idempotencyKey, response);
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
