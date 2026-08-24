/* eslint-disable */
/**
 * Generated from contracts/operator-api.openapi.json.
 * Do not edit by hand. Source SHA-256: 3ac2385519a3389a380d6b281f4f950b6083bae9cfef769e373b4b8ed6329073
 */

export const OPERATOR_API_CONTRACT_SHA256 = '3ac2385519a3389a380d6b281f4f950b6083bae9cfef769e373b4b8ed6329073' as const; // gitleaks:allow

export type DataAuthority = "event_fact" | "derived_state" | "model_claim" | "operator_decision" | "unknown";
export type OperatorSeverity = "info" | "warning" | "critical";
export type OperatorAuthMode = "oidc_bff" | "deterministic_demo";
export type ApprovalDecision = "grant" | "deny";
export type PeerTrustDecision = "activate" | "quarantine" | "revoke";
export type PeerTrustStatus = "active" | "quarantined" | "revoked";
export type JsonValue = string | number | boolean | null;

export interface OperatorConfig {
  schema_version: 1;
  production_ready: boolean;
  auth_mode: OperatorAuthMode;
  demo: boolean;
  server_time: string;
  oidc_boundary: {
    authorization_code: true;
    pkce: true;
    state: true;
    nonce: true;
    live_exchange_configured: boolean;
  };
}

export interface SessionBootstrap {
  schema_version: 1;
  actor_id: string;
  tenant_id: string;
  roles: string[];
  permissions: string[];
  csrf_token: string | null;
  server_time: string;
  production_ready: boolean;
  demo: boolean;
  stale: boolean;
}

export interface OperatorItem {
  id: string;
  kind: string;
  title: string;
  summary: string;
  status: string;
  authority: DataAuthority;
  occurred_at: string;
  severity: OperatorSeverity;
  stale: boolean;
  citation: string | null;
  metadata: Record<string, JsonValue>;
}

export interface OperatorSnapshot {
  schema_version: 1;
  tenant_id: string;
  generated_at: string;
  source_cursor: string;
  stale: boolean;
  demo: boolean;
  sections: Record<string, OperatorItem[]>;
}

export interface OperatorEventPage {
  events: OperatorItem[];
  next_cursor: string | null;
  server_time: string;
  stale: boolean;
}

export interface ApprovalDecisionRequest {
  approval_id: string;
  plan_digest: string;
  policy_digest: string;
  decision: ApprovalDecision;
  rationale_code: string;
  comment: string;
}

export interface ApprovalDecisionResponse {
  approval_id: string;
  status: 'decision_recorded';
  verification: 'pending';
  version: string;
  duplicate: boolean;
  server_time: string;
}

export interface ErrorEnvelope {
  error: {
    code: string;
    request_id: string;
    retryable: boolean;
  };
}

export interface PeerTrustRequest {
  peer_id: string;
  peer_digest: string;
  decision: PeerTrustDecision;
  rationale_code: string;
  comment?: string;
}

export interface PeerTrustResponse {
  peer_id: string;
  status: PeerTrustStatus;
  version: string;
  duplicate: boolean;
  server_time: string;
}

export interface components {
  schemas: {
    OperatorConfig: OperatorConfig;
    SessionBootstrap: SessionBootstrap;
    DataAuthority: DataAuthority;
    JsonValue: JsonValue;
    OperatorItem: OperatorItem;
    OperatorSnapshot: OperatorSnapshot;
    OperatorEventPage: OperatorEventPage;
    ApprovalDecisionRequest: ApprovalDecisionRequest;
    ApprovalDecisionResponse: ApprovalDecisionResponse;
    ErrorEnvelope: ErrorEnvelope;
    PeerTrustRequest: PeerTrustRequest;
    PeerTrustResponse: PeerTrustResponse;
  };
}
