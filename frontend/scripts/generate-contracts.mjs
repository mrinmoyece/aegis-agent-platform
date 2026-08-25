import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = resolve(root, '..', 'contracts', 'operator-api.openapi.json');
const outputPath = resolve(root, 'src', 'api', 'generated.ts');
const source = await readFile(contractPath, 'utf8');
const document = JSON.parse(source);
const schemas = document.components?.schemas;

if (document.openapi !== '3.1.0' || typeof schemas !== 'object') {
  throw new Error('Operator contract must be an OpenAPI 3.1 document');
}

const authority = union(schemas.DataAuthority, 'DataAuthority');
const severity = union(
  schemas.OperatorItem?.properties?.severity,
  'OperatorItem.severity',
);
const authMode = union(
  schemas.OperatorConfig?.properties?.auth_mode,
  'OperatorConfig.auth_mode',
);
const decision = union(
  schemas.ApprovalDecisionRequest?.properties?.decision,
  'ApprovalDecisionRequest.decision',
);
const peerTrustDecision = union(
  schemas.PeerTrustRequest?.properties?.decision,
  'PeerTrustRequest.decision',
);
const peerTrustStatus = union(
  schemas.PeerTrustResponse?.properties?.status,
  'PeerTrustResponse.status',
);
const digest = createHash('sha256').update(source).digest('hex');

// Verify that the hard-coded interface shapes still match the OpenAPI schema.
// If a property is added or removed, the generator fails loudly rather than
// silently producing stale TypeScript shapes.
assertSchemaFields('OperatorConfig', schemas.OperatorConfig, [
  'schema_version',
  'production_ready',
  'auth_mode',
  'demo',
  'server_time',
  'oidc_boundary',
]);
assertSchemaFields('SessionBootstrap', schemas.SessionBootstrap, [
  'schema_version',
  'actor_id',
  'tenant_id',
  'roles',
  'permissions',
  'csrf_token',
  'server_time',
  'production_ready',
  'demo',
  'stale',
]);
assertSchemaFields('OperatorItem', schemas.OperatorItem, [
  'id',
  'kind',
  'title',
  'summary',
  'status',
  'authority',
  'occurred_at',
  'severity',
  'stale',
  'citation',
  'metadata',
]);
assertSchemaFields('OperatorSnapshot', schemas.OperatorSnapshot, [
  'schema_version',
  'tenant_id',
  'generated_at',
  'source_cursor',
  'stale',
  'demo',
  'sections',
]);
assertSchemaFields('OperatorEventPage', schemas.OperatorEventPage, [
  'events',
  'next_cursor',
  'server_time',
  'stale',
]);
assertSchemaFields('ApprovalDecisionRequest', schemas.ApprovalDecisionRequest, [
  'approval_id',
  'plan_digest',
  'policy_digest',
  'decision',
  'rationale_code',
  'comment',
]);
assertSchemaFields('ApprovalDecisionResponse', schemas.ApprovalDecisionResponse, [
  'approval_id',
  'status',
  'verification',
  'version',
  'duplicate',
  'server_time',
]);

const generated = `/* eslint-disable */
/**
 * Generated from contracts/operator-api.openapi.json.
 * Do not edit by hand. Source SHA-256: ${digest}
 */

export const OPERATOR_API_CONTRACT_SHA256 = '${digest}' as const; // gitleaks:allow

export type DataAuthority = ${authority};
export type OperatorSeverity = ${severity};
export type OperatorAuthMode = ${authMode};
export type ApprovalDecision = ${decision};
export type PeerTrustDecision = ${peerTrustDecision};
export type PeerTrustStatus = ${peerTrustStatus};
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
`;

if (process.argv.includes('--check')) {
  const current = await readFile(outputPath, 'utf8');
  if (current !== generated) {
    throw new Error(
      'Generated operator API contracts differ; run pnpm contract:generate',
    );
  }
} else {
  await writeFile(outputPath, generated, 'utf8');
}

function union(schema, name) {
  if (
    !Array.isArray(schema?.enum) ||
    schema.enum.some((value) => typeof value !== 'string')
  ) {
    throw new Error(`${name} must define a string enum`);
  }
  return schema.enum.map((value) => JSON.stringify(value)).join(' | ');
}

function assertSchemaFields(schemaName, schema, expectedFields) {
  const properties = Object.keys(schema?.properties ?? {});
  const missing = expectedFields.filter((f) => !properties.includes(f));
  const extra = properties.filter(
    (f) => !expectedFields.includes(f) && (schema.required ?? []).includes(f),
  );
  if (missing.length > 0) {
    throw new Error(
      `${schemaName}: OpenAPI schema is missing expected fields: ${missing.join(', ')}. ` +
        `Update the hard-coded interface in generate-contracts.mjs to match.`,
    );
  }
  if (extra.length > 0) {
    throw new Error(
      `${schemaName}: OpenAPI schema has new required fields not in the hard-coded interface: ` +
        `${extra.join(', ')}. Update the interface in generate-contracts.mjs.`,
    );
  }
}
