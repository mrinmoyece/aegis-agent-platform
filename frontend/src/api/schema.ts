import { z } from 'zod';

import type { components } from './generated';

const boundedIdentifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._-]+$/);
const isoDateTime = z.iso.datetime({ offset: true });
const digest = z.string().regex(/^[0-9a-f]{64}$/);

export const dataAuthoritySchema = z.enum([
  'event_fact',
  'derived_state',
  'model_claim',
  'operator_decision',
  'unknown',
]);

export const operatorItemSchema = z
  .object({
    id: boundedIdentifier,
    kind: boundedIdentifier,
    title: z.string().min(1).max(2_048),
    summary: z.string().min(1).max(2_048),
    status: boundedIdentifier,
    authority: dataAuthoritySchema,
    occurred_at: isoDateTime,
    severity: z.enum(['info', 'warning', 'critical']),
    stale: z.boolean(),
    citation: z.string().max(2_048).nullable(),
    metadata: z
      .record(
        z.string().max(128),
        z.union([z.string().max(2_048), z.number(), z.boolean(), z.null()]),
      )
      .refine((value) => Object.keys(value).length <= 32, 'metadata is too large'),
  })
  .strict();

export const operatorSnapshotSchema = z
  .object({
    schema_version: z.literal(1),
    tenant_id: boundedIdentifier,
    generated_at: isoDateTime,
    source_cursor: z.string().min(1).max(2_048),
    stale: z.boolean(),
    demo: z.boolean(),
    sections: z
      .record(boundedIdentifier, z.array(operatorItemSchema).max(100))
      .refine(
        (value) => Object.keys(value).length >= 1 && Object.keys(value).length <= 16,
        'sections are outside the bound',
      ),
  })
  .strict();

export const sessionBootstrapSchema = z
  .object({
    schema_version: z.literal(1),
    actor_id: boundedIdentifier,
    tenant_id: boundedIdentifier,
    roles: z.array(boundedIdentifier).max(16),
    permissions: z.array(z.string().min(1).max(128)).max(64),
    csrf_token: z.string().min(32).max(256).nullable(),
    server_time: isoDateTime,
    production_ready: z.boolean(),
    demo: z.boolean(),
    stale: z.boolean(),
  })
  .strict();

export const operatorConfigSchema = z
  .object({
    schema_version: z.literal(1),
    production_ready: z.boolean(),
    auth_mode: z.enum(['oidc_bff', 'deterministic_demo']),
    demo: z.boolean(),
    server_time: isoDateTime,
    oidc_boundary: z
      .object({
        authorization_code: z.literal(true),
        pkce: z.literal(true),
        state: z.literal(true),
        nonce: z.literal(true),
        live_exchange_configured: z.boolean(),
      })
      .strict(),
  })
  .strict();

export const operatorEventPageSchema = z
  .object({
    events: z.array(operatorItemSchema).max(100),
    next_cursor: z.string().max(2_048).nullable(),
    server_time: isoDateTime,
    stale: z.boolean(),
  })
  .strict();

export const approvalDecisionRequestSchema = z
  .object({
    approval_id: boundedIdentifier,
    plan_digest: digest,
    policy_digest: digest,
    decision: z.enum(['grant', 'deny']),
    rationale_code: boundedIdentifier,
    comment: z.string().max(1_000),
  })
  .strict();

export const approvalDecisionResponseSchema = z
  .object({
    approval_id: boundedIdentifier,
    status: z.literal('decision_recorded'),
    verification: z.literal('pending'),
    version: boundedIdentifier,
    duplicate: z.boolean(),
    server_time: isoDateTime,
  })
  .strict();

export const errorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: boundedIdentifier,
        request_id: z.uuid(),
        retryable: z.boolean(),
      })
      .strict(),
  })
  .strict();

export type OperatorConfig = z.infer<typeof operatorConfigSchema>;
export type SessionBootstrap = z.infer<typeof sessionBootstrapSchema>;
export type OperatorItem = z.infer<typeof operatorItemSchema>;
export type OperatorSnapshot = z.infer<typeof operatorSnapshotSchema>;
export type OperatorEventPage = z.infer<typeof operatorEventPageSchema>;
export type ApprovalDecisionRequest = z.infer<typeof approvalDecisionRequestSchema>;
export type ApprovalDecisionResponse = z.infer<typeof approvalDecisionResponseSchema>;

type OpenApiSnapshot = components['schemas']['OperatorSnapshot'];
type OpenApiSession = components['schemas']['SessionBootstrap'];
const contractCompatibility: [
  OperatorSnapshot extends OpenApiSnapshot ? true : never,
  OperatorSnapshot extends OpenApiSnapshot ? true : never,
  SessionBootstrap extends OpenApiSession ? true : never,
] = [true, true, true];
void contractCompatibility;
