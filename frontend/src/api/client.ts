import type { z } from 'zod';

import {
  approvalDecisionRequestSchema,
  approvalDecisionResponseSchema,
  errorEnvelopeSchema,
  operatorConfigSchema,
  operatorEventPageSchema,
  operatorSnapshotSchema,
  sessionBootstrapSchema,
  type ApprovalDecisionRequest,
  type ApprovalDecisionResponse,
  type OperatorConfig,
  type OperatorEventPage,
  type OperatorSnapshot,
  type SessionBootstrap,
} from './schema';

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);
const TENANT_ID = /^[A-Za-z0-9._-]{1,128}$/;
const RESOURCE_ID = /^[A-Za-z0-9._-]{1,128}$/;

type ApiErrorKind =
  | 'authentication'
  | 'authorization'
  | 'not_found'
  | 'conflict'
  | 'invalid_response'
  | 'network'
  | 'server'
  | 'validation';

export class ApiError extends Error {
  public constructor(
    public readonly kind: ApiErrorKind,
    public readonly code: string,
    public readonly status: number | null,
    public readonly requestId: string | null,
    public readonly retryable: boolean,
  ) {
    super(code);
    this.name = 'ApiError';
  }
}

export interface RequestOptions {
  readonly signal?: AbortSignal | undefined;
  readonly csrfToken?: string | undefined;
  readonly method?: 'GET' | 'POST' | undefined;
  readonly body?: unknown;
  readonly idempotencyKey?: string | undefined;
  readonly ifMatch?: string | undefined;
  readonly retries?: number | undefined;
}

export interface ApiResult<T> {
  readonly data: T;
  readonly requestId: string | null;
  readonly etag: string | null;
  readonly receivedAt: number;
}

export class OperatorApiClient {
  public constructor(
    private readonly baseUrl = '/operator/api',
    private readonly request: typeof fetch = fetch,
  ) {}

  public config(signal?: AbortSignal): Promise<ApiResult<OperatorConfig>> {
    return this.call('/config', operatorConfigSchema, { signal });
  }

  public createDemoSession(signal?: AbortSignal): Promise<ApiResult<SessionBootstrap>> {
    return this.call('/demo/session', sessionBootstrapSchema, {
      method: 'POST',
      body: {},
      signal,
    });
  }

  public session(signal?: AbortSignal): Promise<ApiResult<SessionBootstrap>> {
    return this.call('/session', sessionBootstrapSchema, { signal });
  }

  public snapshot(
    tenantId: string,
    signal?: AbortSignal,
  ): Promise<ApiResult<OperatorSnapshot>> {
    return this.call(
      `/tenants/${encodeSegment(tenantId, TENANT_ID)}/snapshot`,
      operatorSnapshotSchema,
      { signal },
    );
  }

  public events(
    tenantId: string,
    cursor: string | null,
    signal?: AbortSignal,
  ): Promise<ApiResult<OperatorEventPage>> {
    const path = `/tenants/${encodeSegment(tenantId, TENANT_ID)}/events`;
    const parameters = new URLSearchParams();
    if (cursor !== null) {
      if (!/^[0-9]{1,10}$/.test(cursor)) {
        throw new ApiError('validation', 'invalid_cursor', null, null, false);
      }
      parameters.set('cursor', cursor);
    }
    const query = parameters.size === 0 ? '' : `?${parameters.toString()}`;
    return this.call(`${path}${query}`, operatorEventPageSchema, {
      signal,
    });
  }

  public decideApproval(
    tenantId: string,
    request: ApprovalDecisionRequest,
    headers: {
      readonly csrfToken: string;
      readonly idempotencyKey: string;
      readonly ifMatch: string;
    },
    signal?: AbortSignal,
  ): Promise<ApiResult<ApprovalDecisionResponse>> {
    const approvalId = encodeSegment(request.approval_id, RESOURCE_ID);
    return this.call(
      `/tenants/${encodeSegment(tenantId, TENANT_ID)}/approvals/${approvalId}/decisions/record`,
      approvalDecisionResponseSchema,
      {
        method: 'POST',
        body: approvalDecisionRequestSchema.parse(request),
        csrfToken: headers.csrfToken,
        idempotencyKey: headers.idempotencyKey,
        ifMatch: headers.ifMatch,
        signal,
        retries: 0,
      },
    );
  }

  private async call<T>(
    path: string,
    schema: z.ZodType<T>,
    options: RequestOptions,
  ): Promise<ApiResult<T>> {
    const method = options.method ?? 'GET';
    const retries = method === 'GET' ? (options.retries ?? 2) : 0;
    for (let attempt = 0; ; attempt += 1) {
      const requestId = crypto.randomUUID();
      try {
        const init: RequestInit = {
          method,
          credentials: 'include',
          redirect: 'error',
          cache: 'no-store',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            'X-Request-ID': requestId,
            ...(options.csrfToken ? { 'X-CSRF-Token': options.csrfToken } : {}),
            ...(options.idempotencyKey
              ? { 'Idempotency-Key': options.idempotencyKey }
              : {}),
            ...(options.ifMatch ? { 'If-Match': `"${options.ifMatch}"` } : {}),
          },
          ...(options.signal === undefined ? {} : { signal: options.signal }),
          ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
        };
        const response = await this.request(`${this.baseUrl}${path}`, init);
        if (!response.ok) {
          if (attempt < retries && RETRYABLE_STATUS.has(response.status)) {
            await delay(retryDelay(response, attempt), options.signal);
            continue;
          }
          throw await classifiedError(response);
        }
        const contentLength = Number(response.headers.get('content-length') ?? '0');
        if (contentLength > MAX_RESPONSE_BYTES) {
          throw new ApiError(
            'invalid_response',
            'response_too_large',
            response.status,
            response.headers.get('x-request-id'),
            false,
          );
        }
        // Consume incrementally so an absent or dishonest Content-Length
        // cannot bypass the memory bound by buffering an unbounded body.
        let text = '';
        const reader = response.body?.getReader();
        if (reader) {
          const decoder = new TextDecoder();
          let bytesRead = 0;
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (done) {
                text += decoder.decode();
                break;
              }
              bytesRead += value.byteLength;
              if (bytesRead > MAX_RESPONSE_BYTES) {
                await reader.cancel();
                throw new ApiError(
                  'invalid_response',
                  'response_too_large',
                  response.status,
                  response.headers.get('x-request-id'),
                  false,
                );
              }
              text += decoder.decode(value, { stream: true });
            }
          } catch (err) {
            await reader.cancel();
            throw err;
          }
        } else {
          text = await response.text();
        }
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch {
          throw new ApiError(
            'invalid_response',
            'response_not_json',
            response.status,
            response.headers.get('x-request-id'),
            false,
          );
        }
        const parsed = schema.safeParse(json);
        if (!parsed.success) {
          throw new ApiError(
            'invalid_response',
            'response_schema_rejected',
            response.status,
            response.headers.get('x-request-id'),
            false,
          );
        }
        return {
          data: parsed.data,
          requestId: response.headers.get('x-request-id'),
          etag: unquoteEtag(response.headers.get('etag')),
          receivedAt: Date.now(),
        };
      } catch (error) {
        if (error instanceof ApiError) {
          throw error;
        }
        if (options.signal?.aborted) {
          throw error;
        }
        if (attempt < retries) {
          await delay(250 * 2 ** attempt, options.signal);
          continue;
        }
        throw new ApiError('network', 'network_unavailable', null, requestId, true);
      }
    }
  }
}

async function classifiedError(response: Response): Promise<ApiError> {
  let code = `http_${String(response.status)}`;
  let retryable = RETRYABLE_STATUS.has(response.status);
  try {
    const text = await response.text();
    if (text.length <= 16_384) {
      const parsed = errorEnvelopeSchema.safeParse(JSON.parse(text) as unknown);
      if (parsed.success) {
        code = parsed.data.error.code;
        retryable = parsed.data.error.retryable;
      }
    }
  } catch {
    // Error bodies are optional and never copied into diagnostics.
  }
  const kind: ApiErrorKind =
    response.status === 401
      ? 'authentication'
      : response.status === 403
        ? 'authorization'
        : response.status === 404
          ? 'not_found'
          : response.status === 409
            ? 'conflict'
            : response.status >= 500
              ? 'server'
              : 'validation';
  return new ApiError(
    kind,
    code,
    response.status,
    response.headers.get('x-request-id'),
    retryable,
  );
}

function encodeSegment(value: string, pattern: RegExp): string {
  if (!pattern.test(value)) {
    throw new ApiError('validation', 'invalid_identifier', null, null, false);
  }
  return encodeURIComponent(value);
}

function unquoteEtag(value: string | null): string | null {
  if (value === null || !/^"[A-Za-z0-9._-]{1,128}"$/.test(value)) {
    return null;
  }
  return value.slice(1, -1);
}

function retryDelay(response: Response, attempt: number): number {
  const retryAfter = response.headers.get('retry-after');
  if (retryAfter !== null && /^[0-9]{1,3}$/.test(retryAfter)) {
    return Math.min(Number(retryAfter) * 1_000, 5_000);
  }
  return Math.min(250 * 2 ** attempt, 2_000);
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(resolve, milliseconds);
    signal?.addEventListener(
      'abort',
      () => {
        window.clearTimeout(timer);
        reject(
          signal.reason instanceof Error
            ? signal.reason
            : new DOMException('Request aborted', 'AbortError'),
        );
      },
      { once: true },
    );
  });
}
