import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { demoSession, demoSnapshot } from '../demo/data';
import { ApiError, OperatorApiClient } from './client';

const base = 'http://localhost/operator/api';
const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('operator API client', () => {
  it('validates bounded responses and returns request correlation', async () => {
    server.use(
      http.get(`${base}/tenants/tenant-alpha/snapshot`, () =>
        HttpResponse.json(demoSnapshot, {
          headers: {
            'x-request-id': '58ff2086-7b7d-4df9-8ddb-e2ed225548bb',
            etag: '"46"',
          },
        }),
      ),
    );
    const result = await new OperatorApiClient(base).snapshot('tenant-alpha');
    expect(result.data.tenant_id).toBe('tenant-alpha');
    expect(result.requestId).toBe('58ff2086-7b7d-4df9-8ddb-e2ed225548bb');
    expect(result.etag).toBe('46');
  });

  it('rejects untrusted responses despite successful HTTP status', async () => {
    server.use(
      http.get(`${base}/session`, () =>
        HttpResponse.json({ ...demoSession, bearer_token: 'do-not-accept' }),
      ),
    );
    await expect(new OperatorApiClient(base).session()).rejects.toMatchObject({
      kind: 'invalid_response',
      code: 'response_schema_rejected',
    });
  });

  it('classifies anti-enumeration and authorization errors', async () => {
    server.use(
      http.get(`${base}/tenants/tenant-alpha/snapshot`, () =>
        HttpResponse.json(
          {
            error: {
              code: 'not_found',
              request_id: 'b6ad516f-aecc-4272-9f3b-8c7855f2b109',
              retryable: false,
            },
          },
          { status: 404 },
        ),
      ),
    );
    try {
      await new OperatorApiClient(base).snapshot('tenant-alpha');
      throw new Error('request unexpectedly succeeded');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({
        kind: 'not_found',
        status: 404,
        retryable: false,
      });
    }
  });

  it('retries only safe reads and preserves cursor encoding', async () => {
    let attempts = 0;
    server.use(
      http.get(`${base}/tenants/tenant-alpha/events`, ({ request }) => {
        attempts += 1;
        if (attempts === 1) {
          return HttpResponse.json(
            {
              error: {
                code: 'temporarily_unavailable',
                request_id: '1dad2d11-2fdf-41ca-a56e-273e44b2aa5d',
                retryable: true,
              },
            },
            { status: 503, headers: { 'retry-after': '0' } },
          );
        }
        expect(new URL(request.url).searchParams.get('cursor')).toBe('42');
        return HttpResponse.json({
          events: [],
          next_cursor: null,
          server_time: demoSession.server_time,
          stale: false,
        });
      }),
    );
    const result = await new OperatorApiClient(base).events('tenant-alpha', '42');
    expect(result.data.events).toEqual([]);
    expect(attempts).toBe(2);
  });

  it('cancels in-flight work through AbortSignal', async () => {
    const controller = new AbortController();
    controller.abort(new DOMException('cancelled', 'AbortError'));
    await expect(
      new OperatorApiClient(base).session(controller.signal),
    ).rejects.toHaveProperty('name', 'AbortError');
  });
});
