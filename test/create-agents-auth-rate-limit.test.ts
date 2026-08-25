import { describe, expect, it, vi } from 'vitest';
import express from 'express';
import {
  rateLimitOperationForRequest,
  createAuthRateLimitMiddleware,
  normalizeIp,
  rateLimitPrincipal,
  readAuthRateLimitConfig,
  requestClientIp,
} from '../packages/create-agents/template/src/auth-rate-limit.js';

function request(remoteAddress: string, forwardedFor?: string) {
  return {
    socket: { remoteAddress },
    connection: { remoteAddress },
    get: (name: string) => (name.toLowerCase() === 'x-forwarded-for' ? forwardedFor : undefined),
  } as never;
}

function response() {
  const headers = new Map<string, string>();
  return {
    headers,
    setHeader: vi.fn((name: string, value: string) => headers.set(name, value)),
    status: vi.fn(function status(this: unknown) {
      return this;
    }),
    send: vi.fn(),
  } as never;
}

describe('generated quickstart authentication rate limiting', () => {
  it('loads safe defaults and validates configuration', () => {
    const config = readAuthRateLimitConfig({});
    expect(config.limit).toBe(10);
    expect(config.windowMs).toBe(60_000);
    expect(config.trustedProxyIps.size).toBe(0);

    expect(() => readAuthRateLimitConfig({ AUTH_RATE_LIMIT: '0' })).toThrow(
      'AUTH_RATE_LIMIT must be a positive integer',
    );
  });

  it('normalizes IPv4-mapped IPv6 and groups IPv6 privacy addresses by /64', () => {
    expect(normalizeIp('::ffff:192.0.2.10')).toBe('192.0.2.10');
    expect(normalizeIp('::')).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
    expect(rateLimitPrincipal('2001:db8:1:2:aaaa:bbbb:cccc:1')).toBe(
      rateLimitPrincipal('2001:DB8:1:2:1111:2222:3333:4'),
    );
    expect(rateLimitPrincipal('2001:db8:1:3:aaaa:bbbb:cccc:1')).not.toBe(
      rateLimitPrincipal('2001:db8:1:2:aaaa:bbbb:cccc:1'),
    );
  });

  it('ignores forwarded headers unless the direct peer is trusted', () => {
    const trusted = new Set(['192.0.2.10']);
    expect(requestClientIp(request('198.51.100.8', '203.0.113.5'), trusted)).toBe('198.51.100.8');
    expect(requestClientIp(request('192.0.2.10', '203.0.113.5'), trusted)).toBe('203.0.113.5');
    expect(requestClientIp(request('192.0.2.10', 'not-an-ip'), trusted)).toBe('192.0.2.10');
  });

  it('classifies protected routes independently and normalizes trailing slashes', () => {
    expect(rateLimitOperationForRequest({ method: 'POST', path: '/auth/mock/' } as never)).toBe(
      'mock',
    );
    expect(rateLimitOperationForRequest({ method: 'GET', path: '/auth/google/' } as never)).toBe(
      'oauth-initiation',
    );
    expect(rateLimitOperationForRequest({ method: 'GET', path: '/auth/callback/' } as never)).toBe(
      'oauth-callback',
    );
    expect(rateLimitOperationForRequest({ method: 'POST', path: '/auth/logout/' } as never)).toBe(
      'logout',
    );
    expect(
      rateLimitOperationForRequest({ method: 'POST', path: '/auth/callback' } as never),
    ).toBeUndefined();
  });

  it('returns retry metadata and blocks only the exhausted operation bucket', () => {
    const config = readAuthRateLimitConfig({ AUTH_RATE_LIMIT: '1', AUTH_RATE_WINDOW_MS: '60000' });
    const middleware = createAuthRateLimitMiddleware(config, 'oauth-callback');
    const firstResponse = response();
    const firstNext = vi.fn();
    middleware(request('198.51.100.8'), firstResponse, firstNext);
    expect(firstNext).toHaveBeenCalledOnce();

    const blockedResponse = response();
    const blockedNext = vi.fn();
    middleware(request('198.51.100.8'), blockedResponse, blockedNext);
    expect(blockedNext).not.toHaveBeenCalled();
    expect(blockedResponse.status).toHaveBeenCalledWith(429);
    expect(blockedResponse.headers.get('Retry-After')).toBeDefined();
    expect(blockedResponse.headers.get('RateLimit-Remaining')).toBe('0');
  });

  it('resets an exhausted window and keeps other route buckets independent', () => {
    vi.useFakeTimers();
    try {
      const config = readAuthRateLimitConfig({ AUTH_RATE_LIMIT: '1', AUTH_RATE_WINDOW_MS: '1000' });
      const callback = createAuthRateLimitMiddleware(config, 'oauth-callback');
      const mock = createAuthRateLimitMiddleware(config, 'mock');
      const next = vi.fn();

      callback(request('198.51.100.8'), response(), next);
      callback(request('198.51.100.8'), response(), vi.fn());
      mock(request('198.51.100.8'), response(), next);
      expect(next).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(1001);
      callback(request('198.51.100.8'), response(), next);
      expect(next).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('runs before body parsing and keeps CSRF rejection separate from quota rejection', async () => {
    const app = express();
    const config = readAuthRateLimitConfig({ AUTH_RATE_LIMIT: '2', AUTH_RATE_WINDOW_MS: '60000' });
    const middleware = createAuthRateLimitMiddleware(config, 'mock');
    app.post('/auth/mock', middleware, express.urlencoded({ extended: false }), (req, res) => {
      if (req.body._csrf !== 'valid') {
        res.status(403).send('CSRF validation failed');
        return;
      }
      res.send('ok');
    });
    const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
      const listener = app.listen(0, () => resolve(listener));
    });
    try {
      const address = server.address();
      if (!address || typeof address === 'string')
        throw new Error('test server has no TCP address');
      const url = `http://127.0.0.1:${address.port}/auth/mock`;
      const requestOptions = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      };
      const badCsrf = await fetch(url, { ...requestOptions, body: '_csrf=invalid' });
      const allowed = await fetch(url, { ...requestOptions, body: '_csrf=valid' });
      const rateLimited = await fetch(url, { ...requestOptions, body: '_csrf=valid' });
      expect(badCsrf.status).toBe(403);
      expect(allowed.status).toBe(200);
      expect(rateLimited.status).toBe(429);
      expect(rateLimited.headers.get('retry-after')).toBeDefined();
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});
