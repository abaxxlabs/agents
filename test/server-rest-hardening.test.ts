// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { describe, it, expect } from 'vitest';
import { DEFAULT_CORS_ORIGINS, parseCorsOrigins } from '../packages/server/src/config.js';
import { verifyWithIssuerAliases } from '../packages/server/src/oidc.js';
import { createPerSessionRateLimiter } from '../packages/server/src/rate-limit.js';
import { LiveSessionCache } from '../packages/server/src/session.js';

// ─── Session Expiry Logic ──────────────────────────────────────────

describe('Session Expiry Logic', () => {
  const SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

  function createSessionStore(ttlMs = SESSION_TTL_MS) {
    const cache = new LiveSessionCache<{ humanDid: string }>(ttlMs);
    return {
      create(token: string, humanDid: string, createdAt = Date.now()) {
        cache.set(token, { humanDid }, { portable: false, createdAt });
      },
      get(token: string) {
        return cache.get(token);
      },
      sweep() {
        cache.sweep();
      },
      size: () => cache.size(),
    };
  }

  it('returns session for a valid, non-expired token', () => {
    const store = createSessionStore();
    store.create('token-1', 'did:key:z6Mk...');
    expect(store.get('token-1')).toEqual({ humanDid: 'did:key:z6Mk...' });
  });

  it('returns null for a non-existent token', () => {
    const store = createSessionStore();
    expect(store.get('nonexistent')).toBeNull();
  });

  it('returns null and deletes an expired session', () => {
    const store = createSessionStore(1000); // 1 second TTL
    const pastTime = Date.now() - 2000; // 2 seconds ago
    store.create('expired-token', 'did:key:z6Mk...', pastTime);

    expect(store.get('expired-token')).toBeNull();
    expect(store.size()).toBe(0); // Should have been cleaned up
  });

  it('sweep evicts all expired sessions', () => {
    const store = createSessionStore(1000);
    const pastTime = Date.now() - 2000;
    store.create('expired-1', 'did:key:z1', pastTime);
    store.create('expired-2', 'did:key:z2', pastTime);
    store.create('valid-1', 'did:key:z3'); // current time

    expect(store.size()).toBe(3);
    store.sweep();
    expect(store.size()).toBe(1);
    expect(store.get('valid-1')).toEqual({ humanDid: 'did:key:z3' });
  });

  it('respects configurable TTL', () => {
    const shortStore = createSessionStore(100); // 100ms
    shortStore.create('short-token', 'did:key:z1', Date.now() - 200);
    expect(shortStore.get('short-token')).toBeNull();

    const longStore = createSessionStore(60000); // 60s
    longStore.create('long-token', 'did:key:z1', Date.now() - 200);
    expect(longStore.get('long-token')).not.toBeNull();
  });
});

// ─── Per-Session Rate Limiting ────────────────────────────────────

describe('Per-Session Rate Limiting', () => {
  it('allows requests within the rate limit', () => {
    const limiter = createPerSessionRateLimiter();
    for (let i = 0; i < 100; i++) {
      const result = limiter.check('session-1', 'sign', 100, 60000);
      expect(result.allowed).toBe(true);
    }
  });

  it('rejects the 101st request in a 100/min window', () => {
    const limiter = createPerSessionRateLimiter();
    for (let i = 0; i < 100; i++) {
      limiter.check('session-1', 'sign', 100, 60000);
    }
    const result = limiter.check('session-1', 'sign', 100, 60000);
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeDefined();
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('isolates rate limits per session', () => {
    const limiter = createPerSessionRateLimiter();
    // Exhaust session-1's limit
    for (let i = 0; i < 100; i++) {
      limiter.check('session-1', 'sign', 100, 60000);
    }
    expect(limiter.check('session-1', 'sign', 100, 60000).allowed).toBe(false);
    // session-2 should still be allowed
    expect(limiter.check('session-2', 'sign', 100, 60000).allowed).toBe(true);
  });

  it('isolates rate limits per endpoint', () => {
    const limiter = createPerSessionRateLimiter();
    // Exhaust sign limit
    for (let i = 0; i < 100; i++) {
      limiter.check('session-1', 'sign', 100, 60000);
    }
    expect(limiter.check('session-1', 'sign', 100, 60000).allowed).toBe(false);
    // challenge endpoint should still be allowed
    expect(limiter.check('session-1', 'challenge', 30, 60000).allowed).toBe(true);
  });

  it('resets the bucket when called with a different (fresh) window', () => {
    const limiter = createPerSessionRateLimiter();
    // Exhaust a limit of 2
    limiter.check('session-1', 'sign', 2, 60000);
    limiter.check('session-1', 'sign', 2, 60000);
    const blocked = limiter.check('session-1', 'sign', 2, 60000);
    expect(blocked.allowed).toBe(false);

    // Simulate a new session (different token) — should start fresh
    const fresh = limiter.check('session-2', 'sign', 2, 60000);
    expect(fresh.allowed).toBe(true);
  });

  it('sweep clears stale buckets older than maxAge', () => {
    const limiter = createPerSessionRateLimiter();
    limiter.check('session-1', 'sign', 100, 60000);
    limiter.check('session-2', 'challenge', 30, 60000);
    expect(limiter.size()).toBe(2);

    // Sweep with a generous maxAge should retain recent buckets
    limiter.sweep(60000);
    expect(limiter.size()).toBe(2);

    // Sweep with maxAge=-1 means (now - start > -1) is always true, clears all
    limiter.sweep(-1);
    expect(limiter.size()).toBe(0);
  });
});

// ─── CORS Origin Restriction ──────────────────────────────────────

describe('CORS Origin Restriction Logic', () => {
  it('uses default origins when CORS_ORIGINS is not set', () => {
    const origins = parseCorsOrigins(undefined);
    expect(origins).toEqual(DEFAULT_CORS_ORIGINS);
    expect(origins).toHaveLength(6);
  });

  it('parses CORS_ORIGINS env var into an array', () => {
    const origins = parseCorsOrigins('https://app.example.com,https://admin.example.com');
    expect(origins).toEqual(['https://app.example.com', 'https://admin.example.com']);
  });

  it('trims whitespace from CORS_ORIGINS entries', () => {
    const origins = parseCorsOrigins('  https://app.example.com , https://admin.example.com  ');
    expect(origins).toEqual(['https://app.example.com', 'https://admin.example.com']);
  });

  it('default origins do not include wildcard *', () => {
    const origins = parseCorsOrigins(undefined);
    expect(origins).not.toContain('*');
  });

  it('default origins cover localhost and 127.0.0.1 on known demo ports', () => {
    const origins = parseCorsOrigins(undefined);
    expect(origins).toContain('http://localhost:3001');
    expect(origins).toContain('http://localhost:3100');
    expect(origins).toContain('http://localhost:3200');
    expect(origins).toContain('http://127.0.0.1:3001');
    expect(origins).toContain('http://127.0.0.1:3100');
    expect(origins).toContain('http://127.0.0.1:3200');
  });
});

// ─── OIDC Issuer Alias Matching ───────────────────────────────────

describe('OIDC Issuer Alias Fallback', () => {
  interface VerifyResult {
    payload: Record<string, unknown>;
  }

  it('succeeds on primary issuer match', async () => {
    const result = await verifyWithIssuerAliases<VerifyResult>(
      'https://keycloak.example.com',
      [],
      async (issuer) => {
        if (issuer !== 'https://keycloak.example.com') {
          throw new Error('issuer mismatch');
        }
        return { payload: { iss: issuer } };
      },
    );
    expect(result.payload.iss).toBe('https://keycloak.example.com');
  });

  it('falls back to alias when primary fails with issuer mismatch', async () => {
    const result = await verifyWithIssuerAliases<VerifyResult>(
      'https://localhost:8080',
      ['https://host.docker.internal:8080'],
      async (issuer) => {
        if (issuer !== 'https://host.docker.internal:8080') {
          throw new Error('issuer mismatch');
        }
        return { payload: { iss: issuer } };
      },
    );
    expect(result.payload.iss).toBe('https://host.docker.internal:8080');
  });

  it('throws the last error when no issuer matches', async () => {
    await expect(
      verifyWithIssuerAliases<VerifyResult>(
        'https://primary.example.com',
        ['https://alias.example.com'],
        async () => {
          throw new Error('issuer mismatch');
        },
      ),
    ).rejects.toThrow('issuer mismatch');
  });

  it('rethrows non-issuer-mismatch errors immediately', async () => {
    await expect(
      verifyWithIssuerAliases<VerifyResult>(
        'https://primary.example.com',
        ['https://alias.example.com'],
        async () => {
          throw new Error('invalid signature');
        },
      ),
    ).rejects.toThrow('invalid signature');
  });
});
