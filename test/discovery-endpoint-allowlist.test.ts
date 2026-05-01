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

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { validateDiscoveredEndpoint } from '../src/auth/discovery-utils.js';
import { DiscoveryEndpointBlockedError } from '../src/errors.js';

describe('validateDiscoveredEndpoint — cross-origin allowlist (ABXAGNTS-378)', () => {
  let origNodeEnv: string | undefined;

  beforeEach(() => {
    origNodeEnv = process.env.NODE_ENV;
  });

  afterEach(() => {
    if (origNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = origNodeEnv;
  });

  const ISSUER_ORIGIN = 'https://accounts.example.com';

  // ── Same-origin endpoints pass without any allowlist ─────────────

  it('allows same-origin endpoint with no allowlist configured', () => {
    expect(() =>
      validateDiscoveredEndpoint(
        'https://accounts.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
      ),
    ).not.toThrow();
  });

  it('allows same-origin endpoint with an allowlist configured', () => {
    expect(() =>
      validateDiscoveredEndpoint(
        'https://accounts.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['other.example.com'],
      ),
    ).not.toThrow();
  });

  // ── Cross-origin: on allowlist → passes ──────────────────────────

  it('allows cross-origin endpoint when host is on the allowlist', () => {
    expect(() =>
      validateDiscoveredEndpoint(
        'https://oauth2.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['oauth2.example.com'],
      ),
    ).not.toThrow();
  });

  it('allows cross-origin endpoint when one of several allowlisted hosts matches', () => {
    expect(() =>
      validateDiscoveredEndpoint(
        'https://oauth2.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['other.example.com', 'oauth2.example.com'],
      ),
    ).not.toThrow();
  });

  // ── Cross-origin: NOT on allowlist → blocked ─────────────────────

  it('rejects cross-origin endpoint not on the allowlist', () => {
    const err = getBlockedError(() =>
      validateDiscoveredEndpoint(
        'https://evil.attacker.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['oauth2.example.com'],
      ),
    );
    expect(err.configMissing).toBe(false);
    expect(err.code).toBe('DISCOVERY_ENDPOINT_BLOCKED');
    expect(err.message).toContain('evil.attacker.com');
    expect(err.message).toContain('allowedCrossOriginHosts');
  });

  // ── Cross-origin: no allowlist configured → config error ─────────

  it('rejects cross-origin endpoint when no allowlist is configured', () => {
    const err = getBlockedError(() =>
      validateDiscoveredEndpoint(
        'https://oauth2.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
      ),
    );
    expect(err.configMissing).toBe(true);
    expect(err.code).toBe('DISCOVERY_ENDPOINT_BLOCKED');
    expect(err.message).toContain('no allowedCrossOriginHosts configured');
  });

  it('rejects cross-origin endpoint when allowlist is explicitly undefined', () => {
    const err = getBlockedError(() =>
      validateDiscoveredEndpoint(
        'https://oauth2.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        undefined,
      ),
    );
    expect(err.configMissing).toBe(true);
  });

  // ── Localhost exemption in dev/test ──────────────────────────────

  it('allows localhost cross-origin in development mode without an allowlist', () => {
    process.env.NODE_ENV = 'development';
    expect(() =>
      validateDiscoveredEndpoint(
        'http://localhost:3001/token',
        'token_endpoint',
        'http://localhost:3000',
      ),
    ).not.toThrow();
  });

  it('allows 127.0.0.1 cross-origin in test mode without an allowlist', () => {
    process.env.NODE_ENV = 'test';
    expect(() =>
      validateDiscoveredEndpoint(
        'http://127.0.0.1:4000/token',
        'token_endpoint',
        'http://127.0.0.1:3000',
      ),
    ).not.toThrow();
  });

  // ── HTTPS enforcement still works ────────────────────────────────

  it('rejects non-HTTPS non-localhost endpoint regardless of allowlist', () => {
    process.env.NODE_ENV = 'production';
    expect(() =>
      validateDiscoveredEndpoint(
        'http://accounts.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['accounts.example.com'],
      ),
    ).toThrow(/not HTTPS/);
  });

  // ── Error includes provider label ────────────────────────────────

  it('includes the provider label in the error message', () => {
    const err = getBlockedError(() =>
      validateDiscoveredEndpoint(
        'https://evil.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'AbaxxOne',
        ['safe.com'],
      ),
    );
    expect(err.message).toContain('AbaxxOne discovery');
  });

  // ── All three endpoint fields are covered ────────────────────────

  for (const field of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'] as const) {
    it(`blocks cross-origin ${field} when host is not allowlisted`, () => {
      const err = getBlockedError(() =>
        validateDiscoveredEndpoint(
          'https://rogue.host/path',
          field,
          ISSUER_ORIGIN,
          'Test',
          ['safe.host'],
        ),
      );
      expect(err.message).toContain(field);
    });
  }
});

function getBlockedError(fn: () => void): DiscoveryEndpointBlockedError {
  try {
    fn();
    throw new Error('Expected DiscoveryEndpointBlockedError but no error was thrown');
  } catch (err) {
    if (err instanceof DiscoveryEndpointBlockedError) return err;
    throw err;
  }
}
