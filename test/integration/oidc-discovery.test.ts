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

/**
 * OIDC Integration Test — Abaxx One Discovery
 *
 * Tests real OIDC discovery and token endpoint against a local Abaxx One instance.
 * Requires Abaxx One running on localhost:3001.
 *
 * Skipped by default. When AGENTS_RUN_ABAXX_ONE_OIDC_TESTS=true is set, the
 * local Abaxx One service is required and unavailable service state fails fast.
 */

import { describe, it, expect } from 'vitest';

interface OidcConfig {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  code_challenge_methods_supported: string[];
}

interface JwksResponse {
  keys: unknown[];
}
import {
  abaxxOneOidcSkipReason,
  shouldRunAbaxxOneOidcTests,
} from '../support/integration-gates.js';

const ABAXX_ONE_URL = 'http://localhost:3001';

let _available: boolean | null = null;
async function checkAvailable(): Promise<boolean> {
  if (_available !== null) return _available;
  try {
    const res = await fetch(`${ABAXX_ONE_URL}/.well-known/openid_configuration`, {
      signal: AbortSignal.timeout(2000),
    });
    _available = res.ok;
  } catch {
    _available = false;
  }
  return _available;
}

async function requireAvailable(): Promise<void> {
  if (await checkAvailable()) return;
  throw new Error(
    `Abaxx One OIDC integration tests require ${ABAXX_ONE_URL}. ${abaxxOneOidcSkipReason}`,
  );
}

const describeAbaxxOneOidc: typeof describe = shouldRunAbaxxOneOidcTests ? describe : describe.skip;

if (!shouldRunAbaxxOneOidcTests) {
  describe('Abaxx One OIDC integration gate', () => {
    it.skip(abaxxOneOidcSkipReason, () => {});
  });
}

describeAbaxxOneOidc('Abaxx One OIDC Discovery', () => {
  it('returns valid OIDC configuration', async () => {
    await requireAvailable();

    const res = await fetch(`${ABAXX_ONE_URL}/.well-known/openid_configuration`);
    expect(res.ok).toBe(true);

    const config = (await res.json()) as OidcConfig;
    expect(config.issuer).toBeDefined();
    expect(config.authorization_endpoint).toContain('/auth/authorize');
    expect(config.token_endpoint).toContain('/auth/token');
    expect(config.userinfo_endpoint).toContain('/auth/userinfo');
    expect(config.jwks_uri).toContain('/jwks');
    expect(config.code_challenge_methods_supported).toContain('S256');
  });

  it('serves JWKS endpoint', async () => {
    await requireAvailable();

    const res = await fetch(`${ABAXX_ONE_URL}/.well-known/jwks`);
    expect(res.ok).toBe(true);

    const jwks = (await res.json()) as JwksResponse;
    expect(jwks.keys).toBeDefined();
    expect(Array.isArray(jwks.keys)).toBe(true);
  });

  it('authorization endpoint accepts PKCE params', async () => {
    await requireAvailable();

    const url = new URL(`${ABAXX_ONE_URL}/auth/authorize`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', 'client_agents_test');
    url.searchParams.set('redirect_uri', 'http://localhost:3000/callback');
    url.searchParams.set('scope', 'openid profile');
    url.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', 'test-state-123');

    const res = await fetch(url.toString(), { redirect: 'manual' });
    // Should redirect to login page or return HTML — NOT 404/500
    expect([200, 302, 303]).toContain(res.status);
  });

  it('token endpoint rejects invalid grant', async () => {
    await requireAvailable();

    const res = await fetch(`${ABAXX_ONE_URL}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'invalid_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'client_agents_test',
        code_verifier: 'test_verifier',
      }),
    });

    // Should reject with 400/401, NOT 500
    expect([400, 401, 403]).toContain(res.status);
  });
});

describeAbaxxOneOidc('AbaxxOneOidcProvider OIDC integration', () => {
  it('buildAuthorizationUrl discovers endpoints and builds auth URL', async () => {
    await requireAvailable();

    const { AbaxxOneOidcProvider } = await import('../../src/auth/abaxx-one.js');

    const provider = new AbaxxOneOidcProvider({
      tenantUrl: ABAXX_ONE_URL,
      clientId: 'client_agents_test',
      redirectUri: 'http://localhost:3000/callback',
    });

    const result = await provider.buildAuthorizationUrl();
    expect(result.url).toContain('/auth/authorize');
    expect(result.url).toContain('code_challenge');
    expect(result.url).toContain('S256');
    expect(typeof result.state).toBe('string');
    expect(typeof result.codeVerifier).toBe('string');
  });

  it('loginProgrammatic completes full programmatic flow', async () => {
    await requireAvailable();

    const { AbaxxOneOidcProvider } = await import('../../src/auth/abaxx-one.js');

    const provider = new AbaxxOneOidcProvider({
      tenantUrl: ABAXX_ONE_URL,
      clientId: 'client_agents_test',
      clientSecret: 'test_secret_for_agents',
      redirectUri: 'http://localhost:3000/callback',
      email: 'admin@test.local',
      password: 'TestPass123!',
    });

    const result = await provider.loginProgrammatic();
    expect(result.identity).toBeDefined();
    expect(result.identity.humanDid).toBeDefined();
    expect(typeof result.identity.humanDid).toBe('string');
    expect(result.identity.email).toBe('admin@test.local');
    expect(typeof result.accessToken).toBe('string');
  });

  it('loginProgrammatic rejects wrong credentials', async () => {
    await requireAvailable();

    const { AbaxxOneOidcProvider } = await import('../../src/auth/abaxx-one.js');

    const provider = new AbaxxOneOidcProvider({
      tenantUrl: ABAXX_ONE_URL,
      clientId: 'client_agents_test',
      clientSecret: 'test_secret_for_agents',
      redirectUri: 'http://localhost:3000/callback',
      email: 'nonexistent@test.local',
      password: 'wrong_password',
    });

    await expect(provider.loginProgrammatic()).rejects.toThrow();
  });
});
