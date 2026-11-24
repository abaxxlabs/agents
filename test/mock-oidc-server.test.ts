import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { MockOidcServer } from './mock-oidc-provider/index.js';
import { GenericOidcProvider } from '#auth/generic.js';
import { loopbackSkipReason, shouldRunLoopbackHttpTests } from './support/integration-gates.js';

interface TokenErrorResponse {
  error: string;
  error_description?: string;
}

const describeLoopback = shouldRunLoopbackHttpTests ? describe : describe.skip;

if (!shouldRunLoopbackHttpTests) {
  describe('Loopback HTTP integration gate', () => {
    it.skip(loopbackSkipReason, () => {});
  });
}

describeLoopback('MockOidcServer (loopback HTTP integration)', () => {
  let server: MockOidcServer;
  let baseUrl: string;

  beforeAll(async () => {
    server = new MockOidcServer({
      users: [
        {
          email: 'alice@company.com',
          password: 'password123',
          extraClaims: { hd: 'company.com' },
        },
        {
          email: 'bob@enterprise.com',
          password: 'secure456',
          extraClaims: { tid: 'azure-tenant-12345' },
        },
      ],
    });
    const { url } = await server.start();
    baseUrl = url;
  });

  afterAll(async () => {
    await server.stop();
  });

  it('completes a real GenericOidcProvider authorization and PKCE exchange with verified identity', async () => {
    const provider = new GenericOidcProvider({
      issuerUrl: baseUrl,
      clientId: 'generic-test-client',
      redirectUri: 'http://localhost:9999/callback',
    });
    const { url: authUrl, state, codeVerifier } = await provider.buildAuthorizationUrl();

    const authRes = await fetch(authUrl, { redirect: 'manual' });
    const callback = new URL(authRes.headers.get('location')!);
    expect(callback.searchParams.get('state')).toBe(state);
    const code = callback.searchParams.get('code')!;
    expect(code).toBeTruthy();

    const identity = await provider.exchangeCode(code, state, codeVerifier);
    expect(identity).toMatchObject({
      issuer: baseUrl,
      sub: 'alice@company.com',
      email: 'alice@company.com',
      org: 'company.com',
      claims: { hd: 'company.com' },
    });
    expect(identity.humanDid).toMatch(/^did:key:z/);
  });

  it('rejects PKCE token exchange with wrong code_verifier', async () => {
    const redirectUri = 'http://localhost:9999/callback';
    const realVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(realVerifier).digest('base64url');

    const authUrl = new URL(`${baseUrl}/auth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', 'test-client');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await fetch(authUrl.toString(), { redirect: 'manual' });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!;

    const tokenRes = await fetch(`${baseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'test-client',
        code_verifier: randomBytes(32).toString('base64url'),
      }),
    });
    expect(tokenRes.status).toBe(400);
    const err = (await tokenRes.json()) as TokenErrorResponse;
    expect(err.error).toBe('invalid_grant');
  });
});
