import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
interface OidcConfig {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  code_challenge_methods_supported: string[];
}

interface JwksResponse {
  keys: Array<{
    kty: string;
    crv: string;
    x: string;
    use: string;
    kid?: string;
  }>;
}

interface TokenResponse {
  access_token: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
}

interface TokenErrorResponse {
  error: string;
  error_description?: string;
}

interface UserInfoResponse {
  sub: string;
  email?: string;
  did?: string;
  [key: string]: unknown;
}

interface LoginResponse {
  session_id: string;
}
import { MockOidcServer } from './mock-oidc-provider/index.js';
import { GenericOidcProvider } from '#auth/generic.js';
import { AbaxxOneOidcProvider } from '#auth/abaxx-one.js';
import { ParentCredentialRequestFailedError } from '#errors/index.js';
import { loopbackSkipReason, shouldRunLoopbackHttpTests } from './support/integration-gates.js';

// ─── Shared server setup ──────────────────────────────────────────────────────

const describeLoopback: typeof describe = shouldRunLoopbackHttpTests ? describe : describe.skip;

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

  // ─── Lifecycle ────────────────────────────────────────────────────────────

  it('starts and assigns a port', () => {
    expect(server.port).toBeGreaterThan(0);
    expect(baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  // ─── Discovery ────────────────────────────────────────────────────────────

  it('serves openid-configuration (standard, hyphen)', async () => {
    const res = await fetch(`${baseUrl}/.well-known/openid-configuration`);
    expect(res.ok).toBe(true);
    const config = (await res.json()) as OidcConfig;
    expect(config.issuer).toBe(baseUrl);
    expect(config.authorization_endpoint).toContain('/auth/authorize');
    expect(config.token_endpoint).toContain('/auth/token');
    expect(config.userinfo_endpoint).toContain('/auth/userinfo');
    expect(config.jwks_uri).toContain('jwks');
    expect(config.code_challenge_methods_supported).toContain('S256');
  });

  it('serves openid_configuration (AbaxxOne style, underscore)', async () => {
    const res = await fetch(`${baseUrl}/.well-known/openid_configuration`);
    expect(res.ok).toBe(true);
    const config = (await res.json()) as OidcConfig;
    expect(config.issuer).toBe(baseUrl);
  });

  // ─── JWKS ─────────────────────────────────────────────────────────────────

  it('serves JWKS with Ed25519 key', async () => {
    const res = await fetch(`${baseUrl}/.well-known/jwks`);
    expect(res.ok).toBe(true);
    const jwks = (await res.json()) as JwksResponse;
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBe(1);
    const key = jwks.keys[0];
    expect(key.kty).toBe('OKP');
    expect(key.crv).toBe('Ed25519');
    expect(typeof key.x).toBe('string');
    expect(key.use).toBe('sig');
  });

  // ─── Authorization endpoint ───────────────────────────────────────────────

  it('auto-redirects with code on GET /auth/authorize', async () => {
    const redirectUri = 'http://localhost:9999/callback';
    const url = new URL(`${baseUrl}/auth/authorize`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', 'test-client');
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', 'openid profile');
    url.searchParams.set('state', 'test-state-abc');

    const res = await fetch(url.toString(), { redirect: 'manual' });
    expect(res.status).toBe(302);
    const location = res.headers.get('location');
    expect(location).toBeDefined();
    const cb = new URL(location!);
    expect(cb.searchParams.get('code')).toBeTruthy();
    expect(cb.searchParams.get('state')).toBe('test-state-abc');
  });

  // ─── Full PKCE flow ───────────────────────────────────────────────────────

  it('completes full authorization_code + PKCE S256 flow', async () => {
    const redirectUri = 'http://localhost:9999/callback';
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

    // Step 1: GET /auth/authorize
    const authUrl = new URL(`${baseUrl}/auth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', 'pkce-client');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await fetch(authUrl.toString(), { redirect: 'manual' });
    const location = authRes.headers.get('location')!;
    const code = new URL(location).searchParams.get('code')!;
    expect(code).toBeTruthy();

    // Step 2: POST /auth/token with code_verifier
    const tokenRes = await fetch(`${baseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'pkce-client',
        code_verifier: codeVerifier,
      }),
    });
    expect(tokenRes.ok).toBe(true);
    const tokens = (await tokenRes.json()) as TokenResponse;
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.token_type).toBe('Bearer');

    // Step 3: GET /auth/userinfo
    const userRes = await fetch(`${baseUrl}/auth/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userRes.ok).toBe(true);
    const user = (await userRes.json()) as UserInfoResponse;
    expect(user.sub).toBeTruthy();
    expect(user.email).toBeTruthy();
    expect(user.did).toMatch(/^did:key:z/); // mock generates DID for all users
  });

  it('rejects PKCE token exchange with wrong code_verifier', async () => {
    const redirectUri = 'http://localhost:9999/callback';
    const realVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(realVerifier).digest('base64url');

    const authUrl = new URL(`${baseUrl}/auth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', 'test-client');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await fetch(authUrl.toString(), { redirect: 'manual' });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!;

    // Use a WRONG verifier
    const tokenRes = await fetch(`${baseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'test-client',
        code_verifier: randomBytes(32).toString('base64url'), // wrong verifier
      }),
    });
    expect(tokenRes.status).toBe(400);
    const err = (await tokenRes.json()) as TokenErrorResponse;
    expect(err.error).toBe('invalid_grant');
  });

  it('rejects invalid auth code', async () => {
    const tokenRes = await fetch(`${baseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'not-a-real-code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test-client',
      }),
    });
    expect(tokenRes.status).toBe(400);
  });

  it('rejects invalid access token at userinfo', async () => {
    const res = await fetch(`${baseUrl}/auth/userinfo`, {
      headers: { Authorization: 'Bearer not-a-real-token' },
    });
    expect(res.status).toBe(401);
  });

  it('rejects userinfo with no Authorization header', async () => {
    const res = await fetch(`${baseUrl}/auth/userinfo`);
    expect(res.status).toBe(401);
  });

  // ─── Programmatic login (X-Session-ID) ───────────────────────────────────

  it('POST /auth/login returns session_id for valid credentials', async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'alice@company.com', password: 'password123' }),
    });
    expect(res.ok).toBe(true);
    const data = (await res.json()) as LoginResponse;
    expect(typeof data.session_id).toBe('string');
  });

  it('POST /auth/login rejects wrong password with 401', async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'alice@company.com', password: 'wrongpassword' }),
    });
    expect(res.status).toBe(401);
  });

  it('POST /auth/login rejects unknown user with 401', async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'unknown@nowhere.com', password: 'anything' }),
    });
    expect(res.status).toBe(401);
  });

  it('X-Session-ID flow: login → authorize with session → token', async () => {
    const redirectUri = 'http://localhost:9999/callback';

    // Login to get session_id
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'alice@company.com', password: 'password123' }),
    });
    const { session_id } = (await loginRes.json()) as LoginResponse;

    // Authorize with X-Session-ID
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

    const authUrl = new URL(`${baseUrl}/auth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', 'cli-client');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await fetch(authUrl.toString(), {
      redirect: 'manual',
      headers: { 'X-Session-ID': session_id },
    });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!;

    // Exchange code
    const tokenRes = await fetch(`${baseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'cli-client',
        code_verifier: codeVerifier,
      }),
    });
    expect(tokenRes.ok).toBe(true);
    const tokens = (await tokenRes.json()) as TokenResponse;

    // Verify userinfo includes alice's extra claims
    const userRes = await fetch(`${baseUrl}/auth/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const user = (await userRes.json()) as UserInfoResponse;
    expect(user.email).toBe('alice@company.com');
    expect(user.hd).toBe('company.com'); // from alice's extraClaims
  });

  // ─── Custom user with AbaxxOne DID claim ─────────────────────────────────

  it('user with explicit did extraClaim gets that DID in userinfo', async () => {
    const customDid = 'did:key:z6MkCustomTestDid123';
    server.registerUser({
      email: 'did-user@test.com',
      password: 'test123',
      extraClaims: { did: customDid },
    });

    // Quick PKCE flow to get a token for this user
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'did-user@test.com', password: 'test123' }),
    });
    const { session_id } = (await loginRes.json()) as LoginResponse;

    const authUrl = new URL(`${baseUrl}/auth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', 'test');
    authUrl.searchParams.set('redirect_uri', 'http://localhost:9999/cb');
    const authRes = await fetch(authUrl.toString(), {
      redirect: 'manual',
      headers: { 'X-Session-ID': session_id },
    });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!;

    const tokenRes = await fetch(`${baseUrl}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:9999/cb',
        client_id: 'test',
      }),
    });
    const { access_token } = (await tokenRes.json()) as TokenResponse;

    const userRes = await fetch(`${baseUrl}/auth/userinfo`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const user = (await userRes.json()) as UserInfoResponse;
    // extraClaims.did overrides the auto-derived DID
    expect(user.did).toBe(customDid);
  });
});

// ─── Integration with GenericOidcProvider ────────────────────────────────────

describeLoopback('GenericOidcProvider + MockOidcServer integration', () => {
  let server: MockOidcServer;
  let provider: GenericOidcProvider;

  beforeAll(async () => {
    server = new MockOidcServer({
      users: [
        { email: 'dev@mycompany.com', password: 'devpass', extraClaims: { hd: 'mycompany.com' } },
      ],
    });
    const { url } = await server.start();
    provider = new GenericOidcProvider({
      issuerUrl: url,
      clientId: 'generic-test-client',
    });
  });

  afterAll(() => server.stop());

  it('buildAuthorizationUrl() discovers endpoints and returns PKCE URL', async () => {
    const result = await provider.buildAuthorizationUrl({
      redirectUri: 'http://localhost:9999/callback',
      state: 'state-xyz',
    });
    expect(result.url).toContain('/auth/authorize');
    expect(result.url).toContain('code_challenge');
    expect(result.url).toContain('S256');
    expect(typeof result.codeVerifier).toBe('string');
  });

  it('exchangeCode() completes the PKCE flow and returns OidcIdentity', async () => {
    // Use buildAuthorizationUrl() so the state is registered in the provider's flowStore.
    // exchangeCode() calls flowStore.consume(state, codeVerifier) and rejects any
    // state that wasn't registered via buildAuthorizationUrl().
    const { url: authUrl, state, codeVerifier } = await provider.buildAuthorizationUrl();

    const authRes = await fetch(authUrl, { redirect: 'manual' });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!;
    expect(code).toBeTruthy();

    const identity = await provider.exchangeCode(code, state, codeVerifier);
    expect(identity.email).toBe('dev@mycompany.com');
    expect(typeof identity.humanDid).toBe('string');
    expect(identity.humanDid).toMatch(/^did:key:z/);
    expect(identity.claims.hd).toBe('mycompany.com');
    // issuer + sub are required fields of OidcIdentity
    expect(typeof identity.issuer).toBe('string');
    expect(typeof identity.sub).toBe('string');
  });
});

// ─── AbaxxOneOidcProvider.loginProgrammatic() return shape ──────────────────

describeLoopback(
  'AbaxxOneOidcProvider.loginProgrammatic() returns { identity, accessToken }',
  () => {
    let server: MockOidcServer;
    let serverUrl: string;

    beforeAll(async () => {
      server = new MockOidcServer({
        users: [
          { email: 'prog@company.com', password: 'progpass', extraClaims: { hd: 'company.com' } },
        ],
      });
      const result = await server.start();
      serverUrl = result.url;
    });

    afterAll(() => server.stop());

    it('returns both identity (with OidcIdentity fields) and a non-empty accessToken', async () => {
      const provider = new AbaxxOneOidcProvider({
        tenantUrl: serverUrl,
        clientId: 'login-test-client',
        email: 'prog@company.com',
        password: 'progpass',
      });

      const result = await provider.loginProgrammatic();

      // Verify the return shape is { identity, accessToken } — not a bare OidcIdentity.
      expect(result).toHaveProperty('identity');
      expect(result).toHaveProperty('accessToken');

      // identity must satisfy the OidcIdentity contract
      expect(result.identity.humanDid).toMatch(/^did:key:z/);
      expect(result.identity.email).toBe('prog@company.com');
      expect(typeof result.identity.issuer).toBe('string');
      expect(typeof result.identity.sub).toBe('string');
      expect(result.identity.claims).toBeDefined();

      // accessToken must be a non-empty string suitable for Bearer auth
      expect(typeof result.accessToken).toBe('string');
      expect(result.accessToken.length).toBeGreaterThan(0);
    });
  },
);

// ─── AbaxxOneOidcProvider.requestAgentCredential() timeout ─────────────────

describeLoopback('AbaxxOneOidcProvider.requestAgentCredential() timeout behavior', () => {
  let hangServer: Server;
  let hangUrl: string;

  beforeAll(async () => {
    // Create a server that accepts connections but never responds.
    // This simulates a tenant that is reachable but hangs — the AbortSignal.timeout(5000)
    // in requestAgentCredential should abort the fetch and throw
    // ParentCredentialRequestFailedError within a bounded time.
    hangServer = createServer((_req, _res) => {
      // Intentionally never respond — socket stays open indefinitely.
    });
    await new Promise<void>((resolve) => {
      hangServer.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = hangServer.address() as import('node:net').AddressInfo;
    hangUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => hangServer.close(() => resolve()));
  });

  // AbortSignal.timeout(5000) does not interrupt fetch reliably in Bun's full
  // test suite (passes in isolation; times out in the full run). Covered by
  // the Node/Vitest suite. Skip under Bun to keep the Bun suite green.
  const itOnNode = typeof Bun !== 'undefined' ? it.skip : it;
  itOnNode(
    'throws ParentCredentialRequestFailedError when the server hangs',
    async () => {
      const provider = new AbaxxOneOidcProvider({
        tenantUrl: hangUrl,
        clientId: 'timeout-test-client',
      });

      await expect(
        provider.requestAgentCredential('fake-access-token', 'did:key:z6MktimeoutTestAgent', {
          columns: ['data.test'],
          actions: ['read'],
          expiresIn: '1h',
        }),
      ).rejects.toThrow(ParentCredentialRequestFailedError);
    },
    10_000,
  );
});
