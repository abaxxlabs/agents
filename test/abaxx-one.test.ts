import { describe, it, expect, vi, afterEach } from 'vitest';
import { AbaxxOneOidcProvider, extractAuthorizationCode } from '#auth/abaxx-one.js';
import { mockJsonResponse } from './mocks/response.js';

const TEST_CONFIG = {
  tenantUrl: 'https://id.abaxx.com',
  clientId: 'test-client',
  redirectUri: 'http://localhost:3000/callback',
};

describe('AbaxxOneOidcProvider', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('parseIdentityFromToken', () => {
    it('is synchronous — not a Promise', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
      });
      expect(result).not.toBeInstanceOf(Promise);
    });

    it('extracts humanDid from id_token.did claim (primary AbaxxOne path)', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const claims = {
        sub: 'user@abaxx.com',
        did: 'did:key:z6MkABC123',
        email: 'user@abaxx.com',
        org: 'abaxx.com',
      };
      const idToken = makeIdToken(claims);

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.humanDid).toBe('did:key:z6MkABC123');
      expect(result.email).toBe('user@abaxx.com');
    });

    it('extracts humanDid from id_token.dwn_did — the name AbaxxOne uses today', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const idToken = makeIdToken({
        sub: 'user@example.com',
        dwn_did: 'did:dht:z4w8eORG123',
        email: 'user@example.com',
      });

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.humanDid).toBe('did:dht:z4w8eORG123');
    });

    it('prefers did over dwn_did when a tenant sends both', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const idToken = makeIdToken({
        sub: 'user@example.com',
        did: 'did:key:z6MkPREFERRED',
        dwn_did: 'did:key:z6MkFALLBACK',
      });

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.humanDid).toBe('did:key:z6MkPREFERRED');
    });

    it('rejects an unsupported DID method in dwn_did', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const idToken = makeIdToken({
        sub: 'user@example.com',
        dwn_did: 'did:web:example.com',
      });

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      // Falls through to the userinfo path rather than trusting an unsupported method.
      expect(result.humanDid).toBeUndefined();
    });

    it('extracts humanDid from sub claim when sub is a DID', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const claims = {
        sub: 'did:key:z6MkXYZ789',
        email: 'user@abaxx.com',
      };

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: makeIdToken(claims),
      });

      expect(result.humanDid).toBe('did:key:z6MkXYZ789');
    });

    it('returns Partial without humanDid for older tenants (no DID in token)', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const claims = {
        sub: 'legacy-user-id', // not a DID
        email: 'user@abaxx.com',
      };

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: makeIdToken(claims),
      });

      expect(result.humanDid).toBeUndefined();
      expect(result.claims).toBeDefined();
    });

    it('returns empty partial when no id_token provided', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
      });
      expect(result.humanDid).toBeUndefined();
    });

    it('handles malformed id_token without throwing', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      expect(() =>
        provider.parseIdentityFromToken({
          access_token: 'token',
          token_type: 'Bearer',
          id_token: 'not.valid.jwt.garbage',
        }),
      ).not.toThrow();
    });

    it('makes no network calls (pure function)', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const fetchSpy = vi.spyOn(globalThis, 'fetch');

      provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: makeIdToken({ sub: 'did:key:zABC', did: 'did:key:zABC' }),
      });

      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe('fetchUserInfo', () => {
    it('extracts humanDid from AbaxxOne userinfo.did field', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid_configuration')) {
          return mockJsonResponse(mockDiscovery());
        }
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({
            sub: 'user@abaxx.com',
            did: 'did:key:z6MkFromUserinfo',
            email: 'user@abaxx.com',
          });
        }
        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');
      expect(identity.humanDid).toBe('did:key:z6MkFromUserinfo');
    });

    it('falls back to sub when userinfo has no did field', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid_configuration')) return mockJsonResponse(mockDiscovery());
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({ sub: 'did:key:zFromSub', email: 'u@abaxx.com' });
        }
        throw new Error(`Unexpected: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');
      expect(identity.humanDid).toBe('did:key:zFromSub');
    });
  });

  describe('discovery', () => {
    it('uses underscore path /.well-known/openid_configuration', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      let discoveryUrl = '';

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        discoveryUrl = url.toString();
        if (discoveryUrl.includes('openid_configuration')) return mockJsonResponse(mockDiscovery());
        if (discoveryUrl.includes('oauth2/auth')) {
          return mockJsonResponse({});
        }
        throw new Error(`Unexpected: ${discoveryUrl}`);
      });

      await provider.buildAuthorizationUrl();
      expect(discoveryUrl).toContain('/.well-known/openid_configuration');
      expect(discoveryUrl).not.toContain('openid-configuration');
    });

    it('does not generate or return an OIDC nonce', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockJsonResponse(mockDiscovery()));

      const result = await provider.buildAuthorizationUrl();

      expect(new URL(result.url).searchParams.has('nonce')).toBe(false);
      expect(result).not.toHaveProperty('nonce');
    });

    it('rejects malformed discovery payloads before using discovered endpoints', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockJsonResponse([]));

      await expect(provider.buildAuthorizationUrl()).rejects.toThrow(
        'AbaxxOne discovery missing required field: authorization_endpoint',
      );
    });
  });

  describe('issuerUrl', () => {
    it('returns tenantUrl as issuerUrl', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      expect(provider.issuerUrl).toBe('https://id.abaxx.com');
    });
  });

  // Owner DIDs may be did:ion; issuer DIDs stay restricted because their signatures are verified.
  describe('DID methods — owner label vs verifiable issuer', () => {
    it('accepts a did:ion humanDid from userinfo (owner label)', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid_configuration')) return mockJsonResponse(mockDiscovery());
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({
            sub: 'sso-user@example.com',
            did: 'did:ion:EiAsso123',
            email: 'sso-user@example.com',
          });
        }
        throw new Error(`Unexpected: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');
      expect(identity.humanDid).toBe('did:ion:EiAsso123');
    });

    it('accepts a did:ion humanDid from the id_token', () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);
      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: makeIdToken({ sub: 'sso-user@example.com', did: 'did:ion:EiAsso123' }),
      });
      expect(result.humanDid).toBe('did:ion:EiAsso123');
    });

    it('still rejects a DID method the stack knows nothing about', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid_configuration')) return mockJsonResponse(mockDiscovery());
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({ sub: 'u@example.com', did: 'did:web:example.com' });
        }
        throw new Error(`Unexpected: ${urlStr}`);
      });

      await expect(provider.fetchUserInfo('access-token')).rejects.toThrow(
        'unsupported DID method',
      );
    });

    // The guard that must NOT loosen: an issuer DID is verified, not labelled.
    it('rejects a did:ion ISSUER on an agent credential', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        mockJsonResponse({ jwt: makeJwtWithIssuer('did:ion:EiAorg123') }),
      );

      await expect(
        provider.requestAgentCredential('access-token', 'did:key:zAgent', {
          columns: ['orders.price'],
          actions: ['read'],
          expiresIn: '1h',
        }),
      ).rejects.toThrow('Invalid issuer DID');
    });

    it('accepts a did:dht ISSUER on an agent credential', async () => {
      const provider = new AbaxxOneOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        mockJsonResponse({ jwt: makeJwtWithIssuer('did:dht:z4w8eORG123') }),
      );

      const result = await provider.requestAgentCredential('access-token', 'did:key:zAgent', {
        columns: ['orders.price'],
        actions: ['read'],
        expiresIn: '1h',
      });
      expect(result.issuerDid).toBe('did:dht:z4w8eORG123');
    });
  });

  describe('requestAgentCredential — tenant refusal', () => {
    const refuse = (body: unknown) =>
      vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(new Response(JSON.stringify(body), { status: 403 }));
    const request = () =>
      new AbaxxOneOidcProvider(TEST_CONFIG).requestAgentCredential('access-token', 'did:key:zA', {
        columns: ['orders.price'],
        actions: ['read'],
        expiresIn: '1h',
      });

    it('renders the reason and the excess columns as one sentence', async () => {
      refuse({ error: 'Requested scope exceeds your policy', excessColumns: ['orders.price'] });

      await expect(request()).rejects.toMatchObject({
        httpStatus: 403,
        recoveryHint:
          'Your organization refused to issue this credential: Requested scope exceeds your policy — orders.price',
      });
    });

    it('keeps an unexpected upstream body out of the user-facing hint', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response('<html>stack trace at internal-host:5432</html>', { status: 502 }),
      );

      const err = (await request().catch((e: unknown) => e)) as {
        recoveryHint: string;
        details: Record<string, unknown>;
      };
      expect(err.recoveryHint).not.toContain('internal-host');
      expect(err.recoveryHint).toContain('contact your administrator');
      expect(err.details.upstreamBody).toContain('internal-host');
    });

    it('caps a long reason at 200 characters', async () => {
      refuse({ error: 'x'.repeat(500) });

      const err = (await request().catch((e: unknown) => e)) as { recoveryHint: string };
      const reason = err.recoveryHint.replace(
        'Your organization refused to issue this credential: ',
        '',
      );
      expect(reason).toBe('x'.repeat(200) + '...');
    });
  });

  // AbaxxOne may bounce through an intermediate page that carries the real redirect in `next`.
  describe('extractAuthorizationCode', () => {
    const BASE = 'https://tenant.example.com';

    it('reads the code from a direct redirect to redirect_uri', () => {
      const location = 'http://localhost:3000/callback?code=DIRECT_CODE&state=abc';
      expect(extractAuthorizationCode(location, BASE)).toBe('DIRECT_CODE');
    });

    it('reads the code nested in an intermediate redirect `next` parameter', () => {
      const next = encodeURIComponent('http://localhost:3000/callback?code=NESTED_CODE&state=abc');
      const location = `/auth/redirect?client_id=test-client&next=${next}`;
      expect(extractAuthorizationCode(location, BASE)).toBe('NESTED_CODE');
    });

    it('returns null when neither the redirect nor its `next` carries a code', () => {
      const next = encodeURIComponent('http://localhost:3000/callback?error=access_denied');
      const location = `/auth/redirect?client_id=test-client&next=${next}`;
      expect(extractAuthorizationCode(location, BASE)).toBeNull();
    });

    // One hop only. Chasing `next` recursively would let a redirect loop hang the CLI.
    it('does not follow a second `next` hop', () => {
      const inner = encodeURIComponent('http://localhost:3000/callback?code=TOO_DEEP&state=abc');
      const outer = encodeURIComponent(`${BASE}/auth/redirect?next=${inner}`);
      const location = `/auth/redirect?client_id=test-client&next=${outer}`;
      expect(extractAuthorizationCode(location, BASE)).toBeNull();
    });

    it('returns null when `next` is not a parseable URL', () => {
      const location = '/auth/redirect?client_id=test-client&next=%%%not-a-url';
      expect(extractAuthorizationCode(location, BASE)).toBeNull();
    });
  });

  describe('loginProgrammatic', () => {
    it('completes the flow when authorize bounces through an intermediate page', async () => {
      const provider = new AbaxxOneOidcProvider({
        ...TEST_CONFIG,
        email: 'user@example.com',
        password: 'pw',
      });

      let codeSentToToken: string | null = null;

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
        const urlStr = url.toString();

        if (urlStr.includes('openid_configuration')) return mockJsonResponse(mockDiscovery());

        if (urlStr.includes('/auth/login')) {
          return mockJsonResponse({ session_id: 'sid-abc' });
        }

        if (urlStr.includes('/auth/authorize')) {
          const next = encodeURIComponent(
            'http://localhost:3000/callback?code=NESTED_CODE&state=abc',
          );
          return new Response(null, {
            status: 302,
            headers: { location: `/auth/redirect?client_id=test-client&next=${next}` },
          });
        }

        if (urlStr.includes('/auth/token')) {
          codeSentToToken = new URLSearchParams(init?.body as string).get('code');
          return new Response('nope', { status: 400 });
        }

        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      // The token exchange is stubbed to fail; this test checks which code reaches it.
      await expect(provider.loginProgrammatic()).rejects.toThrow('Token exchange failed');
      expect(codeSentToToken).toBe('NESTED_CODE');
    });

    it('still reports a missing code when the redirect carries neither code nor next', async () => {
      const provider = new AbaxxOneOidcProvider({
        ...TEST_CONFIG,
        email: 'user@example.com',
        password: 'pw',
      });

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid_configuration')) return mockJsonResponse(mockDiscovery());
        if (urlStr.includes('/auth/login')) return mockJsonResponse({ session_id: 'sid-abc' });
        if (urlStr.includes('/auth/authorize')) {
          return new Response(null, {
            status: 302,
            headers: { location: '/auth/login?error=access_denied' },
          });
        }
        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      await expect(provider.loginProgrammatic()).rejects.toThrow('No code in redirect');
    });
  });
});

function makeJwtWithIssuer(iss: string): string {
  return [
    Buffer.from('{"alg":"EdDSA"}').toString('base64url'),
    Buffer.from(JSON.stringify({ iss, sub: 'did:key:zAgent' })).toString('base64url'),
    'fakesig',
  ].join('.');
}

function makeIdToken(claims: Record<string, unknown>): string {
  return [
    Buffer.from('{"alg":"EdDSA"}').toString('base64url'),
    Buffer.from(JSON.stringify(claims)).toString('base64url'),
    'fakesig',
  ].join('.');
}

function mockDiscovery() {
  return {
    issuer: 'https://id.abaxx.com',
    authorization_endpoint: 'https://id.abaxx.com/auth/authorize',
    token_endpoint: 'https://id.abaxx.com/auth/token',
    userinfo_endpoint: 'https://id.abaxx.com/auth/userinfo',
    jwks_uri: 'https://id.abaxx.com/.well-known/jwks',
    code_challenge_methods_supported: ['S256'],
  };
}
