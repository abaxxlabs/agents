import { describe, it, expect, vi, afterEach } from 'vitest';
import { AbaxxOneOidcProvider } from '../src/auth/abaxx-one.js';

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
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

function mockJsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
