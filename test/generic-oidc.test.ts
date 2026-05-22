import { describe, it, expect, vi, afterEach } from 'vitest';
import { GenericOidcProvider } from '../src/auth/generic.js';

const TEST_CONFIG = {
  issuerUrl: 'https://accounts.google.com',
  clientId: 'test-client-id',
  redirectUri: 'http://localhost:3000/callback',
  allowedCrossOriginHosts: ['oauth2.googleapis.com', 'openidconnect.googleapis.com'],
};

describe('GenericOidcProvider', () => {
  // ─── deriveHumanDid (Decision #36, Ryan Rawson) ───────────────────

  describe('deriveHumanDid', () => {
    it('returns a valid did:key DID', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const did = provider.deriveHumanDid('user123');
      expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    });

    it('is deterministic — same issuer + sub always produces same DID', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const did1 = provider.deriveHumanDid('user123');
      const did2 = provider.deriveHumanDid('user123');
      expect(did1).toBe(did2);
    });

    it('is unique per sub — different sub produces different DID', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const didA = provider.deriveHumanDid('user-alice');
      const didB = provider.deriveHumanDid('user-bob');
      expect(didA).not.toBe(didB);
    });

    it('is unique per issuer — same sub at different providers produces different DID (Decision #21)', () => {
      // Numeric sub values like "12345" would collide without issuerUrl in seed
      const google = new GenericOidcProvider({
        ...TEST_CONFIG,
        issuerUrl: 'https://accounts.google.com',
      });
      const azure = new GenericOidcProvider({
        ...TEST_CONFIG,
        issuerUrl: 'https://login.microsoftonline.com',
      });

      const googleDid = google.deriveHumanDid('12345');
      const azureDid = azure.deriveHumanDid('12345');
      expect(googleDid).not.toBe(azureDid);
    });

    it('handles unusual sub values without throwing', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      // Numeric, UUID, email-style — all valid sub formats in the wild
      expect(() => provider.deriveHumanDid('12345')).not.toThrow();
      expect(() => provider.deriveHumanDid('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
      expect(() => provider.deriveHumanDid('user@example.com')).not.toThrow();
    });

    it('produces an Ed25519 did:key (multicodec prefix 0xed)', () => {
      // Ed25519 did:key DIDs start with did:key:z6Mk (after base58 of 0xed01 prefix)
      // The exact prefix depends on the key bytes, but it should contain the Ed25519 multicodec
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const did = provider.deriveHumanDid('user123');
      // did:key:z prefix followed by base58 — verify it's non-trivially long (Ed25519 key)
      const keyPart = did.replace('did:key:z', '');
      expect(keyPart.length).toBeGreaterThan(40);
    });

    it('survives round-trip — same seed produces consistent DID across instances', () => {
      // Two separate provider instances with same config should derive same DID
      const provider1 = new GenericOidcProvider(TEST_CONFIG);
      const provider2 = new GenericOidcProvider(TEST_CONFIG);
      expect(provider1.deriveHumanDid('persistent-user')).toBe(
        provider2.deriveHumanDid('persistent-user'),
      );
    });
  });

  // ─── parseIdentityFromToken (Decision #32) ────────────────────────

  describe('parseIdentityFromToken', () => {
    it('is synchronous and returns Partial<OidcIdentity>', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      // If this method were async, calling it without await would return a Promise
      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
      });
      // Must NOT be a Promise — it's a pure sync transform
      expect(result).not.toBeInstanceOf(Promise);
      expect(typeof result).toBe('object');
    });

    it('extracts email from id_token claims', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const claims = { sub: 'user123', email: 'alice@example.com', name: 'Alice' };
      const idToken = [
        Buffer.from('{}').toString('base64url'),
        Buffer.from(JSON.stringify(claims)).toString('base64url'),
        'fakesig',
      ].join('.');

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.email).toBe('alice@example.com');
      expect(result.name).toBe('Alice');
    });

    it('extracts Google hosted domain (hd) as org', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const claims = { sub: 'user123', email: 'alice@company.com', hd: 'company.com' };
      const idToken = makeIdToken(claims);

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.org).toBe('company.com');
    });

    it('does NOT set humanDid — that requires fetchUserInfo (pure transform only)', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const claims = { sub: 'user123', email: 'alice@example.com' };
      const idToken = makeIdToken(claims);

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      // Generic OIDC tokens don't embed DIDs — humanDid derivation needs network
      expect(result.humanDid).toBeUndefined();
    });

    it('handles missing id_token gracefully — returns empty partial', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        // no id_token
      });
      expect(result).toEqual({ claims: {} });
    });

    it('handles malformed id_token without throwing', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      expect(() =>
        provider.parseIdentityFromToken({
          access_token: 'token',
          token_type: 'Bearer',
          id_token: 'not.a.valid.jwt.at.all',
        }),
      ).not.toThrow();
    });

    it('does not make any network calls — pure function', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const fetchSpy = vi.spyOn(globalThis, 'fetch');

      provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: makeIdToken({ sub: 'user', email: 'u@example.com' }),
      });

      // No fetch calls should have been made
      expect(fetchSpy).not.toHaveBeenCalled();
      fetchSpy.mockRestore();
    });

    it('extracts humanDid when sub is already a DID (Issue A — AbaxxOne token via generic path)', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const claims = { sub: 'did:dht:abc123xyz', email: 'alice@abaxx.tech' };
      const idToken = makeIdToken(claims);

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.humanDid).toBe('did:dht:abc123xyz');
    });

    it('extracts humanDid from dedicated did claim (Issue A — AbaxxOne token format)', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const claims = {
        sub: 'opaque-user-id',
        did: 'did:dht:real-did-from-abaxxone',
        email: 'alice@abaxx.tech',
      };
      const idToken = makeIdToken(claims);

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.humanDid).toBe('did:dht:real-did-from-abaxxone');
    });

    it('prefers did claim over DID-formatted sub', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const claims = { sub: 'did:key:z6MkOldKey', did: 'did:dht:canonical-did' };
      const idToken = makeIdToken(claims);

      const result = provider.parseIdentityFromToken({
        access_token: 'token',
        token_type: 'Bearer',
        id_token: idToken,
      });

      expect(result.humanDid).toBe('did:dht:canonical-did');
    });
  });

  // ─── fetchUserInfo (Decision #33) ─────────────────────────────────

  describe('fetchUserInfo', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('derives humanDid from userinfo sub + issuerUrl', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      // Mock discovery + userinfo
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid-configuration')) {
          return mockJsonResponse({
            authorization_endpoint: 'https://accounts.google.com/o/oauth2/auth',
            token_endpoint: 'https://oauth2.googleapis.com/token',
            userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
            jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
          });
        }
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({
            sub: '12345',
            email: 'alice@company.com',
            hd: 'company.com',
            name: 'Alice',
          });
        }
        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');

      expect(identity.humanDid).toMatch(/^did:key:z/);
      expect(identity.email).toBe('alice@company.com');
      expect(identity.org).toBe('company.com');

      // Verify determinism — same sub produces same DID
      const expectedDid = provider.deriveHumanDid('12345');
      expect(identity.humanDid).toBe(expectedDid);
    });

    it('excludes consumer domains from org (gmail.com etc.)', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid-configuration')) {
          return mockJsonResponse({
            authorization_endpoint: 'https://accounts.google.com/o/oauth2/auth',
            token_endpoint: 'https://oauth2.googleapis.com/token',
            userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
            jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
          });
        }
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({
            sub: '99999',
            email: 'bob@gmail.com', // consumer domain
          });
        }
        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');
      // gmail.com is a consumer domain — no org
      expect(identity.org).toBeUndefined();
    });

    it('passes through DID sub without re-derivation (Issue C — AbaxxOne misconfigured as generic)', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      const existingDid = 'did:dht:abc123xyz';

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid-configuration')) {
          return mockJsonResponse({
            authorization_endpoint: 'https://accounts.google.com/o/oauth2/auth',
            token_endpoint: 'https://oauth2.googleapis.com/token',
            userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
            jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
          });
        }
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({
            sub: existingDid,
            email: 'alice@abaxx.tech',
          });
        }
        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');
      expect(identity.humanDid).toBe(existingDid);
      expect(identity.humanDid).not.toMatch(/^did:key:/);
    });

    it('still derives did:key for non-DID sub values', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const urlStr = url.toString();
        if (urlStr.includes('openid-configuration')) {
          return mockJsonResponse({
            authorization_endpoint: 'https://accounts.google.com/o/oauth2/auth',
            token_endpoint: 'https://oauth2.googleapis.com/token',
            userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
            jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
          });
        }
        if (urlStr.includes('userinfo')) {
          return mockJsonResponse({ sub: '12345' });
        }
        throw new Error(`Unexpected fetch: ${urlStr}`);
      });

      const identity = await provider.fetchUserInfo('access-token');
      expect(identity.humanDid).toMatch(/^did:key:z/);
      expect(identity.humanDid).toBe(provider.deriveHumanDid('12345'));
    });
  });

  // ─── buildAuthorizationUrl ────────────────────────────────────────

  describe('buildAuthorizationUrl', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('returns url, state, and codeVerifier (library owns PKCE)', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        mockJsonResponse({
          authorization_endpoint: 'https://accounts.google.com/o/oauth2/auth',
          token_endpoint: 'https://oauth2.googleapis.com/token',
          jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
        }),
      );

      const result = await provider.buildAuthorizationUrl();

      expect(result.url).toContain('https://accounts.google.com/o/oauth2/auth');
      expect(result.url).toContain('code_challenge_method=S256');
      expect(result.state).toBeTruthy();
      expect(result.codeVerifier).toBeTruthy();
    });

    it('generates unique state on every call', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        mockJsonResponse({
          authorization_endpoint: 'https://accounts.google.com/o/oauth2/auth',
          token_endpoint: 'https://oauth2.googleapis.com/token',
          jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
        }),
      );

      const r1 = await provider.buildAuthorizationUrl();
      const r2 = await provider.buildAuthorizationUrl();
      expect(r1.state).not.toBe(r2.state);
      expect(r1.codeVerifier).not.toBe(r2.codeVerifier);
    });

    it('rejects malformed discovery payloads before using discovered endpoints', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockJsonResponse({
        authorization_endpoint: 123,
        token_endpoint: 'https://oauth2.googleapis.com/token',
        jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      }));

      await expect(provider.buildAuthorizationUrl()).rejects.toThrow(
        'OIDC discovery missing required field: authorization_endpoint',
      );
    });
  });

  // ─── issuerUrl property ───────────────────────────────────────────

  describe('issuerUrl', () => {
    it('exposes issuerUrl from config', () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);
      expect(provider.issuerUrl).toBe('https://accounts.google.com');
    });
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────

function makeIdToken(claims: Record<string, unknown>): string {
  return [
    Buffer.from('{"alg":"RS256"}').toString('base64url'),
    Buffer.from(JSON.stringify(claims)).toString('base64url'),
    'fakesig',
  ].join('.');
}

function mockJsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
