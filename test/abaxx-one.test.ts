import { describe, it, expect, vi, afterEach } from 'vitest';
import { AbaxxOneOidcProvider } from '#auth/abaxx-one.js';
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
  });

  // Owner DIDs may be did:ion; issuer DIDs stay restricted because their signatures are verified.
  describe('DID methods — owner label vs verifiable issuer', () => {
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
