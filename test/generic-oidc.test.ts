import { describe, it, expect, vi, afterEach } from 'vitest';
import { GenericOidcProvider } from '#auth/generic.js';
import { mockJsonResponse } from './mocks/response.js';

const TEST_CONFIG = {
  issuerUrl: 'https://accounts.google.com',
  clientId: 'test-client-id',
  redirectUri: 'http://localhost:3000/callback',
  allowedCrossOriginHosts: ['oauth2.googleapis.com', 'openidconnect.googleapis.com'],
};

describe('GenericOidcProvider', () => {
  describe('fetchUserInfo', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('derives humanDid from userinfo sub + issuerUrl', async () => {
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

      const expectedDid = provider.deriveHumanDid('12345');
      expect(identity.humanDid).toBe(expectedDid);
    });
  });

  describe('buildAuthorizationUrl', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('rejects malformed discovery payloads before using discovered endpoints', async () => {
      const provider = new GenericOidcProvider(TEST_CONFIG);

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        mockJsonResponse({
          authorization_endpoint: 123,
          token_endpoint: 'https://oauth2.googleapis.com/token',
          jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
        }),
      );

      await expect(provider.buildAuthorizationUrl()).rejects.toThrow(
        'OIDC discovery missing required field: authorization_endpoint',
      );
    });
  });
});
