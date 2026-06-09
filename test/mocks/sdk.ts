import { vi } from 'vitest';
import type { IdSdkInstance } from '#types/index.js';
import { createSigner, createJwt } from '#index.js';
import type { generateDidKey } from '#index.js';

export function createMockSdk(overrides: Partial<IdSdkInstance> = {}): IdSdkInstance {
  return {
    vc: {
      createCredential: vi.fn().mockResolvedValue({}),
      signCredential: vi.fn().mockResolvedValue('mock.jwt.token'),
      getSignerOptions: vi.fn().mockResolvedValue({
        kid: 'test-kid',
        issuerDid: 'did:key:z6MkFake',
        subjectDid: 'did:key:z6MkAgent',
        signer: vi.fn(),
      }),
      verifyJWT: vi.fn().mockResolvedValue(true),
      decodeJWT: vi.fn().mockResolvedValue({ header: {}, payload: {}, signature: '' }),
      parseJWT: vi.fn().mockResolvedValue({}),
      createRevocableCredential: vi.fn().mockResolvedValue({}),
      revokeCredential: vi.fn().mockResolvedValue({}),
      checkCredentialStatus: vi.fn().mockResolvedValue({ revoked: false, suspended: false }),
      EdDsaSigner: vi.fn(),
      ...overrides.vc,
    },
    did: {
      resolve: vi.fn().mockResolvedValue({ didDocument: {}, didResolutionMetadata: {} }),
      create: vi.fn().mockResolvedValue({}),
      ...overrides.did,
    },
    agent: overrides.agent ?? {},
    connectedDid: overrides.connectedDid ?? 'did:key:z6MkFake',
  };
}

export function createFailingSdk(connectedDid = 'did:key:z6MkFake'): IdSdkInstance {
  return {
    vc: {
      createCredential: vi.fn().mockRejectedValue(new Error('SDK not ready')),
      signCredential: vi.fn().mockRejectedValue(new Error('SDK not ready')),
      getSignerOptions: vi.fn().mockRejectedValue(new Error('SDK not ready')),
      verifyJWT: vi.fn(),
      decodeJWT: vi.fn().mockResolvedValue({ header: {}, payload: {}, signature: '' }),
      parseJWT: vi.fn().mockResolvedValue({}),
      createRevocableCredential: vi.fn().mockResolvedValue({}),
      revokeCredential: vi.fn().mockRejectedValue(new Error('not available')),
      checkCredentialStatus: vi.fn().mockResolvedValue({ revoked: false, suspended: false }),
      EdDsaSigner: vi.fn(),
    },
    did: { resolve: vi.fn(), create: vi.fn() } as unknown as IdSdkInstance['did'],
    agent: {},
    connectedDid,
  };
}

export function createSigningSdk(signingKey: ReturnType<typeof generateDidKey>): IdSdkInstance {
  return {
    vc: {
      createCredential: async (_issuer, _subject, data) => data,
      getSignerOptions: async (did, subjectDid) => ({
        kid: `${did}#key-1`,
        issuerDid: did,
        subjectDid,
        signer: createSigner(signingKey.privateKey).signJwt as never,
      }),
      signCredential: async (vc) => {
        const data = vc as Record<string, unknown>;
        const now = Math.floor(Date.now() / 1000);
        return createJwt(
          { iss: signingKey.did, sub: String(data.id), iat: now, exp: now + 3600, maxDepth: data.maxDepth },
          signingKey.privateKey,
        );
      },
      verifyJWT: async () => true,
      decodeJWT: async () => ({ header: {}, payload: {}, signature: '' }),
      parseJWT: async () => ({}),
      createRevocableCredential: async () => ({}),
      revokeCredential: async () => ({}),
      checkCredentialStatus: async () => ({ revoked: false, suspended: false }),
      EdDsaSigner: (pk: Uint8Array) => createSigner(pk).signJwt as never,
    },
    did: { resolve: async () => ({ didDocument: {}, didResolutionMetadata: {} }) } as unknown as IdSdkInstance['did'],
    agent: {},
    connectedDid: signingKey.did,
  };
}
