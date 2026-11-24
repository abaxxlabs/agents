import { vi } from 'vitest';
import type { IdSdkInstance } from '#types/index.js';

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
