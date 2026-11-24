import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateDidKey, createMockSession } from '#auth/index.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { createFailingSdk } from './mocks/index.js';

describe('Auth', () => {
  describe('createMockSession', () => {
    it('issued credentials verify successfully', async () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });
      const session = createMockSession(verifier);

      const agent = generateDidKey();
      verifier.registerKey(agent.did, agent.publicKey);

      const jwt = await session.issueCredential({
        agent: agent.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
      expect(result.credential?.scope?.columns).toEqual(['patients.name', 'patients.dob']);
    });
  });

  describe('createMockSession with mock SDK', () => {
    it('falls back to local-key issuance when SDK credential issuance fails', async () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });

      const mockSdk = createFailingSdk();

      const session = createMockSession(verifier, 'Test User', mockSdk);
      const agent = generateDidKey();
      verifier.registerKey(agent.did, agent.publicKey);

      const jwt = await session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      expect(jwt.split('.').length).toBe(3);
      expect(mockSdk.vc.createCredential).toHaveBeenCalled();
    });
  });
});
describe('createMockSession — NODE_ENV guard', () => {
  let _savedNodeEnv: string | undefined;

  beforeEach(() => {
    _savedNodeEnv = process.env.NODE_ENV;
  });

  afterEach(() => {
    if (_savedNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = _savedNodeEnv;
    }
  });

  it('throws when NODE_ENV=production', () => {
    process.env.NODE_ENV = 'production';
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    expect(() => createMockSession(verifier)).toThrow('production');
    expect(() => createMockSession(verifier)).toThrow('development');
  });
});
