// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Unit tests for DID generation, credential issuance, mock sessions, and OIDC flow.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateDidKey, issueCredential, createMockSession } from '../src/auth/index.js';
import { issueCredentialFromParent } from '../src/auth/agent.js';
import { ScopeExceedsCeilingError, type ScopeCeiling } from '../src/auth/ceiling.js';
import { VcVerifier, decodeJwt, verifyJwtSignature } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';

describe('Auth', () => {
  describe('generateDidKey', () => {
    it('generates a valid did:key DID', () => {
      const { did, publicKey, privateKey } = generateDidKey();
      expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
      expect(publicKey.length).toBe(32);
      expect(privateKey.length).toBe(32);
    });

    it('generates unique DIDs', () => {
      const a = generateDidKey();
      const b = generateDidKey();
      expect(a.did).not.toBe(b.did);
    });
  });

  describe('issueCredential (legacy)', () => {
    it('creates a valid JWT credential', () => {
      const human = generateDidKey();
      const agent = generateDidKey();

      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
      });

      expect(jwt.split('.').length).toBe(3);

      const { payload } = decodeJwt(jwt);
      expect(payload.iss).toBe(human.did);
      expect(payload.sub).toBe(agent.did);
      expect(payload.vc?.credentialSubject?.scope?.columns).toEqual([
        'patients.name',
        'patients.dob',
      ]);
      expect(payload.vc?.credentialSubject?.scope?.actions).toEqual(['read']);
    });

    it('sets correct expiry', () => {
      const human = generateDidKey();
      const agent = generateDidKey();

      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      });

      const { payload } = decodeJwt(jwt);
      const expectedExp = Math.floor(Date.now() / 1000) + 3600;
      // Allow 2 second tolerance
      expect(Math.abs((payload.exp ?? 0) - expectedExp)).toBeLessThan(2);
    });

    it('signature is verifiable with human public key', () => {
      const human = generateDidKey();
      const agent = generateDidKey();

      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      expect(verifyJwtSignature(jwt, human.publicKey)).toBe(true);
    });

    it('includes metadata in credential', () => {
      const human = generateDidKey();
      const agent = generateDidKey();

      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
        metadata: { department: 'claims' },
      });

      const { payload } = decodeJwt(jwt);
      expect(payload.vc?.credentialSubject?.department).toBe('claims');
    });

    it('rejects invalid duration format', () => {
      const human = generateDidKey();
      const agent = generateDidKey();

      expect(() =>
        issueCredential(human.did, human.privateKey, {
          agent: agent.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: 'invalid',
        }),
      ).toThrow('Invalid duration');
    });
  });

  describe('createMockSession', () => {
    it('returns a session with a valid DID', () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });

      const session = createMockSession(verifier, 'Test User');
      expect(session.humanDid).toMatch(/^did:key:z/);
      expect(session.email).toBe('test.user@demo.abaxx.tech');
    });

    it('session can issue credentials', async () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });
      const session = createMockSession(verifier);

      const agent = generateDidKey();
      verifier.registerKey(agent.did, agent.publicKey);

      const jwt = await session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      expect(jwt.split('.').length).toBe(3);
      const { payload } = decodeJwt(jwt);
      expect(payload.sub).toBe(agent.did);
    });

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

  describe('createMockSession — DID determinism (generateDidKeyFromSeed behavior)', () => {
    it('same humanName produces the same DID on repeated calls', () => {
      const verifier1 = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });
      const verifier2 = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });

      const session1 = createMockSession(verifier1, 'Dr. Chen');
      const session2 = createMockSession(verifier2, 'Dr. Chen');
      expect(session1.humanDid).toBe(session2.humanDid);
    });

    it('different humanNames produce different DIDs', () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });

      const s1 = createMockSession(verifier, 'Dr. Chen');
      const s2 = createMockSession(verifier, 'Dr. Patel');
      expect(s1.humanDid).not.toBe(s2.humanDid);
    });

    it('produced DID is a valid did:key', () => {
      const session = createMockSession(
        new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() }),
        'Seed Test',
      );
      expect(session.humanDid).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    });
  });

  describe('createMockSession with mock SDK', () => {
    it('falls back to local-key issuance when SDK credential issuance fails', async () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });

      // Mock SDK that fails on credential operations
      const mockSdk = {
        vc: {
          createCredential: vi.fn().mockRejectedValue(new Error('SDK not ready')),
          signCredential: vi.fn().mockRejectedValue(new Error('SDK not ready')),
          getSignerOptions: vi.fn().mockRejectedValue(new Error('SDK not ready')),
          verifyJWT: vi.fn(),
          revokeCredential: vi.fn().mockRejectedValue(new Error('not available')),
          EdDsaSigner: vi.fn(),
        },
        did: { resolve: vi.fn(), create: vi.fn() },
        agent: {},
        connectedDid: 'did:key:z6MkFake',
      } as unknown as Parameters<typeof createMockSession>[2];

      const session = createMockSession(verifier, 'Test User', mockSdk);
      const agent = generateDidKey();
      verifier.registerKey(agent.did, agent.publicKey);

      // SDK fails, so session uses the local-key path
      const jwt = await session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      expect(jwt.split('.').length).toBe(3);
      // SDK was attempted first
      expect(mockSdk.vc.createCredential).toHaveBeenCalled();
    });

    it('uses SDK when available and working', async () => {
      const verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });

      const mockSignedJwt = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtGYWtlIn0.fakesig';

      const mockSdk = {
        vc: {
          createCredential: vi.fn().mockResolvedValue({ type: 'vc' }),
          signCredential: vi.fn().mockResolvedValue(mockSignedJwt),
          getSignerOptions: vi.fn().mockResolvedValue({
            kid: 'test-kid',
            issuerDid: 'did:key:z6MkFake',
            subjectDid: 'did:key:z6MkAgent',
            signer: vi.fn(),
          }),
          verifyJWT: vi.fn(),
          revokeCredential: vi.fn(),
          EdDsaSigner: vi.fn(),
        },
        did: { resolve: vi.fn(), create: vi.fn() },
        agent: {},
        connectedDid: 'did:key:z6MkFake',
      } as unknown as Parameters<typeof createMockSession>[2];

      const session = createMockSession(verifier, 'Test User', mockSdk);
      const agent = generateDidKey();

      const jwt = await session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      // Should use SDK path
      expect(jwt).toBe(mockSignedJwt);
      expect(mockSdk.vc.createCredential).toHaveBeenCalled();
      expect(mockSdk.vc.signCredential).toHaveBeenCalled();
    });
  });

});

describe('issueCredentialFromParent — optional ceiling enforcement', () => {
  const AGENT_DID = 'did:key:z6MkTestAgent';
  const ACCESS_TOKEN = 'mock-access-token';

  function makeProvider(jwt = 'mock.jwt.token') {
    return {
      requestAgentCredential: vi.fn().mockResolvedValue({ jwt, issuerDid: 'did:key:zIssuer' }),
    };
  }

  const requestedOptions = { columns: ['patients.name'], actions: ['read'], expiresIn: '4h' };

  it('calls provider normally when no ceiling is supplied (backwards-compatible)', async () => {
    const provider = makeProvider();
    const result = await issueCredentialFromParent(
      provider,
      ACCESS_TOKEN,
      AGENT_DID,
      requestedOptions,
    );
    expect(result.jwt).toBe('mock.jwt.token');
    expect(provider.requestAgentCredential).toHaveBeenCalledOnce();
  });

  it('calls provider when ceiling accepts the requested scope', async () => {
    const provider = makeProvider();
    const ceiling: ScopeCeiling = {
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      source: 'oidc-claims',
      resolvedFrom: ['scope_columns'],
    };
    const result = await issueCredentialFromParent(
      provider,
      ACCESS_TOKEN,
      AGENT_DID,
      requestedOptions,
      { ceiling },
    );
    expect(result.jwt).toBe('mock.jwt.token');
    expect(provider.requestAgentCredential).toHaveBeenCalledOnce();
  });

  it('throws ScopeExceedsCeilingError and does NOT call provider when ceiling rejects', async () => {
    const provider = makeProvider();
    const restrictiveCeiling: ScopeCeiling = {
      columns: ['patients.dob'], // does not include patients.name
      actions: ['read'],
      source: 'oidc-claims',
      resolvedFrom: ['scope_columns'],
    };
    await expect(
      issueCredentialFromParent(provider, ACCESS_TOKEN, AGENT_DID, requestedOptions, {
        ceiling: restrictiveCeiling,
      }),
    ).rejects.toThrowError(ScopeExceedsCeilingError);
    expect(provider.requestAgentCredential).not.toHaveBeenCalled();
  });

  it('enforces ceiling without context (scope-only check, no policy rules)', async () => {
    // Ceiling with no rules — scope check still runs even with undefined context.
    const provider = makeProvider();
    const ceilingNoContext: ScopeCeiling = {
      columns: ['patients.name'],
      actions: ['read'],
      source: 'oidc-claims',
      resolvedFrom: [],
    };
    const result = await issueCredentialFromParent(
      provider,
      ACCESS_TOKEN,
      AGENT_DID,
      requestedOptions,
      { ceiling: ceilingNoContext }, // no context provided
    );
    expect(result.jwt).toBe('mock.jwt.token');
    expect(provider.requestAgentCredential).toHaveBeenCalledOnce();
  });
});

// Each test mutates process.env.NODE_ENV and restores it in afterEach.
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

  it('succeeds when NODE_ENV=test', () => {
    process.env.NODE_ENV = 'test';
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    expect(() => createMockSession(verifier)).not.toThrow();
  });

  it('succeeds when NODE_ENV=development', () => {
    process.env.NODE_ENV = 'development';
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    expect(() => createMockSession(verifier)).not.toThrow();
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

  it('throws when NODE_ENV is unset (treats as production)', () => {
    delete process.env.NODE_ENV;
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    expect(() => createMockSession(verifier)).toThrow('createSessionFromDid');
  });
});
