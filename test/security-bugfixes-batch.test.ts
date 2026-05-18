import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateDidKey,
  createSigner,
  createJwt,
  issueCredential,
  decodeJwt,
  VcVerifier,
  InMemoryRevocationStore,
} from '../src/index.js';
import { issueDelegatedCredential } from '../src/auth/index.js';
import { AgentIdentity } from '../src/agent-identity.js';
import { resolveDidKeyFallback } from '../src/did-resolve.js';
import { DidResolutionFailedError } from '../src/errors.js';
import { base58Encode } from '../src/crypto/base58.js';
import { createMockSession } from '../src/auth/session-factory.js';
import { asMasterKey } from '../src/crypto/master-key.js';
import { deriveSessionMacKey } from '../src/storage/envelope-mac.js';
import { InMemorySessionStore } from '../src/storage/memory/session-store.js';
import type { ScopeCeiling } from '../src/auth/ceiling.js';
import type { StorageBackend, AgentStore, AuditStore, ContextStore, AgentRecord } from '../src/storage/types.js';
import type { AuditRecord } from '../src/types.js';

describe('VcVerifier.verify() rejects credentials with malformed base58 DID keys', () => {
  it('resolveDidKeyFallback throws DidResolutionFailedError for invalid base58', () => {
    // I, O, l are not valid base58 characters
    expect(() => resolveDidKeyFallback('did:key:zINVALIDBASE58OLIO')).toThrow(
      DidResolutionFailedError,
    );
  });

  it('verify() returns MALFORMED for a credential with an invalid-base58 issuer DID', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const badIss = 'did:key:zINVALIDBASE58OLIO';
    const fakePayload = {
      iss: badIss,
      sub: 'did:key:z123',
      vc: { credentialSubject: { scope: { columns: ['email'] } } },
    };
    const jwt =
      'eyJhbGciOiJFZERTQSJ9.' +
      Buffer.from(JSON.stringify(fakePayload)).toString('base64url') +
      '.fakesig';

    const result = await verifier.verify(jwt);
    expect(result.valid).toBe(false);
    expect(result.status).toMatch(/MALFORMED|UNKNOWN_ISSUER/);
  });
});

describe('VcVerifier rejects clockSkew exceeding 30 seconds', () => {
  it('accepts clockSkew within 30-second limit', () => {
    expect(
      () => new VcVerifier({ clockSkew: '25s', revocationStore: new InMemoryRevocationStore() }),
    ).not.toThrow();
  });

  it('accepts the default 5s clockSkew', () => {
    expect(
      () => new VcVerifier({ revocationStore: new InMemoryRevocationStore() }),
    ).not.toThrow();
  });

  it('rejects clockSkew exceeding 30 seconds', () => {
    expect(
      () => new VcVerifier({ clockSkew: '45s', revocationStore: new InMemoryRevocationStore() }),
    ).toThrow(/exceeds maximum of 30 seconds/);
  });

  it('rejects absurd clockSkew values', () => {
    expect(
      () => new VcVerifier({ clockSkew: '365d', revocationStore: new InMemoryRevocationStore() }),
    ).toThrow(/exceeds maximum of 30 seconds/);
  });
});

describe('issueDelegatedCredential enforces operator delegation depth limit', () => {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();
  const subWorker = generateDidKey();

  let hop1: string;

  beforeAll(async () => {
    hop1 = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
  });

  it('allows single-hop delegation (human → supervisor → worker)', async () => {
    const decoded = decodeJwt(hop1);
    await expect(
      issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        hop1,
        decoded.payload.jti!,
        { columns: ['patients.name'], actions: ['read'] },
        { targetAgent: worker.did, columns: ['patients.name'], actions: ['read'], expiresIn: '2h' },
      ),
    ).resolves.toBeDefined();
  });

});


describe('session factories enforce credentialMaxTtlMs ceiling on credential issuance', () => {
  it('rejects credential issuance exceeding ceiling TTL', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const ceiling: ScopeCeiling = {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
      credentialMaxTtlMs: 4 * 3600 * 1000, // 4 hours
    };
    const session = createMockSession(verifier, 'TTL Test', undefined, ceiling);
    const agent = generateDidKey();

    await expect(
      session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '24h', // exceeds 4h ceiling
      }),
    ).rejects.toThrow(/exceeds maximum credential TTL/);
  });

  it('allows credential issuance within ceiling TTL', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const ceiling: ScopeCeiling = {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
      credentialMaxTtlMs: 4 * 3600 * 1000,
    };
    const session = createMockSession(verifier, 'TTL OK Test', undefined, ceiling);
    const agent = generateDidKey();

    const jwt = await session.issueCredential({
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '2h',
    });
    expect(jwt).toBeTruthy();
  });

  it('skips TTL check when credentialMaxTtlMs is not set', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const session = createMockSession(verifier, 'No TTL Limit');
    const agent = generateDidKey();

    const jwt = await session.issueCredential({
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '36500d', // ~100 years — passes with no ceiling
    });
    expect(jwt).toBeTruthy();
  });
});

describe('clockSkew error message does not leak config value', () => {
  it('error message omits the raw clockSkew value', () => {
    try {
      new VcVerifier({ clockSkew: '999h', revocationStore: new InMemoryRevocationStore() });
      expect.unreachable('should have thrown');
    } catch (e: any) {
      expect(e.message).not.toContain('999h');
      expect(e.message).toContain('exceeds maximum of 30 seconds');
    }
  });
});

describe('resolveDidKeyFallback rejects wrong-length Ed25519 keys', () => {
  it('rejects a DID with correct prefix but truncated key', () => {
    // 0xed01 prefix + only 16 bytes instead of 32 = 18 bytes total
    const shortKey = new Uint8Array([0xed, 0x01, ...new Array(16).fill(0x42)]);
    const encoded = 'z' + base58Encode(shortKey);
    const did = `did:key:${encoded}`;
    expect(() => resolveDidKeyFallback(did as any)).toThrow(DidResolutionFailedError);
    expect(() => resolveDidKeyFallback(did as any)).toThrow(/Expected 34 bytes/);
  });

  it('rejects a DID with correct prefix but extra bytes appended', () => {
    const longKey = new Uint8Array([0xed, 0x01, ...new Array(64).fill(0x42)]);
    const encoded = 'z' + base58Encode(longKey);
    const did = `did:key:${encoded}`;
    expect(() => resolveDidKeyFallback(did as any)).toThrow(DidResolutionFailedError);
    expect(() => resolveDidKeyFallback(did as any)).toThrow(/Expected 34 bytes/);
  });

  it('accepts a correctly-sized Ed25519 DID key', () => {
    const validKey = new Uint8Array([0xed, 0x01, ...new Array(32).fill(0x42)]);
    const encoded = 'z' + base58Encode(validKey);
    const did = `did:key:${encoded}`;
    const result = resolveDidKeyFallback(did as any);
    expect(result.length).toBe(32);
  });
});

describe('VcVerifier rejects zero clockSkew', () => {
  it('rejects clockSkew of 0s', () => {
    expect(
      () => new VcVerifier({ clockSkew: '0s', revocationStore: new InMemoryRevocationStore() }),
    ).toThrow(/must be greater than zero/);
  });

  it('accepts minimal positive clockSkew', () => {
    expect(
      () => new VcVerifier({ clockSkew: '1s', revocationStore: new InMemoryRevocationStore() }),
    ).not.toThrow();
  });
});


function buildTestStorage(): StorageBackend {
  const testMasterKey = asMasterKey(Buffer.alloc(32, 0x99));
  const sessionMacKey = deriveSessionMacKey(testMasterKey);
  const agents = new Map<string, AgentRecord>();
  const agentStore: AgentStore = {
    async create(agent) {
      const record = { ...agent, createdAt: new Date().toISOString() };
      agents.set(agent.did, record);
      return record;
    },
    async findByDid(did) { return agents.get(did) ?? null; },
    async list(filter) {
      let result = Array.from(agents.values());
      if (filter?.ownerDid) result = result.filter((a) => a.ownerDid === filter.ownerDid);
      return result.slice(0, Math.min(filter?.limit ?? 100, 100));
    },
    async listAll() { return Array.from(agents.values()); },
    async count() { return agents.size; },
  };
  const auditRecords: AuditRecord[] = [];
  const auditStore: AuditStore = {
    async append(r) { auditRecords.push(r); },
    async loadLastRecord() { return auditRecords.at(-1) ?? null; },
    async loadLastRecordLocked() { return auditRecords.at(-1) ?? null; },
    async query() { return [...auditRecords]; },
    async count() { return auditRecords.length; },
  };
  const contextStore: ContextStore = {
    async put(entry) { return { ...entry, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }; },
    async get() { return null; },
    async list() { return []; },
    async delete() { return false; },
  };
  return {
    agents: agentStore,
    audit: auditStore,
    context: contextStore,
    revocation: new InMemoryRevocationStore(),
    sessions: new InMemorySessionStore(sessionMacKey),
    async initialize() {},
    async close() {},
  };
}

describe('config.credential.maxTtl merges into effective ceiling', () => {
  it('enforces config maxTtl when no caller ceiling is provided', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { credential: { maxTtl: '4h' } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xa1)) },
    );
    const session = await identity.authenticate({ mockHumanDid: 'did:key:z6MkCfgTtl' });
    const agent = generateDidKey();

    await expect(
      session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '24h',
      }),
    ).rejects.toThrow(/exceeds maximum credential TTL/);

    const jwt = await session.issueCredential({
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '2h',
    });
    expect(jwt).toBeTruthy();
    identity.close();
  });

  it('config maxTtl wins when stricter than caller ceiling', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { credential: { maxTtl: '2h' } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xa2)) },
    );
    const callerCeiling: ScopeCeiling = {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
      credentialMaxTtlMs: 8 * 3600 * 1000, // 8h — looser than config's 2h
    };
    const session = await identity.authenticate({
      mockHumanDid: 'did:key:z6MkCfgWins',
      scopeCeiling: callerCeiling,
    });
    const agent = generateDidKey();

    await expect(
      session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h', // exceeds config's 2h
      }),
    ).rejects.toThrow(/exceeds maximum credential TTL/);
    identity.close();
  });

  it('caller ceiling wins when stricter than config maxTtl', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { credential: { maxTtl: '8h' } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xa3)) },
    );
    const callerCeiling: ScopeCeiling = {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
      credentialMaxTtlMs: 2 * 3600 * 1000, // 2h — stricter than config's 8h
    };
    const session = await identity.authenticate({
      mockHumanDid: 'did:key:z6MkCallerWins',
      scopeCeiling: callerCeiling,
    });
    const agent = generateDidKey();

    await expect(
      session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h', // exceeds caller's 2h
      }),
    ).rejects.toThrow(/exceeds maximum credential TTL/);
    identity.close();
  });

  it('no enforcement when neither config maxTtl nor caller ceiling is set', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      {},
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xa4)) },
    );
    const session = await identity.authenticate({ mockHumanDid: 'did:key:z6MkNoLimit' });
    const agent = generateDidKey();

    const jwt = await session.issueCredential({
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '36500d',
    });
    expect(jwt).toBeTruthy();
    identity.close();
  });
});

describe('delegation depth hardening', () => {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();
  const subWorker = generateDidKey();

  let hop1: string;

  beforeAll(async () => {
    hop1 = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
  });

  it('rejects empty delegationChain at issuance', async () => {
    const now = Math.floor(Date.now() / 1000);
    const craftedJwt = await createJwt(
      {
        iss: human.did,
        sub: supervisor.did,
        jti: 'crafted-empty-chain',
        iat: now,
        exp: now + 3600,
        delegationChain: [],
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: supervisor.did,
            scope: { columns: ['patients.name'], actions: ['read'] },
          },
        },
      },
      human.privateKey,
    );

    await expect(
      issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        craftedJwt,
        'crafted-empty-chain',
        { columns: ['patients.name'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      ),
    ).rejects.toThrow(/empty delegationChain/);
  });

  it('rejects empty delegationChain at verification', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const now = Math.floor(Date.now() / 1000);
    const craftedJwt = await createJwt(
      {
        iss: human.did,
        sub: supervisor.did,
        jti: 'crafted-empty-chain-verify',
        iat: now,
        exp: now + 3600,
        delegationChain: [],
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: supervisor.did,
            scope: { columns: ['patients.name'], actions: ['read'] },
          },
        },
      },
      human.privateKey,
    );

    const result = await verifier.verify(craftedJwt);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/empty delegationChain/);
  });

});
