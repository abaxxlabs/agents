import { describe, it, expect } from 'vitest';
import { AgentIdentity, VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { InMemorySessionStore } from '#storage/memory/session-store.js';
import { asMasterKey } from '#crypto/master-key.js';
import { deriveSessionMacKey } from '#storage/envelope-mac.js';
import { generateDidKey } from '#auth/index.js';
import { createMockSession } from '#auth/session-factory.js';
import type { ScopeCeiling } from '#auth/ceiling.js';
import type {
  StorageBackend,
  AgentStore,
  AuditStore,
  ContextStore,
  AgentRecord,
} from '#storage/types.js';
import type { AuditRecord } from '#types/index.js';

function createInMemoryAgentStore(): AgentStore {
  const agents = new Map<string, AgentRecord>();
  return {
    async create(agent) {
      const record = { ...agent, createdAt: new Date().toISOString() };
      agents.set(agent.did, record);
      return record;
    },
    async findByDid(did) {
      return agents.get(did) ?? null;
    },
    async list(filter) {
      let result = Array.from(agents.values());
      if (filter?.ownerDid) {
        result = result.filter((a) => a.ownerDid === filter.ownerDid);
      }
      const limit = Math.min(filter?.limit ?? 100, 100);
      return result.slice(0, limit);
    },
    async listAll() {
      return Array.from(agents.values());
    },
    async count() {
      return agents.size;
    },
  };
}

function createInMemoryAuditStore(): AuditStore {
  const records: AuditRecord[] = [];
  return {
    async append(record) {
      records.push(record);
    },
    async loadLastRecord() {
      return records.length > 0 ? records[records.length - 1] : null;
    },
    async loadLastRecordLocked() {
      return records.length > 0 ? records[records.length - 1] : null;
    },
    async query() {
      return [...records];
    },
    async count() {
      return records.length;
    },
  };
}

function createInMemoryContextStore(): ContextStore {
  return {
    async put(entry, _identity) {
      return { ...entry, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    },
    async get() {
      return null;
    },
    async list() {
      return [];
    },
    async delete() {
      return false;
    },
  };
}

function buildTestStorage(): StorageBackend {
  // InMemorySessionStore requires a MAC key derived from a master key.
  const testMasterKey = asMasterKey(Buffer.alloc(32, 0x99));
  const sessionMacKey = deriveSessionMacKey(testMasterKey);
  const base: StorageBackend = {
    agents: createInMemoryAgentStore(),
    audit: createInMemoryAuditStore(),
    context: createInMemoryContextStore(),
    revocation: new InMemoryRevocationStore(),
    sessions: new InMemorySessionStore(sessionMacKey),
    async initialize() {},
    async close() {},
  };
  return base;
}

describe('AgentIdentity', () => {
  it('close() zeros the SDK-internal copy of the master key', async () => {
    const storage = buildTestStorage();
    const keyBuf = Buffer.alloc(32, 0x55);
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(keyBuf) },
    );
    identity.close();
    const internalKey: Buffer = (identity as unknown as { masterKey: Buffer }).masterKey;
    expect(internalKey.every((b: number) => b === 0x00)).toBe(true);
    expect(keyBuf.every((b) => b === 0x55)).toBe(true);
  });

  it('createPresentationForAgent rejects non-owner requester', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true }, devMode: true },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x57)) },
    );
    const ownerSession = await identity.authenticate({ mockHumanDid: 'did:key:z6MkOwner' });
    const otherSession = await identity.authenticate({ mockHumanDid: 'did:key:z6MkOther' });
    const agent = await identity.createAgentIdentity({
      name: 'presenter',
      ownerDid: ownerSession.humanDid,
    });
    const credential = await ownerSession.issueCredential({
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });

    await expect(
      identity.createPresentationForAgent({
        agentDid: agent.did,
        credential,
        requesterDid: otherSession.humanDid,
      }),
    ).rejects.toThrow(/does not own agent/i);

    identity.close();
  });
});

describe('session factory credentialMaxTtlMs ceiling', () => {
  it('rejects credential issuance exceeding ceiling TTL', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const ceiling: ScopeCeiling = {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
      credentialMaxTtlMs: 4 * 3600 * 1000,
    };
    const session = createMockSession(verifier, 'TTL Test', undefined, ceiling);
    const agent = generateDidKey();

    await expect(
      session.issueCredential({
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '24h',
      }),
    ).rejects.toThrow(/exceeds maximum credential TTL/);
  });
});
