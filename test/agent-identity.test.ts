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

// Tests for the standalone AgentIdentity factory (SQL-free identity layer).

import { describe, it, expect, vi } from 'vitest';
import { AgentIdentity } from '../src/agent-identity.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { InMemorySessionStore } from '../src/storage/memory/session-store.js';
import { asMasterKey } from '../src/crypto/master-key.js';
import { deriveSessionMacKey } from '../src/storage/envelope-mac.js';
import type {
  StorageBackend,
  AgentStore,
  AuditStore,
  ContextStore,
  AgentRecord,
} from '../src/storage/types.js';
import type { AuditRecord } from '../src/types.js';

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
  it('creates via standalone factory', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xab)) },
    );
    expect(identity.verifierDid).toMatch(/^did:key:/);
    identity.close();
  });

  it('_createWithInternals returns tuple with internals', async () => {
    const storage = buildTestStorage();
    const [identity, internals] = await AgentIdentity._createWithInternals(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xcd)) },
    );
    expect(identity).toBeInstanceOf(AgentIdentity);
    expect(internals.verifier).toBeDefined();
    expect(internals.auditLogger).toBeDefined();
    expect(internals.agentsMap).toBeInstanceOf(Map);
    expect(internals.verifierDid).toMatch(/^did:key:/);
    expect(internals.storage).toBe(storage);
    identity.close();
  });

  it('accepts injected serverIdentity', async () => {
    const storage = buildTestStorage();
    // Use a known server identity
    const { generateDidKey } = await import('../src/auth/agent.js');
    const serverKey = generateDidKey();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      {
        storage,
        masterKey: asMasterKey(Buffer.alloc(32, 0xef)),
        serverIdentity: { did: serverKey.did, publicKey: serverKey.publicKey },
      },
    );
    expect(identity.verifierDid).toBe(serverKey.did);
    identity.close();
  });

  it('getStatus returns counts', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x11)) },
    );
    const status = await identity.getStatus();
    expect(status.agentCount).toBe(0);
    expect(status.auditRecordCount).toBe(0);
    expect(status.inMemoryAgents).toBe(0);
    identity.close();
  });

  it('toJSON redacts masterKey', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x22)) },
    );
    const json = identity.toJSON();
    expect(json.masterKey).toBe('[REDACTED 32 bytes]');
    expect(json.verifierDid).toMatch(/^did:key:/);
    expect(json.sdk).toBe('[none]');
    identity.close();
  });

  it('close() zeros the masterKey buffer', async () => {
    const storage = buildTestStorage();
    const keyBuf = Buffer.alloc(32, 0x33);
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(keyBuf) },
    );
    identity.close();
    expect(keyBuf.every((b) => b === 0)).toBe(true);
  });

  it('exposes verifierInstance and auditLoggerInstance', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x44)) },
    );
    expect(identity.verifierInstance).toBeDefined();
    expect(identity.auditLoggerInstance).toBeDefined();
    identity.close();
  });

  it('authenticate (mock) returns a session with humanDid', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true }, devMode: true },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x55)) },
    );
    const session = await identity.authenticate({ mockHumanDid: 'did:key:z6MkTest' });
    expect(session.humanDid).toMatch(/^did:key:/);
    expect(typeof session.issueCredential).toBe('function');
    identity.close();
  });

  it('createAgent + listAgents round-trip', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true }, devMode: true },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x66)) },
    );
    const session = await identity.authenticate({ mockHumanDid: 'did:key:z6MkOwner' });
    const agent = await identity.createAgent({ name: 'test-agent', ownerDid: session.humanDid });
    expect(agent.did).toMatch(/^did:key:/);
    expect(agent.name).toBe('test-agent');
    expect(agent.ownerDid).toBe(session.humanDid);

    const agents = await identity.listAgents({ ownerDid: session.humanDid });
    expect(agents).toHaveLength(1);
    expect(agents[0].did).toBe(agent.did);
    identity.close();
  });

  it('delegateCredential round-trip', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true }, devMode: true },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x77)) },
    );
    const session = await identity.authenticate({ mockHumanDid: 'did:key:z6MkDelegator' });

    const supervisor = await identity.createAgent({
      name: 'supervisor',
      ownerDid: session.humanDid,
    });
    const worker = await identity.createAgent({ name: 'worker', ownerDid: session.humanDid });

    const cred = await session.issueCredential({
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '1h',
    });

    const delegated = await identity.delegateCredential(supervisor.did, cred, {
      targetAgent: worker.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '30m',
    });
    expect(typeof delegated).toBe('string');
    expect(delegated.split('.').length).toBe(3);
    identity.close();
  });

  it('emits structured log event when agents table is missing', async () => {
    const storage = buildTestStorage();
    const pgError = Object.assign(new Error('relation "agents" does not exist'), { code: '42P01' });
    storage.agents.listAll = async () => { throw pgError; };

    const spy = vi.spyOn(console, 'info').mockImplementation(() => {});
    try {
      const identity = await AgentIdentity.create(
        { audit: { enabled: true } },
        { storage, masterKey: asMasterKey(Buffer.alloc(32, 0xaa)) },
      );

      expect(spy).toHaveBeenCalledOnce();
      const event = JSON.parse(spy.mock.calls[0][0] as string);
      expect(event).toMatchObject({
        event: 'restore_agents_schema_missing',
        level: 'INFO',
        schema: 'public',
        table: 'agents',
      });
      expect(event.nextStep).toContain('migrate');
      expect(event.message).toBeDefined();
      identity.close();
    } finally {
      spy.mockRestore();
    }
  });

  it('throws on method calls after close()', async () => {
    const storage = buildTestStorage();
    const identity = await AgentIdentity.create(
      { audit: { enabled: true } },
      { storage, masterKey: asMasterKey(Buffer.alloc(32, 0x88)) },
    );
    identity.close();

    await expect(identity.authenticate()).rejects.toThrow('AgentIdentity has been closed');
    await expect(identity.createAgent({ name: 'x', ownerDid: 'did:key:z6Mk1' })).rejects.toThrow(
      'AgentIdentity has been closed',
    );
    await expect(identity.listAgents()).rejects.toThrow('AgentIdentity has been closed');
    await expect(identity.getStatus()).rejects.toThrow('AgentIdentity has been closed');
  });
});
