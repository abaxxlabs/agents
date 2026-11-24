import { describe, it, expect, vi } from 'vitest';
import { generateDidKey, createSigner, issueCredential } from '#auth/index.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { ScopeEngine } from '#sql/scope-engine.js';
import { AuditLogger } from '#audit/index.js';
import { CredentialInvalidError, QueryRejectedError } from '#errors/index.js';
import type { AgentStore, AuditStore } from '#storage/types.js';
import type { Pool } from 'pg';

const noopAuditStore: AuditStore = {
  append: vi.fn().mockResolvedValue(undefined),
  loadLastRecord: vi.fn().mockResolvedValue(null),
  loadLastRecordLocked: vi.fn().mockResolvedValue(null),
  query: vi.fn().mockResolvedValue([]),
  count: vi.fn().mockResolvedValue(0),
};

const noopAgentStore = { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore;

describe('AgentSigner opaque handle', () => {
  it('private key is not accessible from signer', () => {
    const { privateKey } = generateDidKey();
    const signer = createSigner(privateKey);

    const keys = Object.keys(signer);
    expect(keys).toEqual(['signJwt']);
    expect((signer as { privateKey?: unknown }).privateKey).toBeUndefined();
    expect((signer as { key?: unknown }).key).toBeUndefined();
  });
});

describe('Explicit table declaration', () => {
  it('rejects attempts to authorize one table while reading another table', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = {
      query: vi.fn().mockResolvedValue({ rows: [{ name: 'Mallory' }], rowCount: 1 }),
    } as unknown as Pool;

    const agents = new Map([
      [
        agent.did,
        {
          did: agent.did,
          name: 'Test Agent',
          ownerDid: human.did,
          signer: createSigner(agent.privateKey),
          publicKey: agent.publicKey,
        },
      ],
    ]);

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger: new AuditLogger({ auditStore: noopAuditStore, enabled: false }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents,
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agent.did,
        credential,
        table: 'patients',
        sql: 'SELECT name FROM employees',
      }),
    ).rejects.toThrow(QueryRejectedError);
  });
});

describe('Remote presentation enforcement', () => {
  async function createPresentationFixtures() {
    const human = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();
    const signer = createSigner(agent.privateKey);

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = {
      query: vi.fn().mockResolvedValue({ rows: [{ name: 'Jane' }], rowCount: 1 }),
    } as unknown as Pool;

    const agents = new Map([
      [
        agent.did,
        {
          did: agent.did,
          name: 'Test Agent',
          ownerDid: human.did,
          signer,
          publicKey: agent.publicKey,
        },
      ],
    ]);

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger: new AuditLogger({ auditStore: noopAuditStore, enabled: false }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents,
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    return { agent, server, signer, engine, credential, pool };
  }

  it('rejects raw credentials when the caller requires an agent-signed presentation', async () => {
    const { agent, engine, credential, pool } = await createPresentationFixtures();

    await expect(
      engine.query({
        agent: agent.did,
        credential,
        table: 'patients',
        sql: 'SELECT name FROM patients',
        requirePresentation: true,
      }),
    ).rejects.toThrow(CredentialInvalidError);
    expect(pool.query).not.toHaveBeenCalled();
  });
});

describe('SQL SELECT restriction', () => {
  it('rejects INSERT queries', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = { query: vi.fn() } as unknown as Pool;
    const agents = new Map([
      [
        agent.did,
        {
          did: agent.did,
          name: 'Test Agent',
          ownerDid: human.did,
          signer: createSigner(agent.privateKey),
          publicKey: agent.publicKey,
        },
      ],
    ]);

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger: new AuditLogger({ auditStore: noopAuditStore, enabled: false }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents,
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agent.did,
        credential,
        table: 'patients',
        sql: "INSERT INTO patients (name) VALUES ('evil')",
      }),
    ).rejects.toThrow('InsertStmt');
  });

  it('rejects writable CTE (DELETE hidden inside WITH)', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = { query: vi.fn() } as unknown as Pool;
    const agents = new Map([
      [
        agent.did,
        {
          did: agent.did,
          name: 'Test Agent',
          ownerDid: human.did,
          signer: createSigner(agent.privateKey),
          publicKey: agent.publicKey,
        },
      ],
    ]);

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger: new AuditLogger({ auditStore: noopAuditStore, enabled: false }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents,
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agent.did,
        credential,
        table: 'patients',
        sql: 'WITH x AS (DELETE FROM patients RETURNING *) SELECT * FROM x',
      }),
    ).rejects.toThrow('DeleteStmt');
  });
});

describe('unregistered agent fail-closed', () => {
  it('rejects query from unregistered agent', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = {
      query: vi.fn().mockResolvedValue({ rows: [{ name: 'Jane' }], rowCount: 1 }),
    } as unknown as Pool;

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger: new AuditLogger({ auditStore: noopAuditStore, enabled: false }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents: new Map(),
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agent.did,
        credential,
        table: 'patients',
        sql: 'SELECT name FROM patients',
      }),
    ).rejects.toThrow('not registered');
  });
});
