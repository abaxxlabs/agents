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

import { describe, it, expect, vi } from 'vitest';
import { generateDidKey, createSigner, issueCredential } from '../src/auth/index.js';
import { createJwt, VcVerifier, verifyJwtSignature } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { decryptRow, encrypt, generateColumnKey } from '../src/column-encryption.js';
import { asMasterKey } from '../src/crypto/master-key.js';
import { ScopeEngine } from '../src/sql/scope-engine.js';
import { AuditLogger } from '../src/audit-logger.js';
import { createPresentation } from '../src/identity/presentation.js';
import { CredentialInvalidError, QueryRejectedError } from '../src/errors.js';
import type { AgentStore, AuditStore } from '../src/storage/types.js';
import type { Pool } from 'pg';

/** No-op AuditStore for tests that disable auditing (enabled: false). */
const noopAuditStore: AuditStore = {
  append: vi.fn().mockResolvedValue(undefined),
  loadLastRecord: vi.fn().mockResolvedValue(null),
  loadLastRecordLocked: vi.fn().mockResolvedValue(null),
  query: vi.fn().mockResolvedValue([]),
  count: vi.fn().mockResolvedValue(0),
};

/** No-op AgentStore for ScopeEngine owner-lookup fallback. Returns null (agent not found). */
const noopAgentStore = { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore;

describe('AgentSigner opaque handle', () => {
  it('signJwt produces a valid JWT', async () => {
    const { privateKey, publicKey } = generateDidKey();
    const signer = createSigner(privateKey);

    const jwt = await signer.signJwt({ iss: 'test', sub: 'test', iat: 123 });
    expect(jwt.split('.').length).toBe(3); // header.payload.signature

    // Verify with the public key
    expect(await verifyJwtSignature(jwt, publicKey)).toBe(true);
  });

  it('signer is frozen (immutable)', () => {
    const { privateKey } = generateDidKey();
    const signer = createSigner(privateKey);

    expect(Object.isFrozen(signer)).toBe(true);
    expect(() => {
      (signer as { extract?: () => void }).extract = () => {};
    }).toThrow();
  });

  it('private key is not accessible from signer', () => {
    const { privateKey } = generateDidKey();
    const signer = createSigner(privateKey);

    // The signer should only have signJwt — no privateKey, no key, no extract
    const keys = Object.keys(signer);
    expect(keys).toEqual(['signJwt']);
    expect((signer as { privateKey?: unknown }).privateKey).toBeUndefined();
    expect((signer as { key?: unknown }).key).toBeUndefined();
  });

  it('signer works with audit logger', async () => {
    const agent = generateDidKey();
    const human = generateDidKey();
    const signer = createSigner(agent.privateKey);

    const logger = new AuditLogger({ auditStore: noopAuditStore, enabled: false });

    const record = await logger.log(
      {
        agentDid: agent.did,
        ownerDid: human.did,
        credentialJwt: 'test',
        sql: 'SELECT 1',
        columnsAccessed: [],
        rowCount: 0,
        durationMs: 0,
      },
      signer,
    );

    expect(record.signature).toBeDefined();
    expect(record.signature.split('.').length).toBe(3);
    // Verify the signature
    const verified = await logger.verifyRecord(record, agent.publicKey);
    expect(verified).toBe(true);
  });
});

describe('Explicit table declaration', () => {
  it('requires options.table to match the SQL base table', async () => {
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

    const key = generateColumnKey();
    const columnKeys = new Map([['patients.dob', key]]);
    const encryptedColumns = new Set(['patients.dob']);

    const sampleRows = [{ id: 1, name: 'Jane', dob: encrypt('1990-03-15', key) }];
    const pool = {
      query: vi.fn().mockResolvedValue({ rows: sampleRows, rowCount: 1 }),
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
      columnKeys,
      encryptedColumns,
      agents,
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.id', 'patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // With correct table name — dob should be decrypted
    const result = await engine.query({
      agent: agent.did,
      credential,
      table: 'patients',
      sql: 'SELECT id, name, dob FROM patients',
    });
    expect(result.rows[0].dob).toBe('1990-03-15');

    // Issue a fresh credential for the second query (replay protection)
    const credential2 = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.id', 'patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agent.did,
        credential: credential2,
        table: 'wrong_table',
        sql: 'SELECT id, name, dob FROM patients',
      }),
    ).rejects.toThrow(QueryRejectedError);
  });

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

  it('rejects schema-qualified table swaps with the same relation name', async () => {
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
        sql: 'SELECT name FROM private.patients',
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

  it('accepts an agent-signed presentation on remote query paths', async () => {
    const { agent, server, signer, engine, credential } = await createPresentationFixtures();
    const presentation = await createPresentation(credential, agent.did, signer, {
      audience: server.did,
    });

    const result = await engine.query({
      agent: agent.did,
      credential: presentation,
      table: 'patients',
      sql: 'SELECT name FROM patients',
      requirePresentation: true,
    });

    expect(result.rows[0].name).toBe('Jane');
  });
});

describe('C1: Issuer authorization check', () => {
  it('rejects credential issued by non-owner', async () => {
    const human = generateDidKey();
    const impostor = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(impostor.did, impostor.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = {
      query: vi.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    } as unknown as Pool;

    const agents = new Map([
      [
        agent.did,
        {
          did: agent.did,
          name: 'Test Agent',
          ownerDid: human.did, // Agent is owned by human
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

    // Credential issued by impostor (not the agent's owner)
    const credential = await issueCredential(impostor.did, impostor.privateKey, {
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
    ).rejects.toThrow('not the registered owner');
  });

  it('accepts credential issued by actual owner', async () => {
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
      query: vi.fn().mockResolvedValue({ rows: [{ id: 1, name: 'Jane' }], rowCount: 1 }),
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

    const result = await engine.query({
      agent: agent.did,
      credential,
      table: 'patients',
      sql: 'SELECT name FROM patients',
    });

    expect(result.rows.length).toBe(1);
  });
});

describe('E-1: SQL SELECT restriction', () => {
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

  it('rejects DELETE queries', async () => {
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
        sql: 'DELETE FROM patients WHERE id = 1',
      }),
    ).rejects.toThrow('DeleteStmt');
  });

  it('allows WITH (CTE) queries', async () => {
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

    const result = await engine.query({
      agent: agent.did,
      credential,
      table: 'patients',
      sql: 'WITH recent AS (SELECT name FROM patients) SELECT name FROM recent',
    });

    expect(result.rows.length).toBe(1);
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

  it('rejects invalid SQL syntax', async () => {
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
        sql: 'NOT VALID SQL AT ALL',
      }),
    ).rejects.toThrow('SQL parse error');
  });
});

describe('E-2: Scope union issuer consistency', () => {
  it('rejects multi-VC from different issuers', async () => {
    const human1 = generateDidKey();
    const human2 = generateDidKey();
    const agent = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human1.did, human1.publicKey);
    verifier.registerKey(human2.did, human2.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const pool = {
      query: vi.fn().mockResolvedValue({ rows: [{ name: 'Jane' }], rowCount: 1 }),
    } as unknown as Pool;

    // Agent is owned by human1 — but we'll make both issuers look like owners
    // by not registering the agent (so C1 check is skipped)
    // Actually, let's register agent with human1 as owner
    const agents = new Map([
      [
        agent.did,
        {
          did: agent.did,
          name: 'Test Agent',
          ownerDid: human1.did,
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

    const cred1 = await issueCredential(human1.did, human1.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Second credential from human2 — different issuer
    const cred2 = await issueCredential(human2.did, human2.privateKey, {
      agent: agent.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // C1 catches this first (issuer not owner), but E-2 is defense-in-depth
    await expect(
      engine.query({
        agent: agent.did,
        credential: cred1,
        credentials: [cred2],
        table: 'patients',
        sql: 'SELECT name, dob FROM patients',
      }),
    ).rejects.toThrow('not the registered owner');
  });

  it('accepts multi-VC from the same issuer', async () => {
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

    const key = generateColumnKey();
    const pool = {
      query: vi.fn().mockResolvedValue({
        rows: [{ name: 'Jane', dob: encrypt('1990-01-01', key) }],
        rowCount: 1,
      }),
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
      columnKeys: new Map([['patients.dob', key]]),
      encryptedColumns: new Set(['patients.dob']),
      agents,
      verifierDid: server.did,
      agentStore: noopAgentStore,
    });

    const cred1 = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const cred2 = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agent.did,
      credential: cred1,
      credentials: [cred2],
      table: 'patients',
      sql: 'SELECT name, dob FROM patients',
    });

    expect(result.rows[0].name).toBe('Jane');
    expect(result.rows[0].dob).toBe('1990-01-01');
  });
});

describe('R-1: Unregistered agent fail-closed', () => {
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

    // Empty agents map — agent is NOT registered
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

describe('Primary key detection in encryptColumnInPlace', () => {
  it('requires a primary key on the table', async () => {
    // encryptColumnInPlace queries pg_index for primary key
    // If no PK found, it should throw a clear error
    const { encryptColumnInPlace } = await import('../src/sql/column-keys.js');

    const pool = {
      query: vi.fn().mockImplementation(async (sql: string) => {
        if (sql.includes('agent_keys')) {
          return { rows: [{ id: 'key-1' }], rowCount: 1 };
        }
        if (sql.includes('information_schema.columns')) {
          return { rows: [{ data_type: 'text' }] };
        }
        if (sql.includes('agent_columns')) {
          return { rows: [], rowCount: 0 };
        }
        if (sql.includes('pg_index')) {
          return { rows: [] }; // No primary key!
        }
        return { rows: [], rowCount: 0 };
      }),
      connect: vi.fn(),
    } as unknown as Pool;

    // Brand the 32-byte buffer as MasterKey for the new MasterKey-typed
    // signature on encryptColumnInPlace (MasterKey branded type).
    const masterKey = asMasterKey(Buffer.alloc(32, 0xab));

    await expect(encryptColumnInPlace(pool, masterKey, 'test_table', 'secret_col')).rejects.toThrow(
      'no primary key',
    );
  });
});

describe('decryptRow edge cases', () => {
  it('handles non-Buffer encrypted value (base64 string)', () => {
    const key = generateColumnKey();
    const encrypted = encrypt('secret data', key);
    const base64 = encrypted.toString('base64');

    const columnKeys = new Map([['t.col', key]]);
    const encryptedColumns = new Set(['t.col']);

    // In-scope: should convert base64 string to Buffer and decrypt
    const { decrypted } = decryptRow({ col: base64 }, ['t.col'], 't', columnKeys, encryptedColumns);
    expect(decrypted.col).toBe('secret data');
  });

  it('returns ciphertext for out-of-scope encrypted columns', () => {
    const key = generateColumnKey();
    const encrypted = encrypt('secret', key);

    const columnKeys = new Map([['t.col', key]]);
    const encryptedColumns = new Set(['t.col']);

    const { decrypted, columnsEncrypted } = decryptRow(
      { col: encrypted },
      [], // empty scope — nothing authorized
      't',
      columnKeys,
      encryptedColumns,
    );

    expect(typeof decrypted.col).toBe('string'); // base64
    expect(decrypted.col).not.toBe('secret');
    expect(columnsEncrypted).toContain('t.col');
  });

  it('passes through unencrypted columns without scope check', () => {
    const columnKeys = new Map<string, Buffer>();
    const encryptedColumns = new Set<string>();

    const { decrypted } = decryptRow(
      { name: 'Jane', age: 30 },
      [],
      't',
      columnKeys,
      encryptedColumns,
    );

    expect(decrypted.name).toBe('Jane');
    expect(decrypted.age).toBe(30);
  });

  it('handles missing column key gracefully', () => {
    const encryptedColumns = new Set(['t.col']);
    const columnKeys = new Map<string, Buffer>(); // no keys loaded!

    const { decrypted, columnsEncrypted } = decryptRow(
      { col: Buffer.from('encrypted-data') },
      ['t.col'], // in scope, but no key
      't',
      columnKeys,
      encryptedColumns,
    );

    // Should pass through the value unchanged
    expect(decrypted.col).toEqual(Buffer.from('encrypted-data'));
    expect(columnsEncrypted).toContain('t.col');
  });
});

describe('nbf/iat validation', () => {
  it('rejects credential with future iat (not yet valid)', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);

    // Issue a credential with iat 1 hour in the future
    const futureIat = Math.floor(Date.now() / 1000) + 3600;
    const jwt = await createJwt(
      {
        iss: human.did,
        sub: agent.did,
        iat: futureIat,
        exp: futureIat + 14400,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: agent.did,
            scope: { columns: ['patients.name'], actions: ['read'] },
          },
        },
      },
      human.privateKey,
    );

    const result = await verifier.verify(jwt);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('not valid until');
  });

  it('rejects credential with future iat (VC nbf is authoritative, no clockSkew)', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '5s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);

    // VC with iat 10 seconds in the future — no clockSkew tolerance on VC nbf
    const nearFutureIat = Math.floor(Date.now() / 1000) + 10;
    const jwt = await createJwt(
      {
        iss: human.did,
        sub: agent.did,
        iat: nearFutureIat,
        exp: nearFutureIat + 14400,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: agent.did,
            scope: { columns: ['patients.name'], actions: ['read'] },
          },
        },
      },
      human.privateKey,
    );

    const result = await verifier.verify(jwt);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('not valid until');
  });
});

describe('Credential replay protection (jti dedup)', () => {
  it('allows the same VC to be verified multiple times (VCs are reusable)', async () => {
    // W3C VC Data Model: VCs are like a driver's license — reusable until expiry.
    // Replay protection belongs on VPs (presentations), not VCs (credentials).
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);

    const jwt = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result1 = await verifier.verify(jwt);
    expect(result1.valid).toBe(true);

    // Same VC again — should still succeed (VCs are reusable)
    const result2 = await verifier.verify(jwt);
    expect(result2.valid).toBe(true);
  });

  it('rejects a replayed VP (same presentation nonce used twice)', async () => {
    // VPs are single-use presentations. The nonce (jti) prevents replay.
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);

    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Create a VP wrapping the VC
    const { createPresentation } = await import('../src/identity/presentation.js');
    const signer = createSigner(agent.privateKey);
    const vp = await createPresentation(vc, agent.did, signer);

    // First presentation — should succeed
    const result1 = await verifier.verify(vp);
    expect(result1.valid).toBe(true);
    expect(result1.status).toBe('VALID');

    // Replay the same VP — should be rejected
    const result2 = await verifier.verify(vp);
    expect(result2.valid).toBe(false);
    expect(result2.status).toBe('REPLAYED');
    expect(result2.error).toContain('already been used');
  });

  it('allows different credentials with different jtis', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);

    const jwt1 = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const jwt2 = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result1 = await verifier.verify(jwt1);
    expect(result1.valid).toBe(true);

    const result2 = await verifier.verify(jwt2);
    expect(result2.valid).toBe(true);
  });

  it('skips replay check when replayProtection is disabled', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      replayProtection: false,
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);

    const jwt = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result1 = await verifier.verify(jwt);
    expect(result1.valid).toBe(true);

    // Same JWT again — should still succeed with replay protection disabled
    const result2 = await verifier.verify(jwt);
    expect(result2.valid).toBe(true);
  });

  it('skips replay check for credentials without jti', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);

    // Manually create a JWT without jti (legacy format)
    const now = Math.floor(Date.now() / 1000);
    const jwt = await createJwt(
      {
        iss: human.did,
        sub: agent.did,
        iat: now,
        exp: now + 14400,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: agent.did,
            scope: { columns: ['patients.name'], actions: ['read'] },
          },
        },
      },
      human.privateKey,
    );

    const result1 = await verifier.verify(jwt);
    expect(result1.valid).toBe(true);

    // Same JWT again — no jti, so replay check doesn't apply
    const result2 = await verifier.verify(jwt);
    expect(result2.valid).toBe(true);
  });

  it('tracks replay cache size (VPs increment, VCs do not)', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);

    expect(verifier.replayCacheSize).toBe(0);

    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Raw VC does NOT increment replay cache
    await verifier.verify(vc);
    expect(verifier.replayCacheSize).toBe(0);

    // VP DOES increment replay cache
    const { createPresentation } = await import('../src/identity/presentation.js');
    const signer = createSigner(agent.privateKey);
    const vp = await createPresentation(vc, agent.did, signer);
    await verifier.verify(vp);
    expect(verifier.replayCacheSize).toBe(1);

    verifier.clearReplayCache();
    expect(verifier.replayCacheSize).toBe(0);
  });

  it('scope engine wraps VCs in VPs — same VC succeeds across queries', async () => {
    // The ScopeEngine creates a fresh VP per query, so the same VC (reusable
    // credential) can be presented multiple times. Each query gets a unique
    // VP nonce, so replay protection on the VP layer doesn't interfere.
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

    // First query — should succeed
    const result1 = await engine.query({
      agent: agent.did,
      credential,
      table: 'patients',
      sql: 'SELECT name FROM patients',
    });
    expect(result1.rows.length).toBe(1);

    // Same credential, second query — should also succeed (VC is reusable,
    // ScopeEngine wraps it in a fresh VP each time)
    const result2 = await engine.query({
      agent: agent.did,
      credential,
      table: 'patients',
      sql: 'SELECT name FROM patients',
    });
    expect(result2.rows.length).toBe(1);
  });
});
