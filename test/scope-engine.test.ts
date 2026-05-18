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
import { ScopeEngine } from '../src/sql/scope-engine.js';
import { VcVerifier } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { AuditLogger } from '../src/audit-logger.js';
import { encrypt, generateColumnKey } from '../src/column-encryption.js';
import { generateDidKey, issueCredential, createSigner } from '../src/auth/index.js';
import { ScopeViolationError } from '../src/errors.js';
import type { RegisteredAgent } from '../src/types.js';
import type { AgentStore, AuditStore } from '../src/storage/types.js';
import type { Pool } from 'pg';

/** Mock AuditStore for tests. */
function createTestAuditStore(): AuditStore {
  return {
    append: vi.fn().mockResolvedValue(undefined),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
  };
}

// ─── Test Fixtures ───────────────────────────────────────────────

function createTestFixtures() {
  const human = generateDidKey();
  const agentA = generateDidKey();
  const agentB = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(agentA.did, agentA.publicKey);
  verifier.registerKey(agentB.did, agentB.publicKey);

  // Column keys
  const dobKey = generateColumnKey();
  const diagKey = generateColumnKey();
  const ssnKey = generateColumnKey();
  const columnKeys = new Map<string, Buffer>([
    ['patients.dob', dobKey],
    ['patients.diagnosis', diagKey],
    ['patients.ssn', ssnKey],
  ]);

  const encryptedColumns = new Set(['patients.dob', 'patients.diagnosis', 'patients.ssn']);

  // Sample encrypted rows
  const sampleRows = [
    {
      id: 1,
      name: 'Jane Doe',
      dob: encrypt('1990-03-15', dobKey),
      diagnosis: encrypt('Type 2 Diabetes', diagKey),
      ssn: encrypt('123-45-6789', ssnKey),
    },
    {
      id: 2,
      name: 'John Smith',
      dob: encrypt('1985-07-22', dobKey),
      diagnosis: encrypt('Hypertension', diagKey),
      ssn: encrypt('987-65-4321', ssnKey),
    },
  ];

  // Mock pool
  const pool = {
    query: vi.fn().mockImplementation(async (sql: string) => {
      if (sql.includes('INSERT INTO agent_audit')) {
        return { rows: [], rowCount: 1 };
      }
      if (sql.includes('SELECT') && sql.includes('patients')) {
        return { rows: sampleRows, rowCount: sampleRows.length };
      }
      return { rows: [], rowCount: 0 };
    }),
  } as unknown as Pool;

  // Agents map
  const agents = new Map<string, RegisteredAgent>([
    [
      agentA.did,
      {
        did: agentA.did,
        name: 'Agent A',
        ownerDid: human.did,
        signer: createSigner(agentA.privateKey),
        publicKey: agentA.publicKey,
      },
    ],
    [
      agentB.did,
      {
        did: agentB.did,
        name: 'Agent B',
        ownerDid: human.did,
        signer: createSigner(agentB.privateKey),
        publicKey: agentB.publicKey,
      },
    ],
  ]);

  const auditLogger = new AuditLogger({
    auditStore: createTestAuditStore(),
    enabled: true,
  });

  // Server identity for VP audience binding
  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

  const engine = new ScopeEngine({
    pool,
    verifier,
    auditLogger,
    columnKeys,
    encryptedColumns,
    agents,
    verifierDid: server.did,
    agentStore: {
      findByDid: vi.fn().mockResolvedValue(null),
      create: vi.fn(),
      list: vi.fn(),
      listAll: vi.fn(),
      count: vi.fn(),
    } as unknown as AgentStore,
  });

  return { human, agentA, agentB, engine, verifier, pool, columnKeys, encryptedColumns };
}

describe('Scope Enforcement Engine', () => {
  describe('valid queries', () => {
    it('decrypts in-scope columns for full-scope agent', async () => {
      const { human, agentA, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name, dob, diagnosis FROM patients',
      });

      expect(result.rows.length).toBe(2);
      expect(result.rows[0].name).toBe('Jane Doe');
      expect(result.rows[0].dob).toBe('1990-03-15');
      expect(result.rows[0].diagnosis).toBe('Type 2 Diabetes');
    });

    it('rejects queries for encrypted columns outside scope', async () => {
      const { human, agentB, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentB.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT name, dob, diagnosis, ssn FROM patients',
        }),
      ).rejects.toThrow(ScopeViolationError);
    });

    it('tracks metadata correctly', async () => {
      const { human, agentA, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name, dob, diagnosis FROM patients',
      });

      expect(result.metadata.agent).toBe(agentA.did);
      expect(result.metadata.owner).toBe(human.did);
      expect(result.metadata.columnsDecrypted).toContain('patients.dob');
      expect(result.metadata.columnsDecrypted).toContain('patients.diagnosis');
      expect(result.metadata.rowCount).toBe(2);
      expect(result.metadata.auditId).toBeDefined();
    });
  });

  describe('credential errors', () => {
    it('rejects invalid credential signature', async () => {
      const { agentA, engine } = createTestFixtures();

      await expect(
        engine.query({
          agent: agentA.did,
          credential: 'eyJ.invalid.jwt',
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow();
    });

    it('rejects expired credential', async () => {
      const { human, agentA } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1s',
      });

      // Wait for expiry (1s credential + margin)
      await new Promise((r) => setTimeout(r, 1500));

      // Use a strict verifier
      const strictVerifier = new VcVerifier({
        clockSkew: '1s',
        revocationStore: new InMemoryRevocationStore(),
      });
      const strictServer = generateDidKey();
      strictVerifier.registerKey(strictServer.did, strictServer.publicKey);
      const strictEngine = new ScopeEngine({
        pool: {} as unknown as Pool,
        verifier: strictVerifier,
        auditLogger: new AuditLogger({ auditStore: createTestAuditStore(), enabled: false }),
        columnKeys: new Map(),
        encryptedColumns: new Set(),
        agents: new Map(),
        agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
        verifierDid: strictServer.did,
      });

      await expect(
        strictEngine.query({
          agent: agentA.did,
          credential,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow('expired');
    });

    it('rejects credential for wrong agent', async () => {
      const { human, agentA, agentB, engine } = createTestFixtures();

      // Issue credential to Agent A
      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      // Try to use it as Agent B — VP wrapping means the subject mismatch is
      // caught when the VP (signed by Agent B) unwraps to reveal the inner VC
      // (issued to Agent A). The VP's iss becomes the expectedSubject for the VC.
      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow('subject mismatch');
    });

    it('rejects credential with missing scope', async () => {
      const { human, agentA, engine } = createTestFixtures();
      const { createJwt } = await import('../src/vc-verifier.js');

      const jwt = await createJwt(
        {
          iss: human.did,
          sub: agentA.did,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          vc: {
            credentialSubject: { id: agentA.did },
          },
        },
        human.privateKey,
      );

      await expect(
        engine.query({
          agent: agentA.did,
          credential: jwt,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow();
    });
  });

  describe('multiple credentials (scope union)', () => {
    it('unions scopes from multiple valid credentials', async () => {
      const { human, agentA, engine } = createTestFixtures();

      const cred1 = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const cred2 = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentA.did,
        credential: cred1,
        credentials: [cred2],
        table: 'patients',
        sql: 'SELECT name, dob, diagnosis FROM patients',
      });

      // Both dob and diagnosis should be decrypted via scope union
      expect(result.rows[0].dob).toBe('1990-03-15');
      expect(result.rows[0].diagnosis).toBe('Type 2 Diabetes');
    });
  });

  describe('unencrypted columns', () => {
    it('rejects unscoped unencrypted columns under projection mode', async () => {
      const { human, agentB, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentB.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT id, name FROM patients',
        }),
      ).rejects.toThrow(/scope/i);
    });

    it('allows unencrypted columns when explicitly in scope', async () => {
      const { human, agentB, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentB.did,
        columns: ['patients.id', 'patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentB.did,
        credential,
        table: 'patients',
        sql: 'SELECT id, name FROM patients',
      });

      expect(result.rows[0].name).toBe('Jane Doe');
      expect(result.rows[0].id).toBe(1);
    });
  });
});

// ─── scopeMode validation ─────────────────────

describe('scopeMode validation', () => {
  function minimalEngineOpts() {
    const server = generateDidKey();
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(server.did, server.publicKey);
    const pool = { query: vi.fn() } as unknown as Pool;
    const auditLogger = new AuditLogger({ auditStore: createTestAuditStore(), enabled: false });
    return {
      pool,
      verifier,
      auditLogger,
      columnKeys: new Map<string, Buffer>(),
      encryptedColumns: new Set<string>(),
      agents: new Map(),
      verifierDid: server.did,
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    };
  }

  it('accepts scopeMode=projection (explicit)', () => {
    expect(
      () => new ScopeEngine({ ...minimalEngineOpts(), scopeMode: 'projection' }),
    ).not.toThrow();
  });

  it('defaults to projection when scopeMode is omitted', () => {
    expect(() => new ScopeEngine({ ...minimalEngineOpts() })).not.toThrow();
  });

  it('rejects any non-projection value', () => {
    expect(
      () =>
        new ScopeEngine({
          ...minimalEngineOpts(),
          scopeMode: 'encryption-only' as unknown as import('../src/sql/scope-engine.js').ScopeMode,
        }),
    ).toThrow(/Invalid scopeMode/);
  });
});
