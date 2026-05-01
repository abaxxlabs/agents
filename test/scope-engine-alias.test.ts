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
import type { AgentStore, AuditStore } from '../src/storage/types.js';
import type { Pool } from 'pg';
import { encrypt, generateColumnKey } from '../src/column-encryption.js';
import { generateDidKey, issueCredential, createSigner } from '../src/auth/index.js';
import { DidAliasRegistry } from '../src/did-alias.js';
import type { RegisteredAgent } from '../src/types.js';

function createAliasTestFixtures() {
  // The "old" human DID (pre-migration, did:key from free tier)
  const humanOld = generateDidKey();
  // The "new" human DID (post-migration, simulated did:dht - but using did:key
  // for testing since generateDidKey only makes did:key. The alias registry
  // doesn't care about the DID method — it just compares strings.)
  const humanNew = generateDidKey();
  const agentA = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(humanOld.did, humanOld.publicKey);
  verifier.registerKey(humanNew.did, humanNew.publicKey);
  verifier.registerKey(agentA.did, agentA.publicKey);

  // Column keys
  const nameKey = generateColumnKey();
  const columnKeys = new Map<string, Buffer>([['patients.name', nameKey]]);
  const encryptedColumns = new Set(['patients.name']);

  const sampleRows = [{ id: 1, name: encrypt('Jane Doe', nameKey) }];

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

  const agents = new Map<string, RegisteredAgent>([
    [
      agentA.did,
      {
        did: agentA.did,
        name: 'Agent A',
        ownerDid: humanNew.did, // <-- migrated to new DID
        signer: createSigner(agentA.privateKey),
        publicKey: agentA.publicKey,
      },
    ],
  ]);

  const mockAuditStore: AuditStore = {
    append: vi.fn().mockResolvedValue(undefined),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
  };
  const auditLogger = new AuditLogger({
    auditStore: mockAuditStore,
    enabled: true,
  });
  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

  // Set up alias registry: old DID → new DID
  const aliasRegistry = new DidAliasRegistry();
  aliasRegistry.addAlias({
    oldDid: humanOld.did,
    newDid: humanNew.did,
    credentialHash: 'test-hash',
    oidcSubject: 'user@test.com',
    oidcIssuer: 'https://login.test.com',
    migratedAt: new Date(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  return {
    humanOld,
    humanNew,
    agentA,
    server,
    verifier,
    pool,
    agents,
    auditLogger,
    columnKeys,
    encryptedColumns,
    aliasRegistry,
  };
}

describe('ScopeEngine — alias-aware DID comparison', () => {
  it('accepts credential from old DID when agent has migrated to new DID (C1 owner check)', async () => {
    const {
      humanOld,
      agentA,
      server,
      verifier,
      pool,
      agents,
      auditLogger,
      columnKeys,
      encryptedColumns,
      aliasRegistry,
    } = createAliasTestFixtures();

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger,
      columnKeys,
      encryptedColumns,
      agents,
      verifierDid: server.did,
      didAliases: aliasRegistry,
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    // Issue credential from the OLD human DID (pre-migration credential)
    const credential = issueCredential(humanOld.did, humanOld.privateKey, {
      agent: agentA.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agentA.did,
      credential,
      table: 'patients',
      sql: 'SELECT name FROM patients',
    });

    expect(result.rows.length).toBe(1);
    expect(result.rows[0].name).toBe('Jane Doe');
  });

  it('rejects credential from old DID without alias registry (strict mode)', async () => {
    const {
      humanOld,
      agentA,
      server,
      verifier,
      pool,
      agents,
      auditLogger,
      columnKeys,
      encryptedColumns,
    } = createAliasTestFixtures();

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger,
      columnKeys,
      encryptedColumns,
      agents,
      verifierDid: server.did,
      // didAliases omitted
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    const credential = issueCredential(humanOld.did, humanOld.privateKey, {
      agent: agentA.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name FROM patients',
      }),
    ).rejects.toThrow('is not the registered owner');
  });

  it('rejects credential from unrelated DID even with alias registry', async () => {
    const {
      agentA,
      server,
      verifier,
      pool,
      agents,
      auditLogger,
      columnKeys,
      encryptedColumns,
      aliasRegistry,
    } = createAliasTestFixtures();

    const engine = new ScopeEngine({
      pool,
      verifier,
      auditLogger,
      columnKeys,
      encryptedColumns,
      agents,
      verifierDid: server.did,
      didAliases: aliasRegistry,
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    const unrelated = generateDidKey();
    verifier.registerKey(unrelated.did, unrelated.publicKey);

    const credential = issueCredential(unrelated.did, unrelated.privateKey, {
      agent: agentA.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name FROM patients',
      }),
    ).rejects.toThrow('is not the registered owner');
  });
});
