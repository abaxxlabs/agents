import { describe, it, expect, vi } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import type { AgentStore } from '#storage/types.js';
import { createMockAuditStore } from './mocks/audit-store.js';
import type { Pool } from 'pg';
import { encrypt, generateColumnKey } from '#encryption/index.js';
import { generateDidKey, issueCredential, createSigner } from '#auth/index.js';
import { DidAliasRegistry } from '#did/alias.js';
import type { RegisteredAgent } from '#types/index.js';

function createAliasTestFixtures() {
  const humanOld = generateDidKey();
  // did:key stands in for did:dht because alias lookup compares DID strings, not methods.
  const humanNew = generateDidKey();
  const agentA = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(humanOld.did, humanOld.publicKey);
  verifier.registerKey(humanNew.did, humanNew.publicKey);
  verifier.registerKey(agentA.did, agentA.publicKey);

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
        ownerDid: humanNew.did,
        signer: createSigner(agentA.privateKey),
        publicKey: agentA.publicKey,
      },
    ],
  ]);

  const auditLogger = new AuditLogger({
    auditStore: createMockAuditStore(),
    enabled: true,
  });
  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

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
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    const credential = await issueCredential(humanOld.did, humanOld.privateKey, {
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
