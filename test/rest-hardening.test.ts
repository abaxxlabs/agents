import { describe, it, expect, vi } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger, hashAuditRecord } from '#audit/index.js';
import { generateDidKey, issueCredential } from '#auth/index.js';
import { ScopeViolationError } from '#errors/index.js';
import type { AgentStore } from '#storage/types.js';
import type { Pool } from 'pg';
import { createMockAuditStore } from './mocks/audit-store.js';

describe('ScopeViolationError.toSafeResponse', () => {
  it('strips column names from the response', () => {
    const err = new ScopeViolationError(
      'did:key:test',
      ['patients.ssn', 'patients.diagnosis'],
      ['patients.name'],
    );

    const safe = err.toSafeResponse();

    expect(safe.code).toBe('SCOPE_VIOLATION');
    expect(safe.message).not.toContain('ssn');
    expect(safe.message).not.toContain('diagnosis');
    expect(safe.message).not.toContain('name');
  });
});

describe('AuditLogger.logRejection', () => {
  it('chains rejection records into the hash chain', async () => {
    const logger = new AuditLogger({
      auditStore: createMockAuditStore(),
      enabled: true,
    });

    const record1 = await logger.logRejection('first', 'TEST');
    const record2 = await logger.logRejection('second', 'TEST');

    expect(record1.previousHash).toBe('GENESIS');
    expect(record2.previousHash).not.toBe('GENESIS');

    const expectedHash = hashAuditRecord({
      id: record1.id,
      timestamp: record1.timestamp,
      agentDid: record1.agentDid,
      ownerDid: record1.ownerDid,
      credentialId: record1.credentialId,
      queryHash: record1.queryHash,
      columnsAccessed: record1.columnsAccessed,
      rowCount: record1.rowCount,
      durationMs: record1.durationMs,
      previousHash: record1.previousHash,
      version: record1.version,
      status: record1.status,
      reason: record1.reason,
      reasonCode: record1.reasonCode,
    });
    expect(record2.previousHash).toBe(expectedHash);
  });
});

describe('Fail-closed DB error on agent lookup', () => {
  it('throws CredentialInvalidError when agent DB lookup fails', async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const failPool = {
      query: vi.fn().mockImplementation(async (sql: string) => {
        if (sql.includes('agents')) throw new Error('connection refused');
        if (sql.includes('INSERT INTO agent_audit')) return { rows: [], rowCount: 1 };
        if (sql.includes('patients')) return { rows: [{ id: 1, name: 'test' }], rowCount: 1 };
        return { rows: [], rowCount: 0 };
      }),
    } as unknown as Pool;

    const engine = new ScopeEngine({
      pool: failPool,
      verifier,
      auditLogger: new AuditLogger({
        auditStore: createMockAuditStore(),
        enabled: true,
      }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents: new Map(),
      verifierDid: server.did,
      agentStore: {
        findByDid: vi.fn().mockRejectedValue(new Error('connection refused')),
      } as unknown as AgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
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
    ).rejects.toThrow('Agent owner lookup failed');
  });
});
