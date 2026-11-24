import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuditLogger, hashAuditRecord } from '#audit/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import type { AuditEntry, AuditRecord } from '#types/index.js';
import { createMockAuditStore } from './mocks/audit-store.js';

describe('Audit Logger', () => {
  let agent: ReturnType<typeof generateDidKey>;
  let human: ReturnType<typeof generateDidKey>;
  let entry: AuditEntry;

  beforeEach(() => {
    agent = generateDidKey();
    human = generateDidKey();
    entry = {
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ...',
      sql: 'SELECT * FROM patients',
      columnsAccessed: ['patients.name', 'patients.dob'],
      rowCount: 5,
      durationMs: 42,
    };
  });

  it('creates a signed audit record', async () => {
    const store = createMockAuditStore();
    const logger = new AuditLogger({ auditStore: store, enabled: true });

    const record = await logger.log(entry, createSigner(agent.privateKey));

    expect(record.id).toBeDefined();
    expect(record.agentDid).toBe(agent.did);
    expect(record.ownerDid).toBe(human.did);
    expect(record.columnsAccessed).toEqual(['patients.name', 'patients.dob']);
    expect(record.rowCount).toBe(5);
    expect(record.signature).toBeDefined();
    expect(record.signature.split('.').length).toBe(3);
  });

  it('throws AuditWriteFailedError on write failure (always fail-closed)', async () => {
    const store = createMockAuditStore({ failOnAppend: true });
    const logger = new AuditLogger({ auditStore: store, enabled: true });

    await expect(logger.log(entry, createSigner(agent.privateKey))).rejects.toThrow(
      'Could not write audit record',
    );
  });

  it('second record chains to first via previousHash', async () => {
    const store = createMockAuditStore();
    const logger = new AuditLogger({ auditStore: store, enabled: true });

    const record1 = await logger.log(entry, createSigner(agent.privateKey));
    const record2 = await logger.log(entry, createSigner(agent.privateKey));

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
    expect(record2.previousHash).not.toBe('GENESIS');
  });
});

describe('AuditLogger.verifyAuditChain', () => {
  function makeAuditStore(records: AuditRecord[]) {
    return {
      append: vi.fn().mockResolvedValue(undefined),
      loadLastRecord: vi.fn().mockResolvedValue(null),
      loadLastRecordLocked: vi.fn().mockResolvedValue(null),
      query: vi.fn().mockResolvedValue(records),
      count: vi.fn().mockResolvedValue(records.length),
    };
  }

  function makeRecord(id: string, previousHash: string): AuditRecord {
    const base: Omit<AuditRecord, 'signature'> = {
      id,
      timestamp: new Date().toISOString(),
      agentDid: 'did:key:zAgent',
      ownerDid: 'did:key:zHuman',
      credentialId: 'cred-001',
      queryHash: 'abc123',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 5,
      previousHash,
      version: 2,
      status: 'success',
    };
    return { ...base, signature: 'unsigned' };
  }

  it('returns ok=false with failedAt pointing to the broken record', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const rec2 = makeRecord('rec-2', 'not-the-right-hash');
    const wrongHash2 = hashAuditRecord(rec2);
    const rec3 = makeRecord('rec-3', wrongHash2);

    const store = makeAuditStore([rec1, rec2, rec3]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe('rec-2');
    expect(result.totalRecords).toBe(3);
  });
});
