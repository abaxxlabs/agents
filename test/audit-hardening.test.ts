import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AuditLogger, hashAuditRecord } from '#audit/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import type { AuditEntry, AuditRecord } from '#types/index.js';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import { deterministicSessionMacKey } from './support/deterministic-session-mac-key.js';

function makeEntry(agentDid: string, ownerDid: string): AuditEntry {
  return {
    agentDid,
    ownerDid,
    credentialJwt: 'eyJ.test.jwt',
    sql: 'SELECT * FROM patients',
    columnsAccessed: ['patients.name'],
    rowCount: 1,
    durationMs: 10,
  };
}

describe('concurrent append — SQLite backend', () => {
  let backend: SqliteStorageBackend;
  const agent = generateDidKey();
  const human = generateDidKey();

  beforeEach(async () => {
    backend = await SqliteStorageBackend.create(
      {
        type: 'sqlite',
        path: ':memory:',
        sessionMacKey: deterministicSessionMacKey('audit-hardening'),
      },
      { sessionMacKey: deterministicSessionMacKey('audit-hardening') },
    );
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('two fresh loggers produce a linear chain under concurrent first writes', async () => {
    const signer = createSigner(agent.privateKey);
    const entry = makeEntry(agent.did, human.did);
    const loggerA = new AuditLogger({ auditStore: backend.audit, enabled: true });
    const loggerB = new AuditLogger({ auditStore: backend.audit, enabled: true });

    await Promise.all([loggerA.log(entry, signer), loggerB.log(entry, signer)]);

    const all = await backend.audit.query();
    expect(all).toHaveLength(2);
    expect(all.filter((record) => record.previousHash === 'GENESIS')).toHaveLength(1);

    const verifier = new AuditLogger({ auditStore: backend.audit, enabled: false });
    const result = await verifier.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.totalRecords).toBe(2);
  });
});

describe('concurrent append — Postgres-style mock store', () => {
  const agent = generateDidKey();
  const human = generateDidKey();

  function makeSerializingStore() {
    const records: AuditRecord[] = [];
    let lockQueue: Promise<void> = Promise.resolve();

    async function withAdvisoryLock<T>(fn: () => Promise<T> | T): Promise<T> {
      let release!: () => void;
      const acquired = new Promise<void>((resolve) => {
        release = resolve;
      });
      const prev = lockQueue;
      lockQueue = acquired;
      await prev;
      try {
        return await fn();
      } finally {
        release();
      }
    }

    const delayedWriter = async (record: AuditRecord) => {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      records.push(record);
    };

    return {
      append: vi.fn(delayedWriter),
      appendWithChainLock: vi.fn(
        async (
          buildRecord: (lastRecord: AuditRecord | null) => AuditRecord | Promise<AuditRecord>,
        ) => {
          return withAdvisoryLock(async () => {
            const lastRecord = records.length === 0 ? null : records[records.length - 1];
            const record = await buildRecord(lastRecord);
            await delayedWriter(record);
            return record;
          });
        },
      ),
      loadLastRecord: vi.fn(async () =>
        records.length === 0 ? null : records[records.length - 1],
      ),
      loadLastRecordLocked: vi.fn(async () => {
        return withAdvisoryLock(() => {
          return records.length === 0 ? null : records[records.length - 1];
        });
      }),
      query: vi.fn(async () => [...records]),
      count: vi.fn(async () => records.length),
      _records: records,
    };
  }

  it('serializing loadLastRecordLocked: second caller sees records from first after it commits', async () => {
    const store = makeSerializingStore();
    const signer = createSigner(agent.privateKey);
    const entry = makeEntry(agent.did, human.did);

    const loggerA = new AuditLogger({ auditStore: store, enabled: true });
    await loggerA.log(entry, signer);

    expect(store._records).toHaveLength(1);
    expect(store._records[0].previousHash).toBe('GENESIS');

    const chainHead = await store.loadLastRecordLocked();
    expect(chainHead).not.toBeNull();
    expect(chainHead!.previousHash).toBe('GENESIS');
  });
});

describe('verifyAuditChain — timing-safe hash comparison', () => {
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
    return {
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
      signature: 'unsigned',
    };
  }

  it('truncated chain (only last record has GENESIS previousHash) is detected', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);
    const store = makeAuditStore([rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe('rec-2');
  });
});
