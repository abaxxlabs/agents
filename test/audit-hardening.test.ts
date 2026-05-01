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

// Tests concurrent audit chain init races and timing-safe hash comparison.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AuditLogger, hashAuditRecord } from '../src/audit-logger.js';
import { generateDidKey, createSigner } from '../src/auth/index.js';
import type { AuditEntry, AuditRecord } from '../src/types.js';
import { SqliteStorageBackend } from '../src/storage/sqlite/index.js';
import { deterministicSessionMacKey } from './support/deterministic-session-mac-key.js';

// ─── Shared test fixtures ────────────────────────────────────────────────────

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

// ─── Concurrent append — SQLite backend ────────────────────────

describe('concurrent append — SQLite backend', () => {
  let backend: SqliteStorageBackend;
  const agent = generateDidKey();
  const human = generateDidKey();

  beforeEach(async () => {
    backend = await SqliteStorageBackend.create(
      { type: 'sqlite', path: ':memory:' },
      { sessionMacKey: deterministicSessionMacKey('audit-hardening') },
    );
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('loadLastRecordLocked() returns null for an empty store (GENESIS state)', async () => {
    const result = await backend.audit.loadLastRecordLocked();
    expect(result).toBeNull();
  });

  it('loadLastRecordLocked() returns the most recent record after one write', async () => {
    const logger = new AuditLogger({ auditStore: backend.audit, enabled: true });
    const signer = createSigner(agent.privateKey);
    await logger.log(makeEntry(agent.did, human.did), signer);

    const last = await backend.audit.loadLastRecordLocked();
    expect(last).not.toBeNull();
    expect(last!.agentDid).toBe(agent.did);
  });

  it('loadLastRecordLocked returns chain head after first process has written records', async () => {
    const signer = createSigner(agent.privateKey);
    const entry = makeEntry(agent.did, human.did);

    // Process A: initialize and write one record
    const loggerA = new AuditLogger({ auditStore: backend.audit, enabled: true });
    const r1 = await loggerA.log(entry, signer);

    const inDb = await backend.audit.query();
    expect(inDb).toHaveLength(1);
    expect(inDb[0].previousHash).toBe('GENESIS');

    const chainHead = await backend.audit.loadLastRecordLocked();
    expect(chainHead).not.toBeNull();
    expect(chainHead!.id).toBe(r1.id);
    expect(chainHead!.previousHash).toBe('GENESIS');
  });

  it('two fresh loggers produce a linear chain under concurrent first writes', async () => {
    const signer = createSigner(agent.privateKey);
    const entry = makeEntry(agent.did, human.did);
    const loggerA = new AuditLogger({ auditStore: backend.audit, enabled: true });
    const loggerB = new AuditLogger({ auditStore: backend.audit, enabled: true });

    await Promise.all([
      loggerA.log(entry, signer),
      loggerB.log(entry, signer),
    ]);

    const all = await backend.audit.query();
    expect(all).toHaveLength(2);
    expect(all.filter((record) => record.previousHash === 'GENESIS')).toHaveLength(1);

    const verifier = new AuditLogger({ auditStore: backend.audit, enabled: false });
    const result = await verifier.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.totalRecords).toBe(2);
  });

  it('appendWithChainLock is called during log() not a split read then append', async () => {
    const signer = createSigner(agent.privateKey);
    const entry = makeEntry(agent.did, human.did);

    const loggerA = new AuditLogger({ auditStore: backend.audit, enabled: true });
    const r1 = await loggerA.log(entry, signer);

    const appendWithLock = vi.spyOn(backend.audit, 'appendWithChainLock');
    const loadLocked = vi.spyOn(backend.audit, 'loadLastRecordLocked');
    const loadRegular = vi.spyOn(backend.audit, 'loadLastRecord');

    const loggerB = new AuditLogger({ auditStore: backend.audit, enabled: true });
    await loggerB.log(entry, signer);

    expect(appendWithLock).toHaveBeenCalledOnce();
    expect(loadLocked).not.toHaveBeenCalled();
    expect(loadRegular).not.toHaveBeenCalled();

    const all = await backend.audit.query();
    expect(all).toHaveLength(2);
    const first = all.find((r) => r.previousHash === 'GENESIS');
    expect(first).toBeDefined();
    expect(first!.id).toBe(r1.id);
  });
});

// ─── Concurrent append — Postgres-style mock AuditStore ───────

describe('concurrent append — Postgres-style mock store', () => {
  const agent = generateDidKey();
  const human = generateDidKey();

  function makeSerializingStore() {
    // In-memory list of records — simulates the DB table.
    const records: AuditRecord[] = [];
    // Mutex simulating the advisory lock: only one locked store operation runs at a time.
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
      appendWithChainLock: vi.fn(async (
        buildRecord: (lastRecord: AuditRecord | null) => AuditRecord,
      ) => {
        return withAdvisoryLock(async () => {
          const lastRecord = records.length === 0 ? null : records[records.length - 1];
          const record = buildRecord(lastRecord);
          await delayedWriter(record);
          return record;
        });
      }),
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

  it('two fresh loggers produce a linear chain under concurrent first writes', async () => {
    const store = makeSerializingStore();
    const signer = createSigner(agent.privateKey);
    const entry = makeEntry(agent.did, human.did);

    const loggerA = new AuditLogger({ auditStore: store, enabled: true });
    const loggerB = new AuditLogger({ auditStore: store, enabled: true });

    await Promise.all([
      loggerA.log(entry, signer),
      loggerB.log(entry, signer),
    ]);

    expect(store._records).toHaveLength(2);
    expect(store.appendWithChainLock).toHaveBeenCalledTimes(2);
    expect(store.append).not.toHaveBeenCalled();
    expect(store._records.filter((record) => record.previousHash === 'GENESIS')).toHaveLength(1);

    // verifyAuditChain
    const verifier = new AuditLogger({ auditStore: store, enabled: false });
    const result = await verifier.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.totalRecords).toBe(2);
  });

  it('appendWithChainLock is called during log() (not split loadLastRecordLocked plus append)', async () => {
    const store = makeSerializingStore();
    const signer = createSigner(agent.privateKey);

    const logger = new AuditLogger({ auditStore: store, enabled: true });
    await logger.log(makeEntry(agent.did, human.did), signer);

    expect(store.appendWithChainLock).toHaveBeenCalledOnce();
    expect(store.append).not.toHaveBeenCalled();
    expect(store.loadLastRecordLocked).not.toHaveBeenCalled();
    expect(store.loadLastRecord).not.toHaveBeenCalled();
  });
});

// ─── timing-safe hash comparison in verifyAuditChain ───────────

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

  it('valid chain passes regardless of mismatch position (constant-time semantics)', async () => {
    // Build a valid 3-record chain
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);
    const hash2 = hashAuditRecord(rec2);
    const rec3 = makeRecord('rec-3', hash2);

    const store = makeAuditStore([rec1, rec2, rec3]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.totalRecords).toBe(3);
  });

  it('mismatch at byte 0 (first character) is detected correctly', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);

    // Flip the first hex character of hash1
    const flippedFirst = hash1[0] === 'a' ? '0' + hash1.slice(1) : 'a' + hash1.slice(1);
    const rec2 = makeRecord('rec-2', flippedFirst); // wrong previousHash

    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe('rec-2');
  });

  it('mismatch at the last byte is detected correctly', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);

    // Flip the last hex character of hash1
    const lastIdx = hash1.length - 1;
    const flippedLast = hash1.slice(0, lastIdx) + (hash1[lastIdx] === 'f' ? '0' : 'f');
    const rec2 = makeRecord('rec-2', flippedLast); // wrong previousHash

    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe('rec-2');
  });

  it('mismatch at a middle byte is detected correctly', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);

    // Flip a hex character near the middle
    const mid = Math.floor(hash1.length / 2);
    const flippedMid =
      hash1.slice(0, mid) + (hash1[mid] === '5' ? '6' : '5') + hash1.slice(mid + 1);
    const rec2 = makeRecord('rec-2', flippedMid);

    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe('rec-2');
  });

  it('completely wrong hash (not hex) produces ok=false without throwing', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const rec2 = makeRecord('rec-2', 'not-a-real-hash');

    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe('rec-2');
  });

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
