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

// Unit tests for AuditLogger: record creation, signing, verification, chain integrity.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuditLogger, hashCredential, hashQuery, hashAuditRecord } from '../src/audit-logger.js';
import { generateDidKey, createSigner } from '../src/auth/index.js';
import { DidAliasRegistry } from '../src/did-alias.js';
import type { AuditEntry, AuditRecord } from '../src/types.js';

function createMockAuditStore(options: { failOnAppend?: boolean } = {}) {
  return {
    append: vi.fn().mockImplementation(async () => {
      if (options.failOnAppend) throw new Error('disk full');
    }),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
  };
}

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

  describe('record creation and signing', () => {
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
      expect(record.signature.split('.').length).toBe(3); // JWT format
    });

    it('persists record via auditStore.append', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      await logger.log(entry, createSigner(agent.privateKey));
      expect(store.append).toHaveBeenCalledTimes(1);
      expect(store.append).toHaveBeenCalledWith(expect.objectContaining({ agentDid: agent.did }));
    });
  });

  describe('signature verification', () => {
    it('verifies a valid audit record signature', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      const record = await logger.log(entry, createSigner(agent.privateKey));
      const verified = await logger.verifyRecord(record, agent.publicKey);
      expect(verified).toBe(true);
    });

    it('rejects record with wrong public key', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      const record = await logger.log(entry, createSigner(agent.privateKey));
      const other = generateDidKey();
      const verified = await logger.verifyRecord(record, other.publicKey);
      expect(verified).toBe(false);
    });
  });

  describe('write failure behavior', () => {
    it('throws AuditWriteFailedError on write failure (always fail-closed)', async () => {
      const store = createMockAuditStore({ failOnAppend: true });
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      await expect(logger.log(entry, createSigner(agent.privateKey))).rejects.toThrow(
        'Could not write audit record',
      );
    });
  });

  describe('disabled audit', () => {
    it('returns record without calling append when disabled', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: false });

      const record = await logger.log(entry, createSigner(agent.privateKey));
      expect(record.id).toBeDefined();
      expect(store.append).not.toHaveBeenCalled();
    });
  });

  describe('A-1: hash chaining', () => {
    it('first record has previousHash = GENESIS', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      const record = await logger.log(entry, createSigner(agent.privateKey));
      expect(record.previousHash).toBe('GENESIS');
    });

    it('second record chains to first via previousHash', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      const record1 = await logger.log(entry, createSigner(agent.privateKey));
      const record2 = await logger.log(entry, createSigner(agent.privateKey));

      // record2.previousHash should be the hash of record1 (without signature)
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

    it('hash chain is deterministic', async () => {
      const store = createMockAuditStore();
      const logger = new AuditLogger({ auditStore: store, enabled: true });

      const record1 = await logger.log(entry, createSigner(agent.privateKey));
      const record2 = await logger.log(entry, createSigner(agent.privateKey));
      const record3 = await logger.log(entry, createSigner(agent.privateKey));

      // Each record should have a different previousHash
      expect(record1.previousHash).toBe('GENESIS');
      expect(record2.previousHash).not.toBe('GENESIS');
      expect(record3.previousHash).not.toBe(record2.previousHash);
    });
  });

  describe('hashing', () => {
    it('hashes credential JWT deterministically', () => {
      const h1 = hashCredential('eyJ.test.jwt');
      const h2 = hashCredential('eyJ.test.jwt');
      expect(h1).toBe(h2);
      expect(h1.length).toBe(16);
    });

    it('hashes SQL query deterministically', () => {
      const h1 = hashQuery('SELECT * FROM patients');
      const h2 = hashQuery('SELECT * FROM patients');
      expect(h1).toBe(h2);
      expect(h1.length).toBe(64); // SHA-256 hex
    });
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

  function makeRecord(
    id: string,
    previousHash: string,
    overrides: Partial<AuditRecord> = {},
  ): AuditRecord {
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
    return { ...base, signature: 'unsigned', ...overrides };
  }

  it('returns ok=true with totalRecords=0 for an empty chain', async () => {
    const store = makeAuditStore([]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.totalRecords).toBe(0);
  });

  it('returns ok=true for a valid 2-record chain', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);

    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.totalRecords).toBe(2);
  });

  it('returns ok=true for a valid 3-record chain', async () => {
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

  it('unfiltered call returns partial=false', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const rec2 = makeRecord('rec-2', hashAuditRecord(rec1));
    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.partial).toBe(false);
  });

  it('filtered call returns ok=true and partial=true for an untampered subset', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);
    const hash2 = hashAuditRecord(rec2);
    const rec3 = makeRecord('rec-3', hash2);

    const store = makeAuditStore([rec2, rec3]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain({ since: new Date('2020-01-01') });
    expect(result.ok).toBe(true);
    expect(result.partial).toBe(true);
    expect(result.totalRecords).toBe(2);
  });

  it('since-filtered call uses the unqualified error message when a record in the subset is tampered', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);
    const rec3 = makeRecord('rec-3', 'tampered-hash');

    const store = makeAuditStore([rec2, rec3]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain({ since: new Date('2020-01-01') });
    expect(result.ok).toBe(false);
    expect(result.partial).toBe(true);
    expect(result.failedAt).toBe('rec-3');

    expect(result.error).toContain('Hash chain broken at record');
    expect(result.error).not.toContain('in filtered subset');
    expect(result.error).not.toContain('may reflect non-consecutive records');
  });

  it('agent-filtered call qualifies the error as a possible non-consecutive subset gap', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);
    const rec3 = makeRecord('rec-3', 'interleaved-record-hash');

    const store = makeAuditStore([rec2, rec3]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain({ agentDid: 'did:key:zAgent' });
    expect(result.ok).toBe(false);
    expect(result.partial).toBe(true);
    expect(result.failedAt).toBe('rec-3');

    expect(result.error).toContain('in filtered subset');
    expect(result.error).toContain('may reflect non-consecutive records');
    expect(result.error).toContain('without filters for root-of-chain proof');
  });

  it('unfiltered call uses the unqualified error message', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const rec2 = makeRecord('rec-2', 'not-the-right-hash');

    const store = makeAuditStore([rec1, rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.partial).toBe(false);
    expect(result.error).toContain('Hash chain broken at record');
    expect(result.error).not.toContain('in filtered subset');
    expect(result.error).not.toContain('may reflect non-consecutive records');
  });

  it('filtered call on a single record returns ok=true and partial=true', async () => {
    const rec1 = makeRecord('rec-1', 'GENESIS');
    const hash1 = hashAuditRecord(rec1);
    const rec2 = makeRecord('rec-2', hash1);

    const store = makeAuditStore([rec2]);
    const logger = new AuditLogger({ auditStore: store, enabled: false });
    const result = await logger.verifyAuditChain({ agentDid: 'did:key:zAgent' });
    expect(result.ok).toBe(true);
    expect(result.partial).toBe(true);
    expect(result.totalRecords).toBe(1);
  });

  it('preserves orgId filter when alias expansion fires', async () => {
    const aliasRegistry = new DidAliasRegistry();
    aliasRegistry.addAlias({
      oldDid: 'did:key:zOld',
      newDid: 'did:dht:New',
      credentialHash: 'hash-deadbeef',
      migratedAt: new Date(),
      expiresAt: new Date(Date.now() + 86_400_000),
    });

    const rec = makeRecord('rec-A', 'GENESIS', { orgId: 'org-A' });
    const store = makeAuditStore([rec]);
    const logger = new AuditLogger({
      auditStore: store,
      aliasRegistry,
      enabled: false,
    });

    await logger.export({ agentDid: 'did:key:zOld', orgId: 'org-A' });

    expect(store.query).toHaveBeenCalledWith(
      expect.objectContaining({
        agentDids: expect.arrayContaining(['did:key:zOld', 'did:dht:New']),
        orgId: 'org-A',
      }),
    );
  });
});
