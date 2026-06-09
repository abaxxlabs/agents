import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend } from '#storage/types.js';
import type { AuditRecord } from '#types/index.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';
import { createMockAuditRecord } from '../mocks/audit-record.js';

interface SqliteDb {
  prepare(sql: string): {
    all(...params: unknown[]): unknown[];
    run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
    get(...params: unknown[]): unknown;
  };
}

async function createBackend(): Promise<StorageBackend> {
  return SqliteStorageBackend.create(
    { type: 'sqlite', path: ':memory:' },
    { sessionMacKey: deterministicSessionMacKey('audit-agentdids') },
  );
}

function mockRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return createMockAuditRecord({
    id: 'test-uuid-' + Math.random().toString(36).slice(2, 8),
    agentDid: 'did:key:zDefaultAgent',
    ...overrides,
  });
}

describe('AuditStore — agentDids filter', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('query() with agentDids returns records matching any DID in the array', async () => {
    const oldDid = 'did:key:z6MkOldUser';
    const newDid = 'did:dht:NewUserDHT';
    const unrelatedDid = 'did:key:z6MkOther';

    await backend.audit.append(mockRecord({ id: 'old-record', agentDid: oldDid }));
    await backend.audit.append(mockRecord({ id: 'new-record', agentDid: newDid }));
    await backend.audit.append(mockRecord({ id: 'unrelated', agentDid: unrelatedDid }));

    const results = await backend.audit.query({ agentDids: [oldDid, newDid] });

    expect(results).toHaveLength(2);
    const ids = results.map((r) => r.id);
    expect(ids).toContain('old-record');
    expect(ids).toContain('new-record');
    // Unrelated record should NOT be included
    expect(ids).not.toContain('unrelated');
  });

  it('query() with agentDids takes precedence over agentDid', async () => {
    const didA = 'did:key:z6MkA';
    const didB = 'did:key:z6MkB';
    const didC = 'did:key:z6MkC';

    await backend.audit.append(mockRecord({ id: 'r-a', agentDid: didA }));
    await backend.audit.append(mockRecord({ id: 'r-b', agentDid: didB }));
    await backend.audit.append(mockRecord({ id: 'r-c', agentDid: didC }));

    // Both agentDid and agentDids set — agentDids should win
    const results = await backend.audit.query({
      agentDid: didC,
      agentDids: [didA, didB],
    });

    expect(results).toHaveLength(2);
    const ids = results.map((r) => r.id);
    expect(ids).toContain('r-a');
    expect(ids).toContain('r-b');
    // didC was in agentDid but NOT in agentDids — should be excluded
    expect(ids).not.toContain('r-c');
  });

  it('query() with empty agentDids falls through to agentDid', async () => {
    const did = 'did:key:z6MkTarget';
    await backend.audit.append(mockRecord({ id: 'target', agentDid: did }));
    await backend.audit.append(mockRecord({ id: 'other', agentDid: 'did:key:z6MkOther' }));

    const results = await backend.audit.query({
      agentDids: [],
      agentDid: did,
    });

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('target');
  });

  it('query() with single-element agentDids works', async () => {
    const did = 'did:key:z6MkSingle';
    await backend.audit.append(mockRecord({ id: 'single', agentDid: did }));
    await backend.audit.append(mockRecord({ id: 'other', agentDid: 'did:key:z6MkOther' }));

    const results = await backend.audit.query({ agentDids: [did] });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('single');
  });

  it('query() with agentDids and since date combines both filters', async () => {
    const oldDid = 'did:key:z6MkOldUser';
    const newDid = 'did:dht:NewUserDHT';

    await backend.audit.append(
      mockRecord({
        id: 'old-early',
        agentDid: oldDid,
        timestamp: '2025-01-01T00:00:00Z',
      }),
    );
    await backend.audit.append(
      mockRecord({
        id: 'old-recent',
        agentDid: oldDid,
        timestamp: '2026-06-01T00:00:00Z',
      }),
    );
    await backend.audit.append(
      mockRecord({
        id: 'new-recent',
        agentDid: newDid,
        timestamp: '2026-06-01T00:00:00Z',
      }),
    );

    const results = await backend.audit.query({
      agentDids: [oldDid, newDid],
      since: new Date('2026-01-01'),
    });

    expect(results).toHaveLength(2);
    const ids = results.map((r) => r.id);
    expect(ids).toContain('old-recent');
    expect(ids).toContain('new-recent');
    // old-early is before the since date — excluded
    expect(ids).not.toContain('old-early');
  });
});

describe('SQLite schema — agent_did_aliases table', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('did_aliases table is created during initialization', async () => {
    // Access the raw SQLite db to verify table exists
    const db = (backend as unknown as { db: SqliteDb }).db;
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_did_aliases'")
      .all();

    expect(tables).toHaveLength(1);
  });

  it('did_aliases table has the expected columns', async () => {
    const db = (backend as unknown as { db: SqliteDb }).db;
    const columns = db.prepare('PRAGMA table_info(agent_did_aliases)').all() as Array<{
      name: string;
    }>;
    const columnNames = columns.map((c) => c.name);

    expect(columnNames).toContain('old_did');
    expect(columnNames).toContain('new_did');
    expect(columnNames).toContain('credential_hash');
    expect(columnNames).toContain('oidc_subject');
    expect(columnNames).toContain('oidc_issuer');
    expect(columnNames).toContain('migrated_at');
    expect(columnNames).toContain('expires_at');
  });

  it('credential_hash has a unique index', async () => {
    const db = (backend as unknown as { db: SqliteDb }).db;

    // Insert one record
    db.prepare(
      `INSERT INTO agent_did_aliases (old_did, new_did, credential_hash, expires_at)
       VALUES ('did:key:z6MkA', 'did:dht:B', 'hash-1', '2099-01-01')`,
    ).run();

    // Inserting a duplicate credential_hash should fail
    expect(() => {
      db.prepare(
        `INSERT INTO agent_did_aliases (old_did, new_did, credential_hash, expires_at)
         VALUES ('did:key:z6MkC', 'did:dht:D', 'hash-1', '2099-01-01')`,
      ).run();
    }).toThrow();
  });
});
