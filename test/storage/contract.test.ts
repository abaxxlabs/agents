import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend } from '#storage/types.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';
import { createMockAuditRecord } from '../mocks/audit-record.js';

async function createBackend(): Promise<StorageBackend> {
  return SqliteStorageBackend.create(
    { type: 'sqlite', path: ':memory:', sessionMacKey: deterministicSessionMacKey('contract') },
    { sessionMacKey: deterministicSessionMacKey('contract') },
  );
}

describe('AgentStore (SQLite)', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('create() returns agent with createdAt', async () => {
    const result = await backend.agents.create({
      did: 'did:key:zAgent1',
      name: 'test-agent',
      ownerDid: 'did:key:zHuman1',
    });

    expect(result.did).toBe('did:key:zAgent1');
    expect(result.name).toBe('test-agent');
    expect(result.ownerDid).toBe('did:key:zHuman1');
    expect(result.createdAt).toBeTruthy();
  });

  it('create() throws on duplicate DID', async () => {
    await backend.agents.create({
      did: 'did:key:zAgent1',
      name: 'first',
      ownerDid: 'did:key:zHuman1',
    });

    await expect(
      backend.agents.create({
        did: 'did:key:zAgent1',
        name: 'duplicate',
        ownerDid: 'did:key:zHuman1',
      }),
    ).rejects.toThrow();
  });
});

describe('AuditStore (SQLite)', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  const mockRecord = (overrides: Partial<import('../../src/types/audit.js').AuditRecord> = {}) =>
    createMockAuditRecord({
      columnsAccessed: ['col1', 'col2'],
      rowCount: 10,
      durationMs: 42,
      signature: 'jws-signature-xyz',
      ...overrides,
    });

  it('append() persists a record', async () => {
    await backend.audit.append(mockRecord());

    const records = await backend.audit.query();
    expect(records).toHaveLength(1);
    expect(records[0].id).toBe('test-uuid-1');
  });
});
