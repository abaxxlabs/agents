import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend } from '#storage/types.js';
import type { AuditRecord } from '#types/index.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';
import { createMockAuditRecord } from '../mocks/audit-record.js';

async function createBackend(): Promise<StorageBackend> {
  return SqliteStorageBackend.create(
    {
      type: 'sqlite',
      path: ':memory:',
      sessionMacKey: deterministicSessionMacKey('audit-agentdids'),
    },
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
    expect(ids).not.toContain('unrelated');
  });
});
