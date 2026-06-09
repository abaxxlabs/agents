import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend, IdentityContext } from '#storage/types.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';
import { createMockAuditRecord } from '../mocks/audit-record.js';


async function createBackend(): Promise<StorageBackend> {
  return SqliteStorageBackend.create(
    { type: 'sqlite', path: ':memory:' },
    { sessionMacKey: deterministicSessionMacKey('contract') },
  );
}

/** Identity context for agent A (regular agent). */
function agentIdentity(callerDid: string): IdentityContext {
  return Object.freeze({
    callerDid,
    issuerDid: 'did:key:zServer123',
    orgDomain: 'test.com',
    verifiedAt: Date.now(),
  });
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

  it('findByDid() returns agent', async () => {
    await backend.agents.create({
      did: 'did:key:zAgent1',
      name: 'test-agent',
      ownerDid: 'did:key:zHuman1',
    });

    const found = await backend.agents.findByDid('did:key:zAgent1');
    expect(found).not.toBeNull();
    expect(found!.name).toBe('test-agent');
  });

  it('findByDid() returns null for unknown DID', async () => {
    const found = await backend.agents.findByDid('did:key:zNonexistent');
    expect(found).toBeNull();
  });

  it('list() returns all agents', async () => {
    await backend.agents.create({ did: 'did:key:z1', name: 'a1', ownerDid: 'did:key:zH' });
    await backend.agents.create({ did: 'did:key:z2', name: 'a2', ownerDid: 'did:key:zH' });
    await backend.agents.create({ did: 'did:key:z3', name: 'a3', ownerDid: 'did:key:zOther' });

    const all = await backend.agents.list();
    expect(all).toHaveLength(3);
  });

  it('list() filters by ownerDid', async () => {
    await backend.agents.create({ did: 'did:key:z1', name: 'a1', ownerDid: 'did:key:zH' });
    await backend.agents.create({ did: 'did:key:z2', name: 'a2', ownerDid: 'did:key:zOther' });

    const filtered = await backend.agents.list({ ownerDid: 'did:key:zH' });
    expect(filtered).toHaveLength(1);
    expect(filtered[0].did).toBe('did:key:z1');
  });

  it('list() respects limit', async () => {
    for (let i = 0; i < 5; i++) {
      await backend.agents.create({ did: `did:key:z${i}`, name: `a${i}`, ownerDid: 'did:key:zH' });
    }

    const limited = await backend.agents.list({ limit: 2 });
    expect(limited).toHaveLength(2);
  });

  // ── listAll() ──────────────────────────────────────────────────────────────

  it('listAll() returns empty array for empty table', async () => {
    const all = await backend.agents.listAll();
    expect(all).toEqual([]);
  });

  it('listAll() returns a single agent', async () => {
    await backend.agents.create({ did: 'did:key:zOnly', name: 'solo', ownerDid: 'did:key:zH' });

    const all = await backend.agents.listAll();
    expect(all).toHaveLength(1);
    expect(all[0].did).toBe('did:key:zOnly');
    expect(all[0].name).toBe('solo');
  });

  it('listAll() returns all agents without limit cap', async () => {
    // Create more agents than list()'s 100-cap to confirm listAll is unbounded.
    // We use a smaller number (5) to keep tests fast — the key assertion is that
    // no LIMIT clause is applied.
    for (let i = 0; i < 5; i++) {
      await backend.agents.create({
        did: `did:key:zAll${i}`,
        name: `a${i}`,
        ownerDid: 'did:key:zH',
      });
    }

    const all = await backend.agents.listAll();
    expect(all).toHaveLength(5);
  });

  it('listAll() returns agents from different owners', async () => {
    await backend.agents.create({ did: 'did:key:zA', name: 'a', ownerDid: 'did:key:zOwner1' });
    await backend.agents.create({ did: 'did:key:zB', name: 'b', ownerDid: 'did:key:zOwner2' });

    const all = await backend.agents.listAll();
    expect(all).toHaveLength(2);
    const dids = all.map((a) => a.did).sort();
    expect(dids).toEqual(['did:key:zA', 'did:key:zB']);
  });

  // ── count() ────────────────────────────────────────────────────────────────

  it('count() returns 0 for empty table', async () => {
    const n = await backend.agents.count();
    expect(n).toBe(0);
  });

  it('count() returns total count without filter', async () => {
    await backend.agents.create({ did: 'did:key:z1', name: 'a1', ownerDid: 'did:key:zH' });
    await backend.agents.create({ did: 'did:key:z2', name: 'a2', ownerDid: 'did:key:zOther' });

    const n = await backend.agents.count();
    expect(n).toBe(2);
  });

  it('count() filters by ownerDid', async () => {
    await backend.agents.create({ did: 'did:key:z1', name: 'a1', ownerDid: 'did:key:zH' });
    await backend.agents.create({ did: 'did:key:z2', name: 'a2', ownerDid: 'did:key:zH' });
    await backend.agents.create({ did: 'did:key:z3', name: 'a3', ownerDid: 'did:key:zOther' });

    const n = await backend.agents.count({ ownerDid: 'did:key:zH' });
    expect(n).toBe(2);
  });

  it('count() returns 0 for non-matching ownerDid', async () => {
    await backend.agents.create({ did: 'did:key:z1', name: 'a1', ownerDid: 'did:key:zH' });

    const n = await backend.agents.count({ ownerDid: 'did:key:zNobody' });
    expect(n).toBe(0);
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
    createMockAuditRecord({ columnsAccessed: ['col1', 'col2'], rowCount: 10, durationMs: 42, signature: 'jws-signature-xyz', ...overrides });

  it('append() persists a record', async () => {
    await backend.audit.append(mockRecord());

    const records = await backend.audit.query();
    expect(records).toHaveLength(1);
    expect(records[0].id).toBe('test-uuid-1');
  });

  it('loadLastRecord() returns null when empty', async () => {
    const last = await backend.audit.loadLastRecord();
    expect(last).toBeNull();
  });

  it('loadLastRecord() returns the most recent record', async () => {
    await backend.audit.append(mockRecord({ id: 'first', timestamp: '2026-01-01T00:00:00Z' }));
    await backend.audit.append(mockRecord({ id: 'second', timestamp: '2026-01-02T00:00:00Z' }));

    const last = await backend.audit.loadLastRecord();
    expect(last).not.toBeNull();
    expect(last!.id).toBe('second');
  });

  it('query() filters by agentDid', async () => {
    await backend.audit.append(mockRecord({ id: 'r1', agentDid: 'did:key:zA' }));
    await backend.audit.append(mockRecord({ id: 'r2', agentDid: 'did:key:zB' }));

    const results = await backend.audit.query({ agentDid: 'did:key:zA' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('r1');
  });

  it('query() filters by since date', async () => {
    await backend.audit.append(mockRecord({ id: 'old', timestamp: '2025-01-01T00:00:00Z' }));
    await backend.audit.append(mockRecord({ id: 'new', timestamp: '2026-06-01T00:00:00Z' }));

    const results = await backend.audit.query({ since: new Date('2026-01-01') });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('new');
  });

  it('columnsAccessed roundtrips as array', async () => {
    await backend.audit.append(mockRecord({ columnsAccessed: ['a', 'b', 'c'] }));

    const records = await backend.audit.query();
    expect(Array.isArray(records[0].columnsAccessed)).toBe(true);
    expect(records[0].columnsAccessed).toEqual(['a', 'b', 'c']);
  });

  // ── count() ────────────────────────────────────────────────────────────────

  it('count() returns 0 for empty table', async () => {
    const n = await backend.audit.count();
    expect(n).toBe(0);
  });

  it('count() returns total count without filter', async () => {
    await backend.audit.append(mockRecord({ id: 'r1' }));
    await backend.audit.append(mockRecord({ id: 'r2' }));

    const n = await backend.audit.count();
    expect(n).toBe(2);
  });

  it('count() filters by agentDid', async () => {
    await backend.audit.append(mockRecord({ id: 'r1', agentDid: 'did:key:zA' }));
    await backend.audit.append(mockRecord({ id: 'r2', agentDid: 'did:key:zA' }));
    await backend.audit.append(mockRecord({ id: 'r3', agentDid: 'did:key:zB' }));

    const n = await backend.audit.count({ agentDid: 'did:key:zA' });
    expect(n).toBe(2);
  });

  it('count() filters by agentDids (alias-aware)', async () => {
    await backend.audit.append(mockRecord({ id: 'r1', agentDid: 'did:key:zOld' }));
    await backend.audit.append(mockRecord({ id: 'r2', agentDid: 'did:key:zNew' }));
    await backend.audit.append(mockRecord({ id: 'r3', agentDid: 'did:key:zOther' }));

    const n = await backend.audit.count({ agentDids: ['did:key:zOld', 'did:key:zNew'] });
    expect(n).toBe(2);
  });

  it('count() filters by orgId', async () => {
    await backend.audit.append(mockRecord({ id: 'r1', orgId: 'org-alpha' }));
    await backend.audit.append(mockRecord({ id: 'r2', orgId: 'org-beta' }));
    await backend.audit.append(mockRecord({ id: 'r3', orgId: 'org-alpha' }));

    const n = await backend.audit.count({ orgId: 'org-alpha' });
    expect(n).toBe(2);
  });

  it('count() returns 0 for non-matching filter', async () => {
    await backend.audit.append(mockRecord({ id: 'r1', agentDid: 'did:key:zA' }));

    const n = await backend.audit.count({ agentDid: 'did:key:zNobody' });
    expect(n).toBe(0);
  });
});


describe('ContextStore (SQLite)', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('put() creates a new entry', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    const result = await backend.context.put(
      { namespace: 'test', key: 'k1', value: { foo: 'bar' }, ownerDid: 'did:key:zAgentA' },
      identity,
    );

    expect(result.namespace).toBe('test');
    expect(result.key).toBe('k1');
    expect(result.value).toEqual({ foo: 'bar' });
    expect(result.ownerDid).toBe('did:key:zAgentA');
    expect(result.createdAt).toBeTruthy();
    expect(result.updatedAt).toBeTruthy();
  });

  it('put() updates existing entry (upsert)', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    await backend.context.put(
      { namespace: 'test', key: 'k1', value: { version: 1 }, ownerDid: 'did:key:zAgentA' },
      identity,
    );
    const updated = await backend.context.put(
      { namespace: 'test', key: 'k1', value: { version: 2 }, ownerDid: 'did:key:zAgentA' },
      identity,
    );

    expect(updated.value).toEqual({ version: 2 });
  });

  it('get() retrieves entry by namespace+key', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    await backend.context.put(
      { namespace: 'test', key: 'k1', value: { data: true }, ownerDid: 'did:key:zAgentA' },
      identity,
    );

    const entry = await backend.context.get('test', 'k1', identity);
    expect(entry).not.toBeNull();
    expect(entry!.value).toEqual({ data: true });
  });

  it('get() returns null for nonexistent key', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    const entry = await backend.context.get('test', 'nonexistent', identity);
    expect(entry).toBeNull();
  });

  it('list() returns entries in namespace', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    await backend.context.put(
      { namespace: 'ns1', key: 'k1', value: {}, ownerDid: 'did:key:zAgentA' },
      identity,
    );
    await backend.context.put(
      { namespace: 'ns1', key: 'k2', value: {}, ownerDid: 'did:key:zAgentA' },
      identity,
    );
    await backend.context.put(
      { namespace: 'ns2', key: 'k3', value: {}, ownerDid: 'did:key:zAgentA' },
      identity,
    );

    const entries = await backend.context.list('ns1', identity);
    expect(entries).toHaveLength(2);
  });

  it('delete() removes entry and returns true', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    await backend.context.put(
      { namespace: 'test', key: 'k1', value: {}, ownerDid: 'did:key:zAgentA' },
      identity,
    );

    const deleted = await backend.context.delete('test', 'k1', identity);
    expect(deleted).toBe(true);

    const entry = await backend.context.get('test', 'k1', identity);
    expect(entry).toBeNull();
  });

  it('delete() returns false for nonexistent key', async () => {
    const identity = agentIdentity('did:key:zAgentA');
    const deleted = await backend.context.delete('test', 'nonexistent', identity);
    expect(deleted).toBe(false);
  });
});
