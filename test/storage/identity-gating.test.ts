import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend, IdentityContext } from '#storage/types.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';

// ─── Test Helpers ─────────────────────────────────────────────────────────────

async function createBackend(): Promise<StorageBackend> {
  return SqliteStorageBackend.create(
    { type: 'sqlite', path: ':memory:' },
    { sessionMacKey: deterministicSessionMacKey('identity-gating') },
  );
}

const SERVER_DID = 'did:key:zServer123';

function agentIdentity(callerDid: string): IdentityContext {
  return Object.freeze({
    callerDid,
    issuerDid: SERVER_DID,
    orgDomain: 'test.com',
    verifiedAt: Date.now(),
  });
}

function serverIdentity(): IdentityContext {
  return Object.freeze({
    callerDid: SERVER_DID,
    issuerDid: SERVER_DID,
    orgDomain: null,
    verifiedAt: Date.now(),
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Context store identity gating', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('agent A cannot read agent B entries', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    const agentB = agentIdentity('did:key:zAgentB');

    // Agent A writes an entry
    await backend.context.put(
      {
        namespace: 'secrets',
        key: 'private-data',
        value: { secret: 'value' },
        ownerDid: 'did:key:zAgentA',
      },
      agentA,
    );

    // Agent B tries to read it — should get null (not found, not access-denied)
    const entry = await backend.context.get('secrets', 'private-data', agentB);
    expect(entry).toBeNull();
  });

  it('agent A cannot list agent B entries', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    const agentB = agentIdentity('did:key:zAgentB');

    await backend.context.put(
      {
        namespace: 'shared-ns',
        key: 'a-entry',
        value: { owner: 'A' },
        ownerDid: 'did:key:zAgentA',
      },
      agentA,
    );
    await backend.context.put(
      {
        namespace: 'shared-ns',
        key: 'b-entry',
        value: { owner: 'B' },
        ownerDid: 'did:key:zAgentB',
      },
      agentB,
    );

    // Agent A lists — should only see own entry
    const aEntries = await backend.context.list('shared-ns', agentA);
    expect(aEntries).toHaveLength(1);
    expect(aEntries[0].key).toBe('a-entry');

    // Agent B lists — should only see own entry
    const bEntries = await backend.context.list('shared-ns', agentB);
    expect(bEntries).toHaveLength(1);
    expect(bEntries[0].key).toBe('b-entry');
  });

  it('agent A cannot delete agent B entries', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    const agentB = agentIdentity('did:key:zAgentB');

    await backend.context.put(
      { namespace: 'test', key: 'b-owned', value: {}, ownerDid: 'did:key:zAgentB' },
      agentB,
    );

    // Agent A tries to delete B's entry — should return false
    const deleted = await backend.context.delete('test', 'b-owned', agentA);
    expect(deleted).toBe(false);

    // Entry still exists (server can verify)
    const entry = await backend.context.get('test', 'b-owned', serverIdentity());
    expect(entry).not.toBeNull();
  });

  it('agent A cannot update agent B entries', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    const agentB = agentIdentity('did:key:zAgentB');

    await backend.context.put(
      { namespace: 'test', key: 'b-owned', value: { original: true }, ownerDid: 'did:key:zAgentB' },
      agentB,
    );

    // Agent A tries to update B's entry — should throw
    await expect(
      backend.context.put(
        {
          namespace: 'test',
          key: 'b-owned',
          value: { tampered: true },
          ownerDid: 'did:key:zAgentA',
        },
        agentA,
      ),
    ).rejects.toThrow(/access denied/i);

    // Original value preserved
    const entry = await backend.context.get('test', 'b-owned', serverIdentity());
    expect(entry!.value).toEqual({ original: true });
  });

  it('put() rejects mismatched callerDid and ownerDid', async () => {
    const agentA = agentIdentity('did:key:zAgentA');

    // Agent A tries to write an entry owned by B
    await expect(
      backend.context.put(
        { namespace: 'test', key: 'k1', value: {}, ownerDid: 'did:key:zAgentB' },
        agentA,
      ),
    ).rejects.toThrow(/access denied/i);
  });

  // ─── Server identity bypass ─────────────────────────────────────────────────

  it('server can read all entries', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    const agentB = agentIdentity('did:key:zAgentB');

    await backend.context.put(
      { namespace: 'test', key: 'a-entry', value: { owner: 'A' }, ownerDid: 'did:key:zAgentA' },
      agentA,
    );
    await backend.context.put(
      { namespace: 'test', key: 'b-entry', value: { owner: 'B' }, ownerDid: 'did:key:zAgentB' },
      agentB,
    );

    // Server lists — should see all entries
    const entries = await backend.context.list('test', serverIdentity());
    expect(entries).toHaveLength(2);
  });

  it('server can read specific agent entry', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    await backend.context.put(
      { namespace: 'test', key: 'private', value: { secret: true }, ownerDid: 'did:key:zAgentA' },
      agentA,
    );

    const entry = await backend.context.get('test', 'private', serverIdentity());
    expect(entry).not.toBeNull();
    expect(entry!.value).toEqual({ secret: true });
  });

  it('server can delete any entry', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    await backend.context.put(
      { namespace: 'test', key: 'to-delete', value: {}, ownerDid: 'did:key:zAgentA' },
      agentA,
    );

    const deleted = await backend.context.delete('test', 'to-delete', serverIdentity());
    expect(deleted).toBe(true);
  });

  it('server can write entries for any agent', async () => {
    const server = serverIdentity();
    const result = await backend.context.put(
      { namespace: 'injected', key: 'k1', value: { injected: true }, ownerDid: 'did:key:zAgentA' },
      server,
    );

    expect(result.ownerDid).toBe('did:key:zAgentA');

    // Agent A can read the server-injected entry
    const agentA = agentIdentity('did:key:zAgentA');
    const entry = await backend.context.get('injected', 'k1', agentA);
    expect(entry).not.toBeNull();
    expect(entry!.value).toEqual({ injected: true });
  });
});
