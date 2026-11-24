import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend, IdentityContext } from '#storage/types.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';

async function createBackend(): Promise<StorageBackend> {
  return SqliteStorageBackend.create(
    {
      type: 'sqlite',
      path: ':memory:',
      sessionMacKey: deterministicSessionMacKey('identity-gating'),
    },
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

describe('Context store identity gating', () => {
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('isolates reads, enumeration, writes and deletion between agents', async () => {
    const agentA = agentIdentity('did:key:zAgentA');
    const agentB = agentIdentity('did:key:zAgentB');

    await backend.context.put(
      {
        namespace: 'secrets',
        key: 'private-data',
        value: { secret: 'value' },
        ownerDid: 'did:key:zAgentA',
      },
      agentA,
    );

    const entry = await backend.context.get('secrets', 'private-data', agentB);
    expect(entry).toBeNull();
    expect(await backend.context.list('secrets', agentB)).toEqual([]);
    expect(await backend.context.list('secrets', agentA)).toHaveLength(1);
    await expect(
      backend.context.put(
        {
          namespace: 'secrets',
          key: 'private-data',
          value: { secret: 'tampered' },
          ownerDid: agentB.callerDid,
        },
        agentB,
      ),
    ).rejects.toThrow(/access denied/i);
    await expect(
      backend.context.put(
        {
          namespace: 'secrets',
          key: 'forged-owner',
          value: {},
          ownerDid: agentA.callerDid,
        },
        agentB,
      ),
    ).rejects.toThrow(/access denied/i);
    expect(await backend.context.delete('secrets', 'private-data', agentB)).toBe(false);
    expect((await backend.context.get('secrets', 'private-data', agentA))?.value).toEqual({
      secret: 'value',
    });
    expect(await backend.context.delete('secrets', 'private-data', agentA)).toBe(true);
    expect(await backend.context.get('secrets', 'private-data', agentA)).toBeNull();
  });

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

    const entries = await backend.context.list('test', serverIdentity());
    expect(entries).toHaveLength(2);
  });
});
