import { createHash } from 'node:crypto';
import { AuditLogger, hashAuditRecord } from '#audit/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import type { AuditStore } from '#storage/types.js';
import type { AuditEntry, AuditRecord, MessageAuditEvent } from '#types/index.js';

function createArrayAuditStore(): AuditStore & { records: AuditRecord[] } {
  const records: AuditRecord[] = [];
  return {
    records,
    async append(record) {
      records.push(record);
    },
    async loadLastRecord() {
      return records.at(-1) ?? null;
    },
    async loadLastRecordLocked() {
      return records.at(-1) ?? null;
    },
    async query() {
      return [...records];
    },
    async count() {
      return records.length;
    },
  };
}

const agent = generateDidKey();
const peer = generateDidKey();
const owner = generateDidKey();
const signer = createSigner(agent.privateKey);
const digest = createHash('sha256').update('sealed ciphertext').digest('hex');

function sentEvent(overrides: Partial<MessageAuditEvent> = {}): MessageAuditEvent {
  return {
    agentDid: agent.did,
    ownerDid: owner.did,
    direction: 'sent',
    status: 'success',
    messageRecordId: 'bafyrecord-one',
    messageDigest: digest,
    counterpartAgentDid: peer.did,
    counterpartInstanceDid: 'did:dht:peerinstance',
    orgId: 'org-one',
    ...overrides,
  };
}

const queryEntry: AuditEntry = {
  agentDid: agent.did,
  ownerDid: owner.did,
  credentialJwt: 'eyJ.test.jwt',
  sql: 'SELECT name FROM patients',
  columnsAccessed: ['patients.name'],
  rowCount: 1,
  durationMs: 4,
};

function decodePayload(jwt: string): { data: Record<string, unknown> } {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
}

describe('AuditLogger.logMessageEvent', () => {
  it('writes a signed version 5 message record', async () => {
    const store = createArrayAuditStore();
    const logger = new AuditLogger({ auditStore: store });

    const record = await logger.logMessageEvent(sentEvent(), signer);

    expect(record).toMatchObject({
      version: 5,
      eventKind: 'message',
      direction: 'sent',
      status: 'success',
      agentDid: agent.did,
      ownerDid: owner.did,
      counterpartAgentDid: peer.did,
      counterpartInstanceDid: 'did:dht:peerinstance',
      messageRecordId: 'bafyrecord-one',
      messageDigest: digest,
      orgId: 'org-one',
      credentialId: 'none',
      queryHash: 'none',
      columnsAccessed: [],
      rowCount: 0,
      durationMs: 0,
      previousHash: 'GENESIS',
    });
    expect(record.reason).toBeUndefined();
    expect(store.records).toEqual([record]);
    expect(await logger.verifyRecord(record, agent.publicKey)).toBe(true);
    expect(await logger.verifyRecord(record, peer.publicKey)).toBe(false);

    const { data } = decodePayload(record.signature);
    expect(data).toMatchObject({
      eventKind: 'message',
      direction: 'sent',
      counterpartAgentDid: peer.did,
      counterpartInstanceDid: 'did:dht:peerinstance',
      messageRecordId: 'bafyrecord-one',
      messageDigest: digest,
      orgId: 'org-one',
      version: 5,
      status: 'success',
    });
  });

  it('rejects a record whose signed message metadata was changed after write', async () => {
    const logger = new AuditLogger({ auditStore: createArrayAuditStore() });
    const record = await logger.logMessageEvent(sentEvent(), signer);

    await expect(
      logger.verifyRecord({ ...record, messageRecordId: 'bafyrecord-forged' }, agent.publicKey),
    ).resolves.toBe(false);
    await expect(
      logger.verifyRecord(
        { ...record, status: 'rejected', reason: 'forged', reasonCode: 'forged' },
        agent.publicKey,
      ),
    ).resolves.toBe(false);
    const refused = await logger.logMessageEvent(
      sentEvent({
        status: 'rejected',
        reason: 'original reason',
        reasonCode: 'server-not-trusted',
      }),
      signer,
    );
    await expect(
      logger.verifyRecord({ ...refused, reason: 'forged reason' }, agent.publicKey),
    ).resolves.toBe(false);
  });

  it('signs the outcome, so a refused message cannot be re-labelled as accepted', async () => {
    const logger = new AuditLogger({ auditStore: createArrayAuditStore() });

    const refused = await logger.logMessageEvent(
      sentEvent({
        direction: 'received',
        status: 'rejected',
        reason: 'did:key:z6MkStranger',
        reasonCode: 'server-not-trusted',
      }),
      signer,
    );

    expect(decodePayload(refused.signature).data).toMatchObject({
      version: 5,
      reason: 'did:key:z6MkStranger',
      status: 'rejected',
      reasonCode: 'server-not-trusted',
    });
  });

  it('leaves the signed payload of query records as it was', async () => {
    const logger = new AuditLogger({ auditStore: createArrayAuditStore() });

    const record = await logger.log(queryEntry, signer);

    const { data } = decodePayload(record.signature);
    expect(Object.keys(data)).not.toEqual(expect.arrayContaining(['version']));
    expect(data).not.toHaveProperty('status');
    expect(data).not.toHaveProperty('reasonCode');
  });

  it('records a rejected receive without a verified peer or digest', async () => {
    const logger = new AuditLogger({ auditStore: createArrayAuditStore() });

    const record = await logger.logMessageEvent(
      sentEvent({
        direction: 'received',
        status: 'rejected',
        reason: 'sender proof failed',
        reasonCode: 'PROOF_INVALID',
        counterpartAgentDid: undefined,
        counterpartInstanceDid: undefined,
        messageDigest: undefined,
      }),
      signer,
    );

    expect(record).toMatchObject({
      version: 5,
      direction: 'received',
      status: 'rejected',
      reason: 'sender proof failed',
      reasonCode: 'PROOF_INVALID',
    });
    const { data } = decodePayload(record.signature);
    expect(data).not.toHaveProperty('counterpartAgentDid');
    expect(data).not.toHaveProperty('messageDigest');
  });

  it('does not touch the store when auditing is disabled', async () => {
    const store = createArrayAuditStore();
    const logger = new AuditLogger({ auditStore: store, enabled: false });

    const first = await logger.logMessageEvent(sentEvent(), signer);
    const second = await logger.logMessageEvent(sentEvent(), signer);

    expect(store.records).toEqual([]);
    expect(second.previousHash).toBe(hashAuditRecord(first));
  });

  it('reports write failures with the message operation label', async () => {
    const store = createArrayAuditStore();
    store.append = async () => {
      throw new Error('disk full');
    };
    const logger = new AuditLogger({ auditStore: store });
    const failures: string[] = [];
    logger.setTelemetrySink({ auditWriteFailed: (event) => failures.push(event.operation) });

    await expect(logger.logMessageEvent(sentEvent(), signer)).rejects.toThrow(
      'Could not write audit record',
    );
    expect(failures).toEqual(['message']);
  });
});

describe('hash chain with version 5 records', () => {
  async function mixedChain() {
    const store = createArrayAuditStore();
    const logger = new AuditLogger({ auditStore: store });
    await logger.log(queryEntry, signer);
    await logger.logMessageEvent(sentEvent(), signer);
    await logger.logMessageEvent(
      sentEvent({ direction: 'received', messageRecordId: 'bafyrecord-two' }),
      signer,
    );
    await logger.logRejection('scope exceeded', 'SCOPE_VIOLATION', signer, {
      agentDid: agent.did,
      ownerDid: owner.did,
    });
    await logger.log(queryEntry, signer);
    return { store, logger };
  }

  it('verifies a chain mixing query, message and rejection records', async () => {
    const { store, logger } = await mixedChain();

    expect(store.records.map((r) => r.version)).toEqual([4, 5, 5, 4, 4]);
    expect(await logger.verifyAuditChain()).toEqual({ ok: true, totalRecords: 5, partial: false });
  });

  const tampered: Array<[keyof AuditRecord, unknown]> = [
    ['eventKind', 'query'],
    ['direction', 'received'],
    ['counterpartAgentDid', 'did:key:zSomeoneElse'],
    ['counterpartInstanceDid', 'did:dht:otherinstance'],
    ['messageRecordId', 'bafyrecord-forged'],
    ['messageDigest', 'f'.repeat(64)],
    ['messageDigest', undefined],
  ];

  it.each(tampered)('detects a change to %s on a message record', async (field, value) => {
    const { store, logger } = await mixedChain();

    store.records[1] = { ...store.records[1], [field]: value };

    const result = await logger.verifyAuditChain();
    expect(result.ok).toBe(false);
    expect(result.failedAt).toBe(store.records[2].id);
  });
});

describe('hashAuditRecord stability for versions 1 to 4', () => {
  const fixture = {
    id: '00000000-0000-4000-8000-000000000001',
    timestamp: '2026-01-02T03:04:05.000Z',
    agentDid: 'did:key:zAgentFixture',
    ownerDid: 'did:key:zOwnerFixture',
    credentialId: 'abcdef0123456789',
    queryHash: 'a'.repeat(64),
    columnsAccessed: ['patients.name', 'patients.dob'],
    rowCount: 3,
    durationMs: 12,
    previousHash: 'GENESIS',
    status: 'rejected' as const,
    reason: 'scope exceeded',
    reasonCode: 'SCOPE_VIOLATION',
    orgId: 'org-fixture',
    delegatorDid: 'did:key:zDelegatorFixture',
    delegatedGrantId: 'grant-fixture',
    eventKind: 'message' as const,
    direction: 'sent' as const,
    counterpartAgentDid: 'did:key:zPeerFixture',
    counterpartInstanceDid: 'did:dht:peerFixture',
    messageRecordId: 'bafyrecord-fixture',
    messageDigest: 'b'.repeat(64),
  };

  // Computed before version 5 existed; message fields on an older version must not enter its hash.
  const frozen: Array<[1 | 2 | 3 | 4, string]> = [
    [1, '1ccdce970a7c99602cdaffc51d4766b3c18afec545a1326f5d6dded03f879642'],
    [2, '7e71bd03575029112e79ae95bd0eed98ae889c2d5fcba6efd2df8d8287c58d1b'],
    [3, '19597ef6c6e9bf427cb9347480e2756c25c2342004d32655d4f2c7953d3ad910'],
    [4, 'ad5f23f4134c7f0fadf2f0371b24aae4041b95ede414ecadd4285c43a48c84b2'],
  ];

  it.each(frozen)('version %i hashes as before', (version, expected) => {
    expect(hashAuditRecord({ ...fixture, version })).toBe(expected);
  });

  it('version 5 hashes the message fields', () => {
    const v5 = hashAuditRecord({ ...fixture, version: 5 });
    expect(v5).not.toBe(hashAuditRecord({ ...fixture, version: 5, messageDigest: 'c'.repeat(64) }));
    expect(v5).not.toBe(hashAuditRecord({ ...fixture, version: 4 }));
  });
});

describe('export filters', () => {
  it('forwards the message filters to the store', async () => {
    const store = createArrayAuditStore();
    const seen: unknown[] = [];
    store.query = async (filter) => {
      seen.push(filter);
      return [];
    };
    const logger = new AuditLogger({ auditStore: store });

    await logger.export({ eventKind: 'message', messageRecordId: 'bafy', direction: 'sent' });

    expect(seen).toEqual([{ eventKind: 'message', messageRecordId: 'bafy', direction: 'sent' }]);
  });
});
