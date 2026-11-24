import { createHash } from 'node:crypto';
import { AuditLogger } from '#audit/index.js';
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

  it('verifies a mixed chain and rejects a changed message digest', async () => {
    const { store, logger } = await mixedChain();

    expect(store.records.map((r) => r.version)).toEqual([4, 5, 5, 4, 4]);
    expect(await logger.verifyAuditChain()).toEqual({ ok: true, totalRecords: 5, partial: false });
    const original = store.records[1];
    store.records[1] = { ...original, messageDigest: 'f'.repeat(64) };
    expect(await logger.verifyAuditChain()).toMatchObject({
      ok: false,
      failedAt: store.records[2].id,
    });
    store.records[1] = original;
    expect((await logger.verifyAuditChain()).ok).toBe(true);
  });
});
