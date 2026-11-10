/**
 * The audit service is what the verify-chain tool and the REST route call. It has to verify a
 * chain that holds message records, and a burst of message records has to keep its order.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditLogger } from '#audit/index.js';
import { createSigner, generateDidKey } from '#auth/index.js';
import { createAuditService } from '#services/audit.js';
import type { AuditStore } from '#storage/types.js';
import type { AuditEntry, AuditRecord, MessageAuditEvent } from '#types/index.js';

function createArrayAuditStore(): AuditStore {
  const records: AuditRecord[] = [];
  return {
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
const owner = generateDidKey();
const signer = createSigner(agent.privateKey);

const query: AuditEntry = {
  agentDid: agent.did,
  ownerDid: owner.did,
  credentialJwt: 'eyJ.test.jwt',
  sql: 'SELECT 1',
  columnsAccessed: [],
  rowCount: 1,
  durationMs: 1,
};

function message(index: number): MessageAuditEvent {
  return {
    agentDid: agent.did,
    ownerDid: owner.did,
    direction: 'received',
    status: 'success',
    messageRecordId: `bafyrecord-${index}`,
    messageDigest: 'a'.repeat(64),
    counterpartAgentDid: 'did:key:z6MkPeer',
    counterpartInstanceDid: 'did:key:z6MkPeerInstance',
  };
}

describe('audit service on chains with message records', () => {
  it('verifies a chain that mixes query and message records', async () => {
    const logger = new AuditLogger({ auditStore: createArrayAuditStore() });
    await logger.log(query, signer);
    await logger.logMessageEvent(message(1), signer);
    await logger.log(query, signer);

    const service = createAuditService({
      auditReader: logger,
      verifier: { verify: async () => ({ valid: true, status: 'VALID' }) },
    });
    // The tool and the REST route always pass the session owner, as here.
    const result = await service.verifyChain({}, { ownerDid: owner.did });

    expect(result).toMatchObject({
      verified: true,
      recordsChecked: 3,
      brokenLinks: [],
      visibilityWindowBreaks: [],
    });
  });
});

describe('a burst of message records on SQLite', () => {
  const directories: string[] = [];
  afterEach(() => {
    for (const directory of directories.splice(0))
      rmSync(directory, { recursive: true, force: true });
  });

  it('keeps insertion order and verifies', async () => {
    const { SqliteStorageBackend } = await import('#storage/sqlite/index.js');
    const { deterministicSessionMacKey } =
      await import('./support/deterministic-session-mac-key.js');
    const directory = mkdtempSync(join(tmpdir(), 'audit-burst-'));
    directories.push(directory);
    const sessionMacKey = deterministicSessionMacKey('audit-burst');
    const backend = await SqliteStorageBackend.create(
      { type: 'sqlite', path: join(directory, 'audit.sqlite'), sessionMacKey },
      { sessionMacKey },
    );
    await backend.initialize();
    const logger = new AuditLogger({ auditStore: backend.audit });

    for (let index = 0; index < 40; index += 1)
      await logger.logMessageEvent(message(index), signer);

    const records = await logger.export();
    expect(records.map((record) => record.messageRecordId)).toEqual(
      Array.from({ length: 40 }, (_, index) => `bafyrecord-${index}`),
    );
    expect(new Set(records.map((record) => String(record.timestamp))).size).toBe(40);
    expect(await logger.verifyAuditChain()).toMatchObject({ ok: true, totalRecords: 40 });
    await backend.close();
  });
});
