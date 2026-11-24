import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuditLogger } from '#audit/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import type { AuditEntry } from '#types/index.js';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import { deterministicSessionMacKey } from './support/deterministic-session-mac-key.js';

function makeEntry(agentDid: string, ownerDid: string): AuditEntry {
  return {
    agentDid,
    ownerDid,
    credentialJwt: 'eyJ.test.jwt',
    sql: 'SELECT * FROM patients',
    columnsAccessed: ['patients.name'],
    rowCount: 1,
    durationMs: 10,
  };
}

describe('SQLite audit store — v3 columns round-trip', () => {
  let backend: SqliteStorageBackend;
  const agent = generateDidKey();
  const human = generateDidKey();

  beforeEach(async () => {
    backend = await SqliteStorageBackend.create(
      {
        type: 'sqlite',
        path: ':memory:',
        sessionMacKey: deterministicSessionMacKey('sqlite-audit-v3'),
      },
      { sessionMacKey: deterministicSessionMacKey('sqlite-audit-v3') },
    );
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('reads back a query audit record with the version it was created with', async () => {
    const logger = new AuditLogger({ auditStore: backend.audit, enabled: true });
    const signer = createSigner(agent.privateKey);

    const written = await logger.log(makeEntry(agent.did, human.did), signer);

    const [readBack] = await backend.audit.query();
    expect(readBack.version).toBe(written.version);
    expect(readBack.status).toBe('success');
  });
});
