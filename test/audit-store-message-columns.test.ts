import { AuditLogger } from '#audit/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import { SQLITE_MIGRATIONS, SQLITE_SCHEMA_STATEMENTS } from '#storage/sqlite/migrations.js';
import type { AuditEntry, AuditRecord, MessageAuditEvent } from '#types/index.js';
import { deterministicSessionMacKey } from './support/deterministic-session-mac-key.js';

const MESSAGE_COLUMNS = [
  'event_kind',
  'direction',
  'counterpart_agent_did',
  'counterpart_instance_did',
  'message_record_id',
  'message_digest',
];

const MESSAGE_FIELDS = [
  'version',
  'eventKind',
  'direction',
  'status',
  'counterpartAgentDid',
  'counterpartInstanceDid',
  'messageRecordId',
  'messageDigest',
  'orgId',
  'signature',
  'previousHash',
] as const;

function messageFields(record: AuditRecord): Partial<AuditRecord> {
  return Object.fromEntries(MESSAGE_FIELDS.map((k) => [k, record[k]]));
}

interface SqliteDb {
  exec(sql: string): unknown;
  prepare(sql: string): {
    all(...params: unknown[]): unknown[];
    run(...params: unknown[]): unknown;
  };
}

function innerDb(backend: SqliteStorageBackend): SqliteDb {
  return (backend as unknown as { db: SqliteDb }).db;
}

function auditColumns(backend: SqliteStorageBackend): string[] {
  const rows = innerDb(backend).prepare('PRAGMA table_info(agent_audit)').all() as Array<{
    name: string;
  }>;
  return rows.map((r) => r.name);
}

async function createBackend(): Promise<SqliteStorageBackend> {
  const sessionMacKey = deterministicSessionMacKey('audit-message-columns');
  return SqliteStorageBackend.create(
    { type: 'sqlite', path: ':memory:', sessionMacKey },
    { sessionMacKey },
  );
}

const agent = generateDidKey();
const peer = generateDidKey();
const owner = generateDidKey();
const signer = createSigner(agent.privateKey);

const entry: AuditEntry = {
  agentDid: agent.did,
  ownerDid: owner.did,
  credentialJwt: 'eyJ.test.jwt',
  sql: 'SELECT name FROM patients',
  columnsAccessed: ['patients.name'],
  rowCount: 1,
  durationMs: 3,
};

function event(overrides: Partial<MessageAuditEvent> = {}): MessageAuditEvent {
  return {
    agentDid: agent.did,
    ownerDid: owner.did,
    direction: 'sent',
    status: 'success',
    messageRecordId: 'bafyrecord-one',
    messageDigest: 'd'.repeat(64),
    counterpartAgentDid: peer.did,
    counterpartInstanceDid: 'did:dht:peerinstance',
    orgId: 'org-one',
    ...overrides,
  };
}

describe('SqliteAuditStore message columns', () => {
  let backend: SqliteStorageBackend;

  beforeEach(async () => {
    backend = await createBackend();
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('reads back every message field and keeps the chain verifiable', async () => {
    const logger = new AuditLogger({ auditStore: backend.audit });
    const written = await logger.logMessageEvent(event(), signer);

    const [readBack] = await backend.audit.query({ id: written.id });
    expect(messageFields(readBack)).toEqual(messageFields(written));
    expect(messageFields(written)).toMatchObject({ version: 5, eventKind: 'message' });
    expect(await logger.verifyRecord(readBack, agent.publicKey)).toBe(true);
  });

  it('filters by eventKind, messageRecordId and direction, with count in agreement', async () => {
    const logger = new AuditLogger({ auditStore: backend.audit });
    await logger.log(entry, signer);
    await logger.logMessageEvent(event(), signer);
    await logger.logMessageEvent(
      event({ direction: 'received', messageRecordId: 'bafyrecord-two' }),
      signer,
    );
    await logger.logRejection('scope exceeded', 'SCOPE_VIOLATION', signer, {
      agentDid: agent.did,
      ownerDid: owner.did,
    });

    const cases = [
      [{ eventKind: 'query' as const }, 2],
      [{ eventKind: 'message' as const }, 2],
      [{ messageRecordId: 'bafyrecord-two' }, 1],
      [{ direction: 'sent' as const }, 1],
      [{ eventKind: 'message' as const, direction: 'received' as const }, 1],
      [{ agentDid: agent.did, messageRecordId: 'bafyrecord-one' }, 1],
      [{ eventKind: 'message' as const, messageRecordId: 'missing' }, 0],
      [{ messageRecordIds: ['bafyrecord-one', 'bafyrecord-two'] }, 2],
      [{ messageRecordIds: ['bafyrecord-two', 'missing'], direction: 'received' as const }, 1],
      [{ messageRecordIds: ['missing'] }, 0],
      [{ messageRecordIds: [] as string[] }, 0],
    ] as const;
    for (const [filter, expected] of cases) {
      expect(await backend.audit.query(filter)).toHaveLength(expected);
      expect(await backend.audit.count(filter)).toBe(expected);
    }

    const [received] = await backend.audit.query({ messageRecordId: 'bafyrecord-two' });
    expect(received.direction).toBe('received');
    const queries = await backend.audit.query({ eventKind: 'query' });
    expect(queries.every((r) => r.eventKind === undefined && r.version === 4)).toBe(true);

    const verifier = new AuditLogger({ auditStore: backend.audit, enabled: false });
    expect(await verifier.verifyAuditChain()).toMatchObject({ ok: true, totalRecords: 4 });
  });

  it('creates the message lookup index', () => {
    const rows = innerDb(backend)
      .prepare('PRAGMA index_info(idx_agent_audit_message)')
      .all() as Array<{
      name: string;
    }>;
    expect(rows.map((r) => r.name)).toEqual(['agent_did', 'message_record_id']);
  });
});

describe('agent_audit message columns on an existing SQLite database', () => {
  const legacySchema = SQLITE_SCHEMA_STATEMENTS.map((sql) =>
    sql.includes('CREATE TABLE IF NOT EXISTS agent_audit')
      ? sql
          .split('\n')
          .filter((line) => !MESSAGE_COLUMNS.some((c) => line.trim().startsWith(`${c} `)))
          .join('\n')
          .replace('reason_code TEXT,', 'reason_code TEXT')
      : sql,
  );
  const legacyMigrations = SQLITE_MIGRATIONS.filter(
    (sql) => !MESSAGE_COLUMNS.some((c) => sql.includes(c)),
  );

  it('writes and reads query records before the columns exist', async () => {
    const backend = await createBackend();
    try {
      const db = innerDb(backend);
      for (const sql of legacySchema) db.exec(sql);
      for (const sql of legacyMigrations) {
        try {
          db.exec(sql);
        } catch {
          // duplicate column, as initialize() tolerates
        }
      }
      expect(auditColumns(backend)).not.toContain('event_kind');

      const logger = new AuditLogger({ auditStore: backend.audit });
      await logger.log(entry, signer);
      await logger.log(entry, signer);

      expect(await logger.verifyAuditChain()).toMatchObject({ ok: true, totalRecords: 2 });
      await expect(logger.logMessageEvent(event(), signer)).rejects.toThrow();
    } finally {
      await backend.close();
    }
  });

  it('initialize() adds the columns and older records still verify', async () => {
    const backend = await createBackend();
    try {
      const db = innerDb(backend);
      for (const sql of legacySchema) db.exec(sql);
      for (const sql of legacyMigrations) {
        try {
          db.exec(sql);
        } catch {
          // duplicate column, as initialize() tolerates
        }
      }
      expect(auditColumns(backend)).not.toContain('event_kind');

      const scratch = new AuditLogger({ auditStore: backend.audit, enabled: false });
      const old = await scratch.log(entry, signer);
      db.prepare(
        `INSERT INTO agent_audit (id, timestamp, agent_did, owner_did, credential_id, query_hash,
          columns_accessed, row_count, duration_ms, previous_hash, signature, version, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        old.id,
        old.timestamp,
        old.agentDid,
        old.ownerDid,
        old.credentialId,
        old.queryHash,
        JSON.stringify(old.columnsAccessed),
        old.rowCount,
        old.durationMs,
        old.previousHash,
        old.signature,
        old.version,
        old.status,
      );

      await backend.initialize();

      expect(auditColumns(backend)).toEqual(expect.arrayContaining(MESSAGE_COLUMNS));
      const logger = new AuditLogger({ auditStore: backend.audit });
      const message = await logger.logMessageEvent(event(), signer);
      const [readBack] = await backend.audit.query({ eventKind: 'message' });
      expect(messageFields(readBack)).toEqual(messageFields(message));
      expect(await backend.audit.count({ eventKind: 'query' })).toBe(1);
      expect(await logger.verifyAuditChain()).toMatchObject({ ok: true, totalRecords: 2 });
    } finally {
      await backend.close();
    }
  });
});
