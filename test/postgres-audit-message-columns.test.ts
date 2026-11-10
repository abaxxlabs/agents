import { randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { AuditLogger, hashAuditRecord } from '#audit/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import { PostgresAuditStore } from '#storage/postgres/audit-store.js';
import type { AuditRecord, MessageAuditEvent } from '#types/index.js';

const { Pool } = pg;

const DB_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:54322/postgres';

const MIGRATIONS_DIR = join(process.cwd(), 'migrations');
const MIGRATION_011 = readFileSync(join(MIGRATIONS_DIR, '011_audit_message_events.sql'), 'utf8');

async function isPostgresReachable(): Promise<boolean> {
  const p = new Pool({ connectionString: DB_URL, max: 1, connectionTimeoutMillis: 2000 });
  try {
    await p.query('SELECT 1');
    await p.end();
    return true;
  } catch {
    await p.end().catch(() => undefined);
    return false;
  }
}

const postgresReachable = await isPostgresReachable();
const describeFn = postgresReachable ? describe : describe.skip;

describeFn('PostgresAuditStore message columns (live Postgres required)', () => {
  // agent_audit is append-only, so rows stay; they are scoped to this run's agent DID.
  const run = randomUUID();
  const agent = generateDidKey();
  const signer = createSigner(agent.privateKey);
  let pool: pg.Pool;
  let store: PostgresAuditStore;

  function event(overrides: Partial<MessageAuditEvent> = {}): MessageAuditEvent {
    return {
      agentDid: agent.did,
      ownerDid: `did:test:${run}:owner`,
      direction: 'sent',
      status: 'success',
      messageRecordId: `bafy-${run}-one`,
      messageDigest: 'e'.repeat(64),
      counterpartAgentDid: `did:test:${run}:peer`,
      counterpartInstanceDid: `did:test:${run}:instance`,
      orgId: `org-${run}`,
      ...overrides,
    };
  }

  // timestamp comes back as a Date, and absent reasons as null, as for every other record.
  function messageFields(record: AuditRecord): Partial<AuditRecord> {
    const keys = Object.keys(record).filter(
      (k) => !['timestamp', 'reason', 'reasonCode'].includes(k),
    ) as Array<keyof AuditRecord>;
    return Object.fromEntries(keys.map((k) => [k, record[k]]));
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 2 });
    // A fresh database gets the whole chain of migrations; an existing one only needs 011.
    const { rows } = await pool.query(`SELECT to_regclass('agent_audit') AS audit`);
    if (!rows[0].audit) {
      const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql') && f < '011');
      for (const file of files.sort()) {
        await pool.query(readFileSync(join(MIGRATIONS_DIR, file), 'utf8'));
      }
    }
    await pool.query(MIGRATION_011);
    store = new PostgresAuditStore(pool);
  });

  afterAll(async () => {
    if (pool) await pool.end();
  });

  it('applying migration 011 again is a no-op and creates the lookup index', async () => {
    await expect(pool.query(MIGRATION_011)).resolves.toBeDefined();
    const { rows } = await pool.query(
      `SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_agent_audit_message'`,
    );
    expect(rows[0].indexdef).toContain('(agent_did, message_record_id)');
  });

  it('round trips message records and honours the message filters', async () => {
    const logger = new AuditLogger({ auditStore: store });
    const sent = await logger.logMessageEvent(event(), signer);
    const received = await logger.logMessageEvent(
      event({
        direction: 'received',
        messageRecordId: `bafy-${run}-two`,
        status: 'rejected',
        reason: 'sender proof failed',
        reasonCode: 'PROOF_INVALID',
        counterpartAgentDid: undefined,
      }),
      signer,
    );

    const [readSent] = await store.query({ id: sent.id });
    expect(messageFields(readSent)).toEqual(messageFields(sent));
    const [readReceived] = await store.query({ id: received.id });
    expect(messageFields(readReceived)).toEqual(messageFields(received));
    expect(readReceived.reasonCode).toBe('PROOF_INVALID');
    expect(received.previousHash).toBe(hashAuditRecord(readSent));
    expect(await logger.verifyRecord(readReceived, agent.publicKey)).toBe(true);

    const mine = { agentDid: agent.did };
    const cases = [
      [{ ...mine, eventKind: 'message' as const }, 2],
      [{ ...mine, eventKind: 'query' as const }, 0],
      [{ ...mine, direction: 'received' as const }, 1],
      [{ ...mine, messageRecordId: `bafy-${run}-one` }, 1],
      [{ ...mine, eventKind: 'message' as const, direction: 'sent' as const }, 1],
    ] as const;
    for (const [filter, expected] of cases) {
      expect(await store.query(filter)).toHaveLength(expected);
      expect(await store.count(filter)).toBe(expected);
    }
  });

  it('finds several record ids in one query', async () => {
    const logger = new AuditLogger({ auditStore: store });
    const ids = [`bafy-${run}-batch-a`, `bafy-${run}-batch-b`];
    for (const messageRecordId of ids) {
      await logger.logMessageEvent(event({ direction: 'received', messageRecordId }), signer);
    }

    const found = await store.query({ messageRecordIds: [...ids, 'missing'] });
    expect(found.map((r) => r.messageRecordId).sort()).toEqual(ids);
    expect(await store.count({ messageRecordIds: [] })).toBe(0);
  });

  it('writes query records on a database that has not run migration 011', async () => {
    const database = `audit_premig_${run.replace(/[^a-z0-9]/gi, '').toLowerCase()}`;
    await pool.query(`CREATE DATABASE ${database}`);
    const url = new URL(DB_URL!);
    url.pathname = `/${database}`;
    const bare = new Pool({ connectionString: url.toString(), max: 2 });
    try {
      const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql') && f < '011');
      for (const file of files.sort()) {
        await bare.query(readFileSync(join(MIGRATIONS_DIR, file), 'utf8'));
      }
      const queryAgent = generateDidKey();
      const logger = new AuditLogger({ auditStore: new PostgresAuditStore(bare) });
      const entry = {
        agentDid: queryAgent.did,
        ownerDid: `did:test:${run}:owner`,
        credentialJwt: 'eyJ.test.jwt',
        sql: 'SELECT 1',
        columnsAccessed: [],
        rowCount: 1,
        durationMs: 1,
      };

      await logger.log(entry, createSigner(queryAgent.privateKey));
      await logger.log(entry, createSigner(queryAgent.privateKey));
      expect(await logger.verifyAuditChain()).toMatchObject({ ok: true, totalRecords: 2 });

      await bare.query(MIGRATION_011);
      const { rows } = await bare.query(
        `SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_agent_audit_message'`,
      );
      expect(rows[0].indexdef).toContain('WHERE (message_record_id IS NOT NULL)');
      await logger.logMessageEvent(
        { ...event(), agentDid: queryAgent.did },
        createSigner(queryAgent.privateKey),
      );
      expect(await logger.verifyAuditChain()).toMatchObject({ ok: true, totalRecords: 3 });
    } finally {
      await bare.end();
      await pool.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    }
  });

  it('gives every record of a burst from two loggers its own timestamp, in chain order', async () => {
    const burstAgent = generateDidKey();
    const loggers = [
      new AuditLogger({ auditStore: store }),
      new AuditLogger({ auditStore: store }),
    ];
    const written = await Promise.all(
      Array.from({ length: 80 }, (_, index) =>
        loggers[index % 2].logMessageEvent(
          event({ agentDid: burstAgent.did, messageRecordId: `bafy-${run}-burst-${index}` }),
          createSigner(burstAgent.privateKey),
        ),
      ),
    );

    const stored = await store.query({ agentDid: burstAgent.did });
    const times = stored.map((record) => new Date(record.timestamp).getTime());
    expect(new Set(times).size).toBe(80);
    expect(times).toEqual([...times].sort((a, b) => a - b));
    // Each record chains to the one written just before it, by either logger.
    const byHash = new Map(stored.map((record) => [hashAuditRecord(record), record]));
    const linked = stored.filter((record) => byHash.has(record.previousHash));
    expect(linked.length).toBe(79);
    for (const record of linked) {
      const previous = byHash.get(record.previousHash)!;
      expect(new Date(previous.timestamp).getTime()).toBeLessThan(
        new Date(record.timestamp).getTime(),
      );
    }
    expect(written).toHaveLength(80);
  });

  it('counts version 4 query rows as queries', async () => {
    const queryAgent = generateDidKey();
    const logger = new AuditLogger({ auditStore: store });
    const written = await logger.log(
      {
        agentDid: queryAgent.did,
        ownerDid: `did:test:${run}:owner`,
        credentialJwt: 'eyJ.test.jwt',
        sql: 'SELECT 1',
        columnsAccessed: [],
        rowCount: 1,
        durationMs: 1,
      },
      createSigner(queryAgent.privateKey),
    );

    expect(written.version).toBe(4);
    expect(await store.count({ agentDid: queryAgent.did, eventKind: 'query' })).toBe(1);
    expect(await store.count({ agentDid: queryAgent.did, eventKind: 'message' })).toBe(0);
    const [readBack] = await store.query({ agentDid: queryAgent.did });
    expect(readBack.eventKind).toBeUndefined();
    expect(readBack.messageDigest).toBeUndefined();
  });
});
