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

  function messageFields(record: AuditRecord): Partial<AuditRecord> {
    const keys = Object.keys(record).filter(
      (k) => !['timestamp', 'reason', 'reasonCode'].includes(k),
    ) as Array<keyof AuditRecord>;
    return Object.fromEntries(keys.map((k) => [k, record[k]]));
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 2 });
    const { rows } = await pool.query(`SELECT to_regclass('agent_audit') AS audit`);
    const files = readdirSync(MIGRATIONS_DIR).filter(
      (file) => file.endsWith('.sql') && (!rows[0].audit || file.includes('_audit_')),
    );
    for (const file of files.sort()) {
      await pool.query(readFileSync(join(MIGRATIONS_DIR, file), 'utf8'));
    }
    store = new PostgresAuditStore(pool);
  });

  afterAll(async () => {
    if (pool) await pool.end();
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
});
