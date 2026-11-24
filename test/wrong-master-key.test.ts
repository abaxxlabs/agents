import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { AgentScope } from '#sql/index.js';
import { asMasterKey } from '#crypto/master-key.js';
import { wrapColumnKey, generateColumnKey } from '#encryption/index.js';
import { MasterKeyMismatchError } from '#errors/index.js';
import { PostgresStorageBackend } from '#storage/postgres/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { composeStorageBackend } from '#storage/compose.js';
import { deterministicSessionMacKey } from './support/deterministic-session-mac-key.js';

const { Pool } = pg;

const DB_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:54322/postgres';

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

describeFn('wrong-master-key safety (live Postgres required)', () => {
  const KEY_A_BYTE = 0xaa;
  const KEY_B_BYTE = 0xbb;
  const keyABuf = Buffer.alloc(32, KEY_A_BYTE);
  const keyBBuf = Buffer.alloc(32, KEY_B_BYTE);

  let pool: pg.Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 2 });
  });

  afterAll(async () => {
    // Remove rows wrapped with test keys so later suites can use their own master keys.
    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);
    await pool.end().catch(() => undefined);
  });

  beforeEach(async () => {
    await pool.query('DELETE FROM agent_keys');
    await pool.query('DELETE FROM agents');
  });

  async function createScope(masterKey: Buffer): Promise<AgentScope> {
    const base = PostgresStorageBackend.fromPool(pool, false, {
      sessionMacKey: deterministicSessionMacKey(),
    });
    const storage = composeStorageBackend(base, { revocation: new InMemoryRevocationStore() });
    return AgentScope.create(
      {
        database: { connectionString: DB_URL },
        abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'b5-test' },
      },
      { masterKey: asMasterKey(masterKey), storage, pool },
    );
  }

  describe('agent_keys wrong-key path (loadColumnKeys gate)', () => {
    it('throws MasterKeyMismatchError when all rows are wrapped under a different key', async () => {
      const colKey1 = generateColumnKey();
      const colKey2 = generateColumnKey();
      const wrapped1 = wrapColumnKey(colKey1, asMasterKey(keyABuf));
      const wrapped2 = wrapColumnKey(colKey2, asMasterKey(keyABuf));

      await pool.query(
        `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
         VALUES ($1, $2, $3, $4), ($5, $6, $7, $8)`,
        [
          'patients',
          'dob',
          wrapped1,
          'aes-256-gcm',
          'patients',
          'diagnosis',
          wrapped2,
          'aes-256-gcm',
        ],
      );

      await expect(createScope(keyBBuf)).rejects.toBeInstanceOf(MasterKeyMismatchError);
    });
  });

  describe('schema-missing path (legitimate pre-migration boot)', () => {
    it('boots cleanly when agent_keys table does not exist', async () => {
      // Recreate the DDL afterward so later tests see the schema intact.
      const recreateDdl = `CREATE TABLE IF NOT EXISTS agent_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        table_name TEXT NOT NULL,
        column_name TEXT NOT NULL,
        encrypted_key BYTEA NOT NULL,
        algorithm TEXT DEFAULT 'aes-256-gcm',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        rotated_at TIMESTAMPTZ,
        UNIQUE(table_name, column_name)
      )`;
      const recreateIndex = `CREATE INDEX IF NOT EXISTS idx_keys_table_column ON agent_keys(table_name, column_name)`;

      await pool.query('DROP TABLE IF EXISTS agent_keys CASCADE');
      try {
        const scope = await createScope(keyBBuf);
        expect(scope).toBeInstanceOf(AgentScope);
        await scope.close();
      } finally {
        await pool.query(recreateDdl);
        await pool.query(recreateIndex);
      }
    });
  });
});
