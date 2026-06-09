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
  // Two distinctive 32-byte keys so the wrong-key path is structurally
  // unambiguous. 0xAA and 0xBB share no bytes; an unwrap with one against
  // ciphertext from the other is guaranteed to fail at the GCM auth tag.
  const KEY_A_BYTE = 0xaa;
  const KEY_B_BYTE = 0xbb;
  const keyABuf = Buffer.alloc(32, KEY_A_BYTE);
  const keyBBuf = Buffer.alloc(32, KEY_B_BYTE);

  let pool: pg.Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 2 });
  });

  afterAll(async () => {
    // Leave the test DB clean so subsequent runs (and the hygiene suite) don't
    // see leftover rows wrapped under our test keys.
    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);
    await pool.end().catch(() => undefined);
  });

  beforeEach(async () => {
    await pool.query('DELETE FROM agent_keys');
    await pool.query('DELETE FROM agents');
  });

  /**
   * Build an AgentScope against the live Postgres but with InMemoryRevocationStore
   * composed in (avoids a hard dependency on migration 007). This mirrors the
   * hygiene suite's harness — the suite is testing the AgentScope.create path's
   * wrong-key gate, not Postgres-side revocation.
   */
  async function createScope(masterKey: Buffer): Promise<AgentScope> {
    const base = PostgresStorageBackend.fromPool(pool, false, { sessionMacKey: deterministicSessionMacKey() });
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
      // Seed two `agent_keys` rows wrapped with key A.
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

      // Boot AgentScope with key B → MUST throw.
      await expect(createScope(keyBBuf)).rejects.toBeInstanceOf(MasterKeyMismatchError);
    });

    it('throws with the exact MasterKeyMismatchError message text', async () => {
      const colKey = generateColumnKey();
      const wrapped = wrapColumnKey(colKey, asMasterKey(keyABuf));
      await pool.query(
        `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
         VALUES ($1, $2, $3, $4)`,
        ['patients', 'dob', wrapped, 'aes-256-gcm'],
      );

      await expect(createScope(keyBBuf)).rejects.toThrow(
        'Column keys exist but cannot be decrypted with the provided master key. Wrong key or corrupted data.',
      );
    });

    it('attaches failedCount + totalCount metadata', async () => {
      const wrapped1 = wrapColumnKey(generateColumnKey(), asMasterKey(keyABuf));
      const wrapped2 = wrapColumnKey(generateColumnKey(), asMasterKey(keyABuf));
      const wrapped3 = wrapColumnKey(generateColumnKey(), asMasterKey(keyABuf));
      await pool.query(
        `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
         VALUES ($1, $2, $3, $4), ($5, $6, $7, $8), ($9, $10, $11, $12)`,
        [
          'patients',
          'dob',
          wrapped1,
          'aes-256-gcm',
          'patients',
          'diagnosis',
          wrapped2,
          'aes-256-gcm',
          'patients',
          'ssn',
          wrapped3,
          'aes-256-gcm',
        ],
      );

      try {
        await createScope(keyBBuf);
        throw new Error('expected MasterKeyMismatchError');
      } catch (err) {
        expect(err).toBeInstanceOf(MasterKeyMismatchError);
        // AgentScopeError stores the third constructor arg as `details`
        // (see src/errors.ts:8-17). MasterKeyMismatchError forwards
        // { failedCount, totalCount } into that bag.
        const e = err as MasterKeyMismatchError;
        expect(e.details?.failedCount).toBe(3);
        expect(e.details?.totalCount).toBe(3);
      }
    });

    it('boots cleanly when all rows are wrapped with the matching key', async () => {
      const colKey = generateColumnKey();
      const wrapped = wrapColumnKey(colKey, asMasterKey(keyABuf));
      await pool.query(
        `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
         VALUES ($1, $2, $3, $4)`,
        ['patients', 'dob', wrapped, 'aes-256-gcm'],
      );

      // Same key A → boots clean. The contract is: matching key in, real
      // scope out, no throw.
      const scope = await createScope(keyABuf);
      expect(scope).toBeInstanceOf(AgentScope);
      await scope.close();
    });

    it('boots cleanly when agent_keys is empty', async () => {
      // No rows → no decrypt-failure signal → no throw, even with a "wrong"
      // key. The wrong-key gate is rows.length > 0 && keys.size === 0.
      const scope = await createScope(keyBBuf);
      expect(scope).toBeInstanceOf(AgentScope);
      await scope.close();
    });
  });

  describe('schema-missing path (legitimate pre-migration boot)', () => {
    it('boots cleanly when agent_keys table does not exist', async () => {
      // Simulate a pre-migration deployment. We drop and then recreate so the
      // suite leaves the test DB schema intact for any later test that queries
      // `agent_keys` (e.g., rotation tests touching `rotated_at`).
      //
      // The recreate DDL mirrors migrations/001_init.sql:80-89 verbatim
      // (table renamed by 005_rename_tables.sql). If migration 001 changes,
      // update this DDL — it is intentionally not import-from-file because
      // the production migration runner expects the file path to resolve from
      // the package root, which a test file shouldn't depend on.
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
