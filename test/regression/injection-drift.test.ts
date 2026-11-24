import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { AgentScope } from '#sql/index.js';
import { asMasterKey } from '#crypto/master-key.js';
import { composeStorageBackend } from '#storage/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { PostgresStorageBackend } from '#storage/postgres/index.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';

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

describeFn('Injection drift regression (live Postgres required)', () => {
  const MASTER_KEY_BYTE = 0xcd;

  let pool: pg.Pool;
  let scope: AgentScope;
  let injectedRevocation: InMemoryRevocationStore;
  let pruneExpiredSpy: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 2 });

    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);

    const base = PostgresStorageBackend.fromPool(pool, false, {
      sessionMacKey: deterministicSessionMacKey(),
    });

    injectedRevocation = new InMemoryRevocationStore();
    pruneExpiredSpy = vi.spyOn(injectedRevocation, 'pruneExpired');

    const storage = composeStorageBackend(base, { revocation: injectedRevocation });
    const masterKey = asMasterKey(Buffer.alloc(32, MASTER_KEY_BYTE));

    scope = await AgentScope.create(
      {
        database: { connectionString: DB_URL },
        abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'd34-test-a' },
      },
      { masterKey, storage, pool },
    );
  });

  afterAll(async () => {
    try {
      await scope.close();
    } catch {
      // Tolerate double-close.
    }
    await pool.end().catch(() => undefined);
  });

  it('scope.pruneRevocations() routes through to injections.storage.revocation', async () => {
    pruneExpiredSpy.mockClear();
    await scope.pruneRevocations(new Date(Date.now() + 1_000_000));

    expect(pruneExpiredSpy).toHaveBeenCalledOnce();
  });
});
