import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { PostgresSessionStore } from '#storage/postgres/session-store.js';
import { deriveSessionMacKey } from '#storage/envelope-mac.js';
import { asMasterKey } from '#crypto/master-key.js';
import {
  EnvelopeIntegrityError,
  ProviderNotAllowedError,
  type SessionEnvelope,
} from '#storage/types.js';

type StoreInternals = { cache: Map<string, unknown> };
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const { Pool } = pg;

const DB_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:54322/postgres';

function env(overrides: Partial<SessionEnvelope> = {}): SessionEnvelope {
  return {
    humanDid: 'did:key:zTestAlice',
    oidcIssuer: 'https://login.abaxx.one/realms/test',
    oidcSubject: 'alice-sub',
    providerKind: 'oidc-abaxx-one',
    createdAt: 0,
    expiresAt: 0,
    ...overrides,
  };
}

/** Probe Postgres reachability to gate the whole suite (CI without a DB skips). */
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

describeFn('PostgresSessionStore (live Postgres required)', () => {
  let pool: pg.Pool;
  let store: PostgresSessionStore;
  // MasterKey must be 32 bytes; pad the test label for deriveSessionMacKey.
  const masterBuf = Buffer.alloc(32);
  Buffer.from('postgres-test-master', 'utf8').copy(masterBuf);
  const macKey = deriveSessionMacKey(asMasterKey(masterBuf));

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 5 });
    const migrationPath = join(process.cwd(), 'migrations', '008_sessions.sql');
    const sql = readFileSync(migrationPath, 'utf8');
    await pool.query(sql);
  });

  afterAll(async () => {
    if (pool) await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`TRUNCATE sessions`);
    store = new PostgresSessionStore(pool, macKey, { readThroughCacheMs: 10_000 });
  });

  it('put + get round-trips', async () => {
    const oidcScopeClaims = {
      scope_columns: ['patients.name'],
      scope_actions: ['read'],
    };
    await store.put('pg-tok-1', env({ humanDid: 'did:alice', oidcScopeClaims }), {
      ttlSeconds: 60,
    });
    const read = await store.get('pg-tok-1');
    expect(read).not.toBeNull();
    expect(read!.humanDid).toBe('did:alice');
    expect(read!.oidcScopeClaims).toEqual(oidcScopeClaims);
    expect(read!.expiresAt).toBeGreaterThan(Date.now());
  });

  it('put() rejects mock providerKind', async () => {
    await expect(
      store.put(
        'pg-m',
        { ...env(), providerKind: 'mock' as unknown as SessionEnvelope['providerKind'] },
        { ttlSeconds: 60 },
      ),
    ).rejects.toThrow(ProviderNotAllowedError);
  });

  it('tampered envelope row → EnvelopeIntegrityError', async () => {
    await store.put('pg-tamper', env(), { ttlSeconds: 60 });
    // Clear cache so we read from DB.
    (store as unknown as StoreInternals).cache.clear();
    await pool.query(
      `UPDATE sessions
          SET envelope = jsonb_set(envelope, '{humanDid}', '"did:attacker"')
        WHERE token = $1`,
      ['pg-tamper'],
    );
    await expect(store.get('pg-tamper')).rejects.toThrow(EnvelopeIntegrityError);
  });
});
