import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { PostgresSessionStore } from '../../src/storage/postgres/session-store.js';
import { deriveSessionMacKey } from '../../src/storage/envelope-mac.js';
import { asMasterKey } from '../../src/crypto/master-key.js';
import {
  EnvelopeIntegrityError,
  ProviderNotAllowedError,
  type SessionEnvelope,
} from '../../src/storage/types.js';

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

/**
 * Try to connect; return true if Postgres is reachable. Used to gate the whole
 * suite so CI without a local Supabase doesn't fail on this file.
 */
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

// Top-level await: probe Postgres once at module-load time. vitest supports
// top-level await in ESM test files. If unreachable, use describe.skip so the
// whole suite is elided without hanging. If reachable, use describe.
const postgresReachable = await isPostgresReachable();
const describeFn = postgresReachable ? describe : describe.skip;

describeFn('PostgresSessionStore (live Postgres required)', () => {
  let pool: pg.Pool;
  let store: PostgresSessionStore;
  // Pad short label to 32 bytes and brand for the MasterKey-typed deriveSessionMacKey signature.
  const masterBuf = Buffer.alloc(32);
  Buffer.from('postgres-test-master', 'utf8').copy(masterBuf);
  const macKey = deriveSessionMacKey(asMasterKey(masterBuf));

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 5 });
    // Apply migration 008 directly (self-contained; tolerates prior runs).
    const migrationPath = join(process.cwd(), 'migrations', '008_sessions.sql');
    const sql = readFileSync(migrationPath, 'utf8');
    await pool.query(sql);
  });

  afterAll(async () => {
    if (pool) await pool.end();
  });

  beforeEach(async () => {
    // Truncate to isolate tests.
    await pool.query(`TRUNCATE sessions`);
    store = new PostgresSessionStore(pool, macKey, { readThroughCacheMs: 10_000 });
  });

  it('put + get round-trips', async () => {
    await store.put('pg-tok-1', env({ humanDid: 'did:alice' }), { ttlSeconds: 60 });
    const read = await store.get('pg-tok-1');
    expect(read).not.toBeNull();
    expect(read!.humanDid).toBe('did:alice');
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
    // Rewrite humanDid in the JSONB envelope column.
    await pool.query(
      `UPDATE sessions
          SET envelope = jsonb_set(envelope, '{humanDid}', '"did:attacker"')
        WHERE token = $1`,
      ['pg-tamper'],
    );
    await expect(store.get('pg-tamper')).rejects.toThrow(EnvelopeIntegrityError);
  });

  it('delete + deleteByHumanDid + pruneExpired', async () => {
    await store.put('p1', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
    await store.put('p2', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
    await store.put('p3', env({ humanDid: 'did:b' }), { ttlSeconds: 60 });

    const n = await store.deleteByHumanDid('did:a');
    expect(n).toBe(2);
    expect(await store.get('p1')).toBeNull();

    await store.delete('p3');
    expect(await store.get('p3')).toBeNull();

    // Insert expired row directly via pool.
    await pool.query(
      `INSERT INTO sessions (token, envelope, mac, human_did, expires_at)
       VALUES ('p-stale', '{}'::jsonb, '\\x00', 'did:stale', NOW() - interval '1 hour')`,
    );
    const pruned = await store.pruneExpired();
    expect(pruned).toBeGreaterThanOrEqual(1);
  });

  it('cache: second get within TTL does not re-query DB', async () => {
    await store.put('pg-cache-1', env({ humanDid: 'did:c' }), { ttlSeconds: 60 });
    // Clear cache after put (put invalidates) so first get populates.
    expect((store as unknown as StoreInternals).cache.size).toBe(0);

    const r1 = await store.get('pg-cache-1');
    expect(r1).not.toBeNull();
    expect((store as unknown as StoreInternals).cache.size).toBe(1);

    // Tamper with the DB row — a D15-abiding cache MUST return the cached
    // value, not re-read the now-corrupted row. (The cache reflects the last
    // MAC-verified fetch; its freshness bound is TTL, not mutation-aware.)
    await pool.query(
      `UPDATE sessions SET envelope = '{"humanDid":"did:attacker","oidcIssuer":"x","oidcSubject":"y","providerKind":"oidc-abaxx-one","createdAt":0,"expiresAt":0}'::jsonb WHERE token = $1`,
      ['pg-cache-1'],
    );

    const r2 = await store.get('pg-cache-1');
    expect(r2).not.toBeNull();
    // Cache returned the original (MAC-verified) value, not the corrupted row.
    expect(r2!.humanDid).toBe('did:c');
  });

  it('cache: delete() evicts cache', async () => {
    await store.put('pg-evict', env(), { ttlSeconds: 60 });
    // Populate cache
    await store.get('pg-evict');
    expect((store as unknown as StoreInternals).cache.size).toBe(1);
    await store.delete('pg-evict');
    expect((store as unknown as StoreInternals).cache.size).toBe(0);
    expect(await store.get('pg-evict')).toBeNull();
  });

  it('cache: put() evicts cache (so next get sees fresh row)', async () => {
    await store.put('pg-refresh', env({ humanDid: 'did:v1' }), { ttlSeconds: 60 });
    // Populate cache
    const r1 = await store.get('pg-refresh');
    expect(r1!.humanDid).toBe('did:v1');
    // Re-put with new envelope.
    await store.put('pg-refresh', env({ humanDid: 'did:v2' }), { ttlSeconds: 60 });
    expect((store as unknown as StoreInternals).cache.size).toBe(0);
    const r2 = await store.get('pg-refresh');
    expect(r2!.humanDid).toBe('did:v2');
  });

  it('singleflight: concurrent get() for unknown token coalesces to 1 SELECT', async () => {
    // We proxy-monkeypatch pool.query to count calls for this one test.
    type PoolQueryFn = pg.Pool['query'];
    const originalQuery = pool.query.bind(pool) as PoolQueryFn;
    let selectCount = 0;
    const patchedQuery = function (this: pg.Pool, ...args: unknown[]) {
      const first = args[0];
      const text =
        typeof first === 'string' ? first : (first as { text?: string } | undefined)?.text;
      if (text?.startsWith('SELECT envelope') || text?.includes('FROM sessions')) {
        if (text?.startsWith('SELECT')) selectCount++;
      }
      return (originalQuery as (...a: unknown[]) => unknown)(...args);
    };
    (pool as unknown as { query: typeof patchedQuery }).query = patchedQuery;

    try {
      await store.put('pg-sf', env(), { ttlSeconds: 60 });
      (store as unknown as StoreInternals).cache.clear();
      // Fire 10 concurrent gets for the same token.
      const promises = Array.from({ length: 10 }, () => store.get('pg-sf'));
      const results = await Promise.all(promises);
      for (const r of results) expect(r).not.toBeNull();
      // With singleflight, we expect just 1 SELECT; without, we'd see ~10.
      expect(selectCount).toBeLessThanOrEqual(2); // tolerate 1-2 depending on scheduling
    } finally {
      (pool as unknown as { query: PoolQueryFn }).query = originalQuery;
    }
  });

  it('backing-store failure propagates', async () => {
    // Construct a store with a pool whose connection string is bogus.
    const deadPool = new Pool({
      connectionString: 'postgresql://nobody@127.0.0.1:1/nodb',
      connectionTimeoutMillis: 500,
    });
    const deadStore = new PostgresSessionStore(deadPool, macKey);
    await expect(deadStore.put('x', env(), { ttlSeconds: 60 })).rejects.toThrow();
    await deadPool.end().catch(() => undefined);
  });
});
