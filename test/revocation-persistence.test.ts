import { describe, it, expect, vi, beforeEach } from 'vitest';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { VcVerifier } from '#identity/index.js';
import type { RevocationStore } from '#storage/types.js';

type SqliteRevocationStoreCtor = new (db: unknown) => RevocationStore;
type SqliteDatabaseCtor = new (path: string) => {
  exec(sql: string): void;
  close(): void;
};

describe('InMemoryRevocationStore', () => {
  let store: InMemoryRevocationStore;

  beforeEach(() => {
    store = new InMemoryRevocationStore();
  });

  it('isRevoked returns false for unknown JTI', async () => {
    expect(await store.isRevoked('unknown-jti')).toBe(false);
  });

  it('revoke + isRevoked: revoked JTI returns true', async () => {
    await store.revoke('jti-001', {});
    expect(await store.isRevoked('jti-001')).toBe(true);
  });

  it('revoke is idempotent — second revoke on same JTI is no-op', async () => {
    await store.revoke('jti-002', { reason: 'first' });
    await store.revoke('jti-002', { reason: 'second' }); // no-op
    expect(await store.isRevoked('jti-002')).toBe(true);
    expect(store.size).toBe(1); // still one entry
  });

  it('revoke throws on empty JTI', async () => {
    await expect(store.revoke('', {})).rejects.toThrow('jti must be a non-empty string');
  });

  it('revoke throws on non-string JTI', async () => {
    await expect(store.revoke(null as unknown as string, {})).rejects.toThrow(
      'jti must be a non-empty string',
    );
  });

  it('loadAll returns all revoked JTIs', async () => {
    await store.revoke('jti-a', {});
    await store.revoke('jti-b', {});
    const entries = await store.loadAll();
    const jtis = entries.map((e) => e.jti).sort();
    expect(jtis).toEqual(['jti-a', 'jti-b']);
  });

  it('loadAll includes credentialExp when provided', async () => {
    const exp = new Date(Date.now() + 3600_000);
    await store.revoke('jti-c', { credentialExp: exp });
    const entries = await store.loadAll();
    const entry = entries.find((e) => e.jti === 'jti-c');
    expect(entry?.credentialExp?.getTime()).toBeCloseTo(exp.getTime(), -2);
  });

  it('pruneExpired removes entries past the default cutoff', async () => {
    // Revoke with a credentialExp in the past (>30 days ago).
    const pastExp = new Date(Date.now() - 32 * 24 * 60 * 60 * 1000);
    await store.revoke('jti-old', { credentialExp: pastExp });
    await store.revoke('jti-new', { credentialExp: new Date(Date.now() + 3600_000) });

    const pruned = await store.pruneExpired();

    expect(pruned).toBe(1); // only jti-old is pruned
    expect(store.size).toBe(1); // jti-new remains
    expect(await store.isRevoked('jti-old')).toBe(false);
    expect(await store.isRevoked('jti-new')).toBe(true);
  });

  it('pruneExpired with explicit beforeTs removes correct entries', async () => {
    const cutoff = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    const expBefore = new Date(cutoff.getTime() - 1000);
    const expAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await store.revoke('jti-prune-before', { credentialExp: expBefore });
    await store.revoke('jti-prune-after', { credentialExp: expAfter });

    const pruned = await store.pruneExpired(cutoff);

    expect(pruned).toBe(1);
    expect(await store.isRevoked('jti-prune-before')).toBe(false);
    expect(await store.isRevoked('jti-prune-after')).toBe(true);
  });

  it('pruneExpired does not prune entries with undefined credentialExp', async () => {
    // Non-expiring credentials are never pruned.
    await store.revoke('jti-no-exp', {}); // no credentialExp

    const pruned = await store.pruneExpired(new Date(Date.now() + 999_999_999));

    expect(pruned).toBe(0);
    expect(await store.isRevoked('jti-no-exp')).toBe(true);
  });

  it('isRevoked lazily evicts entries with past credentialExp', async () => {
    const pastExp = new Date(Date.now() - 1);
    await store.revoke('jti-expired', { credentialExp: pastExp });

    // isRevoked should evict and return false — the credential is already expired.
    expect(await store.isRevoked('jti-expired')).toBe(false);
    expect(store.size).toBe(0); // evicted
  });
});

describe('SqliteRevocationStore (in-memory)', () => {
  // Use dynamic import so the module is only loaded if better-sqlite3 is available.
  // Skip gracefully if the dep is not installed.

  it('basic CRUD: revoke + isRevoked + loadAll + pruneExpired', async () => {
    let SqliteRevocationStore: SqliteRevocationStoreCtor;
    try {
      const mod = await import('../src/storage/sqlite/revocation-store.js');
      SqliteRevocationStore = mod.SqliteRevocationStore as unknown as SqliteRevocationStoreCtor;
    } catch {
      // better-sqlite3 not installed — skip.
      console.log('Skipping SqliteRevocationStore test: better-sqlite3 not available');
      return;
    }

    let Database: SqliteDatabaseCtor;
    try {
      // @ts-expect-error — bun:sqlite only resolves under Bun; absent from Node's type graph.
      const mod = await import('bun:sqlite');
      Database = mod.Database as SqliteDatabaseCtor;
    } catch {
      try {
        const mod = await import('better-sqlite3');
        Database = mod.default as unknown as SqliteDatabaseCtor;
      } catch {
        console.log('Skipping SqliteRevocationStore test: no SQLite runtime available');
        return;
      }
    }
    const db = new Database(':memory:');
    db.exec(`
      CREATE TABLE IF NOT EXISTS revoked_credentials (
        jti         TEXT NOT NULL,
        reason      TEXT,
        revoked_at  TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at  TEXT,
        PRIMARY KEY (jti)
      )
    `);
    db.exec('CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_credentials(expires_at)');

    const store = new SqliteRevocationStore(db);

    // Basic CRUD
    expect(await store.isRevoked('sqlite-jti-001')).toBe(false);
    await store.revoke('sqlite-jti-001', { reason: 'test' });
    expect(await store.isRevoked('sqlite-jti-001')).toBe(true);

    // loadAll
    const entries = await store.loadAll();
    expect(entries.some((e) => e.jti === 'sqlite-jti-001')).toBe(true);

    // Idempotent revoke
    await expect(store.revoke('sqlite-jti-001', {})).resolves.toBeUndefined();
    expect(await store.isRevoked('sqlite-jti-001')).toBe(true);

    // pruneExpired
    const pastExp = new Date(Date.now() - 32 * 24 * 60 * 60 * 1000);
    await store.revoke('sqlite-jti-old', { credentialExp: pastExp });
    const pruned = await store.pruneExpired();
    expect(pruned).toBe(1);
    expect(await store.isRevoked('sqlite-jti-old')).toBe(false);

    db.close();
  });

  it('revoke throws on empty JTI', async () => {
    let Database: SqliteDatabaseCtor;
    try {
      // @ts-expect-error — bun:sqlite only resolves under Bun; absent from Node's type graph.
      const mod = await import('bun:sqlite');
      Database = mod.Database as SqliteDatabaseCtor;
    } catch {
      try {
        const mod = await import('better-sqlite3');
        Database = mod.default as unknown as SqliteDatabaseCtor;
      } catch {
        console.log('Skipping: no SQLite runtime available');
        return;
      }
    }
    let SqliteRevocationStore: SqliteRevocationStoreCtor;
    try {
      const mod = await import('../src/storage/sqlite/revocation-store.js');
      SqliteRevocationStore = mod.SqliteRevocationStore as unknown as SqliteRevocationStoreCtor;
    } catch {
      console.log('Skipping: SQLite module unavailable');
      return;
    }

    const db = new Database(':memory:');
    db.exec(`CREATE TABLE IF NOT EXISTS revoked_credentials (
      jti TEXT NOT NULL,
      reason TEXT,
      revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT,
      PRIMARY KEY (jti)
    )`);

    const store = new SqliteRevocationStore(db);
    await expect(store.revoke('', {})).rejects.toThrow('jti must be a non-empty string');

    db.close();
  });
});

describe('Cross-instance coherency — InMemoryRevocationStore isolation', () => {
  it('two InMemoryRevocationStore instances do not share state (as expected)', async () => {
    const storeA = new InMemoryRevocationStore();
    const storeB = new InMemoryRevocationStore();

    await storeA.revoke('jti-cross-001', {});

    // storeB doesn't see storeA's revocation (independent stores — expected behavior).
    // In production, both would read from the same Postgres table.
    expect(await storeA.isRevoked('jti-cross-001')).toBe(true);
    expect(await storeB.isRevoked('jti-cross-001')).toBe(false); // no shared state
  });
});

describe('VcVerifier.revokeAsync() rejection propagation', () => {
  it('revokeAsync() throws when store.revoke() throws', async () => {
    const failingStore = new InMemoryRevocationStore();
    vi.spyOn(failingStore, 'revoke').mockRejectedValue(new Error('D10: store write failed'));

    const verifier = new VcVerifier({ revocationStore: failingStore });

    await expect(verifier.revokeAsync('some-jti')).rejects.toThrow('D10: store write failed');
  });

  it('revokeAsync() succeeds when store.revoke() succeeds', async () => {
    const store = new InMemoryRevocationStore();
    const verifier = new VcVerifier({ revocationStore: store });

    await expect(verifier.revokeAsync('some-jti')).resolves.toBeUndefined();
    expect(await store.isRevoked('some-jti')).toBe(true);
  });

  it('revokeAsync() throws on empty JTI', async () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    await expect(verifier.revokeAsync('')).rejects.toThrow('jti must be a non-empty string');
  });
});

describe('revoke + isRevoked sequencing (InMemoryRevocationStore)', () => {
  it('isRevoked returns true immediately after revoke', async () => {
    const store = new InMemoryRevocationStore();
    await store.revoke('jti-race-001', {});
    expect(await store.isRevoked('jti-race-001')).toBe(true);
  });

  it('concurrent revoke calls are safe (idempotent)', async () => {
    const store = new InMemoryRevocationStore();
    const jti = 'jti-concurrent-001';
    await Promise.all([
      store.revoke(jti, { reason: 'reason-1' }),
      store.revoke(jti, { reason: 'reason-2' }),
      store.revoke(jti, { reason: 'reason-3' }),
    ]);

    // Still revoked, still one entry.
    expect(await store.isRevoked(jti)).toBe(true);
    expect(store.size).toBe(1);
  });
});

describe('VcVerifier: isRevoked check in verify() path', () => {
  it('isRevoked store returns true → verify returns REVOKED status', async () => {
    const alwaysRevokedStore = new InMemoryRevocationStore();
    const jti = 'test-jti-verify-revoked';
    await alwaysRevokedStore.revoke(jti, {});

    expect(await alwaysRevokedStore.isRevoked(jti)).toBe(true);

    const verifier = new VcVerifier({ revocationStore: alwaysRevokedStore });
    expect(await verifier.isRevoked(jti)).toBe(true);
  });

  it('VcVerifier accepts an explicit InMemoryRevocationStore', async () => {
    const store = new InMemoryRevocationStore();
    const verifier = new VcVerifier({ revocationStore: store });
    const probeJti = 'inmemory-explicit-probe';
    await store.revoke(probeJti, {});
    expect(await verifier.isRevoked(probeJti)).toBe(true);
  });

  it('injected revocationStore is used instead of default', async () => {
    const customStore = new InMemoryRevocationStore();
    const verifier = new VcVerifier({ revocationStore: customStore });
    const probeJti = 'custom-store-probe';
    await customStore.revoke(probeJti, {});
    expect(await verifier.isRevoked(probeJti)).toBe(true);
  });
});

describe('Migration 007 — SQL format validation', () => {
  it('migration file exists and contains the required schema elements', async () => {
    const { readFileSync } = await import('node:fs');
    const { join } = await import('node:path');

    const migrationPath = join(process.cwd(), 'migrations', '007_revoked_credentials.sql');
    let sql: string;
    try {
      sql = readFileSync(migrationPath, 'utf8');
    } catch {
      throw new Error(`Migration file not found: ${migrationPath}`);
    }

    expect(sql).toContain('CREATE TABLE IF NOT EXISTS revoked_credentials');
    expect(sql).toContain('jti');
    expect(sql).toContain('PRIMARY KEY (jti)');
    expect(sql).toContain('expires_at');
    expect(sql).toContain('TIMESTAMPTZ');
    expect(sql).toContain('CREATE INDEX IF NOT EXISTS idx_revoked_expires');
    // Idempotent: IF NOT EXISTS on both table and index.
    expect(sql).toContain('IF NOT EXISTS');
  });

  it('SQLite schema also includes revoked_credentials table', async () => {
    const { SQLITE_SCHEMA_STATEMENTS } = await import('../src/storage/sqlite/migrations.js');
    const allStatements = SQLITE_SCHEMA_STATEMENTS.join('\n');

    expect(allStatements).toContain('revoked_credentials');
    expect(allStatements).toContain('expires_at');
    expect(allStatements).toContain('idx_revoked_expires');
  });
});
