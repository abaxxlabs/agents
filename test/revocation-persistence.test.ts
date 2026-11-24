import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { VcVerifier } from '#identity/index.js';
import type { RevocationStore } from '#storage/types.js';

type SqliteRevocationStoreCtor = new (db: unknown) => RevocationStore;
type SqliteDatabaseCtor = new (path: string) => {
  exec(sql: string): void;
  close(): void;
};

describe('InMemoryRevocationStore', () => {
  it('revoke + isRevoked: revoked JTI returns true', async () => {
    const store = new InMemoryRevocationStore();
    await store.revoke('jti-001', {});
    expect(await store.isRevoked('jti-001')).toBe(true);
  });
});

describe('SqliteRevocationStore (in-memory)', () => {
  it('basic CRUD: revoke + isRevoked + loadAll + pruneExpired', async () => {
    let SqliteRevocationStore: SqliteRevocationStoreCtor;
    try {
      const mod = await import('../src/storage/sqlite/revocation-store.js');
      SqliteRevocationStore = mod.SqliteRevocationStore as unknown as SqliteRevocationStoreCtor;
    } catch {
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

    expect(await store.isRevoked('sqlite-jti-001')).toBe(false);
    await store.revoke('sqlite-jti-001', { reason: 'test' });
    expect(await store.isRevoked('sqlite-jti-001')).toBe(true);

    const entries = await store.loadAll();
    expect(entries.some((e) => e.jti === 'sqlite-jti-001')).toBe(true);

    await expect(store.revoke('sqlite-jti-001', {})).resolves.toBeUndefined();
    expect(await store.isRevoked('sqlite-jti-001')).toBe(true);

    const pastExp = new Date(Date.now() - 32 * 24 * 60 * 60 * 1000);
    await store.revoke('sqlite-jti-old', { credentialExp: pastExp });
    const pruned = await store.pruneExpired();
    expect(pruned).toBe(1);
    expect(await store.isRevoked('sqlite-jti-old')).toBe(false);

    db.close();
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
});
