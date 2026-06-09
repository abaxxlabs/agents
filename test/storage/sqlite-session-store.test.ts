import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import { SQLITE_SCHEMA_STATEMENTS } from '#storage/sqlite/migrations.js';
import type { StorageBackend } from '#storage/types.js';
import {
  EnvelopeIntegrityError,
  EnvelopeTooLargeError,
  ProviderNotAllowedError,
  type SessionEnvelope,
} from '#storage/types.js';
import { deriveSessionMacKey, MAX_ENVELOPE_BYTES } from '#storage/envelope-mac.js';
import { asMasterKey } from '#crypto/master-key.js';

interface SqliteDb {
  prepare(sql: string): {
    all(...params: unknown[]): unknown[];
    run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
    get(...params: unknown[]): unknown;
  };
}

function env(overrides: Partial<SessionEnvelope> = {}): SessionEnvelope {
  return {
    humanDid: 'did:key:zAlice',
    oidcIssuer: 'https://login.abaxx.one/realms/demo',
    oidcSubject: 'alice',
    providerKind: 'oidc-abaxx-one',
    createdAt: 0,
    expiresAt: 0,
    ...overrides,
  };
}

describe('SqliteSessionStore', () => {
  const masterBuf = Buffer.alloc(32);
  Buffer.from('sqlite-test-master', 'utf8').copy(masterBuf);
  const macKey = deriveSessionMacKey(asMasterKey(masterBuf));
  let backend: StorageBackend;

  beforeEach(async () => {
    backend = await SqliteStorageBackend.create(
      { type: 'sqlite', path: ':memory:' },
      { sessionMacKey: macKey },
    );
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('WAL mode + synchronous=NORMAL configured', () => {
    // In-memory databases ignore the WAL setting — SQLite reports "memory" for
    // :memory: regardless of the PRAGMA. The meaningful assertion here is that
    // the PRAGMA is issued at backend initialize time. We verify this by
    // scanning SQLITE_SCHEMA_STATEMENTS for the pragma strings (which the
    // SqliteStorageBackend.initialize() replays verbatim). For file-backed
    // deployments the PRAGMA takes effect; in-memory tests prove the initialize()
    // call site issues the right statements.
    //
    // We also assert synchronous=NORMAL was applied: PRAGMA synchronous is
    // respected even for :memory: databases (returns 1 for NORMAL, 2 for FULL).
    expect(SQLITE_SCHEMA_STATEMENTS).toEqual(
      expect.arrayContaining(['PRAGMA journal_mode = WAL', 'PRAGMA synchronous = NORMAL']),
    );
    const inner = (backend as unknown as { db: SqliteDb }).db;
    const synchronous = inner.prepare('PRAGMA synchronous').get();
    expect(Number(Object.values(synchronous as object)[0])).toBe(1);
  });

  it('schema: sessions table exists with expected columns', () => {
    const inner = (backend as unknown as { db: SqliteDb }).db;
    const cols = (
      inner.prepare(`PRAGMA table_info(sessions)`).all() as Array<{ name: string }>
    ).map((c) => c.name);
    expect(cols).toEqual(
      expect.arrayContaining(['token', 'envelope', 'mac', 'human_did', 'created_at', 'expires_at']),
    );
  });

  it('put + get round-trips', async () => {
    await backend.sessions.put('tok-a', env({ humanDid: 'did:alice' }), { ttlSeconds: 60 });
    const read = await backend.sessions.get('tok-a');
    expect(read).not.toBeNull();
    expect(read!.humanDid).toBe('did:alice');
    expect(read!.expiresAt).toBeGreaterThan(Date.now());
  });

  it('put() rejects mock providerKind', async () => {
    await expect(
      backend.sessions.put(
        'tok-m',
        { ...env(), providerKind: 'mock' as unknown as SessionEnvelope['providerKind'] },
        { ttlSeconds: 60 },
      ),
    ).rejects.toThrow(ProviderNotAllowedError);
  });

  it('get() returns null for expired row (expires_at < now)', async () => {
    await backend.sessions.put('tok-e', env(), { ttlSeconds: 1 });
    // Force expiry by rewriting expires_at to a past value
    const inner = (backend as unknown as { db: SqliteDb }).db;
    inner
      .prepare(`UPDATE sessions SET expires_at = ? WHERE token = ?`)
      .run(Date.now() - 1000, 'tok-e');
    expect(await backend.sessions.get('tok-e')).toBeNull();
  });

  it('tampered envelope row → EnvelopeIntegrityError', async () => {
    await backend.sessions.put('tok-t', env({ humanDid: 'did:real' }), { ttlSeconds: 60 });

    // Simulate row-tamper: rewrite envelope column's humanDid to a different
    // DID while leaving the MAC column alone.
    const inner = (backend as unknown as { db: SqliteDb }).db;
    const row = inner.prepare(`SELECT envelope FROM sessions WHERE token = ?`).get('tok-t') as {
      envelope: string;
    };
    const parsed = JSON.parse(row.envelope);
    parsed.humanDid = 'did:attacker';
    inner
      .prepare(`UPDATE sessions SET envelope = ? WHERE token = ?`)
      .run(JSON.stringify(parsed), 'tok-t');

    await expect(backend.sessions.get('tok-t')).rejects.toThrow(EnvelopeIntegrityError);
  });

  it('oversize envelope row → EnvelopeTooLargeError before JSON.parse', async () => {
    await backend.sessions.put('tok-big', env(), { ttlSeconds: 60 });

    const inner = (backend as unknown as { db: SqliteDb }).db;
    const oversized = JSON.stringify({ ...env(), padding: 'x'.repeat(MAX_ENVELOPE_BYTES + 1) });
    inner
      .prepare(`UPDATE sessions SET envelope = ? WHERE token = ?`)
      .run(oversized, 'tok-big');

    await expect(backend.sessions.get('tok-big')).rejects.toThrow(EnvelopeTooLargeError);
  });

  it('within-cap envelope passes size gate and reaches MAC check', async () => {
    await backend.sessions.put('tok-ok', env(), { ttlSeconds: 60 });

    // Tamper the envelope but keep it under the size cap — should reach MAC check, not size check.
    const inner = (backend as unknown as { db: SqliteDb }).db;
    const row = inner.prepare(`SELECT envelope FROM sessions WHERE token = ?`).get('tok-ok') as {
      envelope: string;
    };
    const parsed = JSON.parse(row.envelope);
    parsed.humanDid = 'did:tampered';
    inner
      .prepare(`UPDATE sessions SET envelope = ? WHERE token = ?`)
      .run(JSON.stringify(parsed), 'tok-ok');

    await expect(backend.sessions.get('tok-ok')).rejects.toThrow(EnvelopeIntegrityError);
  });

  it('delete() + deleteByHumanDid() remove rows', async () => {
    await backend.sessions.put('t1', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
    await backend.sessions.put('t2', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
    await backend.sessions.put('t3', env({ humanDid: 'did:b' }), { ttlSeconds: 60 });

    const n = await backend.sessions.deleteByHumanDid('did:a');
    expect(n).toBe(2);
    expect(await backend.sessions.get('t1')).toBeNull();
    expect(await backend.sessions.get('t3')).not.toBeNull();

    await backend.sessions.delete('t3');
    expect(await backend.sessions.get('t3')).toBeNull();
  });

  it('pruneExpired() removes only expired rows and returns count', async () => {
    await backend.sessions.put('fresh', env(), { ttlSeconds: 60 });
    await backend.sessions.put('stale-1', env(), { ttlSeconds: 60 });
    await backend.sessions.put('stale-2', env(), { ttlSeconds: 60 });

    // Back-date two rows to the past so pruneExpired picks them up.
    const inner = (backend as unknown as { db: SqliteDb }).db;
    const past = Date.now() - 1000;
    inner.prepare(`UPDATE sessions SET expires_at = ? WHERE token = ?`).run(past, 'stale-1');
    inner.prepare(`UPDATE sessions SET expires_at = ? WHERE token = ?`).run(past, 'stale-2');

    const n = await backend.sessions.pruneExpired();
    expect(n).toBe(2);
    expect(await backend.sessions.get('fresh')).not.toBeNull();
  });

  it('pruneExpired(limit) bounds single-call deletion size', async () => {
    const past = Date.now() - 1000;
    const inner = (backend as unknown as { db: SqliteDb }).db;
    for (let i = 0; i < 5; i++) {
      await backend.sessions.put(`tok-${i}`, env(), { ttlSeconds: 60 });
      inner.prepare(`UPDATE sessions SET expires_at = ? WHERE token = ?`).run(past, `tok-${i}`);
    }
    const n = await backend.sessions.pruneExpired(undefined, 2);
    expect(n).toBe(2);
  });
});
