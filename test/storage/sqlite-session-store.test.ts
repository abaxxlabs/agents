import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import type { StorageBackend } from '#storage/types.js';
import { EnvelopeIntegrityError, type SessionEnvelope } from '#storage/types.js';
import { deriveSessionMacKey } from '#storage/envelope-mac.js';
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
      { type: 'sqlite', path: ':memory:', sessionMacKey: macKey },
      { sessionMacKey: macKey },
    );
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  it('get() returns null for expired row (expires_at < now)', async () => {
    await backend.sessions.put('tok-e', env(), { ttlSeconds: 1 });
    const inner = (backend as unknown as { db: SqliteDb }).db;
    inner
      .prepare(`UPDATE sessions SET expires_at = ? WHERE token = ?`)
      .run(Date.now() - 1000, 'tok-e');
    expect(await backend.sessions.get('tok-e')).toBeNull();
  });

  it('tampered envelope row → EnvelopeIntegrityError', async () => {
    await backend.sessions.put('tok-t', env({ humanDid: 'did:real' }), { ttlSeconds: 60 });

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
});
