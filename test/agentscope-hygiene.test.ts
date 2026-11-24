import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { inspect } from 'node:util';
import pg from 'pg';
import { AgentScope } from '#sql/index.js';
import { asMasterKey } from '#crypto/master-key.js';
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

describeFn('AgentScope hygiene (live Postgres required)', () => {
  const MASTER_KEY_BYTE = 0xab;
  const HEX_NEEDLE = 'ab'.repeat(32);

  let masterKeyBuf: Buffer;
  let scope: AgentScope;
  let pool: pg.Pool;
  let revocation: InMemoryRevocationStore;

  beforeAll(async () => {
    masterKeyBuf = Buffer.alloc(32, MASTER_KEY_BYTE);
    pool = new Pool({ connectionString: DB_URL, max: 2 });

    // Remove keys from earlier runs so their wrapping key cannot prevent setup.
    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);

    const base = PostgresStorageBackend.fromPool(pool, false, {
      sessionMacKey: deterministicSessionMacKey(),
    });
    revocation = new InMemoryRevocationStore();
    const storage = composeStorageBackend(base, { revocation });

    scope = await AgentScope.create(
      {
        database: { connectionString: DB_URL },
        abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'b4-test' },
      },
      { masterKey: asMasterKey(masterKeyBuf), storage, pool },
    );
  });

  afterAll(async () => {
    try {
      await scope.close();
    } catch {
      // A lifecycle test may have already closed the scope.
    }
    // Pool was supplied externally, so AgentScope.close() won't end it.
    await pool.end().catch(() => undefined);
  });

  describe('pruneRevocations()', () => {
    it('prunes a revocation whose credentialExp is past the default cutoff', async () => {
      // Default cutoff is now − 30 days; revoke with credentialExp 31 days in the past.
      const longPast = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);
      await revocation.revoke('jti-b4-prune-old', { credentialExp: longPast });
      await revocation.revoke('jti-b4-prune-fresh', {
        credentialExp: new Date(Date.now() + 60 * 60 * 1000),
      });

      const pruned = await scope.pruneRevocations();
      expect(pruned).toBe(1);
      expect(await revocation.isRevoked('jti-b4-prune-fresh')).toBe(true);
      expect(await revocation.isRevoked('jti-b4-prune-old')).toBe(false);
    });

    it('passes an explicit cutoff Date through to the store', async () => {
      // Use loadAll(): isRevoked() evicts expired entries and would hide whether pruning worked.
      const oneHourPast = new Date(Date.now() - 60 * 60 * 1000);
      await revocation.revoke('jti-b4-cutoff', { credentialExp: oneHourPast });

      const presentBefore = (await revocation.loadAll()).some((e) => e.jti === 'jti-b4-cutoff');
      expect(presentBefore).toBe(true);

      const survives = await scope.pruneRevocations(new Date(Date.now() - 2 * 60 * 60 * 1000));
      expect(survives).toBe(0);
      const presentAfterSurvives = (await revocation.loadAll()).some(
        (e) => e.jti === 'jti-b4-cutoff',
      );
      expect(presentAfterSurvives).toBe(true);

      const removed = await scope.pruneRevocations(new Date(Date.now() - 30 * 1000));
      expect(removed).toBe(1);
      const presentAfterRemoved = (await revocation.loadAll()).some(
        (e) => e.jti === 'jti-b4-cutoff',
      );
      expect(presentAfterRemoved).toBe(false);
    });
  });

  describe('redaction', () => {
    it('toJSON() does not contain master-key hex', () => {
      const snapshot = scope.toJSON();
      const serialised = JSON.stringify(snapshot);
      expect(serialised).not.toContain(HEX_NEEDLE);
      expect(snapshot.masterKey).toBe('[REDACTED 32 bytes]');
    });

    it('util.inspect(scope) does not contain master-key hex', () => {
      const out = inspect(scope, { depth: 5 });
      expect(out).not.toContain(HEX_NEEDLE);
      expect(out).toContain('[REDACTED 32 bytes]');
    });

    it('console.log path (util.inspect with default opts) is also redacted', () => {
      const out = inspect(scope);
      expect(out).not.toContain(HEX_NEEDLE);
    });
  });

  describe('close() leaves caller-owned masterKey intact', () => {
    it('after close(), the caller-owned masterKey buffer is unchanged', async () => {
      expect(masterKeyBuf[0]).toBe(MASTER_KEY_BYTE);
      expect(masterKeyBuf[31]).toBe(MASTER_KEY_BYTE);

      await scope.close();

      for (let i = 0; i < 32; i++) {
        expect(masterKeyBuf[i]).toBe(MASTER_KEY_BYTE);
      }
    });
  });
});
