// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// AgentScope hygiene regressions: pruneRevocations, masterKey redaction, close zeroing.
// Postgres-gated: AgentScope.create requires a live DB; skips when unavailable.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { inspect } from 'node:util';
import pg from 'pg';
import { AgentScope } from '../src/sql/index.js';
import { asMasterKey } from '../src/crypto/master-key.js';
import { PostgresStorageBackend } from '../src/storage/postgres/index.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { composeStorageBackend } from '../src/storage/compose.js';

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
  // 64-char hex needle used to detect master-key leakage in output
  const MASTER_KEY_BYTE = 0xab;
  const HEX_NEEDLE = 'ab'.repeat(32);

  let masterKeyBuf: Buffer;
  let scope: AgentScope;
  let pool: pg.Pool;
  let revocation: InMemoryRevocationStore;

  beforeAll(async () => {
    masterKeyBuf = Buffer.alloc(32, MASTER_KEY_BYTE);
    pool = new Pool({ connectionString: DB_URL, max: 2 });

    // Clear rows from prior runs that may be wrapped with a different master key.
    // MasterKeyMismatchError would prevent AgentScope.create from succeeding here.
    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);

    const base = PostgresStorageBackend.fromPool(pool, false);
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
      // close-zeroes-masterKey test may have already closed it
    }
    // Pool was supplied externally, so AgentScope.close() won't end it.
    await pool.end().catch(() => undefined);
  });

  // ─── pruneRevocations delegates to storage.revocation ───────────────
  describe('pruneRevocations()', () => {
    it('returns 0 when no revocations are present', async () => {
      const pruned = await scope.pruneRevocations();
      expect(pruned).toBe(0);
    });

    it('prunes a revocation whose credentialExp is past the default cutoff', async () => {
      // Seed the in-memory store directly so we can assert the delegation
      // actually deleted something. Default cutoff in InMemoryRevocationStore
      // is now − 30 days; we revoke with a credentialExp 31 days in the past.
      const longPast = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);
      await revocation.revoke('jti-b4-prune-old', { credentialExp: longPast });
      // Plus a fresh entry that should NOT be pruned.
      await revocation.revoke('jti-b4-prune-fresh', {
        credentialExp: new Date(Date.now() + 60 * 60 * 1000),
      });

      const pruned = await scope.pruneRevocations();
      expect(pruned).toBe(1);
      // Fresh entry survives.
      expect(await revocation.isRevoked('jti-b4-prune-fresh')).toBe(true);
      // Old entry is gone.
      expect(await revocation.isRevoked('jti-b4-prune-old')).toBe(false);
    });

    it('passes an explicit cutoff Date through to the store', async () => {
      // Probe via loadAll() not isRevoked() — the in-memory store lazy-evicts
      // past-exp entries on isRevoked(), which would make cutoff unverifiable.
      const oneHourPast = new Date(Date.now() - 60 * 60 * 1000);
      await revocation.revoke('jti-b4-cutoff', { credentialExp: oneHourPast });

      const presentBefore = (await revocation.loadAll()).some((e) => e.jti === 'jti-b4-cutoff');
      expect(presentBefore).toBe(true);

      // Cutoff 2h in the past → 1h_ago < 2h_ago is FALSE → entry survives.
      const survives = await scope.pruneRevocations(new Date(Date.now() - 2 * 60 * 60 * 1000));
      expect(survives).toBe(0);
      const presentAfterSurvives = (await revocation.loadAll()).some(
        (e) => e.jti === 'jti-b4-cutoff',
      );
      expect(presentAfterSurvives).toBe(true);

      // Cutoff 30s in the past → 1h_ago < 30s_ago is TRUE → entry pruned.
      const removed = await scope.pruneRevocations(new Date(Date.now() - 30 * 1000));
      expect(removed).toBe(1);
      const presentAfterRemoved = (await revocation.loadAll()).some(
        (e) => e.jti === 'jti-b4-cutoff',
      );
      expect(presentAfterRemoved).toBe(false);
    });
  });

  // ─── redaction in toJSON / inspect ────────────────────────────
  describe('redaction', () => {
    it('toJSON() does not contain master-key hex', () => {
      const snapshot = scope.toJSON();
      const serialised = JSON.stringify(snapshot);
      expect(serialised).not.toContain(HEX_NEEDLE);
      expect(snapshot.masterKey).toBe('[REDACTED 32 bytes]');
    });

    it('JSON.stringify(scope) does not contain master-key hex', () => {
      // JSON.stringify invokes toJSON() if present.
      const out = JSON.stringify(scope);
      expect(out).not.toContain(HEX_NEEDLE);
      expect(out).toContain('[REDACTED 32 bytes]');
    });

    it('util.inspect(scope) does not contain master-key hex', () => {
      // Node's util.inspect invokes [inspect.custom] if present.
      const out = inspect(scope, { depth: 5 });
      expect(out).not.toContain(HEX_NEEDLE);
      expect(out).toContain('[REDACTED 32 bytes]');
    });

    it('console.log path (util.inspect with default opts) is also redacted', () => {
      // console.log uses util.inspect under the hood with default opts.
      const out = inspect(scope);
      expect(out).not.toContain(HEX_NEEDLE);
    });

    it('exposes verifierDid and encryptedColumns in the snapshot', () => {
      const snapshot = scope.toJSON();
      expect(snapshot.verifierDid).toMatch(/^did:/);
      expect(Array.isArray(snapshot.encryptedColumns)).toBe(true);
    });
  });

  // ─── close() zeroes masterKey ─────────────────────────────────
  describe('close() zeros masterKey', () => {
    it('after close(), the original masterKey buffer is all zeros', async () => {
      expect(masterKeyBuf[0]).toBe(MASTER_KEY_BYTE);
      expect(masterKeyBuf[31]).toBe(MASTER_KEY_BYTE);

      await scope.close();

      for (let i = 0; i < 32; i++) {
        expect(masterKeyBuf[i]).toBe(0);
      }
    });
  });
});
