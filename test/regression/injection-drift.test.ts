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

/**
 * Proves that injections.storage.revocation is wired through to
 * scope.storage.revocation in AgentScope.create. Requires live Postgres.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { AgentScope } from '../../src/sql/index.js';
import { asMasterKey } from '../../src/crypto/master-key.js';
import { composeStorageBackend } from '../../src/storage/index.js';
import { InMemoryRevocationStore } from '../../src/storage/memory/revocation-store.js';
import { PostgresStorageBackend } from '../../src/storage/postgres/index.js';
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
  // Distinctive byte pattern (matches hygiene-test convention) so that any
  // collision with bytes from prior test runs is vanishingly unlikely.
  const MASTER_KEY_BYTE = 0xcd;

  let pool: pg.Pool;
  let scope: AgentScope;
  let injectedRevocation: InMemoryRevocationStore;
  let pruneExpiredSpy: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 2 });

    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);

    const base = PostgresStorageBackend.fromPool(pool, false, { sessionMacKey: deterministicSessionMacKey() });

    // Custom revocation store held externally; correct wiring means calls
    // through scope.storage.revocation reach this exact instance.
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

  it('a revocation written through the injected store is visible via the same store', async () => {
    const jti = `d34-test-a-${Date.now()}`;
    await injectedRevocation.revoke(jti, { reason: 'd34 test fixture' });

    expect(await injectedRevocation.isRevoked(jti)).toBe(true);

    const prunedCount = await scope.pruneRevocations(new Date(Date.now() - 1_000_000));
    expect(prunedCount).toBe(0);
  });
});
