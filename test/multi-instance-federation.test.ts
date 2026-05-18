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
 * Multi-instance AgentScope federation.
 *
 * Two independent AgentScope instances (org A and org B) with separate master
 * keys and storage backends. Verifies that org A's credentials are correctly
 * accepted or rejected by org B's verifier.
 *
 * Both scopes are initialised before any agents are created — restoreAgents
 * runs during AgentScope.create, so initialising scope B after scope A has
 * persisted agents would cause a MasterKeyMismatchError.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { AgentScope } from '../src/sql/index.js';
import { asMasterKey } from '../src/crypto/master-key.js';
import { PostgresStorageBackend } from '../src/storage/postgres/index.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { InMemorySessionStore } from '../src/storage/memory/session-store.js';
import { composeStorageBackend } from '../src/storage/compose.js';
import { deriveSessionMacKey } from '../src/storage/envelope-mac.js';
import { deterministicSessionMacKey } from './support/deterministic-session-mac-key.js';
import { createPresentation } from '../src/index.js';

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

describeFn('Multi-instance AgentScope federation (live Postgres required)', () => {
  let pool: pg.Pool;
  let scopeA: AgentScope;
  let scopeB: AgentScope;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DB_URL, max: 4 });

    // Hygiene: remove rows left by prior runs encrypted with a different
    // master key. Mirrors the pattern in agentscope-hygiene.
    await pool.query('DELETE FROM agent_keys').catch(() => undefined);
    await pool.query('DELETE FROM agents').catch(() => undefined);

    const base = PostgresStorageBackend.fromPool(pool, false, { sessionMacKey: deterministicSessionMacKey() });

    const masterKeyA = asMasterKey(Buffer.alloc(32, 0xaa));
    const masterKeyB = asMasterKey(Buffer.alloc(32, 0xbb));

    // Each org gets isolated revocation + session stores. The base Postgres
    // backend (agents/audit/context tables) is shared for test simplicity;
    // in production each org would have a separate database or schema.
    const storageA = composeStorageBackend(base, {
      revocation: new InMemoryRevocationStore(),
      sessions: new InMemorySessionStore(deriveSessionMacKey(masterKeyA)),
    });
    const storageB = composeStorageBackend(base, {
      revocation: new InMemoryRevocationStore(),
      sessions: new InMemorySessionStore(deriveSessionMacKey(masterKeyB)),
    });

    [scopeA, scopeB] = await Promise.all([
      AgentScope.create(
        {
          database: { connectionString: DB_URL },
          abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'org-alpha' },
          orgBoundary: { extraConsumerDomains: ['alpha.example.com'] },
        },
        { masterKey: masterKeyA, storage: storageA, pool },
      ),
      AgentScope.create(
        {
          database: { connectionString: DB_URL },
          abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'org-beta' },
          orgBoundary: { extraConsumerDomains: ['beta.example.com'] },
        },
        { masterKey: masterKeyB, storage: storageB, pool },
      ),
    ]);
  });

  afterAll(async () => {
    await Promise.allSettled([scopeA?.close(), scopeB?.close()]);
    await pool?.end().catch(() => undefined);
  });

  it('accepts a credential issued by org A when presented to org B\'s verifier', async () => {
    const session = await scopeA.authenticate({ mockHumanDid: 'James Park, Head of Trading' });
    const agent = await scopeA.createAgent({
      name: 'trading-executor',
      ownerDid: session.humanDid,
    });

    const credential = await session.issueCredential({
      agent: agent.did,
      columns: ['order_book.ticker', 'order_book.side'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // VP audience is bound to org B's verifier DID — prevents replay at org A.
    const vp = await createPresentation(credential, agent.did, agent.signer, {
      audience: scopeB.verifierDid,
    });

    // did:key self-resolves — no network call.
    const result = await scopeB.verifierInstance.verify(vp, {
      expectedAudience: scopeB.verifierDid,
      expectedSubject: agent.did,
    });

    expect(result.valid).toBe(true);
  });

  it('rejects a VP bound to the wrong audience (cross-org replay prevention)', async () => {
    const session = await scopeA.authenticate({ mockHumanDid: 'Maria Torres, CCO' });
    const agent = await scopeA.createAgent({
      name: 'compliance-monitor',
      ownerDid: session.humanDid,
    });

    const credential = await session.issueCredential({
      agent: agent.did,
      columns: ['order_book.ticker'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // VP is bound to org A's own verifier — not org B's.
    const vp = await createPresentation(credential, agent.did, agent.signer, {
      audience: scopeA.verifierDid,
    });

    const result = await scopeB.verifierInstance.verify(vp, {
      expectedAudience: scopeB.verifierDid,
      expectedSubject: agent.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('WRONG_AUDIENCE');
  });
});
