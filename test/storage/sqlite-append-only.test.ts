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

import { SqliteStorageBackend } from '../../src/storage/sqlite/index.js';
import { deterministicSessionMacKey } from '../support/deterministic-session-mac-key.js';

interface SqliteDb {
  prepare(sql: string): {
    run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  };
}

describe('SQLite audit append-only enforcement', () => {
  let backend: SqliteStorageBackend;

  beforeEach(async () => {
    backend = await SqliteStorageBackend.create(
      { type: 'sqlite', path: ':memory:' },
      { sessionMacKey: deterministicSessionMacKey('append-only') },
    );
    await backend.initialize();
  });

  afterEach(async () => {
    await backend.close();
  });

  const mockRecord = {
    id: 'test-uuid-1',
    timestamp: new Date().toISOString(),
    agentDid: 'did:key:zAgent1',
    ownerDid: 'did:key:zHuman1',
    credentialId: 'cred-hash-123',
    queryHash: 'query-hash-abc',
    columnsAccessed: ['col1', 'col2'],
    rowCount: 10,
    durationMs: 42,
    previousHash: 'GENESIS',
    signature: 'jws-signature-xyz',
  };

  it('append succeeds', async () => {
    await expect(backend.audit.append(mockRecord)).resolves.toBeUndefined();

    const records = await backend.audit.query();
    expect(records).toHaveLength(1);
  });

  it('UPDATE on audit table is rejected by trigger', async () => {
    await backend.audit.append(mockRecord);

    // Attempt a direct UPDATE via the underlying database.
    // Access the private db field for this security test.
    const db = (backend as unknown as { db: SqliteDb }).db;
    expect(() => {
      db.prepare('UPDATE agent_audit SET agent_did = ? WHERE id = ?').run(
        'did:key:zTampered',
        mockRecord.id,
      );
    }).toThrow(/append-only/);

    // Verify original data is unchanged
    const records = await backend.audit.query();
    expect(records[0].agentDid).toBe('did:key:zAgent1');
  });

  it('DELETE on audit table is rejected by trigger', async () => {
    await backend.audit.append(mockRecord);

    // Attempt a direct DELETE via the underlying database.
    const db = (backend as unknown as { db: SqliteDb }).db;
    expect(() => {
      db.prepare('DELETE FROM agent_audit WHERE id = ?').run(mockRecord.id);
    }).toThrow(/append-only/);

    // Verify record still exists
    const records = await backend.audit.query();
    expect(records).toHaveLength(1);
  });
});
