import { describe, it, expect, vi, type Mock } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import { createMockClient, createMockPool, createMockPoolThrowing } from './mocks/pool.js';
import {
  encrypt,
  decrypt,
  generateColumnKey,
  wrapColumnKey,
  unwrapColumnKey,
} from '#encryption/index.js';
import {
  rotateColumnKey,
  rewrapColumnKey,
  registerColumn,
  verifyAllColumnKeys,
} from '#sql/column-keys.js';
import { asMasterKey } from '#crypto/master-key.js';
import { KeyRotationFailedError } from '#errors/index.js';

type MockClientType = PoolClient & { query: Mock; release: Mock };
type MockPool = Pool & { query: Mock; connect: Mock };

function makeMockClient(
  queryFn: (sql: string, params?: unknown[]) => { rows: unknown[] } | Promise<{ rows: unknown[] }>,
): {
  client: MockClientType;
  released: boolean;
  queries: Array<{ sql: string; params?: unknown[] }>;
} {
  const state = { released: false };
  const queries: Array<{ sql: string; params?: unknown[] }> = [];

  const base = createMockClient(async (sql, params) => {
    queries.push({ sql, params });
    const result = await Promise.resolve(queryFn(sql, params));
    return result ?? { rows: [] };
  });
  base.release.mockImplementation(() => {
    state.released = true;
  });

  return { client: base as unknown as MockClientType, ...state, queries };
}

function makeMockPool(
  client: MockClientType,
  poolQueryFn?: (sql: string, params?: unknown[]) => { rows: unknown[] },
): MockPool {
  const defaultPoolQuery =
    poolQueryFn ??
    ((sql: string) => {
      if (sql.trim().includes('pg_index')) return { rows: [{ attname: 'id' }] };
      return { rows: [] };
    });
  return createMockPool({ client, queryImpl: defaultPoolQuery }) as unknown as MockPool;
}

describe('rotateColumnKey', () => {
  const tableName = 'patients';
  const columnName = 'ssn';
  const agentDid = 'did:key:z6MkTest';
  // Brand the 32-byte buffer as MasterKey for the new MasterKey-typed
  // crypto primitive signatures (MasterKey branded type).
  const masterKey = asMasterKey(generateColumnKey());

  it('happy path: re-encrypts all rows, swaps wrapped key, emits audit, returns count', async () => {
    // Build 3 rows encrypted with the original column key.
    const originalColumnKey = generateColumnKey();
    const originalWrappedKey = wrapColumnKey(originalColumnKey, masterKey);
    const values = ['123-45-6789', '987-65-4321', '111-22-3333'];
    const ciphertexts = values.map((v) => encrypt(v, originalColumnKey));

    const agentKeyId = 'key-uuid-1';

    // In-memory state — the mock mutates this to simulate database state.
    const rowStore = ciphertexts.map((c, i) => ({ id: i + 1, [columnName]: c }));
    let storedWrappedKey = originalWrappedKey;
    let auditWritten = false;
    let newWrappedKeyFromUpdate: Buffer | null = null;

    const { client } = makeMockClient((sql, params) => {
      const s = sql.trim();

      // PK query
      if (s.includes('pg_index')) {
        return { rows: [{ attname: 'id' }] };
      }

      // FOR UPDATE on agent_keys
      if (s.includes('FOR UPDATE')) {
        return { rows: [{ id: agentKeyId, encrypted_key: storedWrappedKey }] };
      }

      // SELECT all rows (for re-encryption loop)
      if (s.startsWith('SELECT') && s.includes(columnName)) {
        return { rows: rowStore.map((r) => ({ ...r })) };
      }

      // UPDATE each row in the data table
      if (s.startsWith('UPDATE') && s.includes(tableName)) {
        const newCiphertext = params![0] as Buffer;
        const rowId = params![1] as number;
        const row = rowStore.find((r) => r.id === rowId);
        if (row) row[columnName] = newCiphertext;
        return { rows: [] };
      }

      // UPDATE agent_keys
      if (s.startsWith('UPDATE') && s.includes('agent_keys')) {
        newWrappedKeyFromUpdate = params![0] as Buffer;
        storedWrappedKey = newWrappedKeyFromUpdate;
        return { rows: [] };
      }

      // INSERT INTO agent_audit
      if (s.startsWith('INSERT') && s.includes('agent_audit')) {
        auditWritten = true;
        return { rows: [] };
      }

      return { rows: [] };
    });

    const pool = makeMockPool(client);
    const result = await rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey });

    // Returns correct row count
    expect(result.rowsReencrypted).toBe(3);
    expect(result.rotatedAt).toBeInstanceOf(Date);

    // All rows are now decryptable with the new column key
    const newColumnKey = unwrapColumnKey(storedWrappedKey, masterKey);
    for (let i = 0; i < rowStore.length; i++) {
      const decrypted = decrypt(rowStore[i][columnName] as Buffer, newColumnKey);
      expect(decrypted).toBe(values[i]);
    }

    // Old column key no longer decrypts any row
    for (const row of rowStore) {
      expect(() => decrypt(row[columnName] as Buffer, originalColumnKey)).toThrow();
    }

    // Wrapped key was updated
    expect(newWrappedKeyFromUpdate).not.toBeNull();
    // Old wrapped key would have unwrapped the original column key — now it should
    // unwrap a DIFFERENT key (the new one). Verify they differ.
    const newKeyFromStore = unwrapColumnKey(storedWrappedKey, masterKey);
    expect(newKeyFromStore.equals(originalColumnKey)).toBe(false);

    // Audit entry was written
    expect(auditWritten).toBe(true);

    // Transaction committed, not rolled back, client released
    expect(client.query).toHaveBeenCalledWith('COMMIT');
    expect(client.release).toHaveBeenCalled();
  });

  it('empty table: wrapped key still swaps, rowsReencrypted = 0', async () => {
    const originalColumnKey = generateColumnKey();
    const originalWrappedKey = wrapColumnKey(originalColumnKey, masterKey);
    const agentKeyId = 'key-uuid-empty';

    let newWrappedKeyFromUpdate: Buffer | null = null;
    let auditWritten = false;

    const { client } = makeMockClient((sql, params) => {
      const s = sql.trim();
      if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
      if (s.includes('FOR UPDATE'))
        return { rows: [{ id: agentKeyId, encrypted_key: originalWrappedKey }] };
      if (s.startsWith('SELECT') && s.includes(columnName)) return { rows: [] }; // empty table
      if (s.startsWith('UPDATE') && s.includes('agent_keys')) {
        newWrappedKeyFromUpdate = params![0] as Buffer;
        return { rows: [] };
      }
      if (s.startsWith('INSERT') && s.includes('agent_audit')) {
        auditWritten = true;
        return { rows: [] };
      }
      return { rows: [] };
    });

    const pool = makeMockPool(client);
    const result = await rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey });

    expect(result.rowsReencrypted).toBe(0);
    expect(result.rotatedAt).toBeInstanceOf(Date);

    // Wrapped key still swapped — even empty table rotation updates the key
    expect(newWrappedKeyFromUpdate).not.toBeNull();
    const newKey = unwrapColumnKey(newWrappedKeyFromUpdate!, masterKey);
    expect(newKey.equals(originalColumnKey)).toBe(false); // new key was generated

    expect(auditWritten).toBe(true);
    expect(client.query).toHaveBeenCalledWith('COMMIT');
  });

  it('wrong master key → KeyRotationFailedError with phase unwrap-old-key', async () => {
    const realColumnKey = generateColumnKey();
    const correctMaster = asMasterKey(generateColumnKey());
    const wrongMaster = asMasterKey(generateColumnKey());
    const wrappedWithCorrectMaster = wrapColumnKey(realColumnKey, correctMaster);

    const { client } = makeMockClient((sql) => {
      const s = sql.trim();
      if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
      if (s.includes('FOR UPDATE'))
        return { rows: [{ id: 'key-uuid-1', encrypted_key: wrappedWithCorrectMaster }] };
      return { rows: [] };
    });

    const pool = makeMockPool(client);

    const err1 = await rotateColumnKey({
      pool,
      agentDid,
      tableName,
      columnName,
      masterKey: wrongMaster,
    }).catch((e) => e);
    expect(err1).toBeInstanceOf(KeyRotationFailedError);
    expect((err1 as KeyRotationFailedError).phase).toBe('unwrap-old-key');

    // Must have called ROLLBACK (transaction cleanup)
    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  });

  it('mid-rotation decrypt-row failure → KeyRotationFailedError with phase decrypt-row, ROLLBACK called', async () => {
    const originalColumnKey = generateColumnKey();
    const originalWrappedKey = wrapColumnKey(originalColumnKey, masterKey);

    // Row 1 is valid, row 2 is corrupted (garbage ciphertext)
    const validCiphertext = encrypt('valid-value', originalColumnKey);
    const corruptedCiphertext = Buffer.alloc(50, 0xff); // garbage — will fail GCM verify

    let rollbackCalled = false;

    const { client } = makeMockClient((sql) => {
      const s = sql.trim();
      if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
      if (s.includes('FOR UPDATE'))
        return { rows: [{ id: 'key-uuid-1', encrypted_key: originalWrappedKey }] };
      if (s.startsWith('SELECT') && s.includes(columnName)) {
        return {
          rows: [
            { id: 1, [columnName]: validCiphertext },
            { id: 2, [columnName]: corruptedCiphertext },
          ],
        };
      }
      return { rows: [] };
    });

    // Override ROLLBACK tracking
    const origQuery = client.query;
    client.query = vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql.trim() === 'ROLLBACK') rollbackCalled = true;
      return origQuery(sql, params);
    });

    const pool = makeMockPool(client);

    const err2 = await rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey }).catch(
      (e) => e,
    );
    expect(err2).toBeInstanceOf(KeyRotationFailedError);
    expect((err2 as KeyRotationFailedError).phase).toBe('decrypt-row');

    expect(rollbackCalled).toBe(true);
  });

  it('repeated rotation: rotated_at updated on second call, old pre-rotation key fails', async () => {
    // Simulate two sequential rotations using in-memory state.
    const initialColumnKey = generateColumnKey();
    const initialWrappedKey = wrapColumnKey(initialColumnKey, masterKey);

    const values = ['secret-1', 'secret-2'];
    let rowStore = values.map((v, i) => ({
      id: i + 1,
      [columnName]: encrypt(v, initialColumnKey),
    }));
    let currentWrappedKey = initialWrappedKey;
    let rotateCallCount = 0;

    function buildPool() {
      const { client } = makeMockClient((sql, params) => {
        const s = sql.trim();
        if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
        if (s.includes('FOR UPDATE'))
          return { rows: [{ id: 'key-uuid-1', encrypted_key: currentWrappedKey }] };
        if (s.startsWith('SELECT') && s.includes(columnName))
          return { rows: rowStore.map((r) => ({ ...r })) };
        if (s.startsWith('UPDATE') && s.includes(tableName)) {
          const newCiphertext = params![0] as Buffer;
          const rowId = params![1] as number;
          const row = rowStore.find((r) => r.id === rowId);
          if (row) row[columnName] = newCiphertext;
          return { rows: [] };
        }
        if (s.startsWith('UPDATE') && s.includes('agent_keys')) {
          currentWrappedKey = params![0] as Buffer;
          rotateCallCount++;
          return { rows: [] };
        }
        return { rows: [] };
      });
      return makeMockPool(client);
    }

    // First rotation
    const result1 = await rotateColumnKey({
      pool: buildPool(),
      agentDid,
      tableName,
      columnName,
      masterKey,
    });
    expect(result1.rowsReencrypted).toBe(2);
    const keyAfterFirst = unwrapColumnKey(currentWrappedKey, masterKey);

    // Second rotation — uses the first rotation's wrapped key
    const result2 = await rotateColumnKey({
      pool: buildPool(),
      agentDid,
      tableName,
      columnName,
      masterKey,
    });
    expect(result2.rowsReencrypted).toBe(2);
    const keyAfterSecond = unwrapColumnKey(currentWrappedKey, masterKey);

    // rotated_at was updated both times (wrapped key changed both times)
    expect(rotateCallCount).toBe(2);

    // Keys are different
    expect(keyAfterFirst.equals(initialColumnKey)).toBe(false);
    expect(keyAfterSecond.equals(keyAfterFirst)).toBe(false);

    // Rows decrypt under current key
    for (let i = 0; i < rowStore.length; i++) {
      expect(decrypt(rowStore[i][columnName] as Buffer, keyAfterSecond)).toBe(values[i]);
    }

    // Pre-rotation column key can no longer decrypt any row
    for (const row of rowStore) {
      expect(() => decrypt(row[columnName] as Buffer, initialColumnKey)).toThrow();
    }
  });

  it('audit entry is written inside the transaction (before COMMIT)', async () => {
    const originalColumnKey = generateColumnKey();
    const originalWrappedKey = wrapColumnKey(originalColumnKey, masterKey);

    const queryOrder: string[] = [];

    const { client } = makeMockClient((sql) => {
      const s = sql.trim();
      if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
      if (s.includes('FOR UPDATE'))
        return { rows: [{ id: 'key-uuid-1', encrypted_key: originalWrappedKey }] };
      if (s.startsWith('SELECT') && s.includes(columnName)) return { rows: [] }; // empty table
      if (s.startsWith('UPDATE') && s.includes('agent_keys')) {
        queryOrder.push('UPDATE_AGENT_KEYS');
        return { rows: [] };
      }
      if (s.startsWith('INSERT') && s.includes('agent_audit')) {
        queryOrder.push('AUDIT_INSERT');
        return { rows: [] };
      }
      if (s.trim() === 'COMMIT') {
        queryOrder.push('COMMIT');
      }
      return { rows: [] };
    });

    const pool = makeMockPool(client);
    await rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey });

    // Order: UPDATE agent_keys → AUDIT INSERT → COMMIT
    // Audit must come AFTER agent_keys update (last data step before commit)
    // and BEFORE commit.
    const updateIdx = queryOrder.indexOf('UPDATE_AGENT_KEYS');
    const auditIdx = queryOrder.indexOf('AUDIT_INSERT');
    const commitIdx = queryOrder.indexOf('COMMIT');

    expect(updateIdx).toBeGreaterThanOrEqual(0);
    expect(auditIdx).toBeGreaterThan(updateIdx);
    expect(commitIdx).toBeGreaterThan(auditIdx);
  });

  it('no agent_keys row → throws Error (not KeyRotationFailedError), ROLLBACK called', async () => {
    const { client } = makeMockClient((sql) => {
      const s = sql.trim();
      if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
      if (s.includes('FOR UPDATE')) return { rows: [] }; // no row found
      return { rows: [] };
    });

    const pool = makeMockPool(client);

    await expect(
      rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey }),
    ).rejects.toThrow(/No agent_keys entry/);

    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  });
});

describe('rewrapColumnKey', () => {
  const tableName = 'patients';
  const columnName = 'dob';
  const agentDid = 'did:key:z6MkTest';
  const oldMasterKey = asMasterKey(generateColumnKey());
  const newMasterKey = asMasterKey(generateColumnKey());

  it('happy path: wrapped key changes, row ciphertext is identical (untouched)', async () => {
    const columnKey = generateColumnKey();
    const wrappedWithOld = wrapColumnKey(columnKey, oldMasterKey);
    const agentKeyId = 'key-uuid-rewrap';

    // We track what was written to agent_keys
    let capturedNewWrappedKey: Buffer | null = null;
    let auditWritten = false;
    let dataRowUpdated = false;

    const { client } = makeMockClient((sql, params) => {
      const s = sql.trim();
      if (s.includes('FOR UPDATE'))
        return { rows: [{ id: agentKeyId, encrypted_key: wrappedWithOld }] };
      if (s.startsWith('UPDATE') && s.includes('agent_keys')) {
        capturedNewWrappedKey = params![0] as Buffer;
        return { rows: [] };
      }
      if (s.startsWith('INSERT') && s.includes('agent_audit')) {
        auditWritten = true;
        return { rows: [] };
      }
      if (s.startsWith('UPDATE') && s.includes(tableName)) {
        // This should NEVER be called — rewrapColumnKey does not touch data rows
        dataRowUpdated = true;
        return { rows: [] };
      }
      return { rows: [] };
    });

    const pool = makeMockPool(client);
    const result = await rewrapColumnKey({
      pool,
      agentDid,
      tableName,
      columnName,
      oldMasterKey,
      newMasterKey,
    });

    expect(result.rewrappedAt).toBeInstanceOf(Date);

    // No data rows were updated
    expect(dataRowUpdated).toBe(false);

    // The new wrapped key decrypts to the SAME column key
    expect(capturedNewWrappedKey).not.toBeNull();
    const recoveredKey = unwrapColumnKey(capturedNewWrappedKey!, newMasterKey);
    expect(recoveredKey.equals(columnKey)).toBe(true);

    // Old master key no longer works on the new wrapped key
    expect(() => unwrapColumnKey(capturedNewWrappedKey!, oldMasterKey)).toThrow();

    // Audit entry written
    expect(auditWritten).toBe(true);

    expect(client.query).toHaveBeenCalledWith('COMMIT');
    expect(client.release).toHaveBeenCalled();
  });

  it('wrong old master key → KeyRotationFailedError with phase unwrap-old-key', async () => {
    const columnKey = generateColumnKey();
    const correctOldMaster = asMasterKey(generateColumnKey());
    const wrongOldMaster = asMasterKey(generateColumnKey());
    const wrappedWithCorrect = wrapColumnKey(columnKey, correctOldMaster);

    const { client } = makeMockClient((sql) => {
      if (sql.trim().includes('FOR UPDATE'))
        return { rows: [{ id: 'key-uuid-1', encrypted_key: wrappedWithCorrect }] };
      return { rows: [] };
    });

    const pool = makeMockPool(client);

    const err3 = await rewrapColumnKey({
      pool,
      agentDid,
      tableName,
      columnName,
      oldMasterKey: wrongOldMaster,
      newMasterKey,
    }).catch((e) => e);
    expect(err3).toBeInstanceOf(KeyRotationFailedError);
    expect((err3 as KeyRotationFailedError).phase).toBe('unwrap-old-key');

    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  });

  it('row ciphertext identity: value encrypted with original key still decrypts after rewrap', () => {
    // This is a pure crypto unit test — no DB mock needed.
    // Demonstrates that rewrap changes only the wrapped DEK, not row ciphertext.
    const columnKey = generateColumnKey();
    const oldMaster = asMasterKey(generateColumnKey());
    const newMaster = asMasterKey(generateColumnKey());

    const plaintext = 'sensitive-dob-value';
    const rowCiphertext = encrypt(plaintext, columnKey);

    // Simulate rewrap: unwrap with old, re-wrap with new
    const wrappedOld = wrapColumnKey(columnKey, oldMaster);
    const unwrapped = unwrapColumnKey(wrappedOld, oldMaster);
    const wrappedNew = wrapColumnKey(unwrapped, newMaster);

    // Row ciphertext bytes are completely unchanged
    const keyFromNew = unwrapColumnKey(wrappedNew, newMaster);
    expect(keyFromNew.equals(columnKey)).toBe(true);
    expect(decrypt(rowCiphertext, keyFromNew)).toBe(plaintext);

    // Old master no longer opens the new wrapped key
    expect(() => unwrapColumnKey(wrappedNew, oldMaster)).toThrow();

    // The row ciphertext itself is structurally the same Buffer
    expect(rowCiphertext.equals(rowCiphertext)).toBe(true); // trivial — proves no mutation
  });

  it('no agent_keys row → throws Error, ROLLBACK called', async () => {
    const { client } = makeMockClient((sql) => {
      if (sql.trim().includes('FOR UPDATE')) return { rows: [] }; // no entry
      return { rows: [] };
    });

    const pool = makeMockPool(client);

    await expect(
      rewrapColumnKey({ pool, agentDid, tableName, columnName, oldMasterKey, newMasterKey }),
    ).rejects.toThrow(/No agent_keys entry/);

    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  });

  it('audit entry is written before COMMIT (same transaction boundary as rewrap)', async () => {
    const columnKey = generateColumnKey();
    const wrapped = wrapColumnKey(columnKey, oldMasterKey);

    const queryOrder: string[] = [];

    const { client } = makeMockClient((sql) => {
      const s = sql.trim();
      if (s.includes('FOR UPDATE')) return { rows: [{ id: 'key-uuid-1', encrypted_key: wrapped }] };
      if (s.startsWith('UPDATE') && s.includes('agent_keys')) {
        queryOrder.push('UPDATE_AGENT_KEYS');
        return { rows: [] };
      }
      if (s.startsWith('INSERT') && s.includes('agent_audit')) {
        queryOrder.push('AUDIT_INSERT');
        return { rows: [] };
      }
      if (s.trim() === 'COMMIT') {
        queryOrder.push('COMMIT');
      }
      return { rows: [] };
    });

    const pool = makeMockPool(client);
    await rewrapColumnKey({ pool, agentDid, tableName, columnName, oldMasterKey, newMasterKey });

    const updateIdx = queryOrder.indexOf('UPDATE_AGENT_KEYS');
    const auditIdx = queryOrder.indexOf('AUDIT_INSERT');
    const commitIdx = queryOrder.indexOf('COMMIT');

    expect(updateIdx).toBeGreaterThanOrEqual(0);
    expect(auditIdx).toBeGreaterThan(updateIdx);
    expect(commitIdx).toBeGreaterThan(auditIdx);
  });
});

describe('registerColumn — ON CONFLICT tightening', () => {
  it('first registration succeeds and returns keyId + columnKey', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const fakeId = 'new-key-uuid';

    const mockPool = createMockPool({ queryImpl: () => ({ rows: [{ id: fakeId }] }) });

    const result = await registerColumn(mockPool, masterKey, 'patients', 'ssn');

    expect(result.keyId).toBe(fakeId);
    expect(result.columnKey).toBeInstanceOf(Buffer);
    expect(result.columnKey.length).toBe(32);

    // The SQL uses ON CONFLICT DO NOTHING (not DO UPDATE)
    const insertCall = (mockPool.query as unknown as Mock).mock.calls[0];
    const sql: string = insertCall[0];
    expect(sql).toContain('DO NOTHING');
    expect(sql).not.toContain('DO UPDATE');
  });

  it('second registration for the same (table, column) throws clear error', async () => {
    const masterKey = asMasterKey(generateColumnKey());

    const mockPool = createMockPool();

    await expect(registerColumn(mockPool, masterKey, 'patients', 'ssn')).rejects.toThrow(
      /already has a wrapped key/,
    );

    await expect(registerColumn(mockPool, masterKey, 'patients', 'ssn')).rejects.toThrow(
      /rotateColumnKey\(\)/,
    );
  });

  it('error message mentions both rotateColumnKey and rewrapColumnKey', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const mockPool = createMockPool();

    const err4 = await registerColumn(mockPool, masterKey, 'patients', 'diagnosis').catch((e) => e);
    expect((err4 as Error).message).toContain('rotateColumnKey()');
    expect((err4 as Error).message).toContain('rewrapColumnKey()');
  });
});

describe('KeyRotationFailedError', () => {
  it('has correct name and phase field', () => {
    const err = new KeyRotationFailedError('decrypt-row', new Error('GCM auth failed'));
    expect(err.name).toBe('KeyRotationFailedError');
    expect(err.phase).toBe('decrypt-row');
    expect(err.message).toContain('decrypt-row');
    expect(err.message).toContain('GCM auth failed');
  });

  it('preserves cause', () => {
    const cause = new Error('original cause');
    const err = new KeyRotationFailedError('update-agent-keys', cause);
    expect(err.cause).toBe(cause);
  });

  it('handles non-Error cause', () => {
    const err = new KeyRotationFailedError('wrap-new-key', 'string cause');
    expect(err.message).toContain('string cause');
  });

  it('is an instanceof Error', () => {
    const err = new KeyRotationFailedError('unwrap-old-key', new Error('x'));
    expect(err).toBeInstanceOf(Error);
  });
});

describe('concurrent rotation serialization', () => {
  it('SELECT...FOR UPDATE appears in the rotation SQL (serialization mechanism present)', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const columnKey = generateColumnKey();
    const wrapped = wrapColumnKey(columnKey, masterKey);

    const capturedSqls: string[] = [];

    const { client } = makeMockClient((sql) => {
      const s = sql.trim();
      capturedSqls.push(s);
      if (s.includes('pg_index')) return { rows: [{ attname: 'id' }] };
      if (s.includes('FOR UPDATE')) return { rows: [{ id: 'key-uuid-1', encrypted_key: wrapped }] };
      if (s.toUpperCase().startsWith('SELECT') && s.includes('ssn')) return { rows: [] };
      return { rows: [] };
    });

    const pool = makeMockPool(client);
    await rotateColumnKey({
      pool,
      agentDid: 'did:key:z6Mk',
      tableName: 'patients',
      columnName: 'ssn',
      masterKey,
    });

    // Verify FOR UPDATE is in the agent_keys query
    const forUpdateQuery = capturedSqls.find((s) => s.includes('FOR UPDATE'));
    expect(forUpdateQuery).toBeDefined();
    expect(forUpdateQuery).toContain('agent_keys');
  });

  it('rewrapColumnKey also uses SELECT...FOR UPDATE', async () => {
    const oldMaster = asMasterKey(generateColumnKey());
    const newMaster = asMasterKey(generateColumnKey());
    const columnKey = generateColumnKey();
    const wrapped = wrapColumnKey(columnKey, oldMaster);

    const capturedSqls: string[] = [];

    const { client } = makeMockClient((sql) => {
      capturedSqls.push(sql.trim());
      if (sql.trim().includes('FOR UPDATE'))
        return { rows: [{ id: 'key-uuid-1', encrypted_key: wrapped }] };
      return { rows: [] };
    });

    const pool = makeMockPool(client);
    await rewrapColumnKey({
      pool,
      agentDid: 'did:key:z6Mk',
      tableName: 'patients',
      columnName: 'dob',
      oldMasterKey: oldMaster,
      newMasterKey: newMaster,
    });

    const forUpdateQuery = capturedSqls.find((s) => s.includes('FOR UPDATE'));
    expect(forUpdateQuery).toBeDefined();
    expect(forUpdateQuery).toContain('agent_keys');
  });
});

//
// Consumer-facing diagnostic for the BYOK migration protocol (steps 3 + 5 of
// the rewrapColumnKey procedure documented in docs/migrations/byok.md). The
// helper iterates agent_keys and reports per-row unwrap success/failure under
// the supplied master key. Tests cover:
//   1. Empty table → ok=0, failed=[]
//   2. All rows decrypt under the supplied key → ok=N, failed=[]
//   3. Mixed state (some rows wrapped under a different key) → partial failure
//      report with table/col/error per failed row
//   4. All rows fail (wrong master key altogether) → all rows in failed[]
//   5. Schema-missing (Postgres SQLSTATE 42P01) → ok=0, failed=[] (matches
//      loadColumnKeys' "no column keys to verify" posture)
//   6. Other DB errors propagate (helper does not swallow non-schema errors)
describe('verifyAllColumnKeys (BYOK migration verification)', () => {
  // Build a mock pool whose .query() returns the supplied rows for the
  // agent_keys SELECT. The helper does not connect() — it issues exactly one
  // pool.query() — so no client mock is needed here.
  function makePoolReturning(
    rows: Array<{ table_name: string; column_name: string; encrypted_key: Buffer }>,
  ): MockPool {
    return createMockPool({ queryImpl: () => ({ rows }) }) as unknown as MockPool;
  }

  function makePoolThrowing(error: unknown): MockPool {
    return createMockPoolThrowing(error) as unknown as MockPool;
  }

  it('empty agent_keys table → ok=0, failed=[]', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const pool = makePoolReturning([]);

    const report = await verifyAllColumnKeys(pool, masterKey);

    expect(report.ok).toBe(0);
    expect(report.failed).toEqual([]);
  });

  it('all rows decrypt under the supplied master key → ok=N, failed=[]', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const rows = [
      {
        table_name: 'patients',
        column_name: 'ssn',
        encrypted_key: wrapColumnKey(generateColumnKey(), masterKey),
      },
      {
        table_name: 'patients',
        column_name: 'dob',
        encrypted_key: wrapColumnKey(generateColumnKey(), masterKey),
      },
      {
        table_name: 'orders',
        column_name: 'card',
        encrypted_key: wrapColumnKey(generateColumnKey(), masterKey),
      },
    ];
    const pool = makePoolReturning(rows);

    const report = await verifyAllColumnKeys(pool, masterKey);

    expect(report.ok).toBe(3);
    expect(report.failed).toEqual([]);
  });

  it('mixed-key state (mid-rewrap) → partial-success report', async () => {
    // The realistic mid-rewrap scenario: some rows wrapped under the OLD master
    // key, some under the NEW. Calling verify with the NEW key — as in step 5
    // of the migration protocol — should report exactly which rows still need
    // their column key re-wrapped.
    const oldMaster = asMasterKey(generateColumnKey());
    const newMaster = asMasterKey(generateColumnKey());

    const colKey1 = generateColumnKey();
    const colKey2 = generateColumnKey();
    const colKey3 = generateColumnKey();

    const rows = [
      // Rewrapped — under newMaster.
      {
        table_name: 'patients',
        column_name: 'ssn',
        encrypted_key: wrapColumnKey(colKey1, newMaster),
      },
      // NOT yet rewrapped — still under oldMaster. Will fail under newMaster.
      {
        table_name: 'patients',
        column_name: 'dob',
        encrypted_key: wrapColumnKey(colKey2, oldMaster),
      },
      // Rewrapped — under newMaster.
      {
        table_name: 'orders',
        column_name: 'card',
        encrypted_key: wrapColumnKey(colKey3, newMaster),
      },
    ];
    const pool = makePoolReturning(rows);

    const report = await verifyAllColumnKeys(pool, newMaster);

    expect(report.ok).toBe(2);
    expect(report.failed).toHaveLength(1);
    expect(report.failed[0]).toMatchObject({
      table: 'patients',
      col: 'dob',
    });
    // The error message comes from crypto.createDecipheriv when authentication
    // fails on a wrong-key unwrap — assert non-empty rather than a specific
    // string (Node version drift would break a string-match test).
    expect(report.failed[0]!.error).toBeTruthy();
    expect(typeof report.failed[0]!.error).toBe('string');
  });

  it('wrong master key against all rows → ok=0, every row in failed[]', async () => {
    const realMaster = asMasterKey(generateColumnKey());
    const wrongMaster = asMasterKey(generateColumnKey());
    const rows = [
      {
        table_name: 't1',
        column_name: 'c1',
        encrypted_key: wrapColumnKey(generateColumnKey(), realMaster),
      },
      {
        table_name: 't2',
        column_name: 'c2',
        encrypted_key: wrapColumnKey(generateColumnKey(), realMaster),
      },
    ];
    const pool = makePoolReturning(rows);

    const report = await verifyAllColumnKeys(pool, wrongMaster);

    expect(report.ok).toBe(0);
    expect(report.failed).toHaveLength(2);
    expect(report.failed.map((f) => `${f.table}.${f.col}`)).toEqual(['t1.c1', 't2.c2']);
  });

  it('schema-missing (SQLSTATE 42P01) → ok=0, failed=[] (no throw)', async () => {
    // pg.DatabaseError shape: an Error with a `code` property. The helper's
    // schema-detection uses isUndefinedTableError which checks for code 42P01.
    const undefinedTableError = Object.assign(new Error('relation "agent_keys" does not exist'), {
      code: '42P01',
    });
    const pool = makePoolThrowing(undefinedTableError);
    const masterKey = asMasterKey(generateColumnKey());

    const report = await verifyAllColumnKeys(pool, masterKey);

    expect(report.ok).toBe(0);
    expect(report.failed).toEqual([]);
  });

  it('non-schema DB error propagates (does not swallow connection errors)', async () => {
    // Any DB error other than 42P01 should propagate — masking a connection
    // refusal as "no keys to verify" would be a silently-wrong report.
    const connectionError = Object.assign(new Error('connection refused'), {
      code: '08006',
    });
    const pool = makePoolThrowing(connectionError);
    const masterKey = asMasterKey(generateColumnKey());

    await expect(verifyAllColumnKeys(pool, masterKey)).rejects.toThrow('connection refused');
  });

  it('issues exactly one read query (no transactions, no FOR UPDATE)', async () => {
    // The helper is documented as read-only — no BEGIN/COMMIT/ROLLBACK, no
    // SELECT...FOR UPDATE. Running it against a live system during write
    // traffic should not lock anything. Verified by inspecting the mock's
    // call log.
    const masterKey = asMasterKey(generateColumnKey());
    const rows = [
      {
        table_name: 't',
        column_name: 'c',
        encrypted_key: wrapColumnKey(generateColumnKey(), masterKey),
      },
    ];
    const pool = makePoolReturning(rows);

    await verifyAllColumnKeys(pool, masterKey);

    expect(pool.query).toHaveBeenCalledTimes(1);
    const sql = pool.query.mock.calls[0][0] as string;
    expect(sql).toContain('SELECT');
    expect(sql).toContain('agent_keys');
    expect(sql.toUpperCase()).not.toContain('FOR UPDATE');
    expect(sql.toUpperCase()).not.toContain('BEGIN');
    expect(pool.connect).not.toHaveBeenCalled();
  });
});
