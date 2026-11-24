import { describe, it, expect } from 'vitest';
import { createMockClient, createMockPool } from './mocks/pool.js';
import {
  decrypt,
  encrypt,
  generateColumnKey,
  unwrapColumnKey,
  wrapColumnKey,
} from '#encryption/index.js';
import { rewrapColumnKey, rotateColumnKey } from '#sql/column-keys.js';
import { asMasterKey } from '#crypto/master-key.js';
import { KeyRotationFailedError } from '#errors/index.js';

describe('rotateColumnKey', () => {
  const tableName = 'patients';
  const columnName = 'ssn';
  const agentDid = 'did:key:z6MkTest';
  const masterKey = asMasterKey(generateColumnKey());

  it('rotates and rewraps column keys while preserving readable rows and audit commits', async () => {
    const originalColumnKey = generateColumnKey();
    let storedWrappedKey = wrapColumnKey(originalColumnKey, masterKey);
    const values = ['123-45-6789', '987-65-4321'];
    const rows = values.map((value, index) => ({
      id: index + 1,
      ssn: encrypt(value, originalColumnKey),
    }));
    const client = createMockClient((sql, params) => {
      const statement = sql.trim();
      if (statement.includes('FOR UPDATE')) {
        return { rows: [{ id: 'key-uuid-1', encrypted_key: storedWrappedKey }] };
      }
      if (statement.startsWith('SELECT') && statement.includes(columnName)) {
        return { rows: rows.map((row) => ({ ...row })) };
      }
      if (statement.startsWith('UPDATE agent_keys')) {
        storedWrappedKey = params![0] as Buffer;
      } else if (statement.startsWith(`UPDATE "${tableName}"`)) {
        rows.find((row) => row.id === params![1])!.ssn = params![0] as Buffer;
      }
      return { rows: [] };
    });
    const pool = createMockPool({
      client,
      queryImpl: () => ({ rows: [{ attname: 'id' }] }),
    });

    const result = await rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey });
    expect(result.rowsReencrypted).toBe(values.length);
    const rotatedKey = unwrapColumnKey(storedWrappedKey, masterKey);
    expect(rotatedKey.equals(originalColumnKey)).toBe(false);
    expect(rows.map((row) => decrypt(row.ssn, rotatedKey))).toEqual(values);
    for (const row of rows) expect(() => decrypt(row.ssn, originalColumnKey)).toThrow();

    const ciphertexts = rows.map((row) => Buffer.from(row.ssn));
    const newMasterKey = asMasterKey(generateColumnKey());
    await rewrapColumnKey({
      pool,
      agentDid,
      tableName,
      columnName,
      oldMasterKey: masterKey,
      newMasterKey,
    });
    const rewrappedKey = unwrapColumnKey(storedWrappedKey, newMasterKey);
    expect(rewrappedKey).toEqual(rotatedKey);
    expect(() => unwrapColumnKey(storedWrappedKey, masterKey)).toThrow();
    expect(rows.map((row) => row.ssn)).toEqual(ciphertexts);
    expect(rows.map((row) => decrypt(row.ssn, rewrappedKey))).toEqual(values);
    const transactionEvents = client.query.mock.calls
      .map(([sql]) => (sql.trim().startsWith('INSERT INTO agent_audit') ? 'audit' : sql.trim()))
      .filter((sql) => ['audit', 'COMMIT', 'ROLLBACK'].includes(sql));
    expect(transactionEvents).toEqual(['audit', 'COMMIT', 'audit', 'COMMIT']);
    expect(client.release).toHaveBeenCalledTimes(2);
  });

  it('mid-rotation decrypt-row failure → KeyRotationFailedError with phase decrypt-row, ROLLBACK called', async () => {
    const originalColumnKey = generateColumnKey();
    const originalWrappedKey = wrapColumnKey(originalColumnKey, masterKey);

    const validCiphertext = encrypt('valid-value', originalColumnKey);
    const corruptedCiphertext = Buffer.alloc(50, 0xff);

    const client = createMockClient((sql) => {
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

    const pool = createMockPool({
      client,
      queryImpl: () => ({ rows: [{ attname: 'id' }] }),
    });

    const err2 = await rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey }).catch(
      (e) => e,
    );
    expect(err2).toBeInstanceOf(KeyRotationFailedError);
    expect((err2 as KeyRotationFailedError).phase).toBe('decrypt-row');

    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  });
});
