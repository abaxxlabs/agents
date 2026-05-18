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
 * Pool-dependent column encryption key management.
 *
 * Pure-crypto primitives (encrypt, decrypt, wrap, unwrap) live in column-encryption.ts.
 * Every function here accepts `pool: Pool` — they never own a pool.
 */

import type { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import type { MasterKey } from '../crypto/master-key.js';
import type { ColumnKeyRecord } from '../types.js';
import {
  encrypt,
  decrypt,
  generateColumnKey,
  wrapColumnKey,
  unwrapColumnKey,
  isUndefinedTableError,
} from '../column-encryption.js';
import { MasterKeyMismatchError, KeyRotationFailedError } from '../errors.js';
import type { Logger } from '../logger.js';
import { getLogger } from '../logger.js';

// ─── Types ──────────────────────────────────────────────────────────

/**
 * `'schemaMissing' in loaded` narrows the two cases:
 * table absent (silent boot OK) vs table present but unwrap failed (throw).
 */
export type LoadColumnKeysResult = Map<string, Buffer> | { schemaMissing: true };

// ─── Load Column Keys ───────────────────────────────────────────────

/**
 * Load all column keys from the database, decrypt with the master key.
 *
 * Returns `{ schemaMissing: true }` on SQLSTATE 42P01 (pre-migration boot).
 * Throws `MasterKeyMismatchError` when rows exist but none can be decrypted
 * (wrong key — fail loud rather than booting with empty key map).
 * Partial decrypt success (some rows fail) logs per-row and returns partial Map.
 */
export async function loadColumnKeys(
  pool: Pool,
  masterKey: MasterKey,
  logger: Logger = getLogger(),
): Promise<LoadColumnKeysResult> {
  let rows: ColumnKeyRecord[];
  try {
    const result = await pool.query<ColumnKeyRecord>(
      'SELECT id, table_name, column_name, encrypted_key, algorithm FROM agent_keys',
    );
    rows = result.rows;
  } catch (err) {
    if (isUndefinedTableError(err)) {
      return { schemaMissing: true };
    }
    // Only SQLSTATE 42P01 is caught here; all other DB errors propagate.
    throw err;
  }

  const keys = new Map<string, Buffer>();
  let unwrapFailures = 0;
  for (const row of rows) {
    // Postgres returns snake_case column names
    const r = row as unknown as Record<string, unknown>;
    const tableName = (r.table_name ?? r.tableName) as string;
    const columnName = (r.column_name ?? r.columnName) as string;
    const encryptedKey = (r.encrypted_key ?? r.encryptedKey) as Buffer;
    const tableColumn = `${tableName}.${columnName}`;
    try {
      const decryptedKey = unwrapColumnKey(encryptedKey, masterKey);
      keys.set(tableColumn, decryptedKey);
    } catch {
      unwrapFailures++;
      logger.warn(
        `[agents] Failed to decrypt column key for ${tableColumn} — wrong master key for this row`,
        { tableColumn },
      );
    }
  }

  // If rows exist but none unwrapped, the master key is wrong — fail loud.
  if (rows.length > 0 && keys.size === 0) {
    throw new MasterKeyMismatchError(unwrapFailures, rows.length);
  }

  return keys;
}

// ─── Register Column ────────────────────────────────────────────────

/**
 * Register a new column for encryption. Generates a column key, wraps it,
 * and stores it in the database.
 *
 * Throws if the column is already registered — use `rotateColumnKey()` or
 * `rewrapColumnKey()` to change key material on an existing column.
 */
export async function registerColumn(
  pool: Pool,
  masterKey: MasterKey,
  tableName: string,
  columnName: string,
): Promise<{ keyId: string; columnKey: Buffer }> {
  const columnKey = generateColumnKey();
  const wrappedKey = wrapColumnKey(columnKey, masterKey);

  // ON CONFLICT DO NOTHING — 0 rows returned means already registered.
  const result = await pool.query(
    `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (table_name, column_name) DO NOTHING
     RETURNING id`,
    [tableName, columnName, wrappedKey, 'aes-256-gcm'],
  );

  if (result.rows.length === 0) {
    throw new Error(
      `agent_keys already has a wrapped key for "${tableName}"."${columnName}". ` +
        `Use rotateColumnKey() to change the column key or rewrapColumnKey() to change ` +
        `the master key. Re-registering via registerColumn() would silently destroy ` +
        `existing ciphertext.`,
    );
  }

  return { keyId: result.rows[0].id, columnKey };
}

// ─── Encrypt Column In-Place ────────────────────────────────────────

/**
 * Encrypt an existing cleartext column in-place using a temp-column transaction.
 * If anything fails, the original column is untouched.
 *
 * @returns the number of rows encrypted.
 */
export async function encryptColumnInPlace(
  pool: Pool,
  masterKey: MasterKey,
  tableName: string,
  columnName: string,
): Promise<{ rowsEncrypted: number }> {
  // Register column key
  const { columnKey } = await registerColumn(pool, masterKey, tableName, columnName);

  // Get original column type before we start
  const typeResult = await pool.query(
    `SELECT data_type FROM information_schema.columns
     WHERE table_name = $1 AND column_name = $2`,
    [tableName, columnName],
  );

  if (!typeResult.rows.length) {
    throw new Error(`Column "${tableName}"."${columnName}" not found`);
  }

  const originalType = typeResult.rows[0].data_type;

  // Refuse to encrypt a column that's already bytea (likely already encrypted)
  if (originalType === 'bytea') {
    throw new Error(
      `Column "${tableName}"."${columnName}" is already bytea — it may already be encrypted. ` +
        `If you want to re-encrypt, use key rotation instead.`,
    );
  }

  // Store column metadata
  await pool.query(
    `INSERT INTO agent_columns (table_name, column_name, key_id, original_type, is_encrypted)
     VALUES ($1, $2, (SELECT id FROM agent_keys WHERE table_name = $1 AND column_name = $2), $3, true)
     ON CONFLICT (table_name, column_name) DO UPDATE SET is_encrypted = true, original_type = $3`,
    [tableName, columnName, originalType],
  );

  // Detect primary key column(s) for stable row identification
  // ctid is unstable — changes during VACUUM, HOT updates, and CLUSTER
  const pkResult = await pool.query(
    `SELECT a.attname
     FROM pg_index i
     JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
     WHERE i.indrelid = $1::regclass AND i.indisprimary
     ORDER BY array_position(i.indkey, a.attnum)`,
    [tableName],
  );

  const pkColumns = pkResult.rows.map((r: { attname: string }) => r.attname);
  if (pkColumns.length === 0) {
    throw new Error(
      `Table "${tableName}" has no primary key. ` +
        `encryptColumnInPlace requires a primary key for safe row identification. ` +
        `Add a primary key column before encrypting.`,
    );
  }

  const tempCol = `_agentid_enc_${columnName}`;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Step 1: Add temporary bytea column
    await client.query(`ALTER TABLE "${tableName}" ADD COLUMN "${tempCol}" BYTEA`);

    // Step 2: Read all rows with their primary key columns
    const pkSelect = pkColumns.map((c) => `"${c}"`).join(', ');
    const rows = await client.query(`SELECT ${pkSelect}, "${columnName}" FROM "${tableName}"`);

    // Step 3: Encrypt each value and write to the temp column
    // Build WHERE clause from primary key columns
    const pkWhere = pkColumns.map((c, i) => `"${c}" = $${i + 2}`).join(' AND ');
    let encrypted = 0;
    for (const row of rows.rows) {
      const cleartext = row[columnName];
      const encryptedValue = encrypt(
        cleartext === null || cleartext === undefined ? null : cleartext,
        columnKey,
      );
      const pkValues = pkColumns.map((c) => row[c]);
      await client.query(`UPDATE "${tableName}" SET "${tempCol}" = $1 WHERE ${pkWhere}`, [
        encryptedValue,
        ...pkValues,
      ]);
      encrypted++;
    }

    // Step 4: Drop the original cleartext column
    await client.query(`ALTER TABLE "${tableName}" DROP COLUMN "${columnName}"`);

    // Step 5: Rename the temp column to the original name
    await client.query(`ALTER TABLE "${tableName}" RENAME COLUMN "${tempCol}" TO "${columnName}"`);

    // Step 6: Commit — all or nothing
    await client.query('COMMIT');

    return { rowsEncrypted: encrypted };
  } catch (err) {
    // Rollback on any error — original column stays intact
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ─── Key Rotation ───────────────────────────────────────────────────

/**
 * Generate a new column key and re-encrypt all rows under it.
 *
 * All steps run in a single transaction — failure leaves the column on its old key.
 * SELECT...FOR UPDATE on the agent_keys row serializes concurrent rotations of the
 * same column but does NOT lock the data table. Caller must quiesce writes.
 *
 * @throws KeyRotationFailedError with phase in:
 *   'unwrap-old-key' | 'decrypt-row' | 'encrypt-row' |
 *   'wrap-new-key'   | 'update-agent-keys' | 'audit-append'
 */
export async function rotateColumnKey(opts: {
  pool: Pool;
  /** DID of the agent / human authorizing this rotation — recorded in agent_audit. */
  agentDid: string;
  tableName: string;
  columnName: string;
  /** Master key used to unwrap the old column key and re-wrap the new one. */
  masterKey: MasterKey;
}): Promise<{ rotatedAt: Date; rowsReencrypted: number }> {
  const { pool, agentDid, tableName, columnName, masterKey } = opts;

  // ctid is unstable (VACUUM/HOT/CLUSTER) — use PK columns for row identification.
  const pkResult = await pool.query(
    `SELECT a.attname
     FROM pg_index i
     JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
     WHERE i.indrelid = $1::regclass AND i.indisprimary
     ORDER BY array_position(i.indkey, a.attnum)`,
    [tableName],
  );
  const pkColumns = pkResult.rows.map((r: { attname: string }) => r.attname);
  if (pkColumns.length === 0) {
    throw new Error(
      `Table "${tableName}" has no primary key. ` +
        `rotateColumnKey requires a primary key for stable row identification.`,
    );
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // FOR UPDATE serializes concurrent rotations of the same column only.
    const keyRow = await client.query(
      `SELECT id, encrypted_key FROM agent_keys
       WHERE table_name = $1 AND column_name = $2
       FOR UPDATE`,
      [tableName, columnName],
    );
    if (keyRow.rows.length === 0) {
      await client.query('ROLLBACK');
      throw new Error(
        `No agent_keys entry for "${tableName}"."${columnName}". ` +
          `Call registerColumn() before rotating.`,
      );
    }
    const agentKeyId: string = keyRow.rows[0].id;
    const currentWrappedKey: Buffer = keyRow.rows[0].encrypted_key;

    let oldColumnKey: Buffer;
    try {
      oldColumnKey = unwrapColumnKey(currentWrappedKey, masterKey);
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('unwrap-old-key', err);
    }

    const newColumnKey = generateColumnKey();

    // Wrap before the row loop so a wrap failure rolls back before any data changes.
    let newWrappedKey: Buffer;
    try {
      newWrappedKey = wrapColumnKey(newColumnKey, masterKey);
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('wrap-new-key', err);
    }

    // Re-encrypt all rows in-place. agent_keys is updated last so failures leave
    // the column readable under the old key.
    const pkSelect = pkColumns.map((c) => `"${c}"`).join(', ');
    const rows = await client.query(`SELECT ${pkSelect}, "${columnName}" FROM "${tableName}"`);

    const pkWhere = pkColumns.map((c, i) => `"${c}" = $${i + 2}`).join(' AND ');
    let rowsReencrypted = 0;

    for (const row of rows.rows) {
      const rawCiphertext: Buffer = row[columnName];

      let plainValue: unknown;
      try {
        plainValue = decrypt(rawCiphertext, oldColumnKey);
      } catch (err) {
        await client.query('ROLLBACK');
        throw new KeyRotationFailedError('decrypt-row', err);
      }

      let newCiphertext: Buffer;
      try {
        newCiphertext = encrypt(plainValue, newColumnKey);
      } catch (err) {
        await client.query('ROLLBACK');
        throw new KeyRotationFailedError('encrypt-row', err);
      }

      const pkValues = pkColumns.map((c) => row[c]);
      await client.query(`UPDATE "${tableName}" SET "${columnName}" = $1 WHERE ${pkWhere}`, [
        newCiphertext,
        ...pkValues,
      ]);
      rowsReencrypted++;
    }

    try {
      await client.query(
        `UPDATE agent_keys SET encrypted_key = $1, rotated_at = NOW()
         WHERE id = $2`,
        [newWrappedKey, agentKeyId],
      );
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('update-agent-keys', err);
    }

    const rotatedAt = new Date();
    try {
      await client.query(
        `INSERT INTO agent_audit
         (id, timestamp, agent_did, owner_did, credential_id, query_hash,
          columns_accessed, row_count, duration_ms, previous_hash, signature,
          org_id, version, status, reason, reason_code)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [
          uuidv4(),
          rotatedAt.toISOString(),
          agentDid,
          agentDid,
          'key-rotation',
          `column_key_rotation:${tableName}.${columnName}`,
          JSON.stringify([`${tableName}.${columnName}`]),
          rowsReencrypted,
          0,
          'GENESIS', // rotation events are not chained into the query audit chain
          'unsigned',
          null,
          2,
          'success',
          `column_key_rotation:${tableName}.${columnName}:${rowsReencrypted} rows`,
          'COLUMN_KEY_ROTATION',
        ],
      );
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('audit-append', err);
    }

    await client.query('COMMIT');
    return { rotatedAt, rowsReencrypted };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      /* ignore double-rollback */
    }
    throw err;
  } finally {
    client.release();
  }
}

// ─── Key Rewrap ─────────────────────────────────────────────────────

/**
 * Re-wrap a column key under a new master key (BYOK master-key rotation).
 * Row ciphertext is unchanged; only `agent_keys.encrypted_key` is updated.
 * Failure leaves the column on its old wrapped key.
 *
 * @throws KeyRotationFailedError with phase in:
 *   'unwrap-old-key' | 'wrap-new-key' | 'update-agent-keys' | 'audit-append'
 */
export async function rewrapColumnKey(opts: {
  pool: Pool;
  /** DID of the agent / human authorizing this rewrap — recorded in agent_audit. */
  agentDid: string;
  tableName: string;
  columnName: string;
  /** Master key currently wrapping the column key. */
  oldMasterKey: MasterKey;
  /** New master key to wrap the column key under. */
  newMasterKey: MasterKey;
}): Promise<{ rewrappedAt: Date }> {
  const { pool, agentDid, tableName, columnName, oldMasterKey, newMasterKey } = opts;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // FOR UPDATE serializes concurrent rewraps of the same column.
    const keyRow = await client.query(
      `SELECT id, encrypted_key FROM agent_keys
       WHERE table_name = $1 AND column_name = $2
       FOR UPDATE`,
      [tableName, columnName],
    );
    if (keyRow.rows.length === 0) {
      await client.query('ROLLBACK');
      throw new Error(
        `No agent_keys entry for "${tableName}"."${columnName}". ` +
          `Call registerColumn() before rewrapping.`,
      );
    }
    const agentKeyId: string = keyRow.rows[0].id;
    const currentWrappedKey: Buffer = keyRow.rows[0].encrypted_key;

    let columnKey: Buffer;
    try {
      columnKey = unwrapColumnKey(currentWrappedKey, oldMasterKey);
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('unwrap-old-key', err);
    }

    let newWrappedKey: Buffer;
    try {
      newWrappedKey = wrapColumnKey(columnKey, newMasterKey);
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('wrap-new-key', err);
    }

    try {
      await client.query(
        `UPDATE agent_keys SET encrypted_key = $1, rotated_at = NOW()
         WHERE id = $2`,
        [newWrappedKey, agentKeyId],
      );
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('update-agent-keys', err);
    }

    const rewrappedAt = new Date();
    try {
      await client.query(
        `INSERT INTO agent_audit
         (id, timestamp, agent_did, owner_did, credential_id, query_hash,
          columns_accessed, row_count, duration_ms, previous_hash, signature,
          org_id, version, status, reason, reason_code)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [
          uuidv4(),
          rewrappedAt.toISOString(),
          agentDid,
          agentDid,
          'key-rewrap',
          `column_key_rewrap:${tableName}.${columnName}`,
          JSON.stringify([`${tableName}.${columnName}`]),
          0, // no rows affected — data is unchanged
          0,
          'GENESIS',
          'unsigned',
          null,
          2,
          'success',
          `column_key_rewrap:${tableName}.${columnName}`,
          'COLUMN_KEY_REWRAP',
        ],
      );
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyRotationFailedError('audit-append', err);
    }

    await client.query('COMMIT');
    return { rewrappedAt };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      /* ignore double-rollback */
    }
    throw err;
  } finally {
    client.release();
  }
}

// ─── Migration Verification ─────────────────────────────────────────

/**
 * Diagnostic helper for BYOK master-key migration: verify that every column key
 * in `agent_keys` can be unwrapped by the supplied master key.
 *
 * Read-only. Returns `{ ok, failed }` — never throws on per-row failure.
 * Pass the OLD key before rewrapping, the NEW key after, to confirm all rows
 * transitioned. Schema-missing → `{ ok: 0, failed: [] }` (SQLSTATE 42P01 only).
 *
 * @param pool — `pg.Pool` against the database holding the `agent_keys` table.
 * @param masterKey — the candidate master key to test.
 * @returns `{ ok: number; failed: Array<{ table, col, error }> }`
 */
export async function verifyAllColumnKeys(
  pool: Pool,
  masterKey: MasterKey,
): Promise<{ ok: number; failed: Array<{ table: string; col: string; error: string }> }> {
  let result;
  try {
    result = await pool.query<{
      table_name: string;
      column_name: string;
      encrypted_key: Buffer;
    }>('SELECT table_name, column_name, encrypted_key FROM agent_keys');
  } catch (err) {
    if (isUndefinedTableError(err)) {
      return { ok: 0, failed: [] };
    }
    throw err;
  }

  let ok = 0;
  const failed: Array<{ table: string; col: string; error: string }> = [];

  for (const row of result.rows) {
    try {
      unwrapColumnKey(row.encrypted_key, masterKey);
      ok++;
    } catch (err) {
      failed.push({
        table: row.table_name,
        col: row.column_name,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { ok, failed };
}
