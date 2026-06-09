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
 * CLI: agents encrypt <table.column>
 *
 * Encrypt a column in-place:
 * 1. Generate a new AES-256-GCM column key
 * 2. Wrap it with the master key and store in agent_keys
 * 3. Read all rows, encrypt the column value, write back as bytea
 * 4. Register in agent_columns with original type metadata
 */

import pg from 'pg';
import { encryptColumnInPlace } from '#sql/column-keys.js';
import { loadConfig } from '#config.js';
import { parseMasterKeyHex } from '#bootstrap/index.js';

const { Pool } = pg;

export interface EncryptOptions {
  db?: string;
  config?: string;
}

export async function runEncrypt(tableColumn: string, options: EncryptOptions): Promise<void> {
  const [table, column] = tableColumn.split('.');
  if (!table || !column) {
    console.error(`[agents] Invalid format: "${tableColumn}" — expected table.column`);
    process.exit(1);
  }

  let connectionString = options.db;
  const masterKeyHex = process.env.AGENTS_MASTER_KEY;

  if (!connectionString && options.config) {
    const config = loadConfig(options.config);
    connectionString = config.database.connectionString;
  }

  if (!connectionString) {
    console.error('[agents] No database connection string. Use --db <url> or --config <path>.');
    process.exit(1);
  }

  if (!masterKeyHex) {
    console.error(
      '[agents] No master key. Set AGENTS_MASTER_KEY or pass --master-key-stdin with the key on stdin until EOF.',
    );
    process.exit(1);
  }

  let masterKey;
  try {
    masterKey = parseMasterKeyHex(masterKeyHex);
  } catch (err) {
    console.error(`[agents] ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  const pool = new Pool({ connectionString });

  try {
    await pool.query('SELECT 1');
  } catch (err) {
    console.error(
      `[agents] Cannot connect to PostgreSQL: ${err instanceof Error ? err.message : err}`,
    );
    process.exit(1);
  }

  const existing = await pool.query(
    'SELECT 1 FROM agent_keys WHERE table_name = $1 AND column_name = $2',
    [table, column],
  );

  if (existing.rowCount && existing.rowCount > 0) {
    console.error(`[agents] ${tableColumn} already has an encryption key.`);
    console.error('  To re-encrypt (key rotation), use: agents rotate <table.column>');
    await pool.end();
    process.exit(1);
  }

  const colInfo = await pool.query(
    `SELECT data_type FROM information_schema.columns
     WHERE table_name = $1 AND column_name = $2`,
    [table, column],
  );

  if (!colInfo.rows.length) {
    console.error(`[agents] Column ${tableColumn} not found in database.`);
    await pool.end();
    process.exit(1);
  }

  const originalType = colInfo.rows[0].data_type;
  console.log(`\n[agents] Encrypting ${tableColumn} (${originalType} → bytea)\n`);

  const result = await encryptColumnInPlace(pool, masterKey, table, column);
  console.log(`  ✓ Generated and stored column key`);
  console.log(`  ✓ Registered column metadata (original type: ${originalType})`);
  console.log(`  ✓ Encrypted ${result.rowsEncrypted} rows`);

  console.log(`\n[agents] Done. ${tableColumn} is now encrypted.\n`);

  await pool.end();
}
