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
 * CLI: agents init
 *
 * Initialize agents for a PostgreSQL database: creates infrastructure tables,
 * generates a master encryption key, optionally encrypts columns in-place,
 * and writes agents.config.json.
 */

import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { writeFileSync, existsSync } from 'node:fs';
import { encryptColumnInPlace } from '../sql/column-keys.js';
import { parseMasterKeyHex } from '../bootstrap/index.js';

const { Pool } = pg;

export interface InitOptions {
  db: string;
  abaxxOne?: string;
  clientId?: string;
  encryptColumns?: string;
  config?: string;
}

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS agents (
    did TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    encrypted_private_key BYTEA,
    public_key BYTEA,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS agent_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    encrypted_key BYTEA NOT NULL,
    algorithm TEXT DEFAULT 'aes-256-gcm',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    UNIQUE(table_name, column_name)
  );

  CREATE TABLE IF NOT EXISTS agent_columns (
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    key_id UUID REFERENCES agent_keys(id),
    original_type TEXT NOT NULL,
    is_encrypted BOOLEAN DEFAULT false,
    PRIMARY KEY (table_name, column_name)
  );

  CREATE TABLE IF NOT EXISTS agent_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    agent_did TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    columns_accessed JSONB NOT NULL,
    row_count INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT 'GENESIS',
    signature TEXT NOT NULL
  );

  -- Append-only enforcement — prevent UPDATE and DELETE on audit records
  CREATE OR REPLACE FUNCTION agent_audit_immutable()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION 'agent_audit is append-only: % not allowed', TG_OP;
  END;
  $$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS trg_audit_immutable ON agent_audit;
  CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE ON agent_audit
    FOR EACH ROW EXECUTE FUNCTION agent_audit_immutable();

  CREATE OR REPLACE FUNCTION agent_audit_no_truncate()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION 'agent_audit is append-only: TRUNCATE not allowed';
  END;
  $$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS trg_audit_no_truncate ON agent_audit;
  CREATE TRIGGER trg_audit_no_truncate
    BEFORE TRUNCATE ON agent_audit
    FOR EACH STATEMENT EXECUTE FUNCTION agent_audit_no_truncate();
`;

export async function runInit(options: InitOptions): Promise<void> {
  const configPath = options.config ?? 'agents.config.json';

  console.log('\n[agents] Initializing...\n');

  const pool = new Pool({ connectionString: options.db });
  try {
    await pool.query('SELECT 1');
    console.log(`  ✓ Connected to PostgreSQL`);
  } catch (err) {
    console.error(`  ✗ Cannot connect to PostgreSQL at ${options.db}`);
    console.error(`    ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  await pool.query(SCHEMA_SQL);
  console.log('  ✓ Created agents infrastructure tables (agents, keys, columns, audit)');

  const masterKeyHex =
    process.env.AGENTS_MASTER_KEY ?? randomBytes(32).toString('hex');

  const isNew = !process.env.AGENTS_MASTER_KEY;
  if (isNew) {
    console.log('  ✓ Generated new master key (32 bytes)');
    console.log('    Save this as AGENTS_MASTER_KEY environment variable.');
    // Write to file, not terminal — avoids key material in shell history/logs
    const keyFilePath = '.agents-master-key';
    writeFileSync(keyFilePath, masterKeyHex + '\n', { mode: 0o600 });
    console.log(`    Key written to: ${keyFilePath} (mode 0600 — read it, then delete the file)`);
  } else {
    console.log('  ✓ Using provided master key');
  }

  // parseMasterKeyHex enforces 64-hex-char format AND 32-byte length — closes the
  // silent-truncation footgun in Buffer.from(hex, 'hex') which drops unknown chars.
  let masterKey;
  try {
    masterKey = parseMasterKeyHex(masterKeyHex);
  } catch (err) {
    console.error(`[agents] ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
  const columnsToEncrypt = options.encryptColumns
    ? options.encryptColumns.split(',').map((c) => c.trim())
    : [];

  for (const col of columnsToEncrypt) {
    const [table, column] = col.split('.');
    if (!table || !column) {
      console.error(`  ✗ Invalid column format: "${col}" — expected table.column`);
      continue;
    }

    const existing = await pool.query(
      'SELECT 1 FROM agent_keys WHERE table_name = $1 AND column_name = $2',
      [table, column],
    );

    if (existing.rowCount && existing.rowCount > 0) {
      console.log(`  → ${col} already has an encryption key (skipping)`);
      continue;
    }

    try {
      const result = await encryptColumnInPlace(pool, masterKey, table, column);
      console.log(`  ✓ Encrypted ${col} (${result.rowsEncrypted} rows)`);
    } catch (err) {
      console.error(`  ✗ Failed to encrypt ${col}: ${err instanceof Error ? err.message : err}`);
    }
  }

  const config = {
    database: { connectionString: options.db },
    abaxxOne: {
      tenantUrl: options.abaxxOne ?? 'https://one.abaxx.tech',
      clientId: options.clientId ?? 'agents',
    },
    encryption: {
      columns: columnsToEncrypt,
    },
    audit: { enabled: true },
  };

  if (!existsSync(configPath)) {
    writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
    console.log(`  ✓ Wrote ${configPath}`);
  } else {
    console.log(`  → ${configPath} already exists (not overwriting)`);
  }

  console.log('\n[agents] Ready.\n');

  if (isNew) {
    console.log('  Next steps:');
    console.log('    export AGENTS_MASTER_KEY=$(cat .agents-master-key)');
    console.log('    rm .agents-master-key');
    if (columnsToEncrypt.length === 0) {
      console.log('    npx agents encrypt <table.column>');
    }
    console.log('');
  }

  await pool.end();
}
