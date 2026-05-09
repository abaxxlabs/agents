/**
 * Test-app database setup for Agents++.
 *
 * This file intentionally duplicates only the small infrastructure subset a
 * consumer app must provide before using `AgentScope`: agent identity tables,
 * wrapped column-key storage, append-only audit storage, and durable revocation
 * state. Keeping that setup here makes the smoke app useful as integration
 * documentation rather than hiding the trust boundary behind parent test
 * helpers.
 *
 * Safety model: the selected database is disposable test infrastructure. The
 * smoke app drops and recreates Agents++ infrastructure tables on each run
 * because `AgentScope.create()` restores every persisted agent in those tables.
 * Stale rows encrypted under another run's master key would otherwise fail the
 * boot before the smoke app can exercise the current package.
 */
import pg from 'pg';
import {
  encrypt,
  generateColumnKey,
  wrapColumnKey,
  type MasterKey,
} from '@abaxxlabs/agents';

const { Pool } = pg;

export const DEFAULT_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/postgres';
export const TEST_TABLE = 'agents_plus_smoke_orders';
export const ENCRYPTED_COLUMNS = [
  `${TEST_TABLE}.notional`,
  `${TEST_TABLE}.counterparty`,
  `${TEST_TABLE}.strategy`,
];

export interface SeededOrder {
  desk: string;
  symbol: string;
  notional: string;
  counterparty: string;
  strategy: string;
}

export const SEEDED_ORDERS: SeededOrder[] = [
  {
    desk: 'North America',
    symbol: 'ABXX',
    notional: '1250000',
    counterparty: 'ALPHA-CAP',
    strategy: 'basis-arbitrage',
  },
  {
    desk: 'Europe',
    symbol: 'NGX',
    notional: '875000',
    counterparty: 'BETA-HEDGE',
    strategy: 'risk-transfer',
  },
];

const INFRASTRUCTURE_SQL = `
  CREATE EXTENSION IF NOT EXISTS pgcrypto;

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
    signature TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'success',
    reason TEXT,
    reason_code TEXT,
    org_id TEXT
  );

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

  CREATE TABLE IF NOT EXISTS revoked_credentials (
    jti TEXT NOT NULL,
    reason TEXT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (jti)
  );

  CREATE INDEX IF NOT EXISTS idx_revoked_expires
    ON revoked_credentials (expires_at)
    WHERE expires_at IS NOT NULL;
`;

/**
 * Create a short-lived setup pool.
 *
 * The smoke app lets `AgentScope` own its runtime pool, while setup uses a
 * separate pool so schema reset and scoped queries have clean lifecycles.
 */
export function createSetupPool(databaseUrl: string): pg.Pool {
  return new Pool({ connectionString: databaseUrl, max: 2 });
}

export async function resetSmokeDatabase(pool: pg.Pool): Promise<void> {
  await pool.query(`
    DROP TABLE IF EXISTS ${TEST_TABLE} CASCADE;
    DROP TABLE IF EXISTS agent_columns CASCADE;
    DROP TABLE IF EXISTS agent_keys CASCADE;
    DROP TABLE IF EXISTS agent_audit CASCADE;
    DROP TABLE IF EXISTS agents CASCADE;
    DROP TABLE IF EXISTS revoked_credentials CASCADE;
  `);
}

export async function ensureInfrastructure(pool: pg.Pool): Promise<void> {
  await pool.query(INFRASTRUCTURE_SQL);
}

/**
 * Reset this app's domain objects after infrastructure has been recreated.
 *
 * The table is dropped separately from `resetSmokeDatabase()` so the lifecycle
 * is clear in code: infrastructure reset first, then consumer-domain schema.
 */
export async function resetSmokeDomain(pool: pg.Pool): Promise<void> {
  await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE} CASCADE`);
  await pool.query(`
    CREATE TABLE ${TEST_TABLE} (
      id SERIAL PRIMARY KEY,
      desk TEXT NOT NULL,
      symbol TEXT NOT NULL,
      notional BYTEA NOT NULL,
      counterparty BYTEA NOT NULL,
      strategy BYTEA NOT NULL
    )
  `);
}

/**
 * Register and keep plaintext column keys in memory for seed encryption.
 *
 * Production apps would use library migration helpers or KMS-backed provisioning;
 * the smoke app is deliberately explicit so failures are easy to diagnose.
 */
export async function registerEncryptedColumns(
  pool: pg.Pool,
  masterKey: MasterKey,
): Promise<Map<string, Buffer>> {
  const keys = new Map<string, Buffer>();

  for (const tableColumn of ENCRYPTED_COLUMNS) {
    const [tableName, columnName] = tableColumn.split('.');
    const columnKey = generateColumnKey();
    keys.set(tableColumn, columnKey);

    await pool.query(
      `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
       VALUES ($1, $2, $3, $4)`,
      [tableName, columnName, wrapColumnKey(columnKey, masterKey), 'aes-256-gcm'],
    );
  }

  return keys;
}

export async function seedOrders(
  pool: pg.Pool,
  columnKeys: Map<string, Buffer>,
): Promise<void> {
  for (const order of SEEDED_ORDERS) {
    await pool.query(
      `INSERT INTO ${TEST_TABLE} (desk, symbol, notional, counterparty, strategy)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        order.desk,
        order.symbol,
        encrypt(order.notional, columnKeys.get(`${TEST_TABLE}.notional`)!),
        encrypt(order.counterparty, columnKeys.get(`${TEST_TABLE}.counterparty`)!),
        encrypt(order.strategy, columnKeys.get(`${TEST_TABLE}.strategy`)!),
      ],
    );
  }
}
