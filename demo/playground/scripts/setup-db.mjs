#!/usr/bin/env node
/**
 * Initializes the Playground database with canonical migrations, encrypted
 * order data, and the disposable direct-SQL comparison table.
 */
import pg from 'pg';
import { appendFileSync, readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { encryptColumnInPlace } from '@abaxxlabs/agents/sql';
import { parseMasterKeyHex } from '@abaxxlabs/agents/bootstrap';
import { ORDERS_PLAINTEXT_DDL, ORDERS_PLAINTEXT_SEED } from '../src/demo-data.mjs';
import { adminDatabaseUrlEnvironmentEntry, loadEnvFile } from '../src/env-file.mjs';
import { canonicalMigrationsDir } from './migration-config.mjs';
import {
  DEFAULT_DATABASE_URL,
  PLAYGROUND_NAIVE_PASSWORD_ENV,
  PLAYGROUND_NAIVE_ROLE,
  appendMissingEnvEntries,
  applyMigration,
  assertSetupPrivileges,
  claimPlaygroundDatabase,
  classifyEncryptionState,
  prepareMigrationTracking,
} from './setup-policy.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const PLAYGROUND_APP_ROLE = 'agents_playground_app';
const PLAYGROUND_RUNTIME_DATABASE_URL_ENV = 'PLAYGROUND_RUNTIME_DATABASE_URL';

function databaseEndpoint(value) {
  const url = new URL(value);
  url.username = '';
  url.password = '';
  url.searchParams.delete('user');
  url.searchParams.delete('password');
  return url.toString();
}

async function configureRestrictedLoginRole(pool, role, password) {
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${role}') THEN
        CREATE ROLE ${role} LOGIN;
      END IF;
    END
    $$;
  `);
  await pool.query(
    `ALTER ROLE ${role} WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`,
  );
  await pool.query(`
    DO $$
    DECLARE granted_role RECORD;
    BEGIN
      FOR granted_role IN
        SELECT parent.rolname
        FROM pg_auth_members membership
        JOIN pg_roles parent ON parent.oid = membership.roleid
        JOIN pg_roles member ON member.oid = membership.member
        WHERE member.rolname = '${role}'
      LOOP
        EXECUTE format('REVOKE %I FROM ${role}', granted_role.rolname);
      END LOOP;
    END
    $$;
  `);
  await pool.query(`REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA pg_catalog FROM ${role}`);
  await pool.query(`REVOKE CREATE ON SCHEMA public FROM ${role}`);
}

const envPath = process.env.PLAYGROUND_ENV_FILE
  ? resolve(process.env.PLAYGROUND_ENV_FILE)
  : join(root, '.env');
const existingEnv = existsSync(envPath) ? readFileSync(envPath, 'utf8') : '';
loadEnvFile(envPath);

const DATABASE_URL = process.env.DATABASE_URL || DEFAULT_DATABASE_URL;
const adminDatabaseUrl = process.env.PLAYGROUND_ADMIN_DATABASE_URL ?? DATABASE_URL;
const naiveDbPassword = process.env[PLAYGROUND_NAIVE_PASSWORD_ENV] || randomBytes(32).toString('base64url');
if (!/^[A-Za-z0-9_-]{32,128}$/.test(naiveDbPassword)) {
  throw new Error(`${PLAYGROUND_NAIVE_PASSWORD_ENV} must contain only base64url characters`);
}

if (!process.env.AGENTS_MASTER_KEY) {
  process.env.AGENTS_MASTER_KEY = randomBytes(32).toString('hex');
  console.log('✓ Master key generated for the Playground');
}
const configuredRuntimeDatabaseUrl = process.env[PLAYGROUND_RUNTIME_DATABASE_URL_ENV];
if (configuredRuntimeDatabaseUrl && databaseEndpoint(configuredRuntimeDatabaseUrl) !== databaseEndpoint(DATABASE_URL)) {
  throw new Error(
    `${PLAYGROUND_RUNTIME_DATABASE_URL_ENV} targets a different database. ` +
    'Use the documented full reset before changing the Playground database endpoint.',
  );
}
const runtimeDatabaseUrl = new URL(DATABASE_URL);
const configuredAppDbPassword = configuredRuntimeDatabaseUrl
  ? decodeURIComponent(new URL(configuredRuntimeDatabaseUrl).password)
  : null;
runtimeDatabaseUrl.username = PLAYGROUND_APP_ROLE;
runtimeDatabaseUrl.password = configuredAppDbPassword || randomBytes(32).toString('base64url');
runtimeDatabaseUrl.searchParams.delete('user');
runtimeDatabaseUrl.searchParams.delete('password');
const appDbPassword = decodeURIComponent(runtimeDatabaseUrl.password);
if (runtimeDatabaseUrl.username !== PLAYGROUND_APP_ROLE || !/^[A-Za-z0-9_-]{32,128}$/.test(appDbPassword)) {
  throw new Error(
    `${PLAYGROUND_RUNTIME_DATABASE_URL_ENV} must use ${PLAYGROUND_APP_ROLE} with a base64url password`,
  );
}
const environmentEntries = {
  AGENTS_MASTER_KEY: process.env.AGENTS_MASTER_KEY,
  [PLAYGROUND_NAIVE_PASSWORD_ENV]: naiveDbPassword,
  [PLAYGROUND_RUNTIME_DATABASE_URL_ENV]: runtimeDatabaseUrl.toString(),
  ...adminDatabaseUrlEnvironmentEntry(existingEnv, adminDatabaseUrl),
};
const nextEnv = appendMissingEnvEntries(existingEnv, environmentEntries);
if (nextEnv !== existingEnv) {
  if (existsSync(envPath)) {
    appendFileSync(envPath, nextEnv.slice(existingEnv.length));
  } else {
    writeFileSync(envPath, nextEnv, { mode: 0o600 });
  }
  console.log(`✓ Missing configuration appended to ${envPath} without replacing its content`);
}
const masterKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY);

const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 2 });

// Fail early when the connection user cannot run the privileged DDL below.
await assertSetupPrivileges(pool);

// Claim the database before migrations or business-table changes.
await claimPlaygroundDatabase(pool);

// Apply canonical Agents++ migrations.
await prepareMigrationTracking(pool);
const migrationsDir = canonicalMigrationsDir(root);
const files = readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort();

let applied = 0;
for (const file of files) {
  const sql = readFileSync(join(migrationsDir, file), 'utf8');
  if (await applyMigration(pool, file, sql)) applied++;
}
console.log(applied > 0
  ? `✓ ${applied} Agents++ migrations applied (${files.length - applied} were already applied)`
  : `→ ${files.length} migrations already applied (skipped)`);

// Create and seed the protected order book.
await pool.query(`
  CREATE TABLE IF NOT EXISTS orders (
    id            SERIAL PRIMARY KEY,
    instrument    TEXT NOT NULL,
    side          TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
    quantity      NUMERIC NOT NULL,
    price         NUMERIC NOT NULL,
    counterparty  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'OPEN',
    created_at    TIMESTAMPTZ DEFAULT NOW()
  );
`);

const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM orders');
if (rows[0].n === 0) {
  await pool.query(`
    INSERT INTO orders (instrument, side, quantity, price, counterparty, status) VALUES
      ('LNG-JKM-SEP26',  'BUY',  500,  12.45, 'Meridian Energy',   'OPEN'),
      ('LNG-JKM-OCT26',  'SELL', 250,  12.80, 'Hokuto Gas',        'OPEN'),
      ('NG-HH-SEP26',    'BUY',  1000, 3.215, 'Gulf Coast Trading','FILLED'),
      ('EU-CARBON-DEC26','BUY',  750,  88.10, 'Alpenwerk AG',      'OPEN'),
      ('LNG-JKM-NOV26',  'SELL', 400,  13.05, 'Meridian Energy',   'OPEN'),
      ('NG-HH-OCT26',    'SELL', 600,  3.410, 'Iberdrola Trading', 'CANCELLED'),
      ('EU-CARBON-SEP26','BUY',  320,  86.75, 'Nordvik Kraft',     'OPEN'),
      ('LNG-JKM-DEC26',  'BUY',  150,  13.30, 'Hokuto Gas',        'OPEN');
  `);
  console.log('✓ Seed data loaded (8 orders)');
} else if (rows[0].n !== 8) {
  throw new Error(
    `The protected orders fixture has ${rows[0].n} rows instead of 8. ` +
    'The table was not modified; use the documented full reset to rebuild the demo fixture.',
  );
} else {
  console.log(`→ orders table already has ${rows[0].n} rows (seed skipped)`);
}

// Encrypt sensitive columns after the plaintext seed is present.
for (const col of ['price', 'counterparty']) {
  const { rows: [encryptionState] } = await pool.query(
    `SELECT
       c.data_type,
       k.id IS NOT NULL AS has_key,
       ac.table_name IS NOT NULL AS has_metadata,
       ac.is_encrypted AS metadata_encrypted,
       ac.key_id = k.id AS key_matches
     FROM information_schema.columns c
     LEFT JOIN agent_keys k ON k.table_name = c.table_name AND k.column_name = c.column_name
     LEFT JOIN agent_columns ac ON ac.table_name = c.table_name AND ac.column_name = c.column_name
     WHERE c.table_schema = 'public' AND c.table_name = $1 AND c.column_name = $2`,
    ['orders', col],
  );
  const state = classifyEncryptionState({
    dataType: encryptionState?.data_type,
    hasKey: encryptionState?.has_key ?? false,
    hasMetadata: encryptionState?.has_metadata ?? false,
    metadataEncrypted: encryptionState?.metadata_encrypted ?? null,
    keyMatches: encryptionState?.key_matches ?? false,
  });
  if (state === 'encrypted') {
    console.log(`→ orders.${col} already encrypted (skipped)`);
    continue;
  }
  if (state === 'inconsistent') {
    throw new Error(
      `Inconsistent encryption state for orders.${col}. The column was not modified. ` +
      'Recover the table, agent_keys and agent_columns from the same backup, or use a fresh dedicated database.',
    );
  }
  const result = await encryptColumnInPlace(pool, masterKey, 'orders', col);
  console.log(`✓ orders.${col} encrypted (${result.rowsEncrypted} rows, AES-256-GCM)`);
}

// The disposable direct-SQL table is isolated from protected orders.
await pool.query(ORDERS_PLAINTEXT_DDL);

await configureRestrictedLoginRole(pool, PLAYGROUND_NAIVE_ROLE, naiveDbPassword);
await pool.query('ALTER TABLE orders_plaintext OWNER TO CURRENT_USER');
await pool.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`GRANT USAGE ON SCHEMA public TO ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`GRANT SELECT, UPDATE, DELETE ON TABLE orders_plaintext TO ${PLAYGROUND_NAIVE_ROLE}`);

await pool.query('TRUNCATE orders_plaintext RESTART IDENTITY');
await pool.query(ORDERS_PLAINTEXT_SEED);
await pool.query(`
  CREATE OR REPLACE FUNCTION public.reset_orders_plaintext_sandbox()
  RETURNS void
  LANGUAGE sql
  SECURITY DEFINER
  SET search_path = pg_catalog
  AS $reset$
    TRUNCATE TABLE public.orders_plaintext RESTART IDENTITY;
    ${ORDERS_PLAINTEXT_SEED.replace('INSERT INTO orders_plaintext', 'INSERT INTO public.orders_plaintext')}
  $reset$
`);
await pool.query('REVOKE ALL ON FUNCTION public.reset_orders_plaintext_sandbox() FROM PUBLIC');
console.log('✓ "Without Agents++" world reset (8 orders + role agents_playground_naive)');

await pool.query(`
  REVOKE ALL PRIVILEGES ON TABLE
    agent_keys,
    agents,
    agent_columns,
    agent_audit,
    agent_context,
    agent_did_aliases,
    revoked_credentials,
    sessions,
    demo_migrations,
    demo_playground_metadata,
    orders,
    orders_plaintext
  FROM PUBLIC
`);
await pool.query('REVOKE ALL PRIVILEGES ON SEQUENCE orders_id_seq, orders_plaintext_id_seq FROM PUBLIC');

await configureRestrictedLoginRole(pool, PLAYGROUND_APP_ROLE, appDbPassword);
await pool.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${PLAYGROUND_APP_ROLE}`);
await pool.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${PLAYGROUND_APP_ROLE}`);
await pool.query(`GRANT USAGE ON SCHEMA public TO ${PLAYGROUND_APP_ROLE}`);
await pool.query(`
  GRANT SELECT ON TABLE
    agent_keys,
    agents,
    agent_audit,
    revoked_credentials,
    orders,
    orders_plaintext,
    demo_playground_metadata
  TO ${PLAYGROUND_APP_ROLE}
`);
await pool.query(`GRANT INSERT ON TABLE agents, agent_audit TO ${PLAYGROUND_APP_ROLE}`);
await pool.query(`GRANT EXECUTE ON FUNCTION public.reset_orders_plaintext_sandbox() TO ${PLAYGROUND_APP_ROLE}`);
await pool.query(`
  DO $$
  BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO ${PLAYGROUND_APP_ROLE}', current_database());
  END
  $$;
`);
console.log(`✓ Runtime role ${PLAYGROUND_APP_ROLE} configured with least-privilege table access`);

await pool.end();
console.log('\nSetup complete. Run the demo with: npm start\n');
