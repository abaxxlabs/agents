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
import {
  SANDBOX_CONTROL_PASSWORD_ENV,
  SANDBOX_QUERY_PASSWORD_ENV,
  SANDBOX_RAW_PASSWORD_ENV,
  setupSharedSandboxPool,
} from './shared-sandbox-bootstrap.mjs';
import { loadEnvFile, withoutEnvironmentEntry } from '../src/env-file.mjs';
import { VISITOR_SESSION_SCHEMA_SQL } from '../src/visitor-session-store.mjs';
import { canonicalMigrationsDir } from './migration-config.mjs';
import {
  DEFAULT_DATABASE_URL,
  PLAYGROUND_APP_ROLE,
  PLAYGROUND_NAIVE_PASSWORD_ENV,
  PLAYGROUND_NAIVE_ROLE,
  PLAYGROUND_OWNER,
  appendMissingEnvEntries,
  applyMigration,
  assertOwnershipClaimSafe,
  assertSetupPrivileges,
  claimPlaygroundDatabase,
  classifyEncryptionState,
  prepareMigrationTracking,
} from './setup-policy.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const PLAYGROUND_RUNTIME_DATABASE_URL_ENV = 'PLAYGROUND_RUNTIME_DATABASE_URL';
const PLAYGROUND_SHARED_DATABASE_URL_ENV = 'PLAYGROUND_SHARED_DATABASE_URL';

function quoteIdentifier(identifier) {
  return `"${identifier.replaceAll('"', '""')}"`;
}

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
const templateDatabaseName = decodeURIComponent(new URL(DATABASE_URL).pathname.slice(1));
if (!templateDatabaseName) {
  throw new Error('DATABASE_URL must name the Playground template database');
}
const sharedDatabaseName = `${templateDatabaseName}_shared`;
if (templateDatabaseName.length > 55) {
  throw new Error(
    `The Playground database name must be at most 55 characters so the derived shared and control ` +
    `databases fit PostgreSQL's 63-byte identifier limit.`,
  );
}
const configuredSharedUrl = process.env[PLAYGROUND_SHARED_DATABASE_URL_ENV];
if (configuredSharedUrl) {
  let configuredName;
  try {
    configuredName = decodeURIComponent(new URL(configuredSharedUrl).pathname.slice(1));
  } catch {
    throw new Error(
      `${PLAYGROUND_SHARED_DATABASE_URL_ENV} is not a valid PostgreSQL URL. ` +
      'Update or remove that entry, or use the documented full reset.',
    );
  }
  if (configuredName !== sharedDatabaseName) {
    throw new Error(
      `${PLAYGROUND_SHARED_DATABASE_URL_ENV} points to ${configuredName}, but setup provisions ${sharedDatabaseName}. ` +
      'Update or remove that entry, or use the documented full reset.',
    );
  }
}
const naiveDbPassword = process.env[PLAYGROUND_NAIVE_PASSWORD_ENV] || randomBytes(32).toString('base64url');
if (!/^[A-Za-z0-9_-]{32,128}$/.test(naiveDbPassword)) {
  throw new Error(`${PLAYGROUND_NAIVE_PASSWORD_ENV} must contain only base64url characters`);
}

if (!process.env.AGENTS_MASTER_KEY) {
  process.env.AGENTS_MASTER_KEY = randomBytes(32).toString('hex');
  console.log('✓ Master key generated for the Playground');
}
// Persist the master key before any encryption below: if a later step fails,
// the next run must be able to decrypt what this run already wrote.
let envContents = existingEnv;
function persistEnvironmentEntries(entries) {
  const nextEnv = appendMissingEnvEntries(envContents, entries);
  if (nextEnv === envContents) return;
  if (existsSync(envPath)) {
    appendFileSync(envPath, nextEnv.slice(envContents.length));
  } else {
    writeFileSync(envPath, nextEnv, { mode: 0o600 });
  }
  envContents = nextEnv;
  console.log(`✓ Missing configuration appended to ${envPath} without replacing its content`);
}
persistEnvironmentEntries({ AGENTS_MASTER_KEY: process.env.AGENTS_MASTER_KEY });
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
  [PLAYGROUND_NAIVE_PASSWORD_ENV]: naiveDbPassword,
  [PLAYGROUND_RUNTIME_DATABASE_URL_ENV]: runtimeDatabaseUrl.toString(),
};
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
// Existing databases predate the fixed fixture timestamp; align the column
// default before the truncate/reseed below so the public fixture and the
// per-request copy return the same created_at value.
await pool.query("ALTER TABLE orders_plaintext ALTER COLUMN created_at SET DEFAULT '2026-01-01T00:00:00Z'");

await configureRestrictedLoginRole(pool, PLAYGROUND_NAIVE_ROLE, naiveDbPassword);
await pool.query('ALTER TABLE orders_plaintext OWNER TO CURRENT_USER');
await pool.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`GRANT USAGE ON SCHEMA public TO ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`GRANT SELECT ON TABLE orders_plaintext TO ${PLAYGROUND_NAIVE_ROLE}`);
await pool.query(`
  DO $$
  BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO %I', current_database(), '${PLAYGROUND_NAIVE_ROLE}');
  END
  $$;
`);

await pool.query('TRUNCATE orders_plaintext RESTART IDENTITY');
await pool.query(ORDERS_PLAINTEXT_SEED);
await pool.query('ALTER TABLE orders_plaintext ALTER COLUMN created_at SET NOT NULL');
await pool.query('DROP FUNCTION IF EXISTS public.reset_orders_plaintext_sandbox()');
console.log('✓ "Without Agents++" world seeded (8 orders, SELECT-only role agents_playground_naive)');

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
await pool.query(`
  DO $$
  BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO ${PLAYGROUND_APP_ROLE}', current_database());
  END
  $$;
`);
console.log(`✓ Runtime role ${PLAYGROUND_APP_ROLE} configured with least-privilege table access`);

// Build the shared sandbox data plane. The plane owns its own schemas, roles
// and RLS policies; the REVOKE list above only touches public schema tables.
const sandboxPasswords = await setupSharedSandboxPool(pool, { masterKey });
persistEnvironmentEntries({ ...environmentEntries, ...sandboxPasswords });
console.log('✓ Shared sandbox data plane configured (4 restricted roles + RLS + protected fixture)');

await pool.end();

// Scoped reads use a separate copy of the fixture so they never share a
// connection budget with the direct-SQL pool.
const maintenanceUrl = new URL(DATABASE_URL);
maintenanceUrl.pathname = templateDatabaseName === 'postgres' ? '/template1' : '/postgres';
const maintenanceClient = new pg.Client({ connectionString: maintenanceUrl.toString() });
await maintenanceClient.connect();
try {
  const { rows: [identity] } = await maintenanceClient.query('SELECT current_user AS role');
  const { rows: [existing] } = await maintenanceClient.query(
    'SELECT pg_get_userbyid(datdba) AS owner, datistemplate FROM pg_database WHERE datname = $1',
    [sharedDatabaseName],
  );
  if (existing) {
    if (existing.owner !== identity.role || existing.datistemplate) {
      throw new Error(
        `Refusing to drop ${sharedDatabaseName}: it is not owned by the setup role or is a template database.`,
      );
    }
    const existingUrl = new URL(DATABASE_URL);
    existingUrl.pathname = `/${sharedDatabaseName}`;
    const existingClient = new pg.Client({ connectionString: existingUrl.toString() });
    await existingClient.connect();
    try {
      const { rows: [metadata] } = await existingClient.query(
        "SELECT to_regclass('public.demo_playground_metadata') IS NOT NULL AS has_metadata",
      );
      if (!metadata.has_metadata) {
        throw new Error(`Refusing to drop ${sharedDatabaseName}: it is not claimed by the Playground.`);
      }
      const { rows: [marker] } = await existingClient.query(
        'SELECT value FROM public.demo_playground_metadata WHERE key = $1',
        ['owner'],
      );
      if (marker?.value !== PLAYGROUND_OWNER) {
        throw new Error(`Refusing to drop ${sharedDatabaseName}: it is not claimed by the Playground.`);
      }
    } finally {
      await existingClient.end();
    }
  }
  await maintenanceClient.query(`DROP DATABASE IF EXISTS ${quoteIdentifier(sharedDatabaseName)} WITH (FORCE)`);
  await maintenanceClient.query(
    `CREATE DATABASE ${quoteIdentifier(sharedDatabaseName)} TEMPLATE ${quoteIdentifier(templateDatabaseName)}`,
  );
  await maintenanceClient.query(`REVOKE CONNECT ON DATABASE ${quoteIdentifier(sharedDatabaseName)} FROM PUBLIC`);
  await maintenanceClient.query(`REVOKE TEMPORARY ON DATABASE ${quoteIdentifier(sharedDatabaseName)} FROM PUBLIC`);
  await maintenanceClient.query(
    `GRANT CONNECT ON DATABASE ${quoteIdentifier(sharedDatabaseName)} TO ${PLAYGROUND_APP_ROLE}`,
  );
  await maintenanceClient.query(
    `GRANT CONNECT ON DATABASE ${quoteIdentifier(sharedDatabaseName)} TO ${PLAYGROUND_NAIVE_ROLE}`,
  );
  await maintenanceClient.query(
    `GRANT TEMPORARY ON DATABASE ${quoteIdentifier(sharedDatabaseName)} TO ${PLAYGROUND_NAIVE_ROLE}`,
  );
} finally {
  await maintenanceClient.end();
}
const sharedDatabaseUrl = new URL(runtimeDatabaseUrl);
sharedDatabaseUrl.pathname = `/${sharedDatabaseName}`;
const sharedAdminUrl = new URL(DATABASE_URL);
sharedAdminUrl.pathname = `/${sharedDatabaseName}`;
const sharedFixtureClient = new pg.Client({ connectionString: sharedAdminUrl.toString() });
await sharedFixtureClient.connect();
try {
  await sharedFixtureClient.query(`REVOKE INSERT ON TABLE agents, agent_audit FROM ${PLAYGROUND_APP_ROLE}`);
} finally {
  await sharedFixtureClient.end();
}
persistEnvironmentEntries({ [PLAYGROUND_SHARED_DATABASE_URL_ENV]: sharedDatabaseUrl.toString() });
console.log(`✓ Shared read-only fixture database ${sharedDatabaseName} rebuilt for scoped reads`);

// Admission state lives in a separate control database so the runtime database
// never needs to be reachable from the serving process.
const controlDatabaseName = `${templateDatabaseName}_control`;
const controlMaintenanceUrl = new URL(adminDatabaseUrl);
controlMaintenanceUrl.pathname = maintenanceUrl.pathname;
const controlMaintenanceClient = new pg.Client({ connectionString: controlMaintenanceUrl.toString() });
await controlMaintenanceClient.connect();
try {
  const { rows: [current] } = await controlMaintenanceClient.query('SELECT current_user AS role');
  const { rows: [existing] } = await controlMaintenanceClient.query(
    'SELECT pg_get_userbyid(datdba) AS owner, datistemplate FROM pg_database WHERE datname = $1',
    [controlDatabaseName],
  );
  if (existing) {
    if (existing.owner !== current.role || existing.datistemplate) {
      throw new Error(
        `Refusing to use ${controlDatabaseName}: it is not owned by the setup role or is a template database.`,
      );
    }
  } else {
    await controlMaintenanceClient.query(`CREATE DATABASE ${quoteIdentifier(controlDatabaseName)}`);
  }
} finally {
  await controlMaintenanceClient.end();
}
const controlDatabaseUrl = new URL(adminDatabaseUrl);
controlDatabaseUrl.pathname = `/${controlDatabaseName}`;
const controlClient = new pg.Client({ connectionString: controlDatabaseUrl.toString() });
await controlClient.connect();
try {
  const { rows: [metadata] } = await controlClient.query(
    "SELECT to_regclass('public.demo_playground_metadata') IS NOT NULL AS has_metadata",
  );
  let markerValue = null;
  if (metadata.has_metadata) {
    const { rows: [marker] } = await controlClient.query(
      'SELECT value FROM public.demo_playground_metadata WHERE key = $1',
      ['owner'],
    );
    markerValue = marker?.value ?? null;
  }
  if (markerValue !== PLAYGROUND_OWNER) {
    const { rows: businessTables } = await controlClient.query(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name IN ('orders', 'orders_plaintext')
      ORDER BY table_name
    `);
    assertOwnershipClaimSafe({
      markerValue,
      businessTables: businessTables.map((row) => row.table_name),
    });
    await controlClient.query(`
      CREATE TABLE IF NOT EXISTS demo_playground_metadata (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await controlClient.query(
      'INSERT INTO demo_playground_metadata (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
      ['owner', PLAYGROUND_OWNER],
    );
  }
  // Only touch privileges after the ownership marker or a safe empty database
  // has been confirmed, so an unrelated database with the same derived name
  // is rejected before its connections are affected.
  await controlClient.query(`REVOKE CONNECT ON DATABASE ${quoteIdentifier(controlDatabaseName)} FROM PUBLIC`);
  await controlClient.query(`REVOKE TEMPORARY ON DATABASE ${quoteIdentifier(controlDatabaseName)} FROM PUBLIC`);
  await controlClient.query(VISITOR_SESSION_SCHEMA_SQL);
  // The serving process reads and writes admission state with the same
  // restricted login as scoped reads; it must not need administrative rights.
  await controlClient.query(
    `GRANT CONNECT ON DATABASE ${quoteIdentifier(controlDatabaseName)} TO ${PLAYGROUND_APP_ROLE}`,
  );
  await controlClient.query(`GRANT USAGE ON SCHEMA public TO ${PLAYGROUND_APP_ROLE}`);
  await controlClient.query(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE playground_sandbox_session, playground_new_session_window ` +
    `TO ${PLAYGROUND_APP_ROLE}`,
  );
} finally {
  await controlClient.end();
}
console.log(`✓ Session admission database ${controlDatabaseName} ready`);

// The serving process no longer reads this key; prune stale copies so an
// upgraded volume stops handing administrative credentials to the runtime.
if (existsSync(envPath)) {
  const currentEnv = readFileSync(envPath, 'utf8');
  const pruned = withoutEnvironmentEntry(currentEnv, 'PLAYGROUND_ADMIN_DATABASE_URL');
  if (pruned !== currentEnv) {
    writeFileSync(envPath, pruned, { mode: 0o600 });
    console.log(`✓ Removed obsolete PLAYGROUND_ADMIN_DATABASE_URL from ${envPath}`);
  }
}

console.log('\nSetup complete. Run the demo with: npm start\n');
