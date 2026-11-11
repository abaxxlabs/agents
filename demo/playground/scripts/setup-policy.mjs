export const DEFAULT_DATABASE_URL = 'postgresql://postgres:postgres@localhost:54322/postgres';
export const PLAYGROUND_OWNER = 'agents-demo-playground';
export const PLAYGROUND_NAIVE_ROLE = 'agents_playground_naive';
export const PLAYGROUND_NAIVE_PASSWORD_ENV = 'PLAYGROUND_NAIVE_DB_PASSWORD';

const MIGRATION_LOCK = 'agents-demo-playground-migrations';
const OWNERSHIP_LOCK = 'agents-demo-playground-ownership';
const PRIVILEGE_PROBE_TABLE = 'agents_demo_playground_setup_probe';
const PRIVILEGE_PROBE_ROLE = 'agents_demo_playground_setup_probe_role';

export function appendMissingEnvEntries(contents, entries) {
  const configured = new Set();
  for (const line of contents.split('\n')) {
    const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.+)$/);
    if (match) configured.add(match[1]);
  }

  const additions = Object.entries(entries)
    .filter(([name]) => !configured.has(name))
    .map(([name, value]) => `${name}=${value}`);
  if (additions.length === 0) return contents;

  const separator = contents.length > 0 && !contents.endsWith('\n') ? '\n' : '';
  return `${contents}${separator}${additions.join('\n')}\n`;
}

export function assertMigrationBootstrapSafe({ hasTracking, hasCanonicalAgents }) {
  if (!hasTracking && hasCanonicalAgents) {
    throw new Error(
      'The database already contains the canonical agents table but not demo_migrations. ' +
      'It is not possible to infer which migrations were applied; use a fresh dedicated database for the Playground.',
    );
  }
}

export function assertOwnershipClaimSafe({ markerValue, businessTables }) {
  if (markerValue === PLAYGROUND_OWNER) return;
  if (markerValue !== null) {
    throw new Error(
      `The database has an unknown ownership marker (${markerValue}); use a fresh dedicated database.`,
    );
  }
  if (businessTables.length > 0) {
    throw new Error(
      `The database already contains ${businessTables.join(', ')} without the Playground marker. ` +
      'Foreign tables will not be modified; use a fresh dedicated database.',
    );
  }
}

export function classifyEncryptionState({ dataType, hasKey, hasMetadata, metadataEncrypted, keyMatches }) {
  if (dataType === 'bytea' && hasKey && hasMetadata && metadataEncrypted && keyMatches) {
    return 'encrypted';
  }
  if (dataType && dataType !== 'bytea' && !hasKey && !hasMetadata) {
    return 'plaintext';
  }
  return 'inconsistent';
}

async function withTransactionLock(pool, lockName, operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [lockName]);
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export async function prepareMigrationTracking(pool) {
  return withTransactionLock(pool, MIGRATION_LOCK, async (client) => {
    const { rows: [state] } = await client.query(`
      SELECT
        to_regclass('public.demo_migrations') IS NOT NULL AS has_tracking,
        to_regclass('public.agents') IS NOT NULL AS has_canonical_agents
    `);
    assertMigrationBootstrapSafe({
      hasTracking: state.has_tracking,
      hasCanonicalAgents: state.has_canonical_agents,
    });
    await client.query(`
      CREATE TABLE IF NOT EXISTS demo_migrations (
        name       TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  });
}

export async function applyMigration(pool, name, sql) {
  return withTransactionLock(pool, MIGRATION_LOCK, async (client) => {
    const { rowCount } = await client.query('SELECT 1 FROM demo_migrations WHERE name = $1', [name]);
    if (rowCount > 0) return false;
    await client.query(sql);
    await client.query('INSERT INTO demo_migrations (name) VALUES ($1)', [name]);
    return true;
  });
}

// Setup performs privileged DDL (role creation, password changes, table
// ownership transfer). Probe exactly those capabilities inside a
// rolled-back transaction so an unprivileged connection fails before any
// change is made, with a clear message.
export async function assertSetupPrivileges(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`CREATE TABLE ${PRIVILEGE_PROBE_TABLE} (probe INT)`);
    await client.query(`CREATE ROLE ${PRIVILEGE_PROBE_ROLE}`);
    // ALTER ROLE does not accept a parameterized password; the dummy value
    // is fixed and the whole probe transaction is rolled back.
    await client.query(`ALTER ROLE ${PRIVILEGE_PROBE_ROLE} WITH LOGIN PASSWORD 'agents-demo-setup-probe'`);
    await client.query(`ALTER TABLE ${PRIVILEGE_PROBE_TABLE} OWNER TO ${PRIVILEGE_PROBE_ROLE}`);
    await client.query('ROLLBACK');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw new Error(
      'The setup connection lacks a required database privilege and no changes were made. ' +
      `Failed probe: ${error.message}. ` +
      'Use a superuser, or a database owner able to create roles, set role passwords, and ' +
      'transfer table ownership (README: "External PostgreSQL with Compose").',
    );
  } finally {
    client.release();
  }
}

export async function claimPlaygroundDatabase(pool) {
  return withTransactionLock(pool, OWNERSHIP_LOCK, async (client) => {
    const { rows: [state] } = await client.query(`
      SELECT to_regclass('public.demo_playground_metadata') IS NOT NULL AS has_metadata
    `);
    let markerValue = null;
    if (state.has_metadata) {
      const marker = await client.query(
        'SELECT value FROM demo_playground_metadata WHERE key = $1',
        ['owner'],
      );
      markerValue = marker.rows[0]?.value ?? null;
    }

    if (markerValue !== PLAYGROUND_OWNER) {
      const { rows } = await client.query(`
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN ('orders', 'orders_plaintext')
        ORDER BY table_name
      `);
      assertOwnershipClaimSafe({
        markerValue,
        businessTables: rows.map((row) => row.table_name),
      });
    }

    await client.query(`
      CREATE TABLE IF NOT EXISTS demo_playground_metadata (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(
      'INSERT INTO demo_playground_metadata (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
      ['owner', PLAYGROUND_OWNER],
    );
  });
}
