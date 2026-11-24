/**
 * Bootstrap for the shared sandbox data plane: four restricted roles, the
 * RLS-protected sandbox schema, the HMAC context signer, the per-sandbox
 * seed/reset control functions, and the encrypted protected fixture.
 *
 * Runs after setup-db.mjs has built the shared and control databases, in the
 * same PostgreSQL server. Idempotent: safe to re-run on an already-provisioned
 * plane.
 */
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encrypt,
  generateColumnKey,
  wrapColumnKey,
} from '@abaxxlabs/agents';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const SANDBOX_QUERY_ROLE = 'agents_playground_sandbox_query';
export const SANDBOX_RAW_ROLE = 'agents_playground_sandbox_raw';
export const SANDBOX_CONTROL_ROLE = 'agents_playground_sandbox_control';
export const SANDBOX_PROBE_ROLE = 'agents_playground_sandbox_probe';
export const SANDBOX_QUERY_PASSWORD_ENV = 'PLAYGROUND_SANDBOX_QUERY_DB_PASSWORD';
export const SANDBOX_RAW_PASSWORD_ENV = 'PLAYGROUND_SANDBOX_RAW_DB_PASSWORD';
export const SANDBOX_CONTROL_PASSWORD_ENV = 'PLAYGROUND_SANDBOX_CONTROL_DB_PASSWORD';

// Logical key name for the protected fixture's encrypted columns. Kept
// distinct from the legacy 'orders' table so the shared (table_name,
// column_name) agent_keys primary key never collides between the two planes.
const PROTECTED_KEY_TABLE = 'sandbox_orders';

const PASSWORD_SHAPE = /^[A-Za-z0-9_-]{32,128}$/;

async function configureSandboxLoginRole(pool, role, password, { login }) {
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${role}') THEN
        ${login ? `CREATE ROLE ${role} LOGIN` : `CREATE ROLE ${role}`};
      END IF;
    END
    $$;
  `);
  await pool.query(
    `ALTER ROLE ${role} WITH ${login ? 'LOGIN ' : ''}NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`,
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

function columnEncryptionState(row) {
  if (!row) return 'missing';
  if (row.data_type === 'bytea' && row.has_key && row.has_metadata && row.metadata_encrypted && row.key_matches) {
    return 'encrypted';
  }
  if (!row.has_key && !row.has_metadata) {
    return 'cleartext';
  }
  return 'inconsistent';
}

async function encryptionState(pool, columnName) {
  const { rows: [state] } = await pool.query(
    `SELECT
       c.data_type,
       k.id IS NOT NULL AS has_key,
       ac.table_name IS NOT NULL AS has_metadata,
       ac.is_encrypted AS metadata_encrypted,
       ac.key_id = k.id AS key_matches
     FROM information_schema.columns c
     LEFT JOIN agent_keys k ON k.table_name = $2 AND k.column_name = c.column_name
     LEFT JOIN agent_columns ac ON ac.table_name = $2 AND ac.column_name = c.column_name
     WHERE c.table_schema = 'sandbox' AND c.table_name = 'orders' AND c.column_name = $1`,
    [columnName, PROTECTED_KEY_TABLE],
  );
  return columnEncryptionState(state);
}

/**
 * Encrypts one protected-fixture column in place with a transactional
 * temp-column swap. Registers a distinct agent_keys/agent_columns entry under
 * PROTECTED_KEY_TABLE so the legacy 'orders' keys are untouched. On any failure
 * the original cleartext column is restored by rollback.
 */
async function encryptProtectedColumn(pool, masterKey, columnName) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const typeResult = await client.query(
      "SELECT data_type FROM information_schema.columns WHERE table_schema = 'sandbox' AND table_name = 'orders' AND column_name = $1",
      [columnName],
    );
    const originalType = typeResult.rows[0]?.data_type;
    if (!originalType) throw new Error(`sandbox.orders.${columnName} not found`);
    if (originalType === 'bytea') throw new Error(`sandbox.orders.${columnName} is already bytea`);

    const columnKey = generateColumnKey();
    const wrappedKey = wrapColumnKey(columnKey, masterKey);
    const { rows: [keyRow] } = await client.query(
      `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
       VALUES ($1, $2, $3, 'aes-256-gcm')
       ON CONFLICT (table_name, column_name) DO NOTHING
       RETURNING id`,
      [PROTECTED_KEY_TABLE, columnName, wrappedKey],
    );
    if (!keyRow) throw new Error(`agent_keys already holds ${PROTECTED_KEY_TABLE}.${columnName}`);
    await client.query(
      `INSERT INTO agent_columns (table_name, column_name, key_id, original_type, is_encrypted)
       VALUES ($1, $2, $3, $4, true)
       ON CONFLICT (table_name, column_name) DO UPDATE SET is_encrypted = true, original_type = $4, key_id = $3`,
      [PROTECTED_KEY_TABLE, columnName, keyRow.id, originalType],
    );

    const tempCol = `_agentid_enc_${columnName}`;
    await client.query(`ALTER TABLE sandbox.orders ADD COLUMN "${tempCol}" BYTEA`);
    const { rows } = await client.query(`SELECT id, "${columnName}" AS value FROM sandbox.orders ORDER BY id`);
    for (const row of rows) {
      const encrypted = encrypt(row.value === null || row.value === undefined ? null : row.value, columnKey);
      await client.query(`UPDATE sandbox.orders SET "${tempCol}" = $1 WHERE id = $2`, [encrypted, row.id]);
    }
    await client.query(`ALTER TABLE sandbox.orders DROP COLUMN "${columnName}"`);
    await client.query(`ALTER TABLE sandbox.orders RENAME COLUMN "${tempCol}" TO "${columnName}"`);
    await client.query('COMMIT');
    return rows.length;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Builds the shared sandbox data plane in the connected database. The
 * connection must be able to create roles and schemas (the setup superuser).
 * @returns the role passwords so the caller can persist them to the env file.
 */
export async function setupSharedSandboxPool(pool, { masterKey } = {}) {
  const planeSql = readFileSync(join(__dirname, 'sandbox-plane.sql'), 'utf8');

  // Reuse a password already persisted in the env file so a re-run rotates the
  // DB roles in place instead of orphaning the credentials the app connects
  // with (setup-db.mjs loads the env into process.env before calling here).
  // The probe role is NOLOGIN and its password is never persisted, so it is
  // always freshly generated.
  const queryPassword = process.env[SANDBOX_QUERY_PASSWORD_ENV] || randomBytes(32).toString('base64url');
  const rawPassword = process.env[SANDBOX_RAW_PASSWORD_ENV] || randomBytes(32).toString('base64url');
  const controlPassword = process.env[SANDBOX_CONTROL_PASSWORD_ENV] || randomBytes(32).toString('base64url');
  const probePassword = randomBytes(32).toString('base64url');

  for (const [role, password, login] of [
    [SANDBOX_QUERY_ROLE, queryPassword, true],
    [SANDBOX_RAW_ROLE, rawPassword, true],
    [SANDBOX_CONTROL_ROLE, controlPassword, true],
    [SANDBOX_PROBE_ROLE, probePassword, false],
  ]) {
    if (!PASSWORD_SHAPE.test(password)) throw new Error(`Invalid password shape for ${role}`);
    await configureSandboxLoginRole(pool, role, password, { login });
  }

  await pool.query(planeSql);

  for (const [role, path] of [
    [SANDBOX_QUERY_ROLE, 'pg_catalog, sandbox, public'],
    [SANDBOX_RAW_ROLE, 'pg_catalog, sandbox'],
    [SANDBOX_PROBE_ROLE, 'pg_catalog, sandbox'],
    [SANDBOX_CONTROL_ROLE, 'pg_catalog'],
  ]) {
    await pool.query(`ALTER ROLE ${role} SET search_path = ${path}`);
  }

  // The HMAC signing secret for the context tokens. Inserted exactly once per
  // database; the buffer is zeroed after it reaches Postgres.
  const { rows: [secretState] } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM sandbox_private.context_secret',
  );
  if (secretState.n === 0) {
    const signingKey = randomBytes(32);
    try {
      await pool.query('INSERT INTO sandbox_private.context_secret VALUES ($1)', [signingKey]);
    } finally {
      signingKey.fill(0);
    }
  } else if (secretState.n !== 1) {
    throw new Error('sandbox_private.context_secret must hold exactly one row');
  }

  // Protected fixture: seed once, then encrypt in place. Re-runs detect the
  // already-encrypted state and skip, exactly like the legacy orders path.
  const { rows: [{ n: fixtureRows }] } = await pool.query('SELECT COUNT(*)::int AS n FROM sandbox.orders');
  if (fixtureRows === 0) {
    await pool.query(`
      INSERT INTO sandbox.orders (id, instrument, side, quantity, price, counterparty, status) VALUES
        (1, 'LNG-JKM-SEP26',  'BUY',  500,  12.45, 'Meridian Energy',   'OPEN'),
        (2, 'LNG-JKM-OCT26',  'SELL', 250,  12.80, 'Hokuto Gas',        'OPEN'),
        (3, 'NG-HH-SEP26',    'BUY',  1000, 3.215, 'Gulf Coast Trading','FILLED'),
        (4, 'EU-CARBON-DEC26','BUY',  750,  88.10, 'Alpenwerk AG',      'OPEN'),
        (5, 'LNG-JKM-NOV26',  'SELL', 400,  13.05, 'Meridian Energy',   'OPEN'),
        (6, 'NG-HH-OCT26',    'SELL', 600,  3.410, 'Iberdrola Trading', 'CANCELLED'),
        (7, 'EU-CARBON-SEP26','BUY',  320,  86.75, 'Nordvik Kraft',     'OPEN'),
        (8, 'LNG-JKM-DEC26',  'BUY',  150,  13.30, 'Hokuto Gas',        'OPEN');
    `);
  } else if (fixtureRows !== 8) {
    throw new Error(`The sandbox protected fixture has ${fixtureRows} rows instead of 8`);
  }
  if (masterKey) {
    for (const col of ['price', 'counterparty']) {
      const state = await encryptionState(pool, col);
      if (state === 'encrypted') continue;
      if (state === 'inconsistent') {
        throw new Error(
          `Inconsistent encryption state for sandbox.orders.${col}. ` +
          'The column was not modified; restore the table, agent_keys and agent_columns ' +
          'from the same backup, or use a fresh database.',
        );
      }
      await encryptProtectedColumn(pool, masterKey, col);
    }
  }

  return {
    [SANDBOX_QUERY_PASSWORD_ENV]: queryPassword,
    [SANDBOX_RAW_PASSWORD_ENV]: rawPassword,
    [SANDBOX_CONTROL_PASSWORD_ENV]: controlPassword,
  };
}

/**
 * Provisions one sandbox in an already-bootstrapped plane: registers it in the
 * control-plane registry and seeds its orders_plaintext rows. Uses a control
 * pool (a connection running as the control role).
 */
export async function provisionSandbox(controlPool, sandboxId) {
  await controlPool.query('SELECT sandbox_private.provision_sandbox($1::uuid)', [sandboxId]);
}

/**
 * Resets one sandbox to its seed rows. Uses a control pool.
 */
export async function resetSandbox(controlPool, sandboxId) {
  await controlPool.query('SELECT sandbox_private.reset_sandbox($1::uuid)', [sandboxId]);
}

/**
 * Control-role integrity snapshot for test evidence.
 */
export async function sandboxSnapshot(controlPool) {
  const { rows } = await controlPool.query('SELECT sandbox_private.snapshot() AS data');
  return rows[0]?.data;
}
