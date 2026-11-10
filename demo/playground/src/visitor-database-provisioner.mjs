import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { logSafeError } from './safe-diagnostics.mjs';
import { PLAYGROUND_OWNER } from '../scripts/setup-policy.mjs';

const VISITOR_DATABASE_PREFIX = 'agents_playground_visitor_';
const VISITOR_DATABASE_NAME = /^agents_playground_visitor_[0-9a-f]{32}$/;
const TEMPLATE_DATABASE_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

function quoteIdentifier(identifier) {
  return `"${identifier.replaceAll('"', '""')}"`;
}

/** Provision and remove cloned Playground databases using a caller-owned administrative pool. */
export async function createVisitorDatabaseProvisioner({
  adminPool,
  adminDatabaseUrl,
  templateDatabaseName,
  appDatabaseUrl,
}) {
  const adminUrl = new URL(adminDatabaseUrl);
  const appUrl = new URL(appDatabaseUrl);
  if (!adminPool.options?.connectionString ||
    new URL(adminPool.options.connectionString).toString() !== adminUrl.toString()) {
    throw new Error('Administrative pool and URL must use the same connection string');
  }
  if (!TEMPLATE_DATABASE_NAME.test(templateDatabaseName) || VISITOR_DATABASE_NAME.test(templateDatabaseName)) {
    throw new Error('Invalid Playground template database name');
  }
  if (!adminUrl.pathname.slice(1) || adminUrl.pathname.slice(1) === templateDatabaseName ||
    VISITOR_DATABASE_NAME.test(adminUrl.pathname.slice(1))) {
    throw new Error('Administrative connection must use a separate maintenance database');
  }
  if (appUrl.username !== 'agents_playground_app' || appUrl.searchParams.has('user') || appUrl.searchParams.has('password')) {
    throw new Error('Application connection must use the restricted Playground role');
  }

  const { rows: [identity] } = await adminPool.query('SELECT current_user AS role');
  const adminRole = identity?.role;
  if (!adminRole) throw new Error('Cannot determine administrative database role');

  async function dropVisitorDatabase(databaseName) {
    if (typeof databaseName !== 'string' || !VISITOR_DATABASE_NAME.test(databaseName)) {
      throw new Error('Invalid Playground visitor database name');
    }

    const { rows: [database] } = await adminPool.query(
      `SELECT pg_get_userbyid(datdba) AS owner, datistemplate AS is_template
       FROM pg_database WHERE datname = $1`,
      [databaseName],
    );
    if (!database) throw new Error('Playground visitor database does not exist');
    if (database.owner !== adminRole || database.is_template) {
      throw new Error('Playground visitor database is not owned by the provisioner');
    }

    const inspectionUrl = new URL(adminUrl);
    inspectionUrl.pathname = `/${databaseName}`;
    const client = new pg.Client({ connectionString: inspectionUrl.toString() });
    try {
      await client.connect();
      const { rows: [marker] } = await client.query(
        'SELECT value FROM public.demo_playground_metadata WHERE key = $1',
        ['owner'],
      );
      if (marker?.value !== PLAYGROUND_OWNER) {
        throw new Error('Database is not claimed by the Playground');
      }
    } finally {
      await client.end();
    }

    const { rows: [connections] } = await adminPool.query(
      'SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname = $1',
      [databaseName],
    );
    if (connections.count !== 0) throw new Error('Playground visitor database still has open connections');
    await adminPool.query(`DROP DATABASE ${quoteIdentifier(databaseName)}`);
  }

  async function createVisitorDatabase() {
    const databaseName = `${VISITOR_DATABASE_PREFIX}${randomBytes(16).toString('hex')}`;
    let created = false;
    try {
      await adminPool.query(
        `CREATE DATABASE ${quoteIdentifier(databaseName)} TEMPLATE ${quoteIdentifier(templateDatabaseName)}`,
      );
      created = true;
      await adminPool.query(`REVOKE CONNECT ON DATABASE ${quoteIdentifier(databaseName)} FROM PUBLIC`);
      await adminPool.query(`GRANT CONNECT ON DATABASE ${quoteIdentifier(databaseName)} TO agents_playground_app`);
      await adminPool.query(`GRANT CONNECT ON DATABASE ${quoteIdentifier(databaseName)} TO agents_playground_naive`);

      const visitorUrl = new URL(appUrl);
      visitorUrl.pathname = `/${databaseName}`;
      return { databaseName, appDatabaseUrl: visitorUrl.toString() };
    } catch (err) {
      if (created) {
        try {
          await dropVisitorDatabase(databaseName);
        } catch (closeErr) {
          err.orphanedDatabaseName = databaseName;
          err.cleanupError = closeErr;
          logSafeError(console, 'error', 'Partially provisioned visitor database requires cleanup', closeErr, { databaseName });
        }
      }
      throw err;
    }
  }

  async function cleanupVisitorDatabases() {
    let rows;
    try {
      ({ rows } = await adminPool.query(
        `SELECT datname FROM pg_database
         WHERE left(datname, length($1)) = $1 AND datname <> $2
         ORDER BY datname`,
        [VISITOR_DATABASE_PREFIX, templateDatabaseName],
      ));
    } catch (error) {
      return { deleted: [], failed: [{ databaseName: null, error }] };
    }
    const candidates = rows.map(({ datname }) => datname).filter((databaseName) =>
      databaseName !== templateDatabaseName && VISITOR_DATABASE_NAME.test(databaseName));
    const results = await Promise.allSettled(candidates.map((databaseName) => dropVisitorDatabase(databaseName)));
    const deleted = [];
    const failures = [];

    for (const [index, result] of results.entries()) {
      const databaseName = candidates[index];
      if (result.status === 'fulfilled') {
        deleted.push(databaseName);
      } else {
        failures.push({ databaseName, error: result.reason });
      }
    }

    return { deleted, failed: failures };
  }

  return { createVisitorDatabase, dropVisitorDatabase, cleanupVisitorDatabases };
}
