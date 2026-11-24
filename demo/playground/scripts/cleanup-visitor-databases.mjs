#!/usr/bin/env node
/**
 * Inspect or drop Playground visitor databases left by the retired per-visitor
 * clone path. Dry run by default; pass --apply to drop eligible databases.
 */
import pg from 'pg';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadEnvFile } from '../src/env-file.mjs';
import { PLAYGROUND_OWNER } from './setup-policy.mjs';

export const VISITOR_DATABASE_NAME = /^agents_playground_visitor_[0-9a-f]{32}$/;
const VISITOR_DATABASE_PATTERN = '^agents_playground_visitor_[0-9a-f]{32}$';

function quoteIdentifier(identifier) {
  return `"${identifier.replaceAll('"', '""')}"`;
}

/** Decide whether a leftover visitor database is safe to drop. */
export function assessVisitorDatabase({ name, owner, isTemplate, marker, connections, adminRole }) {
  if (!VISITOR_DATABASE_NAME.test(name)) return { eligible: false, reason: 'name does not match the visitor pattern' };
  if (isTemplate) return { eligible: false, reason: 'database is marked as a template' };
  if (owner !== adminRole) return { eligible: false, reason: 'database is not owned by the setup role' };
  if (marker !== PLAYGROUND_OWNER) return { eligible: false, reason: 'Playground ownership marker is missing' };
  if (connections !== 0) return { eligible: false, reason: 'database still has open connections' };
  return { eligible: true };
}

async function inspectMarker(adminUrl, databaseName) {
  const target = new URL(adminUrl);
  target.pathname = `/${databaseName}`;
  const client = new pg.Client({ connectionString: target.toString() });
  try {
    await client.connect();
    const { rows: [table] } = await client.query(
      "SELECT to_regclass('public.demo_playground_metadata') IS NOT NULL AS has_marker",
    );
    if (!table?.has_marker) return null;
    const { rows: [marker] } = await client.query(
      'SELECT value FROM public.demo_playground_metadata WHERE key = $1',
      ['owner'],
    );
    return marker?.value ?? null;
  } finally {
    await client.end().catch(() => {});
  }
}

async function main() {
  const apply = process.argv.includes('--apply');
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const envPath = process.env.PLAYGROUND_ENV_FILE
    ? resolve(process.env.PLAYGROUND_ENV_FILE)
    : join(root, '.env');
  loadEnvFile(envPath);
  const adminValue = process.env.PLAYGROUND_ADMIN_DATABASE_URL ?? process.env.DATABASE_URL;
  if (!adminValue) throw new Error('DATABASE_URL or PLAYGROUND_ADMIN_DATABASE_URL is required');

  const adminUrl = new URL(adminValue);
  const maintenanceName = decodeURIComponent(adminUrl.pathname.slice(1)) === 'postgres' ? 'template1' : 'postgres';
  const maintenanceUrl = new URL(adminUrl);
  maintenanceUrl.pathname = `/${maintenanceName}`;
  const pool = new pg.Pool({ connectionString: maintenanceUrl.toString(), max: 1 });
  try {
    const { rows: [identity] } = await pool.query('SELECT current_user AS role');
    const adminRole = identity?.role;
    const { rows } = await pool.query(
      `SELECT datname AS name, pg_get_userbyid(datdba) AS owner, datistemplate
       FROM pg_database WHERE datname ~ $1 ORDER BY datname`,
      [VISITOR_DATABASE_PATTERN],
    );

    let wouldDrop = 0;
    let dropped = 0;
    let refused = 0;
    let failed = 0;
    for (const database of rows) {
      let marker;
      try {
        marker = await inspectMarker(adminUrl, database.name);
      } catch (err) {
        console.error(`skip ${database.name}: cannot inspect (${err.code ?? err.name})`);
        refused += 1;
        continue;
      }
      const { rows: [{ count: connections }] } = await pool.query(
        'SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname = $1',
        [database.name],
      );
      const verdict = assessVisitorDatabase({
        name: database.name,
        owner: database.owner,
        isTemplate: database.datistemplate,
        marker,
        connections,
        adminRole,
      });
      if (!verdict.eligible) {
        console.log(`skip ${database.name}: ${verdict.reason}`);
        refused += 1;
        continue;
      }
      if (!apply) {
        console.log(`would drop ${database.name}`);
        wouldDrop += 1;
        continue;
      }
      try {
        await pool.query(`DROP DATABASE ${quoteIdentifier(database.name)}`);
        console.log(`dropped ${database.name}`);
        dropped += 1;
      } catch (err) {
        console.error(`failed ${database.name}: ${err.code ?? 'unknown'}`);
        failed += 1;
      }
    }

    console.log(
      `${rows.length} candidate(s), ${wouldDrop} would drop, ${dropped} dropped, ` +
      `${refused} refused, ${failed} failed`,
    );
    if (apply && refused + failed > 0) process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
