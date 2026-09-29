#!/usr/bin/env node
/**
 * CI database setup — runs all migrations against the test Postgres instance.
 *
 * Used by .github/workflows/ci.yml before `npm run release:gate` so that
 * Postgres-gated tests (AgentScope hygiene, injection drift, session store,
 * multi-instance federation) find an initialised schema rather than skipping.
 *
 * Uses `pg` directly (already a prod dependency) so no extra tooling
 * (psql, supabase CLI) is required in the CI runner.
 */

import pg from 'pg';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(__dirname, '..', 'migrations');

const connectionString =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:5432/postgres';

const pool = new pg.Pool({ connectionString, max: 1 });

const files = readdirSync(migrationsDir)
  .filter(f => f.endsWith('.sql'))
  .sort();

for (const file of files) {
  process.stdout.write(`  migration: ${file} ... `);
  const sql = readFileSync(join(migrationsDir, file), 'utf8');
  await pool.query(sql);
  process.stdout.write('ok\n');
}

await pool.end();
console.log('Database setup complete.');
