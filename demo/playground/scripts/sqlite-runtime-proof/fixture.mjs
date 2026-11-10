import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { asMasterKey } from '@abaxxlabs/agents';
import { encryptColumnInPlace } from '@abaxxlabs/agents/sql';
import { canonicalMigrationsDir } from '../migration-config.mjs';

const pool = new pg.Pool({ connectionString: process.env.PROOF_ADMIN_DATABASE_URL,
  max: 1, connectionTimeoutMillis: 3000, statement_timeout: 15000 });
const masterKey = Buffer.from(process.env.PROOF_MASTER_KEY ?? '', 'hex');
let stage = 'configuration';

try {
  if (masterKey.length !== 32 || !process.env.PROOF_ADMIN_DATABASE_URL) throw new Error('Missing fixture configuration');
  const passwords = [process.env.PROOF_QUERY_PASSWORD, process.env.PROOF_RAW_PASSWORD];
  if (passwords.some((value) => !/^[a-f0-9]{64}$/.test(value ?? ''))) throw new Error('Invalid role credentials');
  stage = 'fresh-database';
  const { rows: [state] } = await pool.query(`SELECT current_database() AS database,
    (SELECT count(*)::int FROM pg_tables WHERE schemaname = 'public') AS tables`);
  if (state.database !== 'runtime_proof' || state.tables !== 0) throw new Error('Fixture must use a fresh proof database');
  stage = 'canonical-migrations';
  const migrations = canonicalMigrationsDir(fileURLToPath(new URL('../..', import.meta.url)));
  const files = (await readdir(migrations)).filter((name) => /^\d+.*\.sql$/.test(name)).sort();
  if (!files.length) throw new Error('Missing canonical migrations');
  for (const file of files) await pool.query(await readFile(join(migrations, file), 'utf8'));
  stage = 'protected-fixture';
  await pool.query(`CREATE TABLE orders (
    id integer PRIMARY KEY, instrument text NOT NULL, quantity integer NOT NULL,
    price numeric NOT NULL, counterparty text NOT NULL
  );
  INSERT INTO orders VALUES (1, 'LNG', 10, 12.45, 'Example A'), (2, 'CARBON', 20, 88.1, 'Example B');
  CREATE TABLE orders_plaintext AS SELECT * FROM orders;`);
  for (const column of ['price', 'counterparty']) {
    await encryptColumnInPlace(pool, asMasterKey(masterKey), 'orders', column);
  }
  stage = 'restricted-roles';
  await pool.query(`REVOKE ALL ON SCHEMA public FROM PUBLIC;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
    REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
    CREATE ROLE proof_query LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[0]}';
    CREATE ROLE proof_raw LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[1]}';
    GRANT CONNECT ON DATABASE runtime_proof TO proof_query, proof_raw;
    GRANT USAGE ON SCHEMA public TO proof_query, proof_raw;
    GRANT SELECT ON orders, agent_keys, agent_columns TO proof_query;
    GRANT SELECT ON orders_plaintext TO proof_raw;`);
  console.log(`SQLITE_RUNTIME_PROOF ${JSON.stringify({ type: 'fixture', status: 'PASS',
    migrations: files, protectedRows: 2, encryptedColumns: 2, roles: ['proof_query', 'proof_raw'] })}`);
} catch (error) {
  console.log(`SQLITE_RUNTIME_PROOF ${JSON.stringify({ type: 'fixture', status: 'FAIL', stage,
    code: /^[0-9A-Z]{5}$/.test(error?.code ?? '') ? error.code : 'REDACTED' })}`);
  process.exitCode = 1;
} finally {
  masterKey.fill(0);
  await pool.end();
}
