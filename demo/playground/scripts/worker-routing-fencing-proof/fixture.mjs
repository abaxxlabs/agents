import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { asMasterKey } from '@abaxxlabs/agents';
import { encryptColumnInPlace } from '@abaxxlabs/agents/sql';
import { canonicalMigrationsDir } from '../migration-config.mjs';

const PREFIX = 'WORKER_ROUTING_FENCING_PROOF ';
const SANDBOX_A = '11111111-1111-4111-8111-111111111111';
const SANDBOX_B = '22222222-2222-4222-8222-222222222222';

const pool = new pg.Pool({ connectionString: process.env.ROUTING_ADMIN_URL,
  max: 1, connectionTimeoutMillis: 3000, statement_timeout: 30000 });
const masterKey = Buffer.from(process.env.ROUTING_MASTER_KEY ?? '', 'hex');
let stage = 'configuration';

try {
  if (!/^[a-f0-9]{64}$/.test(process.env.ROUTING_MASTER_KEY ?? '') || !process.env.ROUTING_ADMIN_URL) {
    throw new Error('Missing fixture configuration');
  }
  const passwords = ['QUERY', 'RAW', 'CONTROL'].map((role) => process.env[`ROUTING_${role}_PASSWORD`]);
  if (passwords.some((value) => !/^[a-f0-9]{64}$/.test(value ?? ''))) throw new Error('Invalid role credentials');

  stage = 'fresh-database';
  const { rows: [state] } = await pool.query(`SELECT current_database() AS database,
    (SELECT count(*)::int FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public', 'information_schema')) AS schemas,
    (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public') AS objects`);
  if (state.database !== 'routing_proof' || state.schemas !== 0 || state.objects !== 0) {
    throw new Error('Fixture must use a fresh routing_proof database');
  }

  stage = 'canonical-migrations';
  const migrations = canonicalMigrationsDir(fileURLToPath(new URL('../..', import.meta.url)));
  const files = (await readdir(migrations)).filter((name) => /^\d+.*\.sql$/.test(name)).sort();
  if (!files.length) throw new Error('Missing canonical migrations');
  for (const file of files) await pool.query(await readFile(join(migrations, file), 'utf8'));

  stage = 'protected-fixture';
  // Common protected fixture (encrypted) + per-sandbox plaintext (RLS-gated).
  await pool.query(`CREATE TABLE public.orders (
    id integer PRIMARY KEY, instrument text NOT NULL, quantity integer NOT NULL,
    price numeric NOT NULL, counterparty text NOT NULL
  );
  INSERT INTO public.orders VALUES (1, 'LNG', 10, 12.45, 'Example A'), (2, 'CARBON', 20, 88.1, 'Example B');
  CREATE TABLE public.orders_plaintext (
    sandbox_id uuid NOT NULL,
    id integer NOT NULL, instrument text NOT NULL, quantity integer NOT NULL,
    price numeric NOT NULL, counterparty text NOT NULL,
    PRIMARY KEY (sandbox_id, id)
  );`);
  for (const column of ['price', 'counterparty']) {
    await encryptColumnInPlace(pool, asMasterKey(masterKey), 'orders', column);
  }

  stage = 'restricted-roles';
  // Three proof roles. The data-plane roles (query/raw) are what the 887 SDK
  // runtime and direct-SQL path connect as; control drives the catalog
  // lifecycle (janitor_sweep runs as a SECURITY DEFINER function it may call).
  await pool.query(`
    REVOKE ALL ON DATABASE routing_proof FROM PUBLIC;
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
    REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proof_query') THEN
        ALTER ROLE proof_query   LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[0]}';
      ELSE
        CREATE ROLE proof_query   LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[0]}';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proof_raw') THEN
        ALTER ROLE proof_raw     LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[1]}';
      ELSE
        CREATE ROLE proof_raw     LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[1]}';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proof_control') THEN
        ALTER ROLE proof_control LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[2]}';
      ELSE
        CREATE ROLE proof_control LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[2]}';
      END IF;
    END $$;
    GRANT CONNECT ON DATABASE routing_proof TO proof_query, proof_raw, proof_control;
    GRANT USAGE ON SCHEMA public TO proof_query, proof_raw, proof_control;
    GRANT SELECT ON public.orders, public.agent_keys, public.agent_columns TO proof_query;
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.orders_plaintext TO proof_raw;
    ALTER ROLE proof_query   SET search_path = pg_catalog, public;
    ALTER ROLE proof_raw     SET search_path = pg_catalog, public;
    ALTER ROLE proof_control SET search_path = pg_catalog;
  `);

  stage = 'session-catalog';
  // catalog.sql creates the proof_ctrl/proof_guard objects, the fencing,
  // lease, janitor and context functions, plus their grants.
  await pool.query(await readFile(join(fileURLToPath(new URL('.', import.meta.url)), 'catalog.sql'), 'utf8'));
  await pool.query('GRANT SELECT, UPDATE ON public.proof_sessions, public.proof_workers TO proof_control');

  stage = 'row-security-enable';
  // Data-plane RLS boundary (888 contract): the immutable-owner trigger and
  // the sandbox_boundary policy gate every orders_plaintext access.
  await pool.query(`
    CREATE TRIGGER immutable_sandbox_owner BEFORE UPDATE ON public.orders_plaintext
      FOR EACH ROW EXECUTE FUNCTION proof_guard.immutable_owner();
    ALTER TABLE public.orders_plaintext ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.orders_plaintext FORCE ROW LEVEL SECURITY;
    CREATE POLICY sandbox_boundary ON public.orders_plaintext
      USING (sandbox_id = proof_guard.current_sandbox())
      WITH CHECK (sandbox_id = proof_guard.current_sandbox());
  `);

  stage = 'seed-sandboxes';
  const signingKey = randomBytes(32);
  try {
    await pool.query('INSERT INTO proof_ctrl.context_secret VALUES (1, $1)', [signingKey]);
  } finally {
    signingKey.fill(0);
  }
  await pool.query('INSERT INTO public.proof_workers (worker_id) VALUES ($1), ($2) ON CONFLICT DO NOTHING', ['worker-a', 'worker-b']);
  await pool.query('SELECT proof_ctrl.seed_sandbox($1::uuid)', [SANDBOX_A]);
  await pool.query('SELECT proof_ctrl.seed_sandbox($1::uuid)', [SANDBOX_B]);

  const { rows: [{ sandboxrows }] } = await pool.query(
    'SELECT count(*)::int AS sandboxrows FROM public.orders_plaintext');
  if (sandboxrows !== 4) throw new Error(`Expected 4 sandbox rows, got ${sandboxrows}`);

  console.log(`${PREFIX}${JSON.stringify({ type: 'fixture', status: 'PASS',
    migrations: files, protectedRows: 2, sandboxes: 2, sandboxrows,
    roles: ['proof_query', 'proof_raw', 'proof_control'] })}`);
} catch (error) {
  console.log(`${PREFIX}${JSON.stringify({ type: 'fixture', status: 'FAIL', stage,
    code: /^[0-9A-Z]{5}$/.test(error?.code ?? '') ? error.code : 'REDACTED',
    message: error?.message ?? 'fixture failed' })}`);
  process.exitCode = 1;
} finally {
  masterKey.fill(0);
  await pool.end();
}
