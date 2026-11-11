import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { asMasterKey } from '@abaxxlabs/agents';
import { encryptColumnInPlace } from '@abaxxlabs/agents/sql';
import { canonicalMigrationsDir } from '../migration-config.mjs';

const sandboxA = '11111111-1111-4111-8111-111111111111';
const sandboxB = '22222222-2222-4222-8222-222222222222';
const masterKey = Buffer.from(process.env.ISOLATION_MASTER_KEY ?? '', 'hex');
const pool = new pg.Pool({ connectionString: process.env.ISOLATION_ADMIN_URL,
  max: 1, connectionTimeoutMillis: 3000, statement_timeout: 15000 });
let stage = 'configuration';

try {
  if (!/^[a-f0-9]{64}$/.test(process.env.ISOLATION_MASTER_KEY ?? '') || !process.env.ISOLATION_ADMIN_URL) {
    throw new Error('Missing fixture configuration');
  }
  const passwords = ['QUERY', 'RAW', 'CONTROL'].map((role) => process.env[`ISOLATION_${role}_PASSWORD`]);
  if (passwords.some((value) => !/^[a-f0-9]{64}$/.test(value ?? ''))) throw new Error('Invalid role credentials');
  stage = 'fresh-database';
  const { rows: [state] } = await pool.query(`SELECT current_database() AS database,
    (SELECT count(*)::int FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public', 'information_schema')) AS schemas,
    (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public') AS objects`);
  if (state.database !== 'sandbox_proof' || state.schemas !== 0 || state.objects !== 0) {
    throw new Error('Fixture must use a fresh proof database');
  }
  stage = 'canonical-migrations';
  const migrations = canonicalMigrationsDir(fileURLToPath(new URL('../..', import.meta.url)));
  const files = (await readdir(migrations)).filter((name) => /^\d+.*\.sql$/.test(name)).sort();
  if (!files.length) throw new Error('Missing canonical migrations');
  for (const file of files) await pool.query(await readFile(join(migrations, file), 'utf8'));
  stage = 'protected-fixture';
  await pool.query(`CREATE TABLE public.orders (
    id integer PRIMARY KEY, instrument text NOT NULL, quantity integer NOT NULL,
    price numeric NOT NULL, counterparty text NOT NULL
  );
  INSERT INTO public.orders VALUES (1, 'LNG', 10, 12.45, 'Example A'), (2, 'CARBON', 20, 88.1, 'Example B');
  CREATE SCHEMA proof_private;
  CREATE SCHEMA proof_guard;
  CREATE EXTENSION pgcrypto WITH SCHEMA proof_private;
  CREATE TABLE proof_private.sandboxes (id uuid PRIMARY KEY, marker text NOT NULL);
  INSERT INTO proof_private.sandboxes VALUES ('${sandboxA}', 'A-private'), ('${sandboxB}', 'B-private');
  CREATE TABLE proof_private.context_secret (secret bytea NOT NULL);
  CREATE TABLE proof_private.delete_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, sandbox_id uuid NOT NULL, id integer NOT NULL
  );
  CREATE TABLE public.orders_plaintext (
    sandbox_id uuid NOT NULL REFERENCES proof_private.sandboxes(id),
    id integer NOT NULL, instrument text NOT NULL, quantity integer NOT NULL,
    price numeric NOT NULL, counterparty text NOT NULL,
    PRIMARY KEY (sandbox_id, id)
  );
  INSERT INTO public.orders_plaintext
    SELECT s.id, o.id, o.instrument, o.quantity, o.price, s.marker
    FROM proof_private.sandboxes s CROSS JOIN public.orders o;`);
  const signingKey = randomBytes(32);
  try {
    await pool.query('INSERT INTO proof_private.context_secret VALUES ($1)', [signingKey]);
  } finally {
    signingKey.fill(0);
  }
  for (const column of ['price', 'counterparty']) {
    await encryptColumnInPlace(pool, asMasterKey(masterKey), 'orders', column);
  }
  stage = 'restricted-roles';
  await pool.query(`REVOKE ALL ON DATABASE sandbox_proof FROM PUBLIC;
    REVOKE ALL ON SCHEMA public, proof_private, proof_guard FROM PUBLIC;
    REVOKE ALL ON ALL TABLES IN SCHEMA public, proof_private FROM PUBLIC;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public, proof_private FROM PUBLIC;
    REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public, proof_private, proof_guard FROM PUBLIC;
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    CREATE ROLE proof_query LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[0]}';
    CREATE ROLE proof_raw LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[1]}';
    CREATE ROLE proof_control LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${passwords[2]}';
    CREATE ROLE proof_probe NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT CONNECT ON DATABASE sandbox_proof TO proof_query, proof_raw, proof_control;
    GRANT USAGE ON SCHEMA public TO proof_query, proof_raw, proof_probe;
    GRANT USAGE ON SCHEMA proof_guard TO proof_query, proof_raw, proof_probe;
    GRANT USAGE ON SCHEMA proof_private TO proof_control;
    GRANT SELECT ON public.orders, public.agent_keys, public.agent_columns TO proof_query;
    GRANT SELECT, DELETE ON public.orders_plaintext TO proof_raw;
    GRANT UPDATE (instrument, quantity, price, counterparty) ON public.orders_plaintext TO proof_raw;
    GRANT SELECT, INSERT, DELETE ON public.orders_plaintext TO proof_probe;
    ALTER ROLE proof_query SET search_path = pg_catalog, public;
    ALTER ROLE proof_raw SET search_path = pg_catalog, public;
    ALTER ROLE proof_control SET search_path = pg_catalog;`);
  stage = 'signed-context';
  await pool.query(`CREATE FUNCTION proof_private.issue_context(sandbox uuid, backend integer, transaction_id text, target_role text)
    RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
    DECLARE payload text; signing_key bytea;
    BEGIN
      IF target_role NOT IN ('proof_query', 'proof_raw', 'proof_control') OR
         NOT EXISTS (SELECT 1 FROM proof_private.sandboxes WHERE id = sandbox) OR
         transaction_id !~ '^[0-9]+$' OR
         NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity
           WHERE pid = backend AND usename = target_role AND datname = current_database()
             AND backend_xid::text = transaction_id) THEN
        RAISE EXCEPTION 'Invalid context target' USING ERRCODE = '42501';
      END IF;
      SELECT secret INTO STRICT signing_key FROM proof_private.context_secret;
      payload := sandbox::text || ':' || backend::text || ':' || transaction_id || ':' || target_role;
      RETURN payload || ':' || encode(proof_private.hmac(convert_to(payload, 'UTF8'), signing_key, 'sha256'), 'hex');
    END $body$;
    CREATE FUNCTION proof_guard.current_sandbox()
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
    DECLARE token text; parts text[]; payload text; signature text; signing_key bytea; sandbox uuid;
    BEGIN
      token := current_setting('proof.sandbox_token', true);
      IF token IS NULL OR token = '' THEN
        RAISE EXCEPTION 'Missing sandbox context' USING ERRCODE = '42501';
      END IF;
      parts := string_to_array(token, ':');
      IF cardinality(parts) <> 5 OR parts[2] <> pg_backend_pid()::text OR
         parts[3] <> txid_current()::text OR parts[4] <> session_user::text OR
         session_user NOT IN ('proof_query', 'proof_raw', 'proof_control') THEN
        RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
      END IF;
      payload := array_to_string(parts[1:4], ':');
      SELECT secret INTO STRICT signing_key FROM proof_private.context_secret;
      signature := encode(proof_private.hmac(convert_to(payload, 'UTF8'), signing_key, 'sha256'), 'hex');
      IF parts[5] IS DISTINCT FROM signature THEN
        RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
      END IF;
      BEGIN
        sandbox := parts[1]::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
      END;
      IF NOT EXISTS (SELECT 1 FROM proof_private.sandboxes WHERE id = sandbox) THEN
        RAISE EXCEPTION 'Unknown sandbox context' USING ERRCODE = '42501';
      END IF;
      RETURN sandbox;
    END $body$;
    CREATE FUNCTION proof_guard.immutable_owner()
    RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
    BEGIN
      IF NEW.sandbox_id IS DISTINCT FROM OLD.sandbox_id THEN
        RAISE EXCEPTION 'Sandbox ownership is immutable' USING ERRCODE = '42501';
      END IF;
      RETURN NEW;
    END $body$;
    CREATE TRIGGER immutable_sandbox_owner BEFORE UPDATE ON public.orders_plaintext
      FOR EACH ROW EXECUTE FUNCTION proof_guard.immutable_owner();
    CREATE FUNCTION proof_private.observe_delete()
    RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
    BEGIN
      INSERT INTO proof_private.delete_events(sandbox_id, id) VALUES (OLD.sandbox_id, OLD.id);
      RETURN OLD;
    END $body$;
    CREATE TRIGGER observe_sandbox_delete AFTER DELETE ON public.orders_plaintext
      FOR EACH ROW EXECUTE FUNCTION proof_private.observe_delete();
    CREATE FUNCTION proof_private.forbid_truncate()
    RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
    BEGIN
      RAISE EXCEPTION 'Shared sandbox TRUNCATE is forbidden' USING ERRCODE = '42501';
    END $body$;
    CREATE TRIGGER forbid_shared_truncate BEFORE TRUNCATE ON public.orders_plaintext
      FOR EACH STATEMENT EXECUTE FUNCTION proof_private.forbid_truncate();
    ALTER TABLE public.orders_plaintext ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.orders_plaintext FORCE ROW LEVEL SECURITY;
    CREATE POLICY sandbox_boundary ON public.orders_plaintext
      USING (sandbox_id = proof_guard.current_sandbox())
      WITH CHECK (sandbox_id = proof_guard.current_sandbox());
    GRANT EXECUTE ON FUNCTION proof_guard.current_sandbox() TO proof_query, proof_raw, proof_probe;
    GRANT EXECUTE ON FUNCTION proof_private.issue_context(uuid, integer, text, text) TO proof_control;`);
  stage = 'scoped-control';
  await pool.query(`CREATE FUNCTION proof_private.reset_sandbox(sandbox uuid)
    RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
    BEGIN
      PERFORM 1 FROM proof_private.sandboxes WHERE id = sandbox FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'Unknown sandbox' USING ERRCODE = '42501'; END IF;
      DELETE FROM public.orders_plaintext WHERE sandbox_id = sandbox;
      INSERT INTO public.orders_plaintext
        SELECT s.id, v.id, v.instrument, v.quantity, v.price, s.marker
        FROM proof_private.sandboxes s CROSS JOIN
          (VALUES (1, 'LNG', 10, 12.45::numeric), (2, 'CARBON', 20, 88.1::numeric))
          AS v(id, instrument, quantity, price)
        WHERE s.id = sandbox;
    END $body$;
    CREATE FUNCTION proof_private.snapshot()
    RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $body$
      SELECT jsonb_build_object(
        'orders', (SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM public.orders o),
        'privateRows', coalesce((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.sandbox_id, o.id)
          FROM public.orders_plaintext o), '[]'::jsonb),
        'deleteEvents', coalesce((SELECT jsonb_agg(jsonb_build_object('sandbox_id', e.sandbox_id,
          'id', e.id) ORDER BY e.sequence) FROM proof_private.delete_events e), '[]'::jsonb),
        'truncateGuardEnabled', EXISTS (SELECT 1 FROM pg_trigger
          WHERE tgrelid = 'public.orders_plaintext'::regclass AND tgname = 'forbid_shared_truncate'
          AND tgenabled IN ('O', 'A') AND tgtype = 34),
        'roles', (SELECT jsonb_agg(jsonb_build_object('name', r.rolname,
          'superuser', r.rolsuper, 'bypassRls', r.rolbypassrls, 'createDb', r.rolcreatedb,
          'createRole', r.rolcreaterole, 'owner', EXISTS (SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relowner = r.oid
            AND n.nspname IN ('public', 'proof_private', 'proof_guard'))) ORDER BY r.rolname)
          FROM pg_roles r WHERE r.rolname IN ('proof_query', 'proof_raw', 'proof_control', 'proof_probe')),
        'policies', (SELECT jsonb_agg(jsonb_build_object('name', p.polname,
          'table', c.relname, 'using', pg_get_expr(p.polqual, p.polrelid),
          'withCheck', pg_get_expr(p.polwithcheck, p.polrelid), 'forced', c.relforcerowsecurity,
          'enabled', c.relrowsecurity) ORDER BY p.polname)
          FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
          WHERE p.polrelid = 'public.orders_plaintext'::regclass),
        'fixtureFingerprint', (SELECT encode(proof_private.digest(convert_to(
          jsonb_agg(to_jsonb(o) ORDER BY o.id)::text, 'UTF8'), 'sha256'), 'hex') FROM public.orders o)
      );
    $body$;
    GRANT EXECUTE ON FUNCTION proof_private.reset_sandbox(uuid), proof_private.snapshot() TO proof_control;`);
  stage = 'with-check-probe';
  await pool.query(`CREATE FUNCTION proof_guard.probe_insert(own_sandbox uuid, other_sandbox uuid)
    RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
    DECLARE rejected_state text; inserted integer; deleted integer;
    BEGIN
      BEGIN
        INSERT INTO public.orders_plaintext VALUES (other_sandbox, 90, 'PROBE', 1, 1, 'probe');
        RAISE EXCEPTION 'WITH CHECK failed to reject cross-sandbox INSERT';
      EXCEPTION WHEN insufficient_privilege THEN
        GET STACKED DIAGNOSTICS rejected_state = RETURNED_SQLSTATE;
      END;
      INSERT INTO public.orders_plaintext VALUES (own_sandbox, 90, 'PROBE', 1, 1, 'probe');
      GET DIAGNOSTICS inserted = ROW_COUNT;
      DELETE FROM public.orders_plaintext WHERE sandbox_id = own_sandbox AND id = 90;
      GET DIAGNOSTICS deleted = ROW_COUNT;
      RETURN jsonb_build_object('crossState', rejected_state, 'ownInsert', inserted = 1, 'ownDelete', deleted = 1);
    END $body$;
    ALTER FUNCTION proof_guard.probe_insert(uuid, uuid) OWNER TO proof_probe;
    CREATE FUNCTION proof_private.probe_with_check(own_sandbox uuid, other_sandbox uuid)
    RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
    DECLARE token text; previous_token text; result jsonb;
    BEGIN
      IF session_user <> 'proof_control' OR own_sandbox = other_sandbox OR
        NOT EXISTS (SELECT 1 FROM proof_private.sandboxes WHERE id = other_sandbox) THEN
        RAISE EXCEPTION 'Invalid probe context' USING ERRCODE = '42501';
      END IF;
      previous_token := current_setting('proof.sandbox_token', true);
      token := proof_private.issue_context(own_sandbox, pg_backend_pid(), txid_current()::text, session_user::text);
      PERFORM set_config('proof.sandbox_token', token, true);
      result := proof_guard.probe_insert(own_sandbox, other_sandbox);
      PERFORM set_config('proof.sandbox_token', coalesce(previous_token, ''), true);
      RETURN result;
    END $body$;
    GRANT EXECUTE ON FUNCTION proof_private.probe_with_check(uuid, uuid) TO proof_control;`);
  console.log(`SANDBOX_ISOLATION_PROOF ${JSON.stringify({ type: 'fixture', status: 'PASS',
    migrations: files, protectedRows: 2, sandboxes: 2, privateRows: 4,
    roles: ['proof_query', 'proof_raw', 'proof_control'], policyProbeRole: 'proof_probe' })}`);
} catch (error) {
  console.log(`SANDBOX_ISOLATION_PROOF ${JSON.stringify({ type: 'fixture', status: 'FAIL', stage,
    code: /^[0-9A-Z]{5}$/.test(error?.code ?? '') ? error.code : 'REDACTED' })}`);
  process.exitCode = 1;
} finally {
  masterKey.fill(0);
  await pool.end();
}
