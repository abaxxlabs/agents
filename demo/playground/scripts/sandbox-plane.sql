-- Shared sandbox data plane for the Playground.
--
-- This is the DDL half of the phase-1 shared plane (see the sandbox isolation
-- proof for the phase-0 reference it promotes). It is applied by
-- shared-sandbox-bootstrap.mjs AFTER the four restricted roles are created,
-- so the GRANT statements below can reference them. Roles and their passwords
-- are managed in JavaScript; this file owns schemas, tables, functions,
-- triggers, RLS policies and privilege grants.
--
-- Layout:
--   sandbox.orders            protected encrypted fixture, one copy for all visitors
--   sandbox.orders_plaintext  shared mutable rows, one set per sandbox, RLS-scoped
--   sandbox_private.*         control plane: registry, HMAC secret, context signer,
--                             sandbox-scoped seed/reset, integrity snapshot
--   sandbox_guard.*           RLS verifier + ownership/TRUNCATE guards + probe oracle
--
-- The context token is transaction-local (sandbox.token GUC) and signed by the
-- control role, bound to sandbox id, backend pid, transaction id and session
-- role. It cannot be forged by visitor SQL because the signing secret is only
-- reachable by the control role and the verifier re-checks every binding.

CREATE SCHEMA IF NOT EXISTS sandbox;
CREATE SCHEMA IF NOT EXISTS sandbox_private;
CREATE SCHEMA IF NOT EXISTS sandbox_guard;

-- HMAC for the context tokens comes from pgcrypto. The extension lives in
-- sandbox_private so the SECURITY DEFINER signers can call it with a
-- pg_catalog-only search_path (no widening, no hijackable names).
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA sandbox_private;

-- CREATE EXTENSION does not relocate a pgcrypto that already exists in another
-- schema, and sandbox_private.hmac below would then fail to resolve at runtime.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pgcrypto' AND n.nspname <> 'sandbox_private'
  ) THEN
    BEGIN
      ALTER EXTENSION pgcrypto SET SCHEMA sandbox_private;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'pgcrypto is in another schema and could not be moved to sandbox_private: %', SQLERRM;
    END;
  END IF;
END
$$;

-- Public has no default rights on this plane: no schema USAGE, no table access,
-- and no EXECUTE on any function, present or created later. The explicit
-- privilege surface at the bottom of this file re-grants exactly what each
-- restricted role needs, mirroring the phase-0 proof.
ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_ROLE REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
REVOKE ALL ON SCHEMA sandbox, sandbox_private, sandbox_guard FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA sandbox, sandbox_private, sandbox_guard FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA sandbox, sandbox_private, sandbox_guard FROM PUBLIC;

-- Protected fixture: identical encrypted rows for every visitor. The column
-- type stays NUMERIC until setup-db.mjs encrypts price/counterparty in place,
-- mirroring the existing public.orders bootstrap.
CREATE TABLE IF NOT EXISTS sandbox.orders (
  id            INTEGER PRIMARY KEY,
  instrument    TEXT NOT NULL,
  side          TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
  quantity      NUMERIC NOT NULL,
  price         NUMERIC NOT NULL,
  counterparty  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'OPEN',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Shared mutable comparison table. sandbox_id + id form the primary key so two
-- visitors keep identical local ids (1..8) while their rows stay distinct.
CREATE TABLE IF NOT EXISTS sandbox.orders_plaintext (
  sandbox_id    UUID NOT NULL,
  id            INTEGER NOT NULL,
  instrument    TEXT NOT NULL,
  side          TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
  quantity      NUMERIC NOT NULL,
  price         NUMERIC NOT NULL,
  counterparty  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'OPEN',
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (sandbox_id, id)
);

-- Control-plane state, reachable only by the control role.
CREATE TABLE IF NOT EXISTS sandbox_private.sandboxes (
  id     UUID PRIMARY KEY,
  marker TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sandbox_private.context_secret (
  secret BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS sandbox_private.delete_events (
  sequence   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sandbox_id UUID NOT NULL,
  id         INTEGER NOT NULL
);

-- Retention: the audit trail grows with every visitor DELETE and reset. The
-- index supports sandbox-scoped lookups and the purge below keeps only the
-- most recent 10000 rows; older events are dropped by
-- sandbox_private.purge_delete_events() (control role, run on demand).
CREATE INDEX IF NOT EXISTS delete_events_sandbox_id_idx ON sandbox_private.delete_events (sandbox_id);

CREATE OR REPLACE FUNCTION sandbox_private.purge_delete_events(keep_rows BIGINT DEFAULT 10000)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE removed INTEGER;
BEGIN
  DELETE FROM sandbox_private.delete_events
  WHERE sequence NOT IN (
    SELECT sequence FROM sandbox_private.delete_events ORDER BY sequence DESC LIMIT keep_rows
  );
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $body$;

-- The signer: only the control role may issue a context token. It verifies the
-- target role is one of the restricted executor roles, the sandbox is
-- registered, the transaction id is numeric, and the backend is alive with a
CREATE OR REPLACE FUNCTION sandbox_private.issue_context(
  sandbox UUID, backend INTEGER, transaction_id TEXT, target_role TEXT
)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE payload TEXT; signing_key BYTEA;
BEGIN
  IF target_role NOT IN (
       'agents_playground_sandbox_query',
       'agents_playground_sandbox_raw',
       'agents_playground_sandbox_control')
     OR NOT EXISTS (SELECT 1 FROM sandbox_private.sandboxes WHERE id = sandbox)
     OR transaction_id !~ '^[0-9]+$'
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity
           WHERE pid = backend AND usename = target_role
             AND datname = current_database()
             AND backend_xid::text = transaction_id) THEN
    RAISE EXCEPTION 'Invalid context target' USING ERRCODE = '42501';
  END IF;
  SELECT secret INTO STRICT signing_key FROM sandbox_private.context_secret;
  payload := sandbox::text || ':' || backend::text || ':' || transaction_id || ':' || target_role;
  RETURN payload || ':' || encode(
    sandbox_private.hmac(convert_to(payload, 'UTF8'), signing_key, 'sha256'::text), 'hex');
END $body$;

-- The verifier used by the RLS policy. Re-reads the token, re-checks every
-- binding and recomputes the HMAC. Any mismatch raises 42501 so the row filter
-- yields no rows and the resulting-row check rejects the write.
-- STABLE (not VOLATILE): the bindings it reads (pid, xid, session role, the
-- transaction-local token GUC) are all fixed for the duration of one
-- transaction, so the RLS policy can evaluate it once per statement.
CREATE OR REPLACE FUNCTION sandbox_guard.current_sandbox()
RETURNS UUID LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE token TEXT; parts TEXT[]; payload TEXT; signature TEXT; signing_key BYTEA; sandbox UUID;
BEGIN
  token := current_setting('sandbox.token', true);
  IF token IS NULL OR token = '' THEN
    RAISE EXCEPTION 'Missing sandbox context' USING ERRCODE = '42501';
  END IF;
  parts := string_to_array(token, ':');
  IF cardinality(parts) <> 5
     OR parts[2] <> pg_backend_pid()::text
     OR parts[3] <> txid_current()::text
     OR parts[4] <> session_user::text
     OR session_user NOT IN (
       'agents_playground_sandbox_query',
       'agents_playground_sandbox_raw',
       'agents_playground_sandbox_control') THEN
    RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
  END IF;
  payload := array_to_string(parts[1:4], ':');
  SELECT secret INTO STRICT signing_key FROM sandbox_private.context_secret;
  signature := encode(sandbox_private.hmac(convert_to(payload, 'UTF8'), signing_key, 'sha256'::text), 'hex');
  IF parts[5] IS DISTINCT FROM signature THEN
    RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
  END IF;
  BEGIN
    sandbox := parts[1]::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
  END;
  IF NOT EXISTS (SELECT 1 FROM sandbox_private.sandboxes WHERE id = sandbox) THEN
    RAISE EXCEPTION 'Unknown sandbox context' USING ERRCODE = '42501';
  END IF;
  RETURN sandbox;
END $body$;

-- Row-level ownership is immutable: visitor SQL cannot move a row to another
-- sandbox even when a column-level UPDATE grant is present.
CREATE OR REPLACE FUNCTION sandbox_guard.immutable_owner()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  IF NEW.sandbox_id IS DISTINCT FROM OLD.sandbox_id THEN
    RAISE EXCEPTION 'Sandbox ownership is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $body$;

DROP TRIGGER IF EXISTS immutable_sandbox_owner ON sandbox.orders_plaintext;
CREATE TRIGGER immutable_sandbox_owner
  BEFORE UPDATE ON sandbox.orders_plaintext
  FOR EACH ROW EXECUTE FUNCTION sandbox_guard.immutable_owner();

-- RLS does not cover TRUNCATE; a shared table must never be wiped wholesale.
CREATE OR REPLACE FUNCTION sandbox_private.forbid_truncate()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  RAISE EXCEPTION 'Shared sandbox TRUNCATE is forbidden' USING ERRCODE = '42501';
END $body$;

DROP TRIGGER IF EXISTS forbid_shared_truncate ON sandbox.orders_plaintext;
CREATE TRIGGER forbid_shared_truncate
  BEFORE TRUNCATE ON sandbox.orders_plaintext
  FOR EACH STATEMENT EXECUTE FUNCTION sandbox_private.forbid_truncate();

-- Audit trail of which rows a reset/visitor DELETE removed, for test evidence.
CREATE OR REPLACE FUNCTION sandbox_private.observe_delete()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  INSERT INTO sandbox_private.delete_events(sandbox_id, id) VALUES (OLD.sandbox_id, OLD.id);
  RETURN OLD;
END $body$;

DROP TRIGGER IF EXISTS observe_sandbox_delete ON sandbox.orders_plaintext;
CREATE TRIGGER observe_sandbox_delete
  AFTER DELETE ON sandbox.orders_plaintext
  FOR EACH ROW EXECUTE FUNCTION sandbox_private.observe_delete();

ALTER TABLE sandbox.orders_plaintext ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox.orders_plaintext FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sandbox_boundary ON sandbox.orders_plaintext;
CREATE POLICY sandbox_boundary ON sandbox.orders_plaintext
  USING (sandbox_id = sandbox_guard.current_sandbox())
  WITH CHECK (sandbox_id = sandbox_guard.current_sandbox());

-- The per-sandbox seed, applied by provision/reset. Values mirror the live
-- demo fixture so local ids and shape stay stable across visitors.
CREATE OR REPLACE FUNCTION sandbox_private.provision_sandbox(sandbox UUID)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  INSERT INTO sandbox_private.sandboxes(id, marker) VALUES (sandbox, 'sandbox')
    ON CONFLICT (id) DO NOTHING;
  INSERT INTO sandbox.orders_plaintext
    (sandbox_id, id, instrument, side, quantity, price, counterparty, status)
    SELECT sandbox, v.id, v.instrument, v.side, v.quantity, v.price, v.counterparty, v.status
    FROM (VALUES
      (1, 'LNG-JKM-SEP26',  'BUY',  500,  12.45,  'Meridian Energy',   'OPEN'),
      (2, 'LNG-JKM-OCT26',  'SELL', 250,  12.80,  'Hokuto Gas',        'OPEN'),
      (3, 'NG-HH-SEP26',    'BUY',  1000, 3.215,  'Gulf Coast Trading','FILLED'),
      (4, 'EU-CARBON-DEC26','BUY',  750,  88.10,  'Alpenwerk AG',      'OPEN'),
      (5, 'LNG-JKM-NOV26',  'SELL', 400,  13.05,  'Meridian Energy',   'OPEN'),
      (6, 'NG-HH-OCT26',    'SELL', 600,  3.410,  'Iberdrola Trading', 'CANCELLED'),
      (7, 'EU-CARBON-SEP26','BUY',  320,  86.75,  'Nordvik Kraft',     'OPEN'),
      (8, 'LNG-JKM-DEC26',  'BUY',  150,  13.30,  'Hokuto Gas',        'OPEN')
    ) AS v(id, instrument, side, quantity, price, counterparty, status)
    WHERE NOT EXISTS (SELECT 1 FROM sandbox.orders_plaintext WHERE sandbox_id = sandbox AND id = v.id);
END $body$;

-- Sandbox-scoped reset: removes and re-seeds only the caller's rows under the
-- registry row lock. Never TRUNCATEs the shared table.
CREATE OR REPLACE FUNCTION sandbox_private.reset_sandbox(sandbox UUID)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  PERFORM 1 FROM sandbox_private.sandboxes WHERE id = sandbox FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown sandbox' USING ERRCODE = '42501'; END IF;
  DELETE FROM sandbox.orders_plaintext WHERE sandbox_id = sandbox;
  INSERT INTO sandbox.orders_plaintext
    (sandbox_id, id, instrument, side, quantity, price, counterparty, status)
    SELECT sandbox, v.id, v.instrument, v.side, v.quantity, v.price, v.counterparty, v.status
    FROM (VALUES
      (1, 'LNG-JKM-SEP26',  'BUY',  500,  12.45,  'Meridian Energy',   'OPEN'),
      (2, 'LNG-JKM-OCT26',  'SELL', 250,  12.80,  'Hokuto Gas',        'OPEN'),
      (3, 'NG-HH-SEP26',    'BUY',  1000, 3.215,  'Gulf Coast Trading','FILLED'),
      (4, 'EU-CARBON-DEC26','BUY',  750,  88.10,  'Alpenwerk AG',      'OPEN'),
      (5, 'LNG-JKM-NOV26',  'SELL', 400,  13.05,  'Meridian Energy',   'OPEN'),
      (6, 'NG-HH-OCT26',    'SELL', 600,  3.410,  'Iberdrola Trading', 'CANCELLED'),
      (7, 'EU-CARBON-SEP26','BUY',  320,  86.75,  'Nordvik Kraft',     'OPEN'),
      (8, 'LNG-JKM-DEC26',  'BUY',  150,  13.30,  'Hokuto Gas',        'OPEN')
    ) AS v(id, instrument, side, quantity, price, counterparty, status);
END $body$;

-- Control-only integrity oracle the integration tests assert against.
CREATE OR REPLACE FUNCTION sandbox_private.snapshot()
RETURNS JSONB LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $body$
  SELECT jsonb_build_object(
    'orders', (SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM sandbox.orders o),
    'privateRows', coalesce((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.sandbox_id, o.id)
      FROM sandbox.orders_plaintext o), '[]'::jsonb),
    'deleteEvents', coalesce((SELECT jsonb_agg(jsonb_build_object('sandbox_id', e.sandbox_id,
      'id', e.id) ORDER BY e.sequence) FROM sandbox_private.delete_events e), '[]'::jsonb),
    'truncateGuardEnabled', EXISTS (SELECT 1 FROM pg_trigger
      WHERE tgrelid = 'sandbox.orders_plaintext'::regclass AND tgname = 'forbid_shared_truncate'
      AND tgenabled IN ('O', 'A')),
    'immutableOwnerEnabled', EXISTS (SELECT 1 FROM pg_trigger
      WHERE tgrelid = 'sandbox.orders_plaintext'::regclass AND tgname = 'immutable_sandbox_owner'
      AND tgenabled IN ('O', 'A')),
    'roles', (SELECT jsonb_agg(jsonb_build_object('name', r.rolname,
      'superuser', r.rolsuper, 'bypassRls', r.rolbypassrls, 'createDb', r.rolcreatedb,
      'createRole', r.rolcreaterole) ORDER BY r.rolname)
      FROM pg_roles r WHERE r.rolname IN (
        'agents_playground_sandbox_query', 'agents_playground_sandbox_raw',
        'agents_playground_sandbox_control', 'agents_playground_sandbox_probe')),
    'policies', (SELECT jsonb_agg(jsonb_build_object('name', p.polname,
      'table', c.relname, 'using', pg_get_expr(p.polqual, p.polrelid),
      'withCheck', pg_get_expr(p.polwithcheck, p.polrelid), 'forced', c.relforcerowsecurity,
      'enabled', c.relrowsecurity) ORDER BY p.polname)
      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
      WHERE p.polrelid = 'sandbox.orders_plaintext'::regclass),
    'fixtureFingerprint', (SELECT md5(
      (SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.id)::text, '') FROM sandbox.orders o)
    ))
  );
$body$;

-- WITH CHECK probe driven by the control role against the NOLOGIN probe role.
CREATE OR REPLACE FUNCTION sandbox_guard.probe_insert(own_sandbox UUID, other_sandbox UUID)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE rejected_state TEXT; inserted INTEGER; deleted INTEGER;
BEGIN
  BEGIN
    INSERT INTO sandbox.orders_plaintext
      (sandbox_id, id, instrument, side, quantity, price, counterparty)
      VALUES (other_sandbox, 90, 'PROBE', 'BUY', 1, 1, 'probe');
    RAISE EXCEPTION 'WITH CHECK failed to reject cross-sandbox INSERT';
  EXCEPTION WHEN insufficient_privilege THEN
    GET STACKED DIAGNOSTICS rejected_state = RETURNED_SQLSTATE;
  END;
  INSERT INTO sandbox.orders_plaintext
    (sandbox_id, id, instrument, side, quantity, price, counterparty)
    VALUES (own_sandbox, 90, 'PROBE', 'BUY', 1, 1, 'probe');
  GET DIAGNOSTICS inserted = ROW_COUNT;
  DELETE FROM sandbox.orders_plaintext WHERE sandbox_id = own_sandbox AND id = 90;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN jsonb_build_object('crossState', rejected_state, 'ownInsert', inserted = 1, 'ownDelete', deleted = 1);
END $body$;

ALTER FUNCTION sandbox_guard.probe_insert(UUID, UUID) OWNER TO agents_playground_sandbox_probe;

CREATE OR REPLACE FUNCTION sandbox_private.probe_with_check(own_sandbox UUID, other_sandbox UUID)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE token TEXT; previous_token TEXT; result JSONB;
BEGIN
  IF session_user <> 'agents_playground_sandbox_control' OR own_sandbox = other_sandbox
     OR NOT EXISTS (SELECT 1 FROM sandbox_private.sandboxes WHERE id = other_sandbox) THEN
    RAISE EXCEPTION 'Invalid probe context' USING ERRCODE = '42501';
  END IF;
  previous_token := current_setting('sandbox.token', true);
  token := sandbox_private.issue_context(own_sandbox, pg_backend_pid(), txid_current()::text, session_user::text);
  PERFORM set_config('sandbox.token', token, true);
  result := sandbox_guard.probe_insert(own_sandbox, other_sandbox);
  PERFORM set_config('sandbox.token', coalesce(previous_token, ''), true);
  RETURN result;
END $body$;

-- Privilege surface. Every visitor-facing role is NOINHERIT NOBYPASSRLS and is
-- never a table owner. The control role is the only one that can sign context,
-- reset or read the registry/secret. The legacy app/naive roles are granted no
-- USAGE on the sandbox schemas, so the fixture path and the shared plane cannot
-- reach each other's objects.
-- Strip the default EXECUTE (PUBLIC) off every function first; the grants
-- below re-enable exactly what each role needs. probe_insert is SECURITY
-- DEFINER owned by the NOLOGIN probe role and is only reached through
-- sandbox_private.probe_with_check (which runs as its owner), so it gets no
-- EXECUTE grant at all.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA sandbox, sandbox_private, sandbox_guard FROM PUBLIC;

GRANT USAGE ON SCHEMA sandbox TO agents_playground_sandbox_query, agents_playground_sandbox_raw, agents_playground_sandbox_probe;
GRANT USAGE ON SCHEMA sandbox_guard TO agents_playground_sandbox_query, agents_playground_sandbox_raw, agents_playground_sandbox_probe;
GRANT USAGE ON SCHEMA sandbox_private TO agents_playground_sandbox_control, agents_playground_sandbox_probe;

GRANT SELECT ON sandbox.orders, agent_keys, agent_columns TO agents_playground_sandbox_query;
GRANT SELECT, DELETE ON sandbox.orders_plaintext TO agents_playground_sandbox_raw;
GRANT UPDATE (instrument, side, quantity, price, counterparty, status) ON sandbox.orders_plaintext TO agents_playground_sandbox_raw;
GRANT SELECT, INSERT, DELETE ON sandbox.orders_plaintext TO agents_playground_sandbox_probe;
GRANT SELECT, INSERT, UPDATE, DELETE ON sandbox_private.sandboxes TO agents_playground_sandbox_control;

GRANT EXECUTE ON FUNCTION sandbox_guard.current_sandbox()
  TO agents_playground_sandbox_query, agents_playground_sandbox_raw, agents_playground_sandbox_probe;
GRANT EXECUTE ON FUNCTION sandbox_private.issue_context(UUID, INTEGER, TEXT, TEXT) TO agents_playground_sandbox_control;
GRANT EXECUTE ON FUNCTION sandbox_private.provision_sandbox(UUID) TO agents_playground_sandbox_control;
GRANT EXECUTE ON FUNCTION sandbox_private.reset_sandbox(UUID) TO agents_playground_sandbox_control;
GRANT EXECUTE ON FUNCTION sandbox_private.snapshot() TO agents_playground_sandbox_control;
GRANT EXECUTE ON FUNCTION sandbox_private.probe_with_check(UUID, UUID) TO agents_playground_sandbox_control;
GRANT EXECUTE ON FUNCTION sandbox_private.purge_delete_events(BIGINT) TO agents_playground_sandbox_control;
