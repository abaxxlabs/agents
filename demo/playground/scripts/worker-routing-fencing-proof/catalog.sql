-- Session catalog for the bounded worker routing/fencing proof.
-- Applied by fixture.mjs after the canonical migrations, on the fresh
-- routing_proof database. The roles (proof_query, proof_raw, proof_control)
-- exist before this script runs.

CREATE SCHEMA IF NOT EXISTS proof_ctrl;
CREATE SCHEMA IF NOT EXISTS proof_guard;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA proof_ctrl;
GRANT USAGE ON SCHEMA proof_ctrl, proof_guard TO proof_query, proof_raw, proof_control;

-- HMAC signing key for transaction-bound sandbox contexts (control-only).
CREATE TABLE proof_ctrl.context_secret (id int PRIMARY KEY CHECK (id = 1), secret bytea NOT NULL);

-- Worker admission state. 'draining' serves existing sessions until the
-- recorded deadline but reserves no new ones; 'retired' accepts nothing.
CREATE TABLE public.proof_workers (
  worker_id text PRIMARY KEY,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'draining', 'retired')),
  drain_deadline_at timestamptz
);

-- One row per visitor session. Ownership = owner + generation, protected by a
-- short-lived lease. The opaque cookie is stored hashed (never plaintext); the
-- hash is unique so one live session exists per cookie.
CREATE TABLE public.proof_sessions (
  token_hash text PRIMARY KEY,
  sandbox_id uuid NOT NULL,
  owner text NOT NULL,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'draining', 'lost', 'deleted')),
  lease_expires_at timestamptz NOT NULL,
  reserved_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  runtime_did text
);
CREATE INDEX proof_sessions_sandbox_idx ON public.proof_sessions(sandbox_id);
CREATE INDEX proof_sessions_owner_idx ON public.proof_sessions(owner, state);
CREATE INDEX proof_sessions_lease_idx ON public.proof_sessions(lease_expires_at);
-- A playground session is one live session per sandbox: verify_fence resolves
-- the live row by sandbox and expects exactly one. Enforce it at the catalog
-- so a duplicate cannot silently break the fence.
CREATE UNIQUE INDEX proof_sessions_one_live_per_sandbox
  ON public.proof_sessions(sandbox_id) WHERE state IN ('active', 'draining');

-- Per-sandbox advisory lock id, distinct across the bounded visitor set.
CREATE FUNCTION proof_ctrl.sandbox_lock_id(p_sandbox uuid)
RETURNS bigint IMMUTABLE LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  RETURN 2000 + get_byte(decode(replace(p_sandbox::text, '-', ''), 'hex'), 15)::bigint;
END $body$;
-- Pure id derivation; the driver (proof_control) needs it to read the
-- in-flight lock evidence from pg_locks.
GRANT EXECUTE ON FUNCTION proof_ctrl.sandbox_lock_id(uuid) TO proof_control;
CREATE FUNCTION proof_ctrl.live_session(p_sandbox uuid)
RETURNS SETOF public.proof_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $body$
  SELECT * FROM public.proof_sessions
  WHERE sandbox_id = p_sandbox AND state IN ('active', 'draining');
$body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.live_session(uuid) TO proof_query, proof_raw, proof_control;

-- Atomic session reservation. Returns the authoritative row plus a marker:
--   created  -> a new live session owned by the caller
--   existing -> a live session already exists for this cookie OR this sandbox
--               (one live session per sandbox; duplicate blocked, no new identity)
--   stale    -> the cookie maps to a lost/deleted session (no resurrection)
CREATE FUNCTION proof_ctrl.reserve_session(p_token_hash text, p_sandbox uuid, p_worker text, p_lease_ms integer)
RETURNS table (token_hash text, sandbox_id uuid, owner text, generation bigint, state text, lease_expires_at timestamptz, marker text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE
  existing public.proof_sessions;
  created  public.proof_sessions;
  wstate   text;
  deadline timestamptz;
BEGIN
  -- Worker admission, authoritative and race-free: the worker row is
  -- locked for the whole transaction, so a concurrent 'draining'
  -- transition cannot slip in between this check and the INSERT.
  SELECT w.state, w.drain_deadline_at INTO wstate, deadline
  FROM public.proof_workers w
  WHERE worker_id = p_worker FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT p_token_hash::text, p_sandbox::uuid, NULL::text,
      NULL::bigint, NULL::text, NULL::timestamptz, 'unknown-worker';
    RETURN;
  END IF;
  IF wstate <> 'active'
     OR (wstate = 'draining' AND deadline IS NOT NULL AND deadline <= now()) THEN
    RETURN QUERY SELECT p_token_hash::text, p_sandbox::uuid, NULL::text,
      NULL::bigint, NULL::text, NULL::timestamptz, 'admission-denied';
    RETURN;
  END IF;
  -- One live session per sandbox: routing never mints a second identity for
  -- the same sandbox, and the fence's single-row resolve stays sound.
  SELECT * INTO existing FROM public.proof_sessions
  WHERE proof_sessions.sandbox_id = p_sandbox AND proof_sessions.state IN ('active', 'draining');
  IF FOUND THEN
    RETURN QUERY SELECT existing.token_hash, existing.sandbox_id, existing.owner,
      existing.generation, existing.state, existing.lease_expires_at, 'existing';
    RETURN;
  END IF;
  SELECT * INTO existing FROM public.proof_sessions
  WHERE proof_sessions.token_hash = p_token_hash FOR UPDATE;
  IF FOUND AND existing.state IN ('active', 'draining') THEN
    RETURN QUERY SELECT existing.token_hash, existing.sandbox_id, existing.owner,
      existing.generation, existing.state, existing.lease_expires_at, 'existing';
    RETURN;
  END IF;
  IF FOUND THEN
    RETURN QUERY SELECT existing.token_hash, existing.sandbox_id, existing.owner,
      existing.generation, existing.state, existing.lease_expires_at, 'stale';
    RETURN;
  END IF;
  INSERT INTO public.proof_sessions
    (token_hash, sandbox_id, owner, generation, state, lease_expires_at)
  VALUES (p_token_hash, p_sandbox, p_worker, 1, 'active',
          now() + (p_lease_ms || ' milliseconds')::interval)
  RETURNING * INTO created;
  RETURN QUERY SELECT created.token_hash, created.sandbox_id, created.owner,
    created.generation, created.state, created.lease_expires_at, 'created';
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.reserve_session(text, uuid, text, integer) TO proof_control;

-- Renew a lease only if the caller still holds owner + generation.
CREATE FUNCTION proof_ctrl.renew_session(p_token_hash text, p_worker text, p_generation bigint, p_lease_ms integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  UPDATE public.proof_sessions
  SET lease_expires_at = now() + (p_lease_ms || ' milliseconds')::interval
  WHERE proof_sessions.token_hash = p_token_hash AND owner = p_worker
    AND generation = p_generation AND state = 'active';
  RETURN FOUND;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.renew_session(text, text, bigint, integer) TO proof_control;

-- Resolve the authoritative owner/generation for a live session by cookie hash.
CREATE FUNCTION proof_ctrl.resolve_session(p_token_hash text)
RETURNS SETOF public.proof_sessions
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $body$
  SELECT * FROM public.proof_sessions
  WHERE token_hash = p_token_hash AND state IN ('active', 'draining');
$body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.resolve_session(text) TO proof_control, proof_query, proof_raw;

-- Resolve a live session by sandbox (the executor fence path).
CREATE FUNCTION proof_ctrl.resolve_sandbox(p_sandbox uuid)
RETURNS SETOF public.proof_sessions
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $body$
  SELECT * FROM public.proof_sessions
  WHERE sandbox_id = p_sandbox AND state IN ('active', 'draining');
$body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.resolve_sandbox(uuid) TO proof_control, proof_query, proof_raw;

-- Worker admission state transitions (control only).
CREATE FUNCTION proof_ctrl.set_worker_state(p_worker text, p_state text, p_drain_deadline_ms integer DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  IF p_state NOT IN ('active', 'draining', 'retired') THEN
    RAISE EXCEPTION 'Invalid worker state' USING ERRCODE = 'P0001';
  END IF;
  UPDATE public.proof_workers
  SET state = p_state,
      drain_deadline_at = CASE WHEN p_state = 'draining'
        THEN now() + (p_drain_deadline_ms || ' milliseconds')::interval ELSE NULL END
  WHERE proof_workers.worker_id = p_worker;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Unknown worker' USING ERRCODE = 'P0001';
  END IF;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.set_worker_state(text, text, integer) TO proof_control;

-- Force a session's lease to expire now (fault injection, control only).
CREATE FUNCTION proof_ctrl.expire_lease(p_token_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  UPDATE public.proof_sessions
  SET lease_expires_at = now() - '5 seconds'::interval
  WHERE proof_sessions.token_hash = p_token_hash AND state = 'active';
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.expire_lease(text) TO proof_control;

-- Explicitly invalidate (delete) a session. Bumps generation so any in-flight
-- mutation still carrying the old generation fences and rolls back. Takes the
-- per-sandbox advisory lock for the transaction (same order as verify_fence,
-- bump_generation, transfer_ownership and janitor_sweep): a stale writer whose
-- pre-commit fence already passed must not commit over a generation bump that
-- lands between its fence and its COMMIT.
CREATE FUNCTION proof_ctrl.delete_session(p_token_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE sandbox uuid;
BEGIN
  SELECT sandbox_id INTO sandbox FROM public.proof_sessions
  WHERE token_hash = p_token_hash AND state IN ('active','draining');
  IF FOUND AND NOT pg_catalog.pg_try_advisory_xact_lock(proof_ctrl.sandbox_lock_id(sandbox)) THEN
    RAISE EXCEPTION 'Sandbox fence lock unavailable' USING ERRCODE = '55P03';
  END IF;
  UPDATE public.proof_sessions
  SET state = 'deleted', deleted_at = now(), generation = generation + 1
  WHERE proof_sessions.token_hash = p_token_hash AND state IN ('active', 'draining');
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.delete_session(text) TO proof_control;

-- Mark a session lost (owner died / lease lapsed without renewal). Same
-- transaction advisory lock as delete_session, so a lost-state commit cannot
-- interleave with an in-flight fenced writer.
CREATE FUNCTION proof_ctrl.lose_session(p_token_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE sandbox uuid;
BEGIN
  SELECT sandbox_id INTO sandbox FROM public.proof_sessions
  WHERE token_hash = p_token_hash AND state IN ('active','draining');
  IF FOUND AND NOT pg_catalog.pg_try_advisory_xact_lock(proof_ctrl.sandbox_lock_id(sandbox)) THEN
    RAISE EXCEPTION 'Sandbox fence lock unavailable' USING ERRCODE = '55P03';
  END IF;
  UPDATE public.proof_sessions
  SET state = 'lost', deleted_at = now(), generation = generation + 1
  WHERE proof_sessions.token_hash = p_token_hash AND state IN ('active', 'draining');
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.lose_session(text) TO proof_control;

-- Generation bump to retire a stale owner while it may still be mutating.
-- Held under the sandbox advisory lock so it cannot interleave with a
-- fence/operation pair; the stale worker's next fence fails.
CREATE FUNCTION proof_ctrl.bump_generation(p_sandbox uuid, p_expected_generation bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  IF NOT pg_catalog.pg_try_advisory_lock(proof_ctrl.sandbox_lock_id(p_sandbox)) THEN
    RAISE EXCEPTION 'Sandbox fence lock unavailable' USING ERRCODE = '55P03';
  END IF;
  BEGIN
    UPDATE public.proof_sessions
    SET generation = generation + 1
    WHERE sandbox_id = p_sandbox AND state IN ('active', 'draining')
      AND generation = p_expected_generation;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Generation changed concurrently' USING ERRCODE = 'P0001';
    END IF;
  EXCEPTION
    WHEN OTHERS THEN
      PERFORM pg_catalog.pg_advisory_unlock(proof_ctrl.sandbox_lock_id(p_sandbox));
      RAISE;
  END;
  PERFORM pg_catalog.pg_advisory_unlock(proof_ctrl.sandbox_lock_id(p_sandbox));
  RETURN p_expected_generation + 1;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.bump_generation(uuid, bigint) TO proof_control;

-- Ownership transfer (re-route) for a live session. Re-assigns the owner and
-- bumps the generation so the previous owner's in-memory belief (fenced by
-- generation) is immediately stale: its next mutation fences and rolls back.
-- This is what "no random reroute" in the dead-owner case rules out -- a
-- deliberate transfer is the only way ownership changes, and the new owner
-- must establish the generation from the catalog.
CREATE FUNCTION proof_ctrl.transfer_ownership(p_token_hash text, p_new_worker text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE
  session record;
  sandbox uuid;
  new_generation bigint;
BEGIN
  -- Pre-read the sandbox id (without the row lock) to learn the lock id.
  SELECT sandbox_id INTO sandbox FROM public.proof_sessions
  WHERE proof_sessions.token_hash = p_token_hash
    AND state IN ('active','draining');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'No live session to transfer' USING ERRCODE = 'P0001';
  END IF;
  -- Take the per-sandbox advisory lock BEFORE the session row lock, in the
  -- same order verify_fence (transaction lock) and bump_generation take
  -- theirs. A transfer attempted while a fenced operation is in flight
  -- fails fast instead of deadlocking or committing over a concurrent
  -- write.
  IF NOT pg_catalog.pg_try_advisory_lock(proof_ctrl.sandbox_lock_id(sandbox)) THEN
    RAISE EXCEPTION 'Sandbox fence lock unavailable' USING ERRCODE = '55P03';
  END IF;
  BEGIN
    SELECT * INTO session FROM public.proof_sessions
    WHERE proof_sessions.token_hash = p_token_hash
      AND state IN ('active','draining') FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'No live session to transfer' USING ERRCODE = 'P0001';
    END IF;
    -- Only transfer a session whose lease is still valid, from a known
    -- current owner, to a roster worker that can still accept sessions.
    IF session.lease_expires_at <= now() THEN
      RAISE EXCEPTION 'Lease expired' USING ERRCODE = 'P0001';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.proof_workers
                   WHERE worker_id = session.owner) THEN
      RAISE EXCEPTION 'Unknown current owner' USING ERRCODE = 'P0001';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.proof_workers
                   WHERE worker_id = p_new_worker AND state IN ('active','draining')) THEN
      RAISE EXCEPTION 'New worker not accepting sessions' USING ERRCODE = 'P0001';
    END IF;
    new_generation := session.generation + 1;
    UPDATE public.proof_sessions
    SET owner = p_new_worker, generation = new_generation
    WHERE proof_sessions.token_hash = p_token_hash
      AND generation = session.generation;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Generation changed concurrently' USING ERRCODE = 'P0001';
    END IF;
  EXCEPTION
    WHEN OTHERS THEN
      PERFORM pg_catalog.pg_advisory_unlock(proof_ctrl.sandbox_lock_id(sandbox));
      RAISE;
  END;
  PERFORM pg_catalog.pg_advisory_unlock(proof_ctrl.sandbox_lock_id(sandbox));
  RETURN new_generation;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.transfer_ownership(text, text) TO proof_control;

-- Signed, transaction-bound sandbox context for the executor roles:
-- token = sandbox:pid:xid:role:<hmac>. proof_guard.current_sandbox() re-checks
-- the pid/xid/role binding AND the signature, so the token cannot be moved
-- across backends, transactions or roles.
CREATE FUNCTION proof_ctrl.issue_context(p_sandbox uuid, p_backend integer, p_transaction_id text, p_target_role text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE payload text; signing_key bytea;
BEGIN
  IF p_target_role NOT IN ('proof_query', 'proof_raw', 'proof_control')
     OR NOT EXISTS (SELECT 1 FROM public.proof_sessions
          WHERE sandbox_id = p_sandbox AND state IN ('active', 'draining'))
     OR p_transaction_id !~ '^[0-9]+$'
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity
        WHERE pid = p_backend AND usename = p_target_role
          AND datname = current_database() AND backend_xid::text = p_transaction_id) THEN
    RAISE EXCEPTION 'Invalid context target' USING ERRCODE = '42501';
  END IF;
  SELECT secret INTO STRICT signing_key FROM proof_ctrl.context_secret;
  payload := p_sandbox::text || ':' || p_backend::text || ':' || p_transaction_id || ':' || p_target_role;
  RETURN payload || ':' || encode(proof_ctrl.hmac(convert_to(payload, 'UTF8'), signing_key, 'sha256'), 'hex');
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.issue_context(uuid, integer, text, text) TO proof_control;

-- RLS boundary for orders_plaintext: resolves and cryptographically validates
-- the transaction-local token.
CREATE FUNCTION proof_guard.current_sandbox()
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE token text; parts text[]; payload text; signature text; signing_key bytea; sandbox uuid;
BEGIN
  token := current_setting('proof.sandbox_token', true);
  IF token IS NULL OR token = '' THEN
    RAISE EXCEPTION 'Missing sandbox context' USING ERRCODE = '42501';
  END IF;
  parts := string_to_array(token, ':');
  IF cardinality(parts) <> 5 OR parts[2] <> pg_backend_pid()::text
     OR parts[3] <> txid_current()::text OR parts[4] <> session_user::text
     OR session_user NOT IN ('proof_query', 'proof_raw', 'proof_control') THEN
    RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
  END IF;
  payload := array_to_string(parts[1:4], ':');
  SELECT secret INTO STRICT signing_key FROM proof_ctrl.context_secret;
  signature := encode(proof_ctrl.hmac(convert_to(payload, 'UTF8'), signing_key, 'sha256'), 'hex');
  IF parts[5] IS DISTINCT FROM signature THEN
    RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
  END IF;
  BEGIN
    sandbox := parts[1]::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'Invalid sandbox context' USING ERRCODE = '42501';
  END;
  RETURN sandbox;
END $body$;
GRANT EXECUTE ON FUNCTION proof_guard.current_sandbox() TO proof_query, proof_raw;

CREATE FUNCTION proof_guard.immutable_owner()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  IF NEW.sandbox_id IS DISTINCT FROM OLD.sandbox_id THEN
    RAISE EXCEPTION 'Sandbox ownership is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $body$;

-- Ownership fence, called inside the executor transaction before the operation
-- and again before COMMIT. Takes the per-sandbox advisory lock for the
-- transaction, so it is mutually exclusive with the janitor and any generation
-- bump, and is observable in pg_locks as evidence.
CREATE FUNCTION proof_ctrl.verify_fence(p_sandbox uuid, p_worker text, p_generation bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE
  session record;
  wstate   text;
  deadline timestamptz;
BEGIN
  IF NOT pg_catalog.pg_try_advisory_xact_lock(proof_ctrl.sandbox_lock_id(p_sandbox)) THEN
    RAISE EXCEPTION 'Sandbox fence lock unavailable' USING ERRCODE = '55P03';
  END IF;
  SELECT * INTO session FROM proof_ctrl.live_session(p_sandbox);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Session lost' USING ERRCODE = 'P0001';
  END IF;
  IF session.generation IS DISTINCT FROM p_generation
     OR session.owner IS DISTINCT FROM p_worker THEN
    RAISE EXCEPTION 'Stale ownership' USING ERRCODE = 'P0001';
  END IF;
  -- A matching owner/generation is not enough: the session must still be
  -- usable. An expired lease, a retired owner, or a drain whose deadline
  -- passed are terminal for in-flight work and roll the transaction back.
  -- clock_timestamp() (not now()) because now() is frozen at the
  -- transaction start of the surrounding executor transaction: the
  -- pre-commit fence runs after the operation (which can sleep seconds),
  -- and its whole purpose is to catch deadlines that elapse DURING the
  -- operation. The pre-fence call happens immediately after BEGIN, where
  -- the two are equivalent.
  IF session.lease_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'Lease expired' USING ERRCODE = 'P0001';
  END IF;
  SELECT state, drain_deadline_at INTO wstate, deadline
  FROM public.proof_workers WHERE worker_id = session.owner;
  IF NOT FOUND OR wstate = 'retired' THEN
    RAISE EXCEPTION 'Owner retired' USING ERRCODE = 'P0001';
  END IF;
  IF session.state = 'draining' AND wstate = 'draining'
     AND deadline IS NOT NULL AND deadline <= clock_timestamp() THEN
    RAISE EXCEPTION 'Drain deadline passed' USING ERRCODE = 'P0001';
  END IF;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.verify_fence(uuid, text, bigint) TO proof_query, proof_raw;

-- Control-only sandbox reset: delete and reseed this sandbox's private rows
-- from the fixed protected fixture (decoupled from the encrypted orders table).
CREATE FUNCTION proof_ctrl.reset_sandbox(p_sandbox uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  DELETE FROM public.orders_plaintext WHERE sandbox_id = p_sandbox;
  INSERT INTO public.orders_plaintext (id, sandbox_id, instrument, quantity, price, counterparty)
  SELECT v.id, p_sandbox, v.instrument, v.quantity, v.price, v.counterparty
  FROM (VALUES (1, 'LNG', 10, 12.45::numeric, 'Example A'),
               (2, 'CARBON', 20, 88.1::numeric, 'Example B')) AS v(id, instrument, quantity, price, counterparty);
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.reset_sandbox(uuid) TO proof_control;

-- Control-only initial provisioning: seed a sandbox's private rows (idempotent).
CREATE FUNCTION proof_ctrl.seed_sandbox(p_sandbox uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  IF EXISTS (SELECT 1 FROM public.orders_plaintext WHERE sandbox_id = p_sandbox) THEN
    RETURN;
  END IF;
  INSERT INTO public.orders_plaintext (id, sandbox_id, instrument, quantity, price, counterparty)
  SELECT v.id, p_sandbox, v.instrument, v.quantity, v.price, v.counterparty
  FROM (VALUES (1, 'LNG', 10, 12.45::numeric, 'Example A'),
               (2, 'CARBON', 20, 88.1::numeric, 'Example B')) AS v(id, instrument, quantity, price, counterparty);
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.seed_sandbox(uuid) TO proof_control;

-- Control-only scenario helper: retire every live session of a sandbox
-- (state -> deleted, generation bumped) so a later reserve starts fresh and
-- the one-live-per-sandbox invariant holds. Used only by the proof driver.
-- Takes the per-sandbox advisory lock for the transaction like every other
-- generation-changing write, so it cannot commit over an in-flight fence.
CREATE FUNCTION proof_ctrl.clear_sandbox(p_sandbox uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE n integer;
BEGIN
  IF NOT pg_catalog.pg_try_advisory_xact_lock(proof_ctrl.sandbox_lock_id(p_sandbox)) THEN
    RAISE EXCEPTION 'Sandbox fence lock unavailable' USING ERRCODE = '55P03';
  END IF;
  UPDATE public.proof_sessions
  SET state = 'deleted', deleted_at = now(), generation = generation + 1
  WHERE sandbox_id = p_sandbox AND state IN ('active', 'draining');
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.clear_sandbox(uuid) TO proof_control;

-- Control-only snapshot oracle for fingerprinting in the proof.
CREATE FUNCTION proof_ctrl.snapshot()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  RETURN (
    SELECT jsonb_build_object(
      'sessions', (SELECT coalesce(jsonb_agg(row ORDER BY token_hash), '[]'::jsonb) FROM (
         SELECT left(token_hash, 12) AS token_hash,
           jsonb_build_object('token_hash', left(token_hash, 12), 'sandbox_id', sandbox_id,
             'owner', owner, 'generation', generation, 'state', state, 'deleted_at', deleted_at) AS row
         FROM public.proof_sessions) s),
      'workers', (SELECT coalesce(jsonb_agg(row ORDER BY worker_id), '[]'::jsonb) FROM (
         SELECT worker_id,
           jsonb_build_object('worker_id', worker_id, 'state', state, 'drain_deadline_at', drain_deadline_at) AS row
         FROM public.proof_workers) w),
      'orders_plaintext_rows', (SELECT count(*) FROM public.orders_plaintext),
      'orders_rows', (SELECT count(*) FROM public.orders)
    )
  );
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.snapshot() TO proof_control;

-- Janitor cleanup: deletes draining sessions and active sessions whose lease
-- expired, but only when the owning worker has no in-flight executor work.
-- In-flight detection: the executor holds the per-sandbox advisory lock for the
-- whole fenced transaction, so the janitor cannot take it mid-mutation and the
-- sweep defers that sandbox instead of racing it.
CREATE FUNCTION proof_ctrl.janitor_sweep(p_max_deadlines integer DEFAULT 32)
RETURNS table (token_hash text, reason text, outcome text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
DECLARE
  session record;
  reason text;
  owner_dead boolean;
BEGIN
  FOR session IN
    SELECT s.* FROM public.proof_sessions s
    WHERE s.state IN ('active', 'draining')
      AND (
        (s.state = 'draining' AND EXISTS (SELECT 1 FROM public.proof_workers w
          WHERE w.worker_id = s.owner AND w.state = 'draining'
            AND w.drain_deadline_at IS NOT NULL AND w.drain_deadline_at <= now()))
        OR s.lease_expires_at < now()
        OR NOT EXISTS (SELECT 1 FROM public.proof_workers w
                       WHERE w.worker_id = s.owner
                         AND w.state IN ('active', 'draining'))
      )
    ORDER BY s.reserved_at
    LIMIT p_max_deadlines
  LOOP
    IF NOT pg_catalog.pg_try_advisory_lock(proof_ctrl.sandbox_lock_id(session.sandbox_id)) THEN
      RETURN QUERY SELECT session.token_hash, 'mutation-in-flight', 'deferred';
      CONTINUE;
    END IF;
    SELECT (state NOT IN ('active', 'draining')) INTO owner_dead
    FROM public.proof_workers WHERE worker_id = session.owner;
    IF NOT FOUND THEN owner_dead := true; END IF;
    IF owner_dead THEN
      reason := 'owner-dead';
      UPDATE public.proof_sessions
      SET state = 'lost', generation = generation + 1
      WHERE proof_sessions.token_hash = session.token_hash AND proof_sessions.generation = session.generation;
    ELSE
      reason := CASE
        WHEN session.state = 'draining' THEN 'drained'
        WHEN session.lease_expires_at < now() THEN 'expired-lease'
        ELSE 'stale'
      END;
      UPDATE public.proof_sessions
      SET state = 'deleted', deleted_at = now(), generation = generation + 1
      WHERE proof_sessions.token_hash = session.token_hash AND proof_sessions.generation = session.generation;
    END IF;
    IF FOUND THEN
      RETURN QUERY SELECT session.token_hash, reason, 'reaped';
    ELSE
      RETURN QUERY SELECT session.token_hash, reason, 'deferred';
    END IF;
    PERFORM pg_catalog.pg_advisory_unlock(proof_ctrl.sandbox_lock_id(session.sandbox_id));
  END LOOP;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.janitor_sweep(integer) TO proof_control;
-- Bind a session's materialized runtime identity (control only). The first
-- worker to materialize a session records its agent DID; the NULL guard
-- makes this idempotent and forbids a second identity for the same session.
CREATE FUNCTION proof_ctrl.set_runtime_did(p_token_hash text, p_did text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $body$
BEGIN
  UPDATE public.proof_sessions
  SET runtime_did = p_did
  WHERE proof_sessions.token_hash = p_token_hash AND runtime_did IS NULL;
  RETURN FOUND;
END $body$;
GRANT EXECUTE ON FUNCTION proof_ctrl.set_runtime_did(text, text) TO proof_control;

-- Explicit EXECUTE allowlist: PUBLIC loses execute on every proof function.
-- The grants above (per role) are the only path in; a caller outside
-- proof_query/proof_raw/proof_control cannot reach the control surface.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA proof_ctrl FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA proof_guard FROM PUBLIC;
