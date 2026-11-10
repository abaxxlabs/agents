// The worker mutation boundary: every sandbox operation runs inside a pinned
// transaction that (1) fences ownership by owner + generation, (2) installs a
// transaction-local signed sandbox context (888 contract), (3) executes the
// operation under RLS, (4) re-fences before COMMIT, and (5) discards the
// connection on any failure. A stale worker whose lease was lost or whose
// generation was bumped cannot commit: the fence raises, the transaction
// rolls back, and the event is recorded.
import { parseSync } from 'libpg-query';
import { validateDirectSql } from '../../src/direct-sql-policy.mjs';

export const SANDBOX_A = '11111111-1111-4111-8111-111111111111';
export const SANDBOX_B = '22222222-2222-4222-8222-222222222222';
const sandboxes = new Set([SANDBOX_A, SANDBOX_B]);

function requireSandbox(sandbox) {
  if (!sandboxes.has(sandbox)) throw new Error('Unknown sandbox');
}

function fencedError(reason) {
  return Object.assign(new Error(`Sandbox mutation rejected by ownership fence: ${reason ?? 'unknown'}`), {
    code: 'FENCE_REJECTED',
    reason: reason ?? 'unknown',
  });
}

function policyError() {
  return Object.assign(new Error('Direct SQL rejected by sandbox policy'), {
    code: 'SQL_POLICY_REJECTED',
  });
}

function writesOwnership(sql) {
  const root = parseSync(sql)?.stmts?.[0]?.stmt?.UpdateStmt;
  return root?.targetList?.some((target) => target.ResTarget?.name === 'sandbox_id') ?? false;
}

export function createExecutors({ queryPool, rawPool, controlPool, events, worker }) {
  const pools = { query: queryPool, raw: rawPool };

  async function withSandbox(role, sandbox, operation, ownership) {
    requireSandbox(sandbox);
    if (!Object.hasOwn(pools, role)) throw new Error('Unknown executor role');
    const { owner, generation } = ownership;
    if (!owner || !Number.isInteger(generation) || generation < 1) {
      throw fencedError();
    }
    const client = await pools[role].connect();
    const event = { role, sandbox, worker, owner, generation,
      outcome: 'rollback', discarded: false, fenced: false,
      initialContextEmpty: false, cleanupContextEmpty: false };
    let committed = false;
    let failure;
    let result;
    try {
      await client.query('BEGIN');
      const { rows: [initial] } = await client.query(`SELECT pg_backend_pid() AS pid,
        txid_current()::text AS xid, current_setting('proof.sandbox_token', true) AS token,
        session_user::text AS role`);
      event.pid = initial.pid;
      event.xid = initial.xid;
      event.initialContextEmpty = !initial.token;
      if (initial.token || initial.role !== `proof_${role}`) {
        event.discarded = true;
        throw new Error('Executor connection has unexpected context');
      }
      // Fence before installing context: a stale worker raises here and
      // never reaches the operation.
      event.fencePhase = 'pre';
      try {
        await client.query('SELECT proof_ctrl.verify_fence($1::uuid, $2, $3::bigint)',
          [sandbox, owner, generation]);
      } catch (error) {
        event.fenced = true;
        event.fenceReason = fenceReason(error);
        throw fencedError(event.fenceReason);
      }
      const { rows: [signed] } = await controlPool.query(
        'SELECT proof_ctrl.issue_context($1::uuid, $2::integer, $3::text, $4::text) AS token',
        [sandbox, initial.pid, initial.xid, `proof_${role}`]);
      await client.query(`SELECT set_config('proof.sandbox_token', $1, true),
        set_config('statement_timeout', '5000', true), set_config('lock_timeout', '1000', true)`,
        [signed.token]);
      result = await operation(client);
      // Re-fence before COMMIT: a generation bump that landed after the
      // operation must not be committed under stale ownership.
      event.fencePhase = 'pre-commit';
      try {
        await client.query('SELECT proof_ctrl.verify_fence($1::uuid, $2, $3::bigint)',
          [sandbox, owner, generation]);
      } catch (error) {
        event.fenced = true;
        event.fenceReason = fenceReason(error);
        throw fencedError(event.fenceReason);
      }
      const completion = await client.query('COMMIT');
      if (completion.command !== 'COMMIT') throw new Error('Executor transaction did not commit');
      committed = true;
      event.outcome = 'commit';
    } catch (error) {
      failure = error;
      try {
        await client.query('ROLLBACK');
      } catch {
        event.discarded = true;
      }
    } finally {
      try {
        // SET LOCAL alone cannot clean session-level GUC changes executed by
        // hostile SELECTs.
        await client.query('DISCARD ALL');
        const { rows: [clean] } = await client.query(`SELECT
          current_setting('proof.sandbox_token', true) AS token,
          current_setting('statement_timeout') AS statement_timeout,
          current_setting('lock_timeout') AS lock_timeout,
          current_setting('search_path') AS search_path,
          current_user::text AS role`);
        event.cleanupContextEmpty = !clean.token;
        event.cleanupStatementTimeout = clean.statement_timeout;
        event.cleanupLockTimeout = clean.lock_timeout;
        event.cleanupSearchPath = clean.search_path;
        event.cleanupRole = clean.role;
        if (clean.token || clean.role !== `proof_${role}`) throw new Error('Executor cleanup failed');
      } catch (error) {
        event.discarded = true;
        failure ??= error;
      }
      if (failure) event.code = fencedCode(failure);
      event.outcome = committed ? 'commit' : 'rollback';
      events.push(event);
      client.release(event.discarded);
    }
    if (failure) throw failure;
    return result;
  }
  function fencedCode(error) {
    if (error?.code === 'FENCE_REJECTED') return 'FENCE_REJECTED';
    if (/^[0-9A-Z]{5}$/.test(error?.code ?? '')) return error.code;
    return 'EXECUTOR_REJECTED';
  }

  function fenceReason(error) {
    const message = error?.message ?? '';
    if (/Stale ownership/i.test(message)) return 'stale-ownership';
    if (/Session lost/i.test(message)) return 'session-lost';
    if (/fence lock unavailable/i.test(message)) return 'lock-unavailable';
    if (/Lease expired/i.test(message)) return 'lease-expired';
    if (/Owner retired/i.test(message)) return 'owner-retired';
    if (/Drain deadline passed/i.test(message)) return 'drain-deadline';
    return 'unknown';
  }


  function queryAdapter(sandbox, ownership) {
    requireSandbox(sandbox);
    return { query: (sql, params) => withSandbox('query', sandbox,
      (client) => client.query(sql, params), ownership) };
  }

  async function raw(sandbox, sql, params, ownership) {
    requireSandbox(sandbox);
    const policy = await validateDirectSql(sql);
    if (!policy.ok || writesOwnership(sql)) throw policyError();
    return withSandbox('raw', sandbox, (client) => client.query(sql, params), ownership);
  }

  async function rawBytes(sandbox, ownership) {
    // Sequential by design (review W1): two fenced transactions on the same
    // sandbox must not overlap; the xact advisory lock is re-entrant on one
    // backend, but two concurrent checkouts of the same sandbox would take
    // the lock on two connections and the second would 55P03 itself.
    const plain = await withSandbox('raw', sandbox, (client) => client.query(
      'SELECT id, instrument, price, counterparty FROM public.orders_plaintext ORDER BY id LIMIT 4'), ownership);
    const encrypted = await withSandbox('query', sandbox, (client) => client.query(
      'SELECT id, instrument, price, counterparty FROM public.orders ORDER BY id LIMIT 4'), ownership);
    const asPsql = (row) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, Buffer.isBuffer(value) ? `\\x${value.toString('hex')}` : value]));
    return { plaintext: plain.rows, encrypted: encrypted.rows.map(asPsql) };
  }

  // Fenced sandbox reset: delete + reseed the sandbox's private rows inside a
  // normal ownership transaction, so a stale worker cannot reset over a live
  // owner's data (the fence checks run before and before COMMIT).
  function reset(sandbox, ownership) {
    requireSandbox(sandbox);
    return withSandbox('raw', sandbox, async (client) => {
      await client.query('DELETE FROM public.orders_plaintext WHERE sandbox_id = $1', [sandbox]);
      await client.query(
        `INSERT INTO public.orders_plaintext (id, sandbox_id, instrument, quantity, price, counterparty)
         VALUES (1, $1, 'LNG', 10, 12.45, 'Example A'),
                (2, $1, 'CARBON', 20, 88.1, 'Example B')`, [sandbox]);
      return { rows: [] };
    }, ownership);
  }

  return { withSandbox, queryAdapter, raw, rawBytes, reset };
}
