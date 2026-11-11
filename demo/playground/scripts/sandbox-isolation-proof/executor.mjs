import { parseSync } from 'libpg-query';
import { validateDirectSql } from '../../src/direct-sql-policy.mjs';

export const SANDBOX_A = '11111111-1111-4111-8111-111111111111';
export const SANDBOX_B = '22222222-2222-4222-8222-222222222222';
const sandboxes = new Set([SANDBOX_A, SANDBOX_B]);

function requireSandbox(sandbox) {
  if (!sandboxes.has(sandbox)) throw new Error('Unknown sandbox');
}

function policyError() {
  return Object.assign(new Error('Direct SQL rejected by sandbox policy'), { code: 'SQL_POLICY_REJECTED' });
}

function writesOwnership(sql) {
  const root = parseSync(sql)?.stmts?.[0]?.stmt?.UpdateStmt;
  return root?.targetList?.some((target) => target.ResTarget?.name === 'sandbox_id') ?? false;
}

/** Creates caller-owned-pool executors with transaction-local, signed sandbox context. */
export function createExecutors({ queryPool, rawPool, controlPool, events }) {
  const pools = { query: queryPool, raw: rawPool };

  async function withSandbox(role, sandbox, operation) {
    requireSandbox(sandbox);
    if (!Object.hasOwn(pools, role)) throw new Error('Unknown executor role');
    const client = await pools[role].connect();
    const event = { role, sandbox, outcome: 'rollback', discarded: false,
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
      const { rows: [signed] } = await controlPool.query(
        'SELECT proof_private.issue_context($1::uuid, $2::integer, $3::text, $4::text) AS token',
        [sandbox, initial.pid, initial.xid, `proof_${role}`],
      );
      await client.query(`SELECT set_config('proof.sandbox_token', $1, true),
        set_config('statement_timeout', '5000', true), set_config('lock_timeout', '1000', true)`, [signed.token]);
      result = await operation(client);
      const { rows: [final] } = await client.query(`SELECT txid_current()::text AS xid,
        proof_guard.current_sandbox()::text AS sandbox, current_user::text AS role`);
      if (final.xid !== initial.xid || final.sandbox !== sandbox || final.role !== `proof_${role}`) {
        throw new Error('Executor transaction context changed');
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
        // SET LOCAL alone cannot clean session-level GUC changes executed by hostile SELECTs.
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
      if (failure) event.code = /^[0-9A-Z]{5}$/.test(failure?.code ?? '') ? failure.code : 'EXECUTOR_REJECTED';
      event.outcome = committed ? 'commit' : 'rollback';
      events.push(event);
      client.release(event.discarded);
    }
    if (failure) throw failure;
    return result;
  }

  function queryAdapter(sandbox) {
    requireSandbox(sandbox);
    return { query: (sql, params) => withSandbox('query', sandbox, (client) => client.query(sql, params)) };
  }

  async function raw(sandbox, sql, params) {
    requireSandbox(sandbox);
    const policy = await validateDirectSql(sql);
    if (!policy.ok || writesOwnership(sql)) throw policyError();
    return withSandbox('raw', sandbox, (client) => client.query(sql, params));
  }

  async function rawBytes(sandbox) {
    const [plain, encrypted] = await Promise.all([
      withSandbox('raw', sandbox, (client) => client.query(
        'SELECT id, instrument, price, counterparty FROM public.orders_plaintext ORDER BY id LIMIT 4',
      )),
      withSandbox('query', sandbox, (client) => client.query(
        'SELECT id, instrument, price, counterparty FROM public.orders ORDER BY id LIMIT 4',
      )),
    ]);
    const asPsql = (row) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, Buffer.isBuffer(value) ? `\\x${value.toString('hex')}` : value]));
    return { plaintext: plain.rows, encrypted: encrypted.rows.map(asPsql) };
  }

  function reset(sandbox) {
    requireSandbox(sandbox);
    return controlPool.query('SELECT proof_private.reset_sandbox($1::uuid)', [sandbox]);
  }

  return { withSandbox, queryAdapter, raw, rawBytes, reset };
}
