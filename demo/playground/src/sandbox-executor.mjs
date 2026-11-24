/**
 * Shared sandbox data-plane executor for the live Playground.
 *
 * Promotes the phase-0 isolation proof to the serving path: every visitor
 * operation runs inside a pinned, transaction-local PostgreSQL transaction on a
 * caller-owned pool whose role has NOINHERIT and NOBYPASSRLS. The sandbox is
 * bound by an HMAC-signed context token issued by the control role and verified
 * by the RLS policy, so a hostile visitor SELECT cannot read, mutate or reset
 * another sandbox's rows.
 *
 * This module owns no pools and wires no HTTP routes (that is a sibling
 * ticket). The caller creates one single-connection pool per role, so the
 * "same pooled connection serves both visitors" guarantee is testable and true.
 */
import pg from 'pg';
import { validateDirectSql, SANDBOX_PLAINTEXT_SCHEMA } from './direct-sql-policy.mjs';
import { loadModule, parseSync } from 'libpg-query';

let queryParserReady = false;

export const SANDBOX_QUERY_ROLE = 'agents_playground_sandbox_query';
export const SANDBOX_RAW_ROLE = 'agents_playground_sandbox_raw';
export const SANDBOX_CONTROL_ROLE = 'agents_playground_sandbox_control';
export const SANDBOX_PROBE_ROLE = 'agents_playground_sandbox_probe';
export const SANDBOX_TOKEN_GUC = 'sandbox.token';
export const PROTECTED_ORDERS = 'sandbox.orders';
export const MUTABLE_ORDERS = 'sandbox.orders_plaintext';

const ROLE_KEYS = {
  query: SANDBOX_QUERY_ROLE,
  raw: SANDBOX_RAW_ROLE,
};

const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function requireSandboxId(sandbox) {
  if (typeof sandbox !== 'string' || !UUID_SHAPE.test(sandbox)) {
    throw new Error('Invalid sandbox id');
  }
}

function policyError(reason) {
  return Object.assign(new Error('Direct SQL rejected by sandbox policy'), {
    code: 'SQL_POLICY_REJECTED',
    reason,
  });
}

/**
 * Builds the pinned-transaction executor surface over caller-owned pools.
 * @param {{
 *   queryPool: pg.Pool, rawPool: pg.Pool, controlPool: pg.Pool,
 *   events?: object[]
 * }} deps
 * @returns {{
 *   withSandbox: (role: string, sandbox: string, op: (c: pg.Client) => Promise<unknown>) => Promise<unknown>,
 *   query: (sandbox: string) => { query: (sql: string, params?: unknown[]) => Promise<pg.QueryResult> },
 *   raw: (sandbox: string, sql: string, params?: unknown[]) => Promise<pg.QueryResult>,
 *   rawBytes: (sandbox: string) => Promise<{ plaintext: Record<string, unknown>[], encrypted: Record<string, unknown>[] }>,
 *   reset: (sandbox: string) => Promise<pg.QueryResult>,
 *   provision: (sandbox: string) => Promise<void>,
 *   snapshot: () => Promise<object>
 * }}
 */
export function createSandboxExecutors({ queryPool, rawPool, controlPool, events = [] }) {
  const pools = { query: queryPool, raw: rawPool };

  async function withSandbox(role, sandbox, operation) {
    requireSandboxId(sandbox);
    if (!Object.hasOwn(pools, role)) throw new Error('Unknown executor role');
    const roleName = ROLE_KEYS[role];
    const client = await pools[role].connect();
    const event = { role, sandbox, outcome: 'rollback', discarded: false, initialContextEmpty: false, cleanupContextEmpty: false };
    let committed = false;
    let failure;
    let result;
    try {
      await client.query('BEGIN');
      const { rows: [initial] } = await client.query(`SELECT pg_backend_pid() AS pid,
        txid_current()::text AS xid, current_setting('${SANDBOX_TOKEN_GUC}', true) AS token,
        session_user::text AS role`);
      event.pid = initial.pid;
      event.xid = initial.xid;
      event.initialContextEmpty = !initial.token;
      if (initial.token || initial.role !== roleName) {
        event.discarded = true;
        throw new Error('Executor connection has unexpected context');
      }
      const { rows: [signed] } = await controlPool.query(
        'SELECT sandbox_private.issue_context($1::uuid, $2::integer, $3::text, $4::text) AS token',
        [sandbox, initial.pid, initial.xid, roleName],
      );
      await client.query(
        `SELECT set_config('${SANDBOX_TOKEN_GUC}', $1, true),
          set_config('statement_timeout', '5000', true), set_config('lock_timeout', '1000', true)`,
        [signed.token],
      );
      result = await operation(client);
      const { rows: [final] } = await client.query(
        `SELECT txid_current()::text AS xid, sandbox_guard.current_sandbox()::text AS sandbox, current_user::text AS role`,
      );
      if (final.xid !== initial.xid || final.sandbox !== sandbox || final.role !== roleName) {
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
        // SET LOCAL alone cannot clean session-level GUC changes executed by a hostile SELECT.
        await client.query('DISCARD ALL');
        const { rows: [clean] } = await client.query(`SELECT
          current_setting('${SANDBOX_TOKEN_GUC}', true) AS token,
          current_setting('statement_timeout') AS statement_timeout,
          current_setting('lock_timeout') AS lock_timeout,
          current_setting('search_path') AS search_path,
          current_user::text AS role`);
        event.cleanupContextEmpty = !clean.token;
        event.cleanupStatementTimeout = clean.statement_timeout;
        event.cleanupLockTimeout = clean.lock_timeout;
        event.cleanupSearchPath = clean.search_path;
        event.cleanupRole = clean.role;
        if (clean.token || clean.role !== roleName) throw new Error('Executor cleanup failed');
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

  function query(sandbox) {
    return {
      // Simple-protocol queries (no params) accept multiple statements, and an
      // embedded COMMIT would end the pinned transaction early. Enforce one
      // parsed statement before anything reaches the client.
      async query(sql, params) {
        if (!queryParserReady) {
          await loadModule();
          queryParserReady = true;
        }
        let parsed;
        try {
          parsed = parseSync(sql);
        } catch {
          throw policyError('SQL could not be parsed as a valid PostgreSQL statement');
        }
        if ((parsed?.stmts ?? []).length !== 1) {
          throw policyError('exactly one statement is allowed');
        }
        return withSandbox('query', sandbox, (client) => client.query(sql, params));
      },
    };
  }

  async function raw(sandbox, sql, params) {
    requireSandboxId(sandbox);
    const policy = await validateDirectSql(sql, { allowedSchemas: [SANDBOX_PLAINTEXT_SCHEMA] });
    if (!policy.ok) throw policyError(policy.reason);
    return withSandbox('raw', sandbox, (client) => client.query(sql, params));
  }

  async function rawBytes(sandbox) {
    const [plain, encrypted] = await Promise.all([
      withSandbox('raw', sandbox, (client) => client.query(
        `SELECT id, instrument, price, counterparty FROM ${MUTABLE_ORDERS} ORDER BY id`,
      )),
      withSandbox('query', sandbox, (client) => client.query(
        `SELECT id, instrument, price, counterparty FROM ${PROTECTED_ORDERS} ORDER BY id`,
      )),
    ]);
    const asPsql = (row) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, Buffer.isBuffer(value) ? `\\x${value.toString('hex')}` : value]));
    return { plaintext: plain.rows, encrypted: encrypted.rows.map(asPsql) };
  }

  function reset(sandbox) {
    requireSandboxId(sandbox);
    return controlPool.query('SELECT sandbox_private.reset_sandbox($1::uuid)', [sandbox]);
  }

  async function provision(sandbox) {
    requireSandboxId(sandbox);
    await controlPool.query('SELECT sandbox_private.provision_sandbox($1::uuid)', [sandbox]);
  }

  async function snapshot() {
    const { rows } = await controlPool.query('SELECT sandbox_private.snapshot() AS data');
    return rows[0]?.data;
  }

  return { withSandbox, query, raw, rawBytes, reset, provision, snapshot };
}

/**
 * Convenience pool builder for callers (server, tests) that must hold exactly
 * one connection per role so physical reuse is observable.
 * @param {{ queryUrl: string, rawUrl: string, controlUrl: string, events?: object[] }} deps
 * @returns {{ executors: ReturnType<typeof createSandboxExecutors>, pools: Record<string, pg.Pool> }}
 */
export function createSandboxExecutorsWithPools({ queryUrl, rawUrl, controlUrl, events }) {
  const pools = {
    query: new pg.Pool({ connectionString: queryUrl, max: 1, statement_timeout: 5000 }),
    raw: new pg.Pool({ connectionString: rawUrl, max: 1, statement_timeout: 5000 }),
    control: new pg.Pool({ connectionString: controlUrl, max: 1 }),
  };
  for (const pool of Object.values(pools)) pool.on('error', () => {});
  const executors = createSandboxExecutors({ queryPool: pools.query, rawPool: pools.raw, controlPool: pools.control, events });
  return { executors, pools };
}
