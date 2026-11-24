import { ORDER_COLUMNS, ORDER_TABLE, areKnownOrderColumns } from './request-policy.mjs';
import { validateDirectSql } from './direct-sql-policy.mjs';
import { ORDERS_PLAINTEXT_TEMP_DDL, ORDERS_PLAINTEXT_TEMP_SEED } from './demo-data.mjs';
import { createDeadlineExecutor, DIRECT_SQL_REQUEST_TIMEOUT_MS, readCursorRows } from './direct-sql-results.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

/**
 * Maps PostgreSQL cancel error codes to payloads the UI can distinguish:
 * 57014 = statement_timeout. The direct path runs against a private temporary
 * copy, so a permitted statement cannot wait on a shared lock.
 * @param {unknown} err
 * @returns {{ ok: false, error: string, kind?: 'statement', message: string }}
 */
export function directSqlErrorPayload(err) {
  if (err?.code === '57014') {
    return {
      ok: false,
      error: 'TimeoutError',
      kind: 'statement',
      message: 'Statement cancelled by PostgreSQL after 2s (statement_timeout)',
    };
  }
  const code = typeof err?.code === 'string' ? err.code : '';
  const message = code === '42501'
    ? 'Database permission denied'
    : code.startsWith('23')
      ? 'Database constraint rejected the operation'
      : code.startsWith('22')
        ? 'Database rejected the supplied value'
        : 'Database operation failed';
  return { ok: false, error: 'PostgresError', message };
}

/**
 * Rolls back a direct SQL transaction before returning its client to the pool.
 * The temporary copy dies with the transaction, so a successful rollback is
 * also the cleanup path. A rollback failure leaves session state unknown, so
 * discard that client.
 * @param {import('pg').Client} client
 * @param {{ error: (...args: unknown[]) => void }} [logger]
 * @returns {Promise<void>}
 */
async function rollbackAndRelease(client, logger = console) {
  try {
    await client.query('ROLLBACK');
  } catch (rollbackError) {
    logSafeError(logger, 'error', 'Direct SQL ROLLBACK failed; discarding pooled connection', rollbackError);
    client.release(true);
    return;
  }
  client.release();
}

/**
 * Rolls back a failed direct SQL transaction and maps the failure to a payload.
 * @param {import('pg').Client | undefined} client
 * @param {unknown} originalError
 * @param {{ error: (...args: unknown[]) => void }} [logger]
 * @returns {Promise<ReturnType<typeof directSqlErrorPayload>>}
 */
export async function cleanUpFailedDirectSql(client, originalError, logger = console) {
  if (client) await rollbackAndRelease(client, logger);
  return directSqlErrorPayload(originalError);
}

export async function createSimulator({ pool, directSqlPool, scope, readBody, rejected, metrics }) {
  if (!directSqlPool?.connect) throw new Error('Simulator requires the shared direct SQL pool');

  let simColumns = ORDER_COLUMNS.filter((column) => !['orders.price', 'orders.counterparty'].includes(column));
  let simSession;
  let simAgent;
  let simCredential = null;
  let simCredentialExpMs = 0;

  async function getSimCredential() {
    if (simCredential && Date.now() < simCredentialExpMs - 30_000) return simCredential;
    simCredential = await simSession.issueCredential({
      agent: simAgent.did,
      columns: simColumns,
      actions: ['read'],
      expiresIn: '4h',
    });
    const payload = JSON.parse(Buffer.from(simCredential.split('.')[1], 'base64url').toString());
    simCredentialExpMs = payload.exp * 1000;
    return simCredential;
  }

  simSession = await scope.authenticate({
    mockHumanDid: 'demo-operator',
    scopeCeiling: {
      columns: ORDER_COLUMNS,
      actions: ['read'],
      source: 'oidc-groups',
      resolvedFrom: ['desk-junior'],
    },
  });

  simAgent = (await scope.listAgents({ ownerDid: simSession.humanDid }))
    .find((agent) => agent.name === 'sim-agent');
  simAgent ??= await scope.createAgentIdentity({ name: 'sim-agent', ownerDid: simSession.humanDid });
  await getSimCredential();

  return {
    routes: {
      'GET /api/sim/agent': async () => {
        const credential = await getSimCredential();
        const payload = JSON.parse(Buffer.from(credential.split('.')[1], 'base64url').toString());
        return [200, {
          agentDid: simAgent.did,
          owner: simSession.humanDid,
          columns: simColumns,
          actions: ['read'],
          expiresAt: new Date(simCredentialExpMs).toISOString(),
          jti: payload.jti,
        }];
      },

      'POST /api/sim/config': async (req) => {
        const { columns } = await readBody(req);
        if (!Array.isArray(columns) || columns.length === 0 || !columns.every((column) => typeof column === 'string')) {
          return [400, { error: 'ValidationError', message: 'columns must be a non-empty array of column names' }];
        }
        if (new Set(columns).size !== columns.length || !areKnownOrderColumns(columns)) {
          return [400, { error: 'ValidationError', message: 'columns must be unique known order columns' }];
        }
        simColumns = columns;
        simCredential = null;
        const credential = await getSimCredential();
        const payload = JSON.parse(Buffer.from(credential.split('.')[1], 'base64url').toString());
        return [200, { ok: true, columns: simColumns, expiresAt: new Date(simCredentialExpMs).toISOString(), jti: payload.jti }];
      },

      'POST /api/sim/raw': async (req) => {
        const { sql } = await readBody(req);
        if (!sql || typeof sql !== 'string') {
          return [400, { error: 'ValidationError', message: 'sql required' }];
        }
        const verdict = await validateDirectSql(sql);
        if (!verdict.ok) {
          if (verdict.kind === 'unavailable') {
            return [503, { ok: false, error: 'DirectSqlUnavailable', message: verdict.reason }];
          }
          if (verdict.kind === 'parse') metrics?.counter('playground_parser_errors_total');
          return [403, { ok: false, error: 'DirectSqlRejected', message: verdict.reason }];
        }
        const deadline = Date.now() + DIRECT_SQL_REQUEST_TIMEOUT_MS;
        let client;
        try {
          // SET LOCAL reverts at COMMIT/ROLLBACK, so pooled clients are released clean.
          client = await directSqlPool.connect();
          await client.query('BEGIN');
          const execute = createDeadlineExecutor(client, deadline);
          // Pin the resolution order: unqualified names may only reach the
          // session's temporary schema, never public.
          await execute('SET LOCAL search_path = pg_temp');
          // The statement runs against a throwaway copy of the fixture. The
          // copy never commits, so ON COMMIT DROP and ROLLBACK both remove it.
          await execute(ORDERS_PLAINTEXT_TEMP_DDL);
          await execute(ORDERS_PLAINTEXT_TEMP_SEED);
          if (verdict.statement === 'SelectStmt') {
            const { rows, limitedBy } = await readCursorRows(client, sql, execute);
            const payload = { ok: true, command: 'SELECT', rowsReturned: rows.length, rows };
            if (limitedBy) payload.limitedBy = limitedBy;
            return [200, payload];
          }
          const result = await execute(sql);
          return [200, { ok: true, command: result.command, rowCount: result.rowCount }];
        } catch (err) {
          const payload = await cleanUpFailedDirectSql(client, err);
          client = undefined;
          return [200, payload];
        } finally {
          if (client) await rollbackAndRelease(client);
        }
      },

      'POST /api/sim/scoped': async (req) => {
        const { sql } = await readBody(req);
        if (!sql || typeof sql !== 'string') {
          return [400, { error: 'ValidationError', message: 'sql required' }];
        }
        try {
          const credential = await getSimCredential();
          const result = await scope.query({ agent: simAgent.did, credential, sql, table: ORDER_TABLE });
          return [200, { ok: true, ...result }];
        } catch (err) {
          return rejected(err, { ok: false });
        }
      },

      'POST /api/sim/reset': async () => [200, { ok: true, rows: 8 }],

      'GET /api/sim/raw-bytes': async () => {
        const [plain, enc] = await Promise.all([
          pool.query('SELECT id, instrument, price, counterparty, status FROM orders_plaintext ORDER BY id LIMIT 4'),
          pool.query('SELECT id, instrument, price, counterparty, status FROM orders ORDER BY id LIMIT 4'),
        ]);
        const asPsql = (row) => Object.fromEntries(
          Object.entries(row).map(([key, value]) => [key, Buffer.isBuffer(value) ? `\\x${value.toString('hex')}` : value]),
        );
        return [200, { plaintext: plain.rows, encrypted: enc.rows.map(asPsql) }];
      },
    },
  };
}
