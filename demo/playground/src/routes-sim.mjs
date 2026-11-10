import pg from 'pg';
import { ORDER_COLUMNS, ORDER_TABLE, areKnownOrderColumns } from './request-policy.mjs';
import { validateDirectSql } from './direct-sql-policy.mjs';
import { createDeadlineExecutor, DIRECT_SQL_REQUEST_TIMEOUT_MS, readCursorRows } from './direct-sql-results.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

/**
 * Maps PostgreSQL cancel error codes to payloads the UI can distinguish:
 * 57014 = statement_timeout, 55P03 = lock_timeout.
 * @param {unknown} err
 * @returns {{ ok: false, error: string, kind?: 'statement' | 'lock', message: string }}
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
  if (err?.code === '55P03') {
    return {
      ok: false,
      error: 'TimeoutError',
      kind: 'lock',
      message: 'Statement cancelled by PostgreSQL after waiting 1s for a lock (lock_timeout)',
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
 * Rolls back a failed direct SQL transaction before returning its client to the
 * pool. A rollback failure leaves session state unknown, so discard that client.
 * @param {import('pg').Client | undefined} client
 * @param {unknown} originalError
 * @param {{ error: (...args: unknown[]) => void }} [logger]
 * @returns {Promise<ReturnType<typeof directSqlErrorPayload>>}
 */
export async function cleanUpFailedDirectSql(client, originalError, logger = console) {
  if (!client) return directSqlErrorPayload(originalError);
  try {
    await client.query('ROLLBACK');
    client.release();
  } catch (rollbackError) {
    logSafeError(logger, 'error', 'Direct SQL ROLLBACK failed; discarding pooled connection', rollbackError);
    client.release(true);
  }
  return directSqlErrorPayload(originalError);
}

export async function createSimulator({ databaseUrl, naiveDbPassword, pool, scope, readBody, rejected }) {
  const naiveUrl = new URL(databaseUrl);
  naiveUrl.username = 'agents_playground_naive';
  naiveUrl.password = naiveDbPassword;
  const naivePool = new pg.Pool({
    connectionString: naiveUrl.toString(),
    application_name: 'agents-playground-naive',
    max: 2,
    connectionTimeoutMillis: DIRECT_SQL_REQUEST_TIMEOUT_MS,
  });
  naivePool.on('error', (err) => {
    logSafeError(console, 'error', 'Visitor direct-SQL database pool reported an idle connection error', err);
  });

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

  try {
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
  } catch (err) {
    try {
      await naivePool.end();
    } catch (closeErr) {
      logSafeError(console, 'error', 'Direct SQL pool cleanup failed after simulator initialization error', closeErr);
    }
    throw err;
  }

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
          return [403, { ok: false, error: 'DirectSqlRejected', message: verdict.reason }];
        }
        const deadline = Date.now() + DIRECT_SQL_REQUEST_TIMEOUT_MS;
        let client;
        try {
          // SET LOCAL reverts at COMMIT/ROLLBACK, so pooled clients are released clean.
          client = await naivePool.connect();
          await client.query('BEGIN');
          const execute = createDeadlineExecutor(client, deadline);
          await execute("SET LOCAL lock_timeout = '1s'");
          if (verdict.statement === 'SelectStmt') {
            const { rows, limitedBy } = await readCursorRows(client, sql, execute);
            const payload = { ok: true, command: 'SELECT', rowsReturned: rows.length, rows };
            if (limitedBy) payload.limitedBy = limitedBy;
            await execute('COMMIT');
            return [200, payload];
          }
          const result = await execute(sql);
          await execute('COMMIT');
          return [200, { ok: true, command: result.command, rowCount: result.rowCount }];
        } catch (err) {
          const payload = await cleanUpFailedDirectSql(client, err);
          client = undefined;
          return [200, payload];
        } finally {
          client?.release();
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

      'POST /api/sim/reset': async () => {
        const marker = await pool.query(
          'SELECT value FROM demo_playground_metadata WHERE key = $1',
          ['owner'],
        );
        if (marker.rows[0]?.value !== 'agents-demo-playground') {
          throw new Error('Database not claimed by the Playground');
        }
        await pool.query('SELECT public.reset_orders_plaintext_sandbox()');
        return [200, { ok: true, rows: 8 }];
      },

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
    close: () => naivePool.end(),
  };
}
