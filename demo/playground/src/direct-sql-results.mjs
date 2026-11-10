import { Buffer } from 'node:buffer';

export const DIRECT_SQL_ROW_LIMIT = 100;
export const DIRECT_SQL_RESPONSE_BYTE_LIMIT = 64 * 1024;
export const DIRECT_SQL_REQUEST_TIMEOUT_MS = 2_000;
const DIRECT_SQL_CURSOR = 'direct_sql_cursor';

function deadlineError() {
  return Object.assign(new Error('Direct SQL request deadline exceeded'), { code: '57014' });
}

/**
 * Runs each SQL operation with the remaining request budget. PostgreSQL
 * cancels an operation that runs past the remaining statement_timeout.
 * @param {import('pg').Client} client
 * @param {number} deadline
 * @param {() => number} [now]
 * @returns {(sql: string) => Promise<import('pg').QueryResult>}
 */
export function createDeadlineExecutor(client, deadline, now = Date.now) {
  return async (sql) => {
    const remaining = Math.ceil(deadline - now());
    if (remaining <= 0) throw deadlineError();
    await client.query(`SET LOCAL statement_timeout = '${remaining}ms'`);
    return client.query(sql);
  };
}

/**
 * Exact byte size of the SELECT payload as serialized by the HTTP layer.
 * @param {object[]} rows
 * @param {('rows' | 'responseBytes') | undefined} limitedBy
 * @returns {number}
 */
export function selectPayloadBytes(rows, limitedBy) {
  const payload = { ok: true, command: 'SELECT', rowsReturned: rows.length, rows };
  if (limitedBy) payload.limitedBy = limitedBy;
  return Buffer.byteLength(JSON.stringify(payload, null, 2), 'utf8');
}

/**
 * Consumes a validated SELECT through a forward-only PostgreSQL cursor, one
 * row per FETCH, so the full result set is never materialized. The caller
 * owns the surrounding transaction (BEGIN/SET LOCAL/COMMIT or ROLLBACK);
 * the cursor is always closed before this returns.
 * @param {import('pg').Client} client
 * @param {string} sql
 * @param {(sql: string) => Promise<import('pg').QueryResult>} [execute]
 * @returns {Promise<{ rows: object[], limitedBy?: 'rows' | 'responseBytes' }>}
 */
export async function readCursorRows(client, sql, execute = (statement) => client.query(statement)) {
  await execute(`DECLARE ${DIRECT_SQL_CURSOR} NO SCROLL CURSOR FOR ${sql}`);
  try {
    const rows = [];
    let limitedBy;
    while (rows.length < DIRECT_SQL_ROW_LIMIT && !limitedBy) {
      const batch = await execute(`FETCH FORWARD 1 FROM ${DIRECT_SQL_CURSOR}`);
      if (!batch.rowCount) break;
      const candidate = [...rows, batch.rows[0]];
      if (selectPayloadBytes(candidate) > DIRECT_SQL_RESPONSE_BYTE_LIMIT) {
        limitedBy = 'responseBytes';
        break;
      }
      rows.push(batch.rows[0]);
    }
    if (!limitedBy && rows.length === DIRECT_SQL_ROW_LIMIT) {
      const extra = await execute(`FETCH FORWARD 1 FROM ${DIRECT_SQL_CURSOR}`);
      if (extra.rowCount) limitedBy = 'rows';
    }
    while (selectPayloadBytes(rows, limitedBy) > DIRECT_SQL_RESPONSE_BYTE_LIMIT) {
      rows.pop();
      limitedBy = 'responseBytes';
    }
    return { rows, limitedBy };
  } finally {
    await execute(`CLOSE ${DIRECT_SQL_CURSOR}`).catch(() => {});
  }
}
