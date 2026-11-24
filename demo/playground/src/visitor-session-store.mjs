const ADMISSION_LOCK = 'agents-playground-admission';

export const VISITOR_SESSION_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS playground_sandbox_session (
  sandbox_id text PRIMARY KEY,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  origin_hash text NOT NULL,
  -- Dormant clone handle, retained so a rollback can still read pre-cutover sessions.
  legacy_database_name text
);
CREATE INDEX IF NOT EXISTS playground_sandbox_session_expires_idx
  ON playground_sandbox_session (expires_at);
CREATE INDEX IF NOT EXISTS playground_sandbox_session_seen_idx
  ON playground_sandbox_session (last_seen_at);
CREATE TABLE IF NOT EXISTS playground_new_session_window (
  origin_hash text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  attempts integer NOT NULL
);
CREATE INDEX IF NOT EXISTS playground_new_session_window_start_idx
  ON playground_new_session_window (window_start);
-- Dormant orphan queue, retained with the legacy column so a rollback finds the same schema.
CREATE TABLE IF NOT EXISTS playground_orphan_database (
  database_name text PRIMARY KEY,
  first_failed_at timestamptz NOT NULL,
  last_failed_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 1
);
`;

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive safe integer`);
  return value;
}

function timestamp(ms) {
  return new Date(ms);
}

/**
 * Resolve the shared admission and session metadata plane. The signed cookie is
 * the only identity source; this store owns the global cap, inactivity deadline
 * and per-origin new-session limit so every replica observes the same state.
 */
export function createVisitorSessionStore({
  pool,
  absoluteTtlMs,
  inactivityTtlMs,
  maxSessions,
  rateLimit,
  now = () => Date.now(),
}) {
  if (!pool?.query || !pool?.connect) throw new TypeError('Visitor session store requires a PostgreSQL pool');
  if (typeof now !== 'function') throw new TypeError('now must be a function');
  positiveInteger(absoluteTtlMs, 'absoluteTtlMs');
  positiveInteger(inactivityTtlMs, 'inactivityTtlMs');
  positiveInteger(maxSessions, 'maxSessions');
  if (!rateLimit) throw new TypeError('Visitor session store requires a rate limit');
  positiveInteger(rateLimit.maxNewSessions, 'maxNewSessions');
  positiveInteger(rateLimit.windowMs, 'windowMs');

  async function admit({ sandboxId, originHash }) {
    if (typeof sandboxId !== 'string' || sandboxId.length === 0) throw new TypeError('sandboxId is required');
    if (typeof originHash !== 'string' || originHash.length === 0) throw new TypeError('originHash is required');

    const at = now();
    const expiresAt = at + absoluteTtlMs;
    const inactiveBefore = at - inactivityTtlMs;
    const atDate = timestamp(at);
    const expiresDate = timestamp(expiresAt);
    const inactiveDate = timestamp(inactiveBefore);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [ADMISSION_LOCK]);

      const { rows: [window] } = await client.query(
        'SELECT window_start, attempts FROM playground_new_session_window WHERE origin_hash = $1',
        [originHash],
      );
      const windowStartedAt = window ? new Date(window.window_start).getTime() : null;
      if (windowStartedAt === null || at - windowStartedAt >= rateLimit.windowMs) {
        await client.query(
          `INSERT INTO playground_new_session_window (origin_hash, window_start, attempts)
           VALUES ($1, $2, 1)
           ON CONFLICT (origin_hash) DO UPDATE
             SET window_start = EXCLUDED.window_start, attempts = 1`,
          [originHash, atDate],
        );
      } else if (window.attempts >= rateLimit.maxNewSessions) {
        await client.query('ROLLBACK');
        return {
          ok: false,
          reason: 'rate-limit',
          retryAfterMs: Math.max(1, windowStartedAt + rateLimit.windowMs - at),
        };
      } else {
        await client.query(
          'UPDATE playground_new_session_window SET attempts = attempts + 1 WHERE origin_hash = $1',
          [originHash],
        );
      }

      const { rows: [active] } = await client.query(
        `SELECT count(*)::int AS active
         FROM playground_sandbox_session
         WHERE expires_at > $1 AND last_seen_at > $2`,
        [atDate, inactiveDate],
      );
      if (active.active >= maxSessions) {
        await client.query('ROLLBACK');
        return { ok: false, reason: 'capacity' };
      }

      await client.query(
        `INSERT INTO playground_sandbox_session
           (sandbox_id, created_at, expires_at, last_seen_at, origin_hash)
         VALUES ($1, $2, $3, $4, $5)`,
        [sandboxId, atDate, expiresDate, atDate, originHash],
      );
      await client.query('COMMIT');
      return { ok: true, expiresAt, lastSeenAt: at };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async function resolve({ sandboxId }) {
    const { rows: [row] } = await pool.query(
      `SELECT sandbox_id, expires_at, last_seen_at
       FROM playground_sandbox_session WHERE sandbox_id = $1`,
      [sandboxId],
    );
    if (!row) return { ok: false, reason: 'unknown' };
    const at = now();
    const expiresAt = new Date(row.expires_at).getTime();
    const lastSeenAt = new Date(row.last_seen_at).getTime();
    if (expiresAt <= at) return { ok: false, reason: 'absolute-expired' };
    if (lastSeenAt <= at - inactivityTtlMs) return { ok: false, reason: 'inactive' };
    return { ok: true, expiresAt, lastSeenAt };
  }

  async function touch({ sandboxId }) {
    const at = now();
    const inactiveBefore = timestamp(at - inactivityTtlMs);
    const { rowCount } = await pool.query(
      `UPDATE playground_sandbox_session
       SET last_seen_at = $2
       WHERE sandbox_id = $1
         AND expires_at > $2
         AND last_seen_at > $3`,
      [sandboxId, timestamp(at), inactiveBefore],
    );
    return rowCount > 0;
  }

  async function release({ sandboxId }) {
    const { rowCount } = await pool.query(
      'DELETE FROM playground_sandbox_session WHERE sandbox_id = $1',
      [sandboxId],
    );
    return rowCount > 0;
  }

  async function releaseMany({ sandboxIds }) {
    if (!Array.isArray(sandboxIds) || sandboxIds.some((sandboxId) => typeof sandboxId !== 'string' || !sandboxId)) {
      throw new TypeError('sandboxIds must be an array of non-empty strings');
    }
    if (sandboxIds.length === 0) return 0;
    const { rowCount } = await pool.query(
      'DELETE FROM playground_sandbox_session WHERE sandbox_id = ANY($1::text[])',
      [sandboxIds],
    );
    return rowCount;
  }

  async function claimExpired({ limit }) {
    positiveInteger(limit, 'limit');
    const at = now();
    const { rows } = await pool.query(
      `WITH expired AS (
         SELECT sandbox_id
         FROM playground_sandbox_session
         WHERE expires_at <= $1 OR last_seen_at <= $2
         ORDER BY expires_at
         LIMIT $3
         FOR UPDATE SKIP LOCKED
       )
       DELETE FROM playground_sandbox_session session
       USING expired
       WHERE session.sandbox_id = expired.sandbox_id
       RETURNING session.sandbox_id,
         CASE WHEN session.expires_at <= $1 THEN 'absolute' ELSE 'inactivity' END AS reason`,
      [timestamp(at), timestamp(at - inactivityTtlMs), limit],
    );
    return rows.map((row) => ({
      sandboxId: row.sandbox_id,
      reason: row.reason,
    }));
  }

  async function cleanupRateWindows({ limit = 1000, maxBatches = 10 } = {}) {
    positiveInteger(limit, 'limit');
    positiveInteger(maxBatches, 'maxBatches');
    const cutoff = timestamp(now() - rateLimit.windowMs);
    let total = 0;
    // Drain in bounded batches so one tick keeps up with high origin cardinality.
    for (let batch = 0; batch < maxBatches; batch += 1) {
      const { rowCount } = await pool.query(
        `WITH stale AS (
           SELECT origin_hash
           FROM playground_new_session_window
           WHERE window_start <= $1
           LIMIT $2
         )
         DELETE FROM playground_new_session_window w
         USING stale
         WHERE w.origin_hash = stale.origin_hash
           AND w.window_start <= $1`,
        [cutoff, limit],
      );
      const deleted = rowCount ?? 0;
      total += deleted;
      if (deleted < limit) break;
    }
    return total;
  }

  async function countActive() {
    const at = now();
    const { rows: [row] } = await pool.query(
      `SELECT count(*)::int AS active
       FROM playground_sandbox_session
       WHERE expires_at > $1 AND last_seen_at > $2`,
      [timestamp(at), timestamp(at - inactivityTtlMs)],
    );
    return row.active;
  }

  return {
    admit,
    resolve,
    touch,
    release,
    releaseMany,
    claimExpired,
    cleanupRateWindows,
    countActive,
  };
}
