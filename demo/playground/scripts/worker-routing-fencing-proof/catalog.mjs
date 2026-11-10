import pg from 'pg';
import { createHash } from 'node:crypto';


function catalogUrl(value) {
  const url = value || process.env.ROUTING_ADMIN_URL;
  if (!url) throw new Error('ROUTING_ADMIN_URL is required');
  return url;
}

// Node-side client for the proof session catalog (routing_proof db, admin
// connection). Workers call this over the wire for the serve path only; the
// proof driver runs its own catalog SQL directly for fault injection.
export function createCatalog({ pg: Pg = pg, adminUrl, onPoolError }) {
  const pool = new Pg.Pool({ connectionString: catalogUrl(adminUrl), max: 5,
    connectionTimeoutMillis: 3000, idleTimeoutMillis: 10000 });
  if (typeof onPoolError === 'function') pool.on('error', onPoolError);
  const run = (text, params) => pool.query(text, params);

  const api = {
    pool,
    async close() {
      await pool.end();
    },


    // Reserve a session. Returns { sandboxId, owner, generation, state, marker }.
    // marker: 'created' | 'existing' | 'stale'.
    async reserve(tokenHash, sandboxId, worker, leaseMs) {
      const { rows } = await run(
        `SELECT * FROM proof_ctrl.reserve_session($1, $2::uuid, $3, $4)`,
        [tokenHash, sandboxId, worker, leaseMs],
      );
      const row = rows[0];
      if (!row) throw new Error('reserve_session returned no row');
      return {
        sandboxId: row.sandbox_id,
        owner: row.owner,
        generation: Number(row.generation),
        state: row.state,
        marker: row.marker,
      };
    },


    // Resolve owner/generation by cookie token hash. null = no live session.
    async resolve(tokenHash) {
      const { rows } = await run(
        `SELECT sandbox_id, owner, generation, state, runtime_did FROM proof_ctrl.resolve_session($1)`,
        [tokenHash],
      );
      const row = rows[0];
      if (!row) return null;
      return {
        sandboxId: row.sandbox_id,
        owner: row.owner,
        generation: Number(row.generation),
        state: row.state,
        runtimeDid: row.runtime_did ?? null,
      };
    },


    // Drain a worker: its sessions become draining, new reservations denied.
    // Atomic: both the worker-state transition and the session marking run in
    // a single transaction, so a crash between them can never leave a session
    // active while the worker is already draining (which would let it miss the
    // drain-deadline branch of verify_fence).
    async drainWorker(worker, graceMs) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT proof_ctrl.set_worker_state($1, $2, $3)', [worker, 'draining', graceMs]);
        await client.query(
          `UPDATE public.proof_sessions SET state = 'draining'
           WHERE owner = $1 AND state = 'active'`,
          [worker],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },

    async retireWorker(worker) {
      await run('SELECT proof_ctrl.set_worker_state($1, $2)', [worker, 'retired']);
    },
    async renewLease(worker, tokenHash, generation, leaseMs) {
      const { rows } = await run(
        'SELECT proof_ctrl.renew_session($1, $2, $3::bigint, $4) AS renewed',
        [tokenHash, worker, generation, leaseMs],
      );
      return rows[0].renewed === true;
    },

    // Record the materialized runtime identity (first-wins, idempotent).
    async setRuntimeDid(tokenHash, did) {
      await run('SELECT proof_ctrl.set_runtime_did($1, $2)', [tokenHash, did]);
    },
    async workerState(worker) {
      const { rows } = await run(
        'SELECT state, drain_deadline_at FROM public.proof_workers WHERE worker_id = $1',
        [worker],
      );
      if (!rows[0]) return null;
      return { state: rows[0].state, drainDeadlineAt: rows[0].drain_deadline_at };
    },

  };
  return api;
}

// Opaque cookie: sha256 hex of the raw token. The catalog stores only this.
export function tokenHash(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

