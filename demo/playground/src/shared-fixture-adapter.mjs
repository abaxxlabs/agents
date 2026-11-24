/** Process-wide Playground pool and per-visitor scoped SDK runtime over the shared fixture. */
import pg from 'pg';
import {
  asMasterKey,
  createStorageBackend,
  deriveSessionMacKey,
} from '@abaxxlabs/agents';
import { AgentScope } from '@abaxxlabs/agents/sql';
import { logSafeError } from './safe-diagnostics.mjs';

const ENCRYPTED_COLUMNS = ['orders.price', 'orders.counterparty'];

/**
 * Create the server-owned pool that serves scoped queries against the shared
 * protected fixture. The pool is opened once per process and reused by every
 * visitor runtime.
 *
 * @param {{ sharedDatabaseUrl: string, poolMax?: number }} options
 * @returns {Promise<{ sharedDatabaseUrl: string, pool: pg.Pool, close: () => Promise<void> }>}
 */
export async function createSharedFixtureRuntime({ sharedDatabaseUrl, poolMax = 10 }) {
  if (!sharedDatabaseUrl) throw new Error('Shared fixture runtime requires the shared database URL');
  if (!Number.isSafeInteger(poolMax) || poolMax < 1) {
    throw new RangeError('poolMax must be a positive safe integer');
  }

  const pool = new pg.Pool({
    connectionString: sharedDatabaseUrl,
    application_name: 'agents-playground-shared',
    max: poolMax,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
  });
  pool.on('error', (err) => {
    logSafeError(console, 'error', 'Shared fixture pool reported an idle connection error', err);
  });

  try {
    await pool.query('SELECT 1');
  } catch (err) {
    await pool.end().catch(() => {});
    throw err;
  }

  let closePromise;
  return {
    sharedDatabaseUrl,
    pool,
    close() {
      closePromise ??= pool.end();
      return closePromise;
    },
  };
}

/**
 * Build one visitor's SDK scope over the shared fixture: identity, credentials
 * and audit live in an ephemeral in-memory SQLite store, while scoped reads use
 * the process-wide pool. The caller owns and closes the returned runtime.
 *
 * @param {{
 *   sharedFixture: { sharedDatabaseUrl: string, pool: pg.Pool },
 *   masterKeyBuffer: Buffer,
 *   createStorage?: typeof createStorageBackend,
 *   createScope?: typeof AgentScope.create,
 * }} options
 * @returns {Promise<{ scope: AgentScope, close: () => Promise<void> }>}
 */
export async function createScopedSdkRuntime({
  sharedFixture,
  masterKeyBuffer,
  createStorage = createStorageBackend,
  createScope = (config, injections) => AgentScope.create(config, injections),
}) {
  if (!sharedFixture?.pool) throw new Error('Scoped SDK runtime requires the shared fixture pool');
  if (!sharedFixture.sharedDatabaseUrl) {
    throw new Error('Scoped SDK runtime requires the shared fixture connection string');
  }
  if (!masterKeyBuffer) throw new Error('Scoped SDK runtime requires the master key');

  const masterKey = asMasterKey(masterKeyBuffer);
  const sessionMacKey = deriveSessionMacKey(masterKey);
  let storage;
  let scope;

  try {
    storage = await createStorage({ type: 'sqlite', path: ':memory:', sessionMacKey });
    await storage.initialize();
    scope = await createScope({
      database: { connectionString: sharedFixture.sharedDatabaseUrl },
      encryption: { columns: ENCRYPTED_COLUMNS },
      audit: { enabled: true },
      credential: { maxTtl: '4h' },
      devMode: true,
    }, { pool: sharedFixture.pool, storage, masterKey });
  } catch (err) {
    if (storage) await storage.close().catch(() => {});
    sessionMacKey.fill(0);
    throw err;
  }

  let closePromise;
  return {
    scope,
    close() {
      // Memoize only the attempt in flight, but always zeroize the derived key.
      closePromise ??= (async () => {
        const failures = [];
        try {
          await scope.close();
        } catch (err) {
          failures.push(err);
        }
        try {
          await storage.close();
        } catch (err) {
          failures.push(err);
        }
        sessionMacKey.fill(0);
        if (failures.length) throw new AggregateError(failures, 'Failed to close the scoped SDK runtime');
      })().catch((err) => {
        closePromise = undefined;
        throw err;
      });
      return closePromise;
    },
  };
}
