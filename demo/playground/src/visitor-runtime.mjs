import { isConfiguredMockUser } from './request-policy.mjs';
import { createScopedSdkRuntime } from './shared-fixture-adapter.mjs';
import { createSimulator } from './routes-sim.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

/** A mock identity has not logged in to this visitor runtime. */
export class NotAuthenticatedError extends Error {}

async function closeResources(scoped, sessions) {
  const failures = [];
  if (scoped) {
    try {
      await scoped.close();
    } catch (err) {
      failures.push(err);
    }
  }
  sessions.clear();
  if (failures.length) throw new AggregateError(failures, 'Failed to close visitor runtime resources');
}

/**
 * Create one visitor's SDK scope and simulator over the process-wide pools.
 * Identity, credentials and audit stay in the visitor's ephemeral SQLite store;
 * PostgreSQL connections are borrowed from the shared fixture and direct pools.
 */
export async function createVisitorRuntime({
  sharedFixture,
  directSqlPool,
  masterKeyBuffer,
  userCeilings,
  readBody,
  rejected,
  metrics,
}) {
  if (!sharedFixture?.pool) throw new Error('Visitor runtime requires the shared fixture pool');
  if (!directSqlPool) throw new Error('Visitor runtime requires the shared direct SQL pool');

  const sessions = new Map();
  let scoped;
  let simulator;
  try {
    scoped = await createScopedSdkRuntime({ sharedFixture, masterKeyBuffer });
    simulator = await createSimulator({
      pool: sharedFixture.pool,
      directSqlPool,
      scope: scoped.scope,
      readBody,
      rejected,
      metrics,
    });
  } catch (err) {
    try {
      await closeResources(scoped, sessions);
    } catch (closeErr) {
      logSafeError(console, 'error', 'Visitor runtime cleanup failed after initialization error', closeErr);
    }
    throw err;
  }

  let closePromise;
  return {
    scope: scoped.scope,
    simulator: { routes: simulator.routes },
    async loginSession(alias) {
      if (!isConfiguredMockUser(alias)) throw new Error('Unknown mock identity');
      if (closePromise) throw new Error('Visitor runtime is closed');
      const session = await scoped.scope.authenticate({ mockHumanDid: alias, scopeCeiling: userCeilings[alias] });
      if (closePromise) throw new Error('Visitor runtime is closed');
      sessions.set(session.humanDid, session);
      return session;
    },
    getSession(humanDid) {
      const session = closePromise ? undefined : sessions.get(humanDid);
      if (!session) throw new NotAuthenticatedError(`No session for ${humanDid} — authenticate first`);
      return session;
    },
    close() {
      // Memoize only the attempt in flight so a failed close can be retried.
      closePromise ??= closeResources(scoped, sessions).catch((err) => {
        closePromise = undefined;
        throw err;
      });
      return closePromise;
    },
  };
}
