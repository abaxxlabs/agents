import pg from 'pg';
import { AgentScope } from '@abaxxlabs/agents/sql';
import { parseMasterKeyHex } from '@abaxxlabs/agents/bootstrap';
import { isConfiguredMockUser } from './request-policy.mjs';
import { createSimulator } from './routes-sim.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

/** A mock identity has not logged in to this visitor runtime. */
export class NotAuthenticatedError extends Error {}

async function closeResources(scope, simulator, appPool, masterKey, sessions) {
  const failures = [];
  for (const close of [
    scope ? () => scope.close() : null,
    simulator ? () => simulator.close() : null,
    appPool ? () => appPool.end() : null,
  ]) {
    if (!close) continue;
    try {
      await close();
    } catch (err) {
      failures.push(err);
    }
  }
  sessions.clear();
  masterKey.fill(0);
  if (failures.length) throw new AggregateError(failures, 'Failed to close visitor runtime resources');
}

/** Create the scoped resources and mock sessions for one existing visitor database. */
export async function createVisitorRuntime({
  databaseName,
  appDatabaseUrl,
  masterKeyHex,
  naiveDbPassword,
  userCeilings,
  readBody,
  rejected,
}) {
  if (!databaseName || new URL(appDatabaseUrl).pathname.slice(1) !== databaseName) {
    throw new Error('appDatabaseUrl must target databaseName');
  }

  const masterKey = parseMasterKeyHex(masterKeyHex);
  const sessions = new Map();
  let appPool;
  let scope;
  let simulator;
  try {
    appPool = new pg.Pool({
      connectionString: appDatabaseUrl,
      application_name: 'agents-playground-server',
      max: 10,
      statement_timeout: 5_000,
    });
    appPool.on('error', (err) => {
      logSafeError(console, 'error', 'Visitor application database pool reported an idle connection error', err);
    });
    scope = await AgentScope.create({
      database: { connectionString: appDatabaseUrl },
      encryption: { columns: ['orders.price', 'orders.counterparty'] },
      audit: { enabled: true },
      credential: { maxTtl: '4h' },
      devMode: true,
    }, { masterKey, pool: appPool });
    simulator = await createSimulator({
      databaseUrl: appDatabaseUrl,
      naiveDbPassword,
      pool: appPool,
      scope,
      readBody,
      rejected,
    });
  } catch (err) {
    try {
      await closeResources(scope, simulator, appPool, masterKey, sessions);
    } catch (closeErr) {
      logSafeError(console, 'error', 'Visitor runtime cleanup failed after initialization error', closeErr);
    }
    throw err;
  }

  let closePromise;
  return {
    databaseName,
    scope,
    simulator: { routes: simulator.routes },
    async loginSession(alias) {
      if (!isConfiguredMockUser(alias)) throw new Error('Unknown mock identity');
      if (closePromise) throw new Error('Visitor runtime is closed');
      const session = await scope.authenticate({ mockHumanDid: alias, scopeCeiling: userCeilings[alias] });
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
      closePromise ??= closeResources(scope, simulator, appPool, masterKey, sessions);
      return closePromise;
    },
  };
}
