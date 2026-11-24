/** Playground HTTP server with signed session cookies over shared PostgreSQL pools. */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
import {
  loadEnvFile,
  HttpBoundaryConfigurationError,
  PlaygroundConfigurationError,
  resolveControlDatabaseUrl,
  resolveControlPoolMax,
  resolveDirectSqlPoolMax,
  resolveHttpBoundaryConfig,
  resolveSessionConfig,
  resolveSessionCookieKey,
  resolveSharedFixtureDatabaseUrl,
  resolveSharedPoolMax,
  resolveVisitorSessionRateLimit,
} from './env-file.mjs';
import { parseBody, resolveHostGatewayIps } from './request-policy.mjs';
import { createVisitorRuntime } from './visitor-runtime.mjs';
import { createSharedFixtureRuntime } from './shared-fixture-adapter.mjs';
import { createVisitorSessionRegistry } from './visitor-session-registry.mjs';
import { createVisitorSessionCleaner } from './visitor-session-cleaner.mjs';
import { createVisitorSessionStore } from './visitor-session-store.mjs';
import { createVisitorSessionCookie } from './visitor-session-cookie.mjs';
import { createVisitorSessionJanitor } from './visitor-session-janitor.mjs';
import { createPlaygroundMetrics } from './playground-metrics.mjs';
import { createVisitorHttpHandler, READINESS_CHECK_TIMEOUT_MS } from './visitor-http.mjs';
import { rejected } from './visitor-errors.mjs';
import { shutdownVisitorServer } from './visitor-server-lifecycle.mjs';
import { logSafeError } from './safe-diagnostics.mjs';
import { PLAYGROUND_NAIVE_ROLE } from '../scripts/setup-policy.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const repoRoot = resolve(root, '..', '..');
const { version: libraryVersion } = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));

const USER_CEILINGS = {
  alice: undefined,
  bob: {
    columns: ['orders.instrument', 'orders.side', 'orders.quantity', 'orders.status'],
    actions: ['read'],
    source: 'oidc-groups',
    resolvedFrom: ['desk-junior'],
  },
};

function poolUsage(pool) {
  if (!pool) return {};
  return {
    total: pool.totalCount,
    idle: pool.idleCount,
    waiting: pool.waitingCount,
    max: pool.options?.max ?? 0,
  };
}

async function start() {
  const envPath = process.env.PLAYGROUND_ENV_FILE
    ? resolve(process.env.PLAYGROUND_ENV_FILE)
    : join(root, '.env');
  loadEnvFile(envPath);
  const httpBoundaryConfig = resolveHttpBoundaryConfig(process.env);
  const sessionRateLimit = resolveVisitorSessionRateLimit(process.env);
  const sessionConfig = resolveSessionConfig(process.env);
  const directSqlPoolMax = resolveDirectSqlPoolMax(process.env);
  const controlPoolMax = resolveControlPoolMax(process.env);

  const appDatabaseUrl = process.env.PLAYGROUND_RUNTIME_DATABASE_URL;
  const naiveDbPassword = process.env.PLAYGROUND_NAIVE_DB_PASSWORD;
  const port = Number(process.env.PORT ?? 3100);
  const host = process.env.HOST ?? '127.0.0.1';
  if (!naiveDbPassword) throw new Error('PLAYGROUND_NAIVE_DB_PASSWORD is missing; run npm run setup first');
  if (!appDatabaseUrl) throw new Error('PLAYGROUND_RUNTIME_DATABASE_URL is missing; run npm run setup first');
  if (!process.env.NODE_ENV) process.env.NODE_ENV = 'development';

  const trustComposeGateway = process.env.PLAYGROUND_TRUST_COMPOSE_GATEWAY === 'true';
  const hostGatewayIps = trustComposeGateway ? await resolveHostGatewayIps() : null;
  if (trustComposeGateway && hostGatewayIps === null) {
    throw new Error('PLAYGROUND_TRUST_COMPOSE_GATEWAY is enabled but no Docker host gateway was found');
  }

  const runtimeDatabaseName = decodeURIComponent(new URL(appDatabaseUrl).pathname.slice(1));
  const controlDatabaseUrl = resolveControlDatabaseUrl(runtimeDatabaseName, appDatabaseUrl);

  const masterKeyBuffer = resolveMasterKeyFromEnv();
  let sessionCookieKey;
  let controlPool;
  let sharedFixture;
  let directSqlPool;
  let sessionStore;
  let sessionCookie;
  let registry;
  let janitor;
  const metrics = createPlaygroundMetrics();

  try {
    sessionCookieKey = resolveSessionCookieKey(process.env, masterKeyBuffer);

    controlPool = new pg.Pool({
      connectionString: controlDatabaseUrl,
      application_name: 'agents-playground-control',
      max: controlPoolMax,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 5_000,
    });
    controlPool.on('error', (err) => {
      logSafeError(console, 'error', 'Control database pool connection failed', err);
    });

    sessionStore = createVisitorSessionStore({
      pool: controlPool,
      ...sessionConfig,
      rateLimit: sessionRateLimit,
    });
    try {
      await controlPool.query({
        text: 'SELECT 1 FROM playground_sandbox_session LIMIT 1',
        query_timeout: READINESS_CHECK_TIMEOUT_MS,
      });
    } catch {
      throw new PlaygroundConfigurationError(
        'PLAYGROUND_CONTROL_SCHEMA_MISSING',
        'The Playground control database is unavailable or its schema is missing; run npm run setup first',
      );
    }

    sharedFixture = await createSharedFixtureRuntime({
      sharedDatabaseUrl: resolveSharedFixtureDatabaseUrl(process.env),
      poolMax: resolveSharedPoolMax(process.env),
    });

    const directUrl = new URL(sharedFixture.sharedDatabaseUrl);
    directUrl.username = PLAYGROUND_NAIVE_ROLE;
    directUrl.password = naiveDbPassword;
    directSqlPool = new pg.Pool({
      connectionString: directUrl.toString(),
      application_name: 'agents-playground-direct',
      max: directSqlPoolMax,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 5_000,
    });
    directSqlPool.on('error', (err) => {
      logSafeError(console, 'error', 'Direct SQL database pool connection failed', err);
    });
    await directSqlPool.query('SELECT 1');

    registry = createVisitorSessionRegistry({
      createRuntime: createVisitorRuntime,
      runtimeOptions: {
        sharedFixture,
        directSqlPool,
        masterKeyBuffer,
        userCeilings: USER_CEILINGS,
        readBody: parseBody,
        rejected,
        metrics,
      },
    });

    const sessionCleaner = createVisitorSessionCleaner({ registry, sessionStore });

    sessionCookie = createVisitorSessionCookie({
      key: sessionCookieKey,
      absoluteTtlMs: sessionConfig.absoluteTtlMs,
    });

    janitor = createVisitorSessionJanitor({
      store: sessionStore,
      intervalMs: sessionConfig.janitor.intervalMs,
      batchSize: sessionConfig.janitor.batchSize,
      maxAttempts: sessionConfig.janitor.maxAttempts,
      retryDelayMs: sessionConfig.janitor.retryDelayMs,
      metrics,
      onExpired: (entry) => sessionCleaner.dispose(entry),
      onSweep: async () => {
        const { failures } = await registry.expireLocal({
          absoluteTtlMs: sessionConfig.absoluteTtlMs,
          inactivityTtlMs: sessionConfig.inactivityTtlMs,
        });
        for (const err of failures) {
          logSafeError(console, 'error', 'Locally expired visitor runtime cleanup failed', err);
        }
      },
    });

    const server = createServer(createVisitorHttpHandler({
      registry,
      sessionStore,
      sessionCleaner,
      sessionCookie,
      metrics,
      poolUsage: () => ({
        shared: poolUsage(sharedFixture.pool),
        direct: poolUsage(directSqlPool),
        control: poolUsage(controlPool),
      }),
      libraryVersion,
      httpBoundaryConfig,
      hostGatewayIps,
      publicRoot: join(root, 'public'),
      checkReadiness: () => Promise.all([
        controlPool.query({
          text: 'SELECT 1 FROM playground_sandbox_session LIMIT 1',
          query_timeout: READINESS_CHECK_TIMEOUT_MS,
        }),
        sharedFixture.pool.query({
          text: 'SELECT 1',
          query_timeout: READINESS_CHECK_TIMEOUT_MS,
        }),
      ]),
    }));
    server.on('error', (err) => {
      logSafeError(console, 'error', 'Visitor Playground HTTP server failed', err);
      process.exitCode = 1;
    });
    janitor.start();
    server.listen(port, host, () => {
      console.log(`\nDemo Agents++ → http://${host}:${port}`);
      console.log(`HTTP boundary mode: ${httpBoundaryConfig.mode}`);
      console.log(
        `Visitor sessions: ${sessionConfig.absoluteTtlMs} ms absolute, ` +
        `${sessionConfig.inactivityTtlMs} ms inactivity, global cap ${sessionConfig.maxSessions}`,
      );
      console.log(
        `Pools per process: shared ${poolUsage(sharedFixture.pool).max}, direct ${directSqlPoolMax}, ` +
        `control ${controlPoolMax}`,
      );
      console.log('Visitor sessions start lazily on login.');
    });

    let shutdownPromise;
    const shutdown = () => {
      shutdownPromise ??= (async () => {
        const failures = [];
        try {
          await shutdownVisitorServer({
            server,
            registry,
            janitor,
            sessionStore,
            directSqlPool,
            controlPool,
            sessionCookie,
          });
        } catch (err) {
          failures.push(err);
        }
        masterKeyBuffer.fill(0);
        try {
          await sharedFixture.close();
        } catch (err) {
          failures.push(err);
        }
        if (failures.length === 1) throw failures[0];
        if (failures.length > 1) throw new AggregateError(failures, 'Visitor Playground shutdown was incomplete');
      })();
      return shutdownPromise;
    };
    for (const signal of ['SIGINT', 'SIGTERM']) {
      process.on(signal, async () => {
        try {
          await shutdown();
        } catch (err) {
          logSafeError(console, 'error', 'Visitor Playground shutdown failed', err);
          process.exitCode = 1;
        }
      });
    }
  } catch (err) {
    await janitor?.stop().catch(() => {});
    await registry?.closeAll().catch(() => {});
    await directSqlPool?.end().catch(() => {});
    await controlPool?.end().catch(() => {});
    await sharedFixture?.close().catch(() => {});
    sessionCookie?.close();
    sessionCookieKey?.fill(0);
    masterKeyBuffer.fill(0);
    throw err;
  }
}

try {
  await start();
} catch (err) {
  if (err instanceof HttpBoundaryConfigurationError || err instanceof PlaygroundConfigurationError) {
    console.error('Visitor Playground startup configuration failed', { code: err.code, message: err.message });
  } else {
    logSafeError(console, 'error', 'Visitor Playground startup failed', err);
  }
  process.exitCode = 1;
}
