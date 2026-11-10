/** Playground HTTP server backed by one isolated VisitorRuntime per browser session. */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
import {
  loadEnvFile,
  HttpBoundaryConfigurationError,
  resolveAdminDatabaseUrl,
  resolveHttpBoundaryConfig,
  resolveVisitorSessionRateLimit,
} from './env-file.mjs';
import { parseBody, resolveHostGatewayIps } from './request-policy.mjs';
import { createVisitorDatabaseProvisioner } from './visitor-database-provisioner.mjs';
import { cleanupVisitorDatabasesAtStartup } from './visitor-database-startup.mjs';
import { createVisitorSessionRegistry } from './visitor-session-registry.mjs';
import { rejected, createVisitorHttpHandler, READINESS_CHECK_TIMEOUT_MS } from './visitor-http.mjs';
import { shutdownVisitorServer } from './visitor-server-lifecycle.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

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

async function start() {
  const envPath = process.env.PLAYGROUND_ENV_FILE
    ? resolve(process.env.PLAYGROUND_ENV_FILE)
    : join(root, '.env');
  loadEnvFile(envPath);
  const httpBoundaryConfig = resolveHttpBoundaryConfig(process.env);
  const sessionRateLimit = resolveVisitorSessionRateLimit(process.env);

  const appDatabaseUrl = process.env.PLAYGROUND_RUNTIME_DATABASE_URL;
  const adminConfiguredUrl = resolveAdminDatabaseUrl(process.env);
  const naiveDbPassword = process.env.PLAYGROUND_NAIVE_DB_PASSWORD;
  const port = Number(process.env.PORT ?? 3100);
  const host = process.env.HOST ?? '127.0.0.1';
  if (!naiveDbPassword) throw new Error('PLAYGROUND_NAIVE_DB_PASSWORD is missing; run npm run setup first');
  if (!appDatabaseUrl) throw new Error('PLAYGROUND_RUNTIME_DATABASE_URL is missing; run npm run setup first');
  if (!adminConfiguredUrl) throw new Error('PLAYGROUND_ADMIN_DATABASE_URL or DATABASE_URL is required for visitor sessions');
  if (!process.env.NODE_ENV) process.env.NODE_ENV = 'development';

  const trustComposeGateway = process.env.PLAYGROUND_TRUST_COMPOSE_GATEWAY === 'true';
  const hostGatewayIps = trustComposeGateway ? await resolveHostGatewayIps() : null;
  if (trustComposeGateway && hostGatewayIps === null) {
    throw new Error('PLAYGROUND_TRUST_COMPOSE_GATEWAY is enabled but no Docker host gateway was found');
  }

  const templateDatabaseName = decodeURIComponent(new URL(appDatabaseUrl).pathname.slice(1));
  const maintenanceDatabaseName = templateDatabaseName === 'postgres' ? 'template1' : 'postgres';
  const adminUrl = new URL(adminConfiguredUrl);
  adminUrl.pathname = `/${maintenanceDatabaseName}`;
  const adminDatabaseUrl = adminUrl.toString();
  const adminPool = new pg.Pool({
    connectionString: adminDatabaseUrl,
    application_name: 'agents-playground-admin',
    max: 1,
  });
  adminPool.on('error', (err) => {
    logSafeError(console, 'error', 'Administrative database pool connection failed', err);
  });

  const provisioner = await createVisitorDatabaseProvisioner({
    adminPool,
    adminDatabaseUrl,
    templateDatabaseName,
    appDatabaseUrl,
  });
  await cleanupVisitorDatabasesAtStartup({
    adminPool,
    provisioner,
  });

  const masterKeyHex = process.env.AGENTS_MASTER_KEY;
  resolveMasterKeyFromEnv().fill(0);
  const registry = createVisitorSessionRegistry({
    provisioner,
    runtimeOptions: {
      masterKeyHex,
      naiveDbPassword,
      userCeilings: USER_CEILINGS,
      readBody: parseBody,
      rejected,
    },
    maxSessions: Number(process.env.PLAYGROUND_MAX_VISITOR_SESSIONS ?? 10),
    inactivityTtlMs: Number(process.env.PLAYGROUND_VISITOR_INACTIVITY_TTL_MS ?? 30 * 60 * 1000),
  });

  const server = createServer(createVisitorHttpHandler({
    registry,
    libraryVersion,
    httpBoundaryConfig,
    hostGatewayIps,
    publicRoot: join(root, 'public'),
    checkReadiness: () => adminPool.query({
      text: 'SELECT 1',
      query_timeout: READINESS_CHECK_TIMEOUT_MS,
    }),
    sessionRateLimit,
  }));
  server.on('error', (err) => {
    logSafeError(console, 'error', 'Visitor Playground HTTP server failed', err);
    process.exitCode = 1;
  });
  server.listen(port, host, () => {
    console.log(`\nDemo Agents++ → http://${host}:${port}`);
    console.log(`HTTP boundary mode: ${httpBoundaryConfig.mode}`);
    console.log('Visitor sessions are provisioned lazily on login.');
  });

  let shutdownPromise;
  const shutdown = () => {
    shutdownPromise ??= shutdownVisitorServer({ server, registry, adminPool });
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
}

try {
  await start();
} catch (err) {
  if (err instanceof HttpBoundaryConfigurationError) {
    console.error('Visitor Playground startup configuration failed', { code: err.code });
  } else {
    logSafeError(console, 'error', 'Visitor Playground startup failed', err);
  }
  process.exitCode = 1;
}
