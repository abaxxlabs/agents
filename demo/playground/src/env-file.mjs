import { existsSync, readFileSync } from 'node:fs';
import { parseTrustedProxyNetwork } from './request-policy.mjs';
import { PLAYGROUND_APP_ROLE } from '../scripts/setup-policy.mjs';
import { deriveVisitorSessionCookieKey } from './visitor-session-cookie.mjs';

export class HttpBoundaryConfigurationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/** A Playground runtime setting is missing or inconsistent. */
export class PlaygroundConfigurationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * Resolve the database that serves scoped reads. It must be a separate copy of
 * the fixture so scoped reads and direct SQL never share a connection budget.
 */
export function resolveSharedFixtureDatabaseUrl(env) {
  const sharedValue = env.PLAYGROUND_SHARED_DATABASE_URL;
  if (!sharedValue) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_MISSING',
      'PLAYGROUND_SHARED_DATABASE_URL is missing; run npm run setup first',
    );
  }
  let shared;
  try {
    shared = new URL(sharedValue);
  } catch {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_INVALID',
      'PLAYGROUND_SHARED_DATABASE_URL must be a valid PostgreSQL URL',
    );
  }

  let sharedName;
  try {
    sharedName = decodeURIComponent(shared.pathname.slice(1));
  } catch {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID',
      'PLAYGROUND_SHARED_DATABASE_URL must name a database',
    );
  }
  let sharedRole;
  try {
    sharedRole = decodeURIComponent(shared.username);
  } catch {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_ROLE_INVALID',
      `PLAYGROUND_SHARED_DATABASE_URL must connect as ${PLAYGROUND_APP_ROLE}`,
    );
  }
  if (sharedRole !== PLAYGROUND_APP_ROLE) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_ROLE_INVALID',
      `PLAYGROUND_SHARED_DATABASE_URL must connect as ${PLAYGROUND_APP_ROLE}`,
    );
  }

  const runtimeValue = env.PLAYGROUND_RUNTIME_DATABASE_URL;
  if (!runtimeValue) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_RUNTIME_DATABASE_URL_INVALID',
      'PLAYGROUND_RUNTIME_DATABASE_URL is required to validate the shared fixture database',
    );
  }
  let runtime;
  try {
    runtime = new URL(runtimeValue);
  } catch {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_RUNTIME_DATABASE_URL_INVALID',
      'PLAYGROUND_RUNTIME_DATABASE_URL must be a valid PostgreSQL URL',
    );
  }
  let runtimeName;
  try {
    runtimeName = decodeURIComponent(runtime.pathname.slice(1));
  } catch {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_RUNTIME_DATABASE_URL_INVALID',
      'PLAYGROUND_RUNTIME_DATABASE_URL must name a database',
    );
  }
  if (shared.hostname !== runtime.hostname || (shared.port || '5432') !== (runtime.port || '5432')) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID',
      'PLAYGROUND_SHARED_DATABASE_URL must target the runtime server',
    );
  }
  const expectedName = `${runtimeName}_shared`;
  if (!sharedName || sharedName !== expectedName) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID',
      `PLAYGROUND_SHARED_DATABASE_URL must name the ${expectedName} database`,
    );
  }
  return shared.toString();
}

/** Resolve the maximum size of the process-wide shared fixture pool. */
export function resolveSharedPoolMax(env) {
  const max = Number(env.PLAYGROUND_SHARED_POOL_MAX ?? 10);
  if (!Number.isSafeInteger(max) || max < 1) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SHARED_POOL_MAX_INVALID',
      'PLAYGROUND_SHARED_POOL_MAX must be a positive integer',
    );
  }
  return max;
}

export function resolveHttpBoundaryConfig(env) {
  const mode = env.PLAYGROUND_HTTP_MODE ?? 'local';
  if (mode !== 'local' && mode !== 'public') {
    throw new HttpBoundaryConfigurationError('PLAYGROUND_HTTP_MODE_INVALID', 'PLAYGROUND_HTTP_MODE must be local or public');
  }

  if (mode === 'local') return { mode };

  const configuredOrigin = env.PLAYGROUND_PUBLIC_ORIGIN;
  if (!configuredOrigin) {
    throw new HttpBoundaryConfigurationError('PLAYGROUND_PUBLIC_ORIGIN_MISSING', 'PLAYGROUND_PUBLIC_ORIGIN is required in public mode');
  }
  let publicOrigin;
  try {
    const parsedOrigin = new URL(configuredOrigin);
    if (parsedOrigin.protocol !== 'https:' || parsedOrigin.username || parsedOrigin.password ||
      parsedOrigin.pathname !== '/' || parsedOrigin.search || parsedOrigin.hash) {
      throw new Error();
    }
    publicOrigin = parsedOrigin.origin;
  } catch {
    throw new HttpBoundaryConfigurationError(
      'PLAYGROUND_PUBLIC_ORIGIN_INVALID',
      'PLAYGROUND_PUBLIC_ORIGIN must be an HTTPS origin without a path, query, or credentials',
    );
  }

  const trustedProxyNetworks = (env.PLAYGROUND_TRUSTED_PROXY_IPS ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (trustedProxyNetworks.length === 0) {
    throw new HttpBoundaryConfigurationError(
      'PLAYGROUND_TRUSTED_PROXY_IPS_INVALID',
      'PLAYGROUND_TRUSTED_PROXY_IPS must contain one or more comma-separated IP addresses or CIDR networks',
    );
  }
  const parsedNetworks = trustedProxyNetworks.map((entry) => ({ entry, network: parseTrustedProxyNetwork(entry) }));
  const invalid = parsedNetworks.find(({ network }) => network === null);
  if (invalid !== undefined) {
    throw new HttpBoundaryConfigurationError(
      'PLAYGROUND_TRUSTED_PROXY_IPS_INVALID',
      `PLAYGROUND_TRUSTED_PROXY_IPS contains an invalid IP address or CIDR network: ${invalid.entry}`,
    );
  }

  const seen = new Set();
  const networks = [];
  for (const { network } of parsedNetworks) {
    const key = `${network.family === 4 ? '4' : '6'}:${network.prefix}:${network.net.join('.')}`;
    if (!seen.has(key)) {
      seen.add(key);
      networks.push(network);
    }
  }

  return { mode, publicOrigin, trustedProxyNetworks: networks };
}

export function resolveVisitorSessionRateLimit(env) {
  const maxNewSessions = Number(env.PLAYGROUND_NEW_SESSION_RATE_LIMIT ?? 10);
  const windowMs = Number(env.PLAYGROUND_NEW_SESSION_RATE_WINDOW_MS ?? 60_000);
  if (!Number.isSafeInteger(maxNewSessions) || maxNewSessions < 1) {
    throw new Error('PLAYGROUND_NEW_SESSION_RATE_LIMIT must be a positive safe integer');
  }
  if (!Number.isSafeInteger(windowMs) || windowMs < 1) {
    throw new Error('PLAYGROUND_NEW_SESSION_RATE_WINDOW_MS must be a positive safe integer');
  }
  return { maxNewSessions, windowMs };
}

function positiveIntegerSetting(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new PlaygroundConfigurationError(`${name}_INVALID`, `${name} must be a positive safe integer`);
  }
  return parsed;
}

/** Resolve the signed-cookie, global admission and janitor settings. */
export function resolveSessionConfig(env) {
  const absoluteTtlMs = positiveIntegerSetting(
    env.PLAYGROUND_SESSION_ABSOLUTE_TTL_MS ?? 4 * 60 * 60 * 1000,
    'PLAYGROUND_SESSION_ABSOLUTE_TTL_MS',
  );
  const inactivityTtlMs = positiveIntegerSetting(
    env.PLAYGROUND_SESSION_INACTIVITY_TTL_MS ?? env.PLAYGROUND_VISITOR_INACTIVITY_TTL_MS ?? 60 * 60 * 1000,
    'PLAYGROUND_SESSION_INACTIVITY_TTL_MS',
  );
  const maxSessions = positiveIntegerSetting(
    env.PLAYGROUND_MAX_VISITOR_SESSIONS ?? 10,
    'PLAYGROUND_MAX_VISITOR_SESSIONS',
  );
  if (inactivityTtlMs > absoluteTtlMs) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SESSION_TTLS_INCONSISTENT',
      'PLAYGROUND_SESSION_INACTIVITY_TTL_MS must not exceed PLAYGROUND_SESSION_ABSOLUTE_TTL_MS',
    );
  }
  return {
    absoluteTtlMs,
    inactivityTtlMs,
    maxSessions,
    janitor: {
      intervalMs: positiveIntegerSetting(
        env.PLAYGROUND_SESSION_JANITOR_INTERVAL_MS ?? 30_000,
        'PLAYGROUND_SESSION_JANITOR_INTERVAL_MS',
      ),
      batchSize: positiveIntegerSetting(
        env.PLAYGROUND_SESSION_JANITOR_BATCH_SIZE ?? 100,
        'PLAYGROUND_SESSION_JANITOR_BATCH_SIZE',
      ),
      maxAttempts: positiveIntegerSetting(
        env.PLAYGROUND_SESSION_JANITOR_MAX_ATTEMPTS ?? 3,
        'PLAYGROUND_SESSION_JANITOR_MAX_ATTEMPTS',
      ),
      retryDelayMs: positiveIntegerSetting(
        env.PLAYGROUND_SESSION_JANITOR_RETRY_DELAY_MS ?? 250,
        'PLAYGROUND_SESSION_JANITOR_RETRY_DELAY_MS',
      ),
    },
  };
}

/** Resolve the size of the process-wide direct-SQL pool. */
export function resolveDirectSqlPoolMax(env) {
  return positiveIntegerSetting(env.PLAYGROUND_DIRECT_SQL_POOL_MAX ?? 2, 'PLAYGROUND_DIRECT_SQL_POOL_MAX');
}

/** Resolve the size of the process-wide admission and session metadata pool. */
export function resolveControlPoolMax(env) {
  return positiveIntegerSetting(env.PLAYGROUND_CONTROL_POOL_MAX ?? 4, 'PLAYGROUND_CONTROL_POOL_MAX');
}

/**
 * Derive the control database URL from the runtime name and the restricted
 * runtime credentials. The serving process must never need administrative
 * privileges, so the control pool connects with the same login as scoped reads.
 */
export function resolveControlDatabaseUrl(runtimeDatabaseName, runtimeDatabaseUrl) {
  if (typeof runtimeDatabaseName !== 'string' || !runtimeDatabaseName) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_CONTROL_DATABASE_NAME_INVALID',
      'The Playground runtime database name is required to derive the control database',
    );
  }
  const name = `${runtimeDatabaseName}_control`;
  if (name.length > 63) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_CONTROL_DATABASE_NAME_INVALID',
      'The Playground database name must be at most 55 characters so the control database name fits',
    );
  }
  let url;
  try {
    url = new URL(runtimeDatabaseUrl);
  } catch {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_CONTROL_DATABASE_URL_INVALID',
      'PLAYGROUND_RUNTIME_DATABASE_URL must be a valid PostgreSQL URL',
    );
  }
  let role;
  try {
    role = decodeURIComponent(url.username);
  } catch {
    role = '';
  }
  if (role !== PLAYGROUND_APP_ROLE || url.searchParams.has('user') || url.searchParams.has('password')) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_RUNTIME_DATABASE_URL_ROLE_INVALID',
      `PLAYGROUND_RUNTIME_DATABASE_URL must connect as ${PLAYGROUND_APP_ROLE} without credential overrides`,
    );
  }
  url.pathname = `/${name}`;
  return url.toString();
}

/**
 * Resolve the cookie signing key. Every replica must share it; by default it is
 * derived from the master key so the existing key distribution is sufficient.
 */
export function resolveSessionCookieKey(env, masterKeyBuffer) {
  const configured = env.PLAYGROUND_SESSION_COOKIE_KEY;
  if (configured === undefined || configured === '') {
    return deriveVisitorSessionCookieKey(masterKeyBuffer);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(configured)) {
    throw new PlaygroundConfigurationError(
      'PLAYGROUND_SESSION_COOKIE_KEY_INVALID',
      'PLAYGROUND_SESSION_COOKIE_KEY must be a 64-character hex value',
    );
  }
  return Buffer.from(configured, 'hex');
}

export function loadEnvironment(content, env = process.env) {
  for (const line of content.split('\n')) {
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (match && !env[match[1]]) env[match[1]] = match[2];
  }
}

export function loadEnvFile(path, env = process.env) {
  if (existsSync(path)) loadEnvironment(readFileSync(path, 'utf8'), env);
}

/** Remove one assignment from an env file body, leaving the remaining lines intact. */
export function withoutEnvironmentEntry(contents, name) {
  return contents.replace(new RegExp(`^${name}=.*\\n?`, 'm'), '');
}
