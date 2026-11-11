import { existsSync, readFileSync } from 'node:fs';
import { parseTrustedProxyNetwork } from './request-policy.mjs';

export class HttpBoundaryConfigurationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
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

export function loadEnvironment(content, env = process.env) {
  for (const line of content.split('\n')) {
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (match && !env[match[1]]) env[match[1]] = match[2];
  }
}

export function loadEnvFile(path, env = process.env) {
  if (existsSync(path)) loadEnvironment(readFileSync(path, 'utf8'), env);
}

export function resolveAdminDatabaseUrl(env) {
  return env.PLAYGROUND_ADMIN_DATABASE_URL ?? env.DATABASE_URL;
}

export function adminDatabaseUrlEnvironmentEntry(contents, adminDatabaseUrl) {
  const existingAdminUrl = contents.match(/^PLAYGROUND_ADMIN_DATABASE_URL=(.*)$/m)?.[1];
  const existingDatabaseUrl = contents.match(/^DATABASE_URL=(.*)$/m)?.[1];
  if (existingAdminUrl !== undefined || existingDatabaseUrl === adminDatabaseUrl) return {};
  return { PLAYGROUND_ADMIN_DATABASE_URL: adminDatabaseUrl };
}
