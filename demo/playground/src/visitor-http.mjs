import { ScopeExceedsCeilingError } from '@abaxxlabs/agents';
import { AgentScopeError } from '@abaxxlabs/agents/sql';
import { existsSync, readFileSync } from 'node:fs';
import { extname, resolve, sep } from 'node:path';
import {
  ORDER_TABLE,
  RequestBodyTooLargeError,
  areKnownOrderColumns,
  consumeBody,
  isConfiguredMockUser,
  isJsonContentType,
  isValidAgentName,
  parseBody,
  requestPassesBoundary,
  requestClientAddress,
} from './request-policy.mjs';
import { NotAuthenticatedError } from './visitor-runtime.mjs';
import {
  VisitorRegistryClosingError,
  VisitorSessionCapacityError,
  VisitorSessionCleanupError,
  VisitorSessionNotFoundError,
  VisitorSessionUnavailableError,
} from './visitor-session-registry.mjs';
import { allowedQueryInspection, rejectedQueryInspection } from './query-inspection.mjs';
import { logSafeError } from './safe-diagnostics.mjs';
import { createVisitorSessionRateLimiter } from './visitor-session-rate-limiter.mjs';

const VISITOR_COOKIE = 'visitorSessionId';
const PUBLIC_VISITOR_COOKIE = '__Host-visitorSessionId';
const EXPIRE_LEGACY_VISITOR_COOKIE = Symbol('expireLegacyVisitorCookie');
const VISITOR_SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SIMULATOR_ROUTES = [
  'GET /api/sim/agent',
  'POST /api/sim/config',
  'POST /api/sim/raw',
  'POST /api/sim/scoped',
  'POST /api/sim/reset',
  'GET /api/sim/raw-bytes',
];
const DOMAIN_ERROR_CODES = new Set([
  'CREDENTIAL_INVALID',
  'CREDENTIAL_EXPIRED',
  'CREDENTIAL_REVOKED',
  'CREDENTIAL_MALFORMED',
  'CREDENTIAL_REPLAYED',
  'UNKNOWN_ISSUER',
  'QUERY_REJECTED',
  'SCOPE_VIOLATION',
  'TTL_EXCEEDED',
  'UNTRUSTED_ISSUER',
  'WRONG_ORG',
  'UNAUTHORIZED',
  'PARENT_SCOPE_EXCEEDED',
]);
const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
};
export const READINESS_CHECK_TIMEOUT_MS = 2_000;
const READINESS_CACHE_TTL_MS = 2_000;

function errorPayload(err) {
  return { error: err.constructor?.name ?? 'Error', message: err.message };
}

function isDomainRejection(err) {
  return (err instanceof AgentScopeError && DOMAIN_ERROR_CODES.has(err.code)) ||
    err instanceof ScopeExceedsCeilingError ||
    (err instanceof Error && err.message.startsWith('Delegation error:'));
}

function isDelegationRejection(err) {
  return err instanceof Error && /^(Delegation error:|Agent .* not found\.|Source credential)/.test(err.message);
}

export function rejected(err, extra = {}) {
  if (!isDomainRejection(err)) throw err;
  return [403, { ...extra, ...errorPayload(err) }];
}

class DuplicateVisitorSessionCookieError extends Error {}

function visitorSessionId(req, cookieName) {
  let sessionId;
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== cookieName) continue;
    let value;
    try {
      value = decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      continue;
    }
    if (!VISITOR_SESSION_ID_PATTERN.test(value)) continue;
    if (sessionId !== undefined) throw new DuplicateVisitorSessionCookieError();
    sessionId = value;
  }
  return sessionId;
}

function hasCookie(req, cookieName) {
  return (req.headers.cookie ?? '').split(';').some((part) => {
    const separator = part.indexOf('=');
    return separator >= 0 && part.slice(0, separator).trim() === cookieName;
  });
}

function send(res, code, body, headers = {}) {
  res.writeHead(code, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body, null, 2));
}

function visitorRoute(registry, cookieName, handler) {
  return async (req, url) => {
    const sessionId = visitorSessionId(req, cookieName);
    if (!sessionId) throw new VisitorSessionNotFoundError('Visitor session cookie is missing');
    const runtime = registry.getSession(sessionId);
    registry.touchSession(sessionId);
    return handler(runtime, req, url);
  };
}

/** Create the HTTP handler; all visitor data routes resolve resources through the registry. */
export function createVisitorHttpHandler({
  registry,
  libraryVersion,
  httpBoundaryConfig,
  hostGatewayIps,
  publicRoot,
  checkReadiness = async () => {},
  sessionRateLimit = { maxNewSessions: 10, windowMs: 60_000 },
}) {
  const sessionRateLimiter = createVisitorSessionRateLimiter(sessionRateLimit);
  const visitorCookieName = httpBoundaryConfig?.mode === 'public' ? PUBLIC_VISITOR_COOKIE : VISITOR_COOKIE;
  const securityHeaders = {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    ...(httpBoundaryConfig?.mode === 'public' ? { 'strict-transport-security': 'max-age=31536000' } : {}),
  };
  const visitorCookieAttributes = [
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    ...(httpBoundaryConfig?.mode === 'public' ? ['Secure'] : []),
  ].join('; ');
  const legacyVisitorCookie = [
    `${VISITOR_COOKIE}=`,
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'HttpOnly',
    'SameSite=Lax',
    'Path=/api',
    ...(httpBoundaryConfig?.mode === 'public' ? ['Secure'] : []),
  ].join('; ');
  let readinessResult;
  let readinessQuery;
  // Share a pending check so timed-out probes cannot queue duplicate admin queries.
  const checkReadinessWithinTimeout = () => {
    readinessQuery ??= Promise.resolve().then(checkReadiness).finally(() => {
      readinessQuery = undefined;
    });
    let timer;
    return Promise.race([
      readinessQuery,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Readiness check timed out')), READINESS_CHECK_TIMEOUT_MS);
      }),
    ]).finally(() => clearTimeout(timer));
  };
  const routes = {
    'GET /api/status': async () => [200, { status: 'ok', libraryVersion }],

    'POST /api/login': async (req) => {
      const { humanDid } = parseBody(req);
      if (!isConfiguredMockUser(humanDid)) {
        return [400, { error: 'ValidationError', message: 'humanDid must be alice or bob' }];
      }

      let sessionId;
      try {
        sessionId = visitorSessionId(req, visitorCookieName);
      } catch (err) {
        if (!(err instanceof DuplicateVisitorSessionCookieError) || visitorCookieName !== VISITOR_COOKIE) throw err;
        req[EXPIRE_LEGACY_VISITOR_COOKIE] = true;
      }
      let runtime;
      if (sessionId) {
        try {
          runtime = registry.getSession(sessionId);
          registry.touchSession(sessionId);
        } catch (err) {
          if (!(err instanceof VisitorSessionNotFoundError)) throw err;
          sessionId = undefined;
        }
      }
      if (!runtime) {
        const admission = sessionRateLimiter.consumeNewSession(requestClientAddress(req, httpBoundaryConfig));
        if (!admission.allowed) {
          return [429, {
            error: 'RateLimitExceeded',
            message: 'New visitor session limit reached; retry later',
          }, { 'retry-after': String(Math.ceil(admission.retryAfterMs / 1000)) }];
        }
        try {
          await registry.cleanupExpiredSessions();
        } catch (err) {
          if (!(err instanceof AggregateError) || err.errors.length === 0 ||
            !err.errors.every((failure) => failure instanceof VisitorSessionCleanupError)) {
            throw err;
          }
          for (const failure of err.errors) {
            logSafeError(
              console,
              'warn',
              'Expired visitor session cleanup failed; continuing login',
              failure.dropError ?? failure.closeError ?? failure,
            );
          }
        }
        ({ sessionId, runtime } = await registry.createSession());
      }

      const session = await runtime.loginSession(humanDid);
      const ceiling = session.scopeCeiling;
      return [200, {
        humanDid: session.humanDid,
        ceiling: {
          columns: ceiling.columns,
          actions: ceiling.actions,
          source: ceiling.source,
          resolvedFrom: ceiling.resolvedFrom,
          credentialMaxTtlMs: ceiling.credentialMaxTtlMs,
        },
      }, { 'set-cookie': [
        `${visitorCookieName}=${encodeURIComponent(sessionId)}; ${visitorCookieAttributes}`,
        legacyVisitorCookie,
      ] }];
    },

    'GET /api/agents': visitorRoute(registry, visitorCookieName, async (runtime, req, url) => {
      const ownerDid = url.searchParams.get('ownerDid') ?? undefined;
      return [200, { agents: await runtime.scope.listAgents({ ownerDid }) }];
    }),

    'POST /api/agents': visitorRoute(registry, visitorCookieName, async (runtime, req) => {
      const { humanDid, name } = parseBody(req);
      if (!humanDid || !isValidAgentName(name)) {
        return [400, { error: 'ValidationError', message: 'humanDid required and name must be an identifier of 1 to 64 characters' }];
      }
      const session = runtime.getSession(humanDid);
      const agent = await runtime.scope.createAgentIdentity({ name, ownerDid: session.humanDid });
      return [201, { did: agent.did, name: agent.name, ownerDid: agent.ownerDid, publicKey: Buffer.from(agent.publicKey).toString('hex') }];
    }),

    'POST /api/credentials': visitorRoute(registry, visitorCookieName, async (runtime, req) => {
      const { humanDid, agent, columns, expiresIn } = parseBody(req);
      if (!humanDid || !agent || !areKnownOrderColumns(columns)) {
        return [400, { error: 'ValidationError', message: 'humanDid, agent and valid orders columns[] required' }];
      }
      const session = runtime.getSession(humanDid);
      try {
        const credential = await session.issueCredential({
          agent,
          columns,
          actions: ['read'],
          expiresIn: expiresIn ?? '1h',
        });
        return [201, { credential }];
      } catch (err) {
        return rejected(err);
      }
    }),

    'POST /api/delegate': visitorRoute(registry, visitorCookieName, async (runtime, req) => {
      const { sourceAgentDid, sourceCredential, targetAgentDid, columns, expiresIn } = parseBody(req);
      if (!sourceAgentDid || !sourceCredential || !targetAgentDid || !areKnownOrderColumns(columns)) {
        return [400, { error: 'ValidationError', message: 'sourceAgentDid, sourceCredential, targetAgentDid and valid orders columns[] required' }];
      }
      try {
        const credential = await runtime.scope.delegateCredential(sourceAgentDid, sourceCredential, {
          targetAgent: targetAgentDid,
          columns,
          actions: ['read'],
          expiresIn: expiresIn ?? '15m',
        });
        return [201, { credential }];
      } catch (err) {
        if (isDelegationRejection(err)) return [403, errorPayload(err)];
        return rejected(err);
      }
    }),

    'POST /api/query': visitorRoute(registry, visitorCookieName, async (runtime, req) => {
      const { agent, credential, sql, table } = parseBody(req);
      if (!agent || !credential || typeof sql !== 'string' || !sql || (table !== undefined && table !== ORDER_TABLE)) {
        return [400, { error: 'ValidationError', message: 'agent, credential and sql required; table can only be orders' }];
      }
      try {
        const result = await runtime.scope.query({ agent, credential, sql, table: ORDER_TABLE });
        return [200, { ok: true, ...result, inspection: allowedQueryInspection(agent, sql, result.metadata) }];
      } catch (err) {
        return rejected(err, { ok: false, inspection: rejectedQueryInspection(agent, sql, err) });
      }
    }),

    'GET /api/audit': visitorRoute(registry, visitorCookieName, async (runtime) => {
      const records = await runtime.scope.auditLoggerInstance.export();
      return [200, { records: records.slice(-50).reverse() }];
    }),

    'POST /api/audit/verify': visitorRoute(registry, visitorCookieName, async (runtime) => [
      200,
      await runtime.scope.auditLoggerInstance.verifyAuditChain(),
    ]),
  };

  for (const routeKey of SIMULATOR_ROUTES) {
    routes[routeKey] = visitorRoute(registry, visitorCookieName, (runtime, req, url) => {
      const handler = runtime.simulator.routes[routeKey];
      if (!handler) throw new Error(`Visitor simulator route is unavailable: ${routeKey}`);
      return handler(req, url);
    });
  }

  return async (req, res) => {
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch (err) {
      const apiRequest = typeof req.url === 'string' && req.url.startsWith('/api/');
      const responseHeaders = { ...securityHeaders };
      if (apiRequest) responseHeaders['cache-control'] = 'no-store';
      logSafeError(console, 'warn', 'Rejected malformed Playground request path', err);
      return send(res, 400, { error: 'BadRequest', message: 'Invalid request path' }, responseHeaders);
    }
    const apiRequest = url.pathname.startsWith('/api/');
    const respond = (code, body, headers = {}) => {
      const responseHeaders = { ...securityHeaders, ...headers };
      if (apiRequest) responseHeaders['cache-control'] = 'no-store';
      if (req[EXPIRE_LEGACY_VISITOR_COOKIE] ||
        (httpBoundaryConfig?.mode === 'public' && hasCookie(req, VISITOR_COOKIE))) {
        const cookies = responseHeaders['set-cookie'];
        const setCookies = Array.isArray(cookies) ? cookies : cookies ? [cookies] : [];
        if (!setCookies.includes(legacyVisitorCookie)) setCookies.push(legacyVisitorCookie);
        responseHeaders['set-cookie'] = setCookies;
      }
      return send(res, code, body, responseHeaders);
    };

    if (req.method === 'GET' && url.pathname === '/healthz') {
      return respond(200, { status: 'ok' }, { 'cache-control': 'no-store' });
    }
    if (req.method === 'GET' && url.pathname === '/readyz') {
      if (readinessResult && performance.now() < readinessResult.expiresAt) {
        return respond(readinessResult.ready ? 200 : 503,
          { status: readinessResult.ready ? 'ready' : 'not-ready' }, { 'cache-control': 'no-store' });
      }
      try {
        await checkReadinessWithinTimeout();
        readinessResult = { ready: true, expiresAt: performance.now() + READINESS_CACHE_TTL_MS };
        return respond(200, { status: 'ready' }, { 'cache-control': 'no-store' });
      } catch (err) {
        logSafeError(console, 'warn', 'Playground readiness check failed', err);
        readinessResult = { ready: false, expiresAt: performance.now() + READINESS_CACHE_TTL_MS };
        return respond(503, { status: 'not-ready' }, { 'cache-control': 'no-store' });
      }
    }

    if (!requestPassesBoundary(req, httpBoundaryConfig, hostGatewayIps)) {
      return respond(403, { error: 'Forbidden', message: 'Request does not satisfy the HTTP boundary policy' });
    }
    const key = `${req.method} ${url.pathname}`;
    try {
      if (apiRequest && (req.method === 'POST' || routes[key])) await consumeBody(req);
      if (req.method === 'POST' && url.pathname.startsWith('/api/') && !isJsonContentType(req.headers['content-type'])) {
        return respond(415, { error: 'UnsupportedMediaType', message: 'POST /api requests require application/json' });
      }
      if (routes[key]) {
        const [code, body, headers] = await routes[key](req, url);
        return respond(code, body, headers);
      }
      const path = url.pathname === '/' ? '/index.html' : url.pathname;
      const file = resolve(publicRoot, `.${path}`);
      if (!publicRoot || !file.startsWith(`${publicRoot}${sep}`)) {
        return respond(404, { error: 'NotFound', message: key });
      }
      if (!existsSync(file)) return respond(404, { error: 'NotFound', message: key });
      res.writeHead(200, { ...securityHeaders, 'content-type': MIME[extname(file)] ?? 'text/plain' });
      res.end(readFileSync(file));
    } catch (err) {
      if (err instanceof DuplicateVisitorSessionCookieError) {
        req[EXPIRE_LEGACY_VISITOR_COOKIE] = true;
        return respond(400, { error: 'InvalidSessionCookie', message: 'Multiple visitor session cookies are not allowed' });
      }
      if (err instanceof RequestBodyTooLargeError) return respond(413, errorPayload(err));
      if (err instanceof VisitorSessionNotFoundError || err instanceof VisitorSessionUnavailableError ||
        err instanceof NotAuthenticatedError) {
        return respond(401, { error: err.constructor?.name ?? 'Unauthorized', message: 'Visitor session is unavailable; authenticate before retrying' });
      }
      if (err instanceof VisitorSessionCapacityError) {
        return respond(503, { error: 'VisitorSessionCapacityError', message: 'Visitor session capacity has been reached' });
      }
      if (err instanceof VisitorRegistryClosingError) {
        return respond(503, { error: 'VisitorRegistryClosingError', message: 'Visitor sessions are temporarily unavailable' });
      }
      logSafeError(console, 'error', 'Playground request failed', err);
      respond(500, { error: 'InternalServerError', message: 'Request could not be completed' });
    }
  };
}
