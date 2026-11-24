import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { extname, resolve, sep } from 'node:path';
import {
  RequestBodyTooLargeError,
  consumeBody,
  isJsonContentType,
  requestPassesBoundary,
  requestClientAddress,
} from './request-policy.mjs';
import { NotAuthenticatedError } from './visitor-runtime.mjs';
import { createVisitorRoutes } from './visitor-api-routes.mjs';
import {
  DuplicateVisitorSessionCookieError,
  SessionPlaneUnavailableError,
  errorPayload,
} from './visitor-errors.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

const VISITOR_COOKIE = 'visitorSessionId';
const PUBLIC_VISITOR_COOKIE = '__Host-visitorSessionId';
const EXPIRE_VISITOR_COOKIE = Symbol('expireVisitorCookie');
const EXPIRE_LEGACY_VISITOR_COOKIE = Symbol('expireLegacyVisitorCookie');
const ROUTE_NAMES = new Map([
  ['POST /api/login', 'login'],
  ['GET /api/agents', 'agents-list'],
  ['POST /api/agents', 'agents-create'],
  ['POST /api/credentials', 'credentials-issue'],
  ['POST /api/delegate', 'delegate'],
  ['POST /api/query', 'query'],
  ['GET /api/audit', 'audit-list'],
  ['GET /api/sim/agent', 'sim-agent'],
  ['POST /api/sim/config', 'sim-config'],
  ['POST /api/sim/raw', 'sim-raw'],
  ['POST /api/sim/scoped', 'sim-scoped'],
  ['POST /api/sim/reset', 'sim-reset'],
  ['GET /api/sim/raw-bytes', 'sim-raw-bytes'],
  ['GET /api/status', 'status'],
]);
const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
};
export const READINESS_CHECK_TIMEOUT_MS = 2_000;
const READINESS_CACHE_TTL_MS = 2_000;

class InvalidVisitorSessionCookieError extends Error {
  constructor(reason) {
    super(`Visitor session cookie is ${reason}`);
    this.reason = reason;
  }
}

class VisitorSessionLostError extends Error {
  constructor(reason) {
    super(`Visitor session is no longer available: ${reason}`);
    this.reason = reason;
  }
}

function send(res, code, body, headers = {}) {
  res.writeHead(code, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body, null, 2));
}

function hasCookie(req, cookieName) {
  return (req.headers.cookie ?? '').split(';').some((part) => {
    const separator = part.indexOf('=');
    return separator >= 0 && part.slice(0, separator).trim() === cookieName;
  });
}

function readCookieValue(req, cookieName) {
  let value;
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== cookieName) continue;
    if (value !== undefined) throw new DuplicateVisitorSessionCookieError();
    try {
      value = decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      value = '';
    }
  }
  return value;
}

function createSandboxId() {
  return randomBytes(32).toString('base64url');
}

function classifyRoute(method, pathname) {
  if (pathname === '/healthz' || pathname === '/readyz' || pathname === '/metrics') return pathname.slice(1);
  return ROUTE_NAMES.get(`${method} ${pathname}`) ?? (pathname.startsWith('/api/') ? 'unknown-api' : 'static');
}

/** Create the HTTP handler; every visitor route resolves the signed cookie and the shared store. */
export function createVisitorHttpHandler({
  registry,
  sessionStore,
  sessionCleaner,
  sessionCookie,
  metrics,
  poolUsage = () => ({}),
  libraryVersion,
  httpBoundaryConfig,
  hostGatewayIps,
  publicRoot,
  checkReadiness = async () => {},
  now = () => Date.now(),
}) {
  const visitorCookieName = httpBoundaryConfig?.mode === 'public' ? PUBLIC_VISITOR_COOKIE : VISITOR_COOKIE;
  const publicMode = httpBoundaryConfig?.mode === 'public';
  const securityHeaders = {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    ...(publicMode ? { 'strict-transport-security': 'max-age=31536000' } : {}),
  };
  const cookieSuffix = publicMode ? '; Secure' : '';
  const legacyVisitorCookie = [
    `${VISITOR_COOKIE}=`,
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'HttpOnly',
    'SameSite=Lax',
    'Path=/api',
    ...(publicMode ? ['Secure'] : []),
  ].join('; ');
  const expiredVisitorCookie = [
    `${visitorCookieName}=`,
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    ...(publicMode ? ['Secure'] : []),
  ].join('; ');
  let readinessResult;
  let readinessQuery;
  // Share a pending check so timed-out probes cannot queue duplicate readiness queries.
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

  const markExpired = (req) => {
    req[EXPIRE_VISITOR_COOKIE] = true;
    req[EXPIRE_LEGACY_VISITOR_COOKIE] = true;
  };

  const markLegacyExpired = (req) => {
    req[EXPIRE_LEGACY_VISITOR_COOKIE] = true;
  };

  const hashOrigin = (origin) => sessionCookie.fingerprint(
    typeof origin === 'string' && origin ? origin : 'unknown',
  );

  const releaseSession = (sandboxId) => sessionCleaner.release(sandboxId);

  const visitorRoute = (renew, handler) => async (req, url) => {
    const token = readCookieValue(req, visitorCookieName);
    if (token === undefined) throw new NotAuthenticatedError('Visitor session cookie is missing');
    const verdict = sessionCookie.verify(token);
    if (!verdict.ok) {
      markExpired(req);
      throw new InvalidVisitorSessionCookieError(verdict.reason);
    }
    const resolution = await sessionStore.resolve({ sandboxId: verdict.sandboxId }).catch((err) => {
      throw new SessionPlaneUnavailableError('Visitor session store is unavailable', { cause: err });
    });
    if (!resolution.ok) {
      await releaseSession(verdict.sandboxId);
      metrics?.counter('playground_sessions_lost_total', { reason: resolution.reason });
      throw new VisitorSessionLostError(resolution.reason);
    }
    if (!registry.hasRuntime(verdict.sandboxId)) {
      metrics?.counter('playground_sessions_lost_total', { reason: 'runtime-lost' });
      throw new VisitorSessionLostError('runtime-lost');
    }
    const runtime = registry.getRuntime(verdict.sandboxId);
    const response = await handler(runtime, req, url);
    const [code, body] = response;
    if (renew && code >= 200 && code < 300 && body?.ok !== false) {
      registry.touchRuntime(verdict.sandboxId);
      await sessionStore.touch({ sandboxId: verdict.sandboxId }).catch((err) => {
        logSafeError(console, 'error', 'Visitor session activity update failed', err);
      });
    }
    return response;
  };

  const routes = createVisitorRoutes({
    registry,
    sessionStore,
    sessionCookie,
    metrics,
    requireVisitor: visitorRoute,
    releaseSession,
    readCookie: readCookieValue,
    markExpired,
    markLegacyExpired,
    createSandboxId,
    hashOrigin,
    requestOrigin: (req) => requestClientAddress(req, httpBoundaryConfig),
    visitorCookieName,
    legacyCookieName: VISITOR_COOKIE,
    cookieSuffix,
    legacyVisitorCookie,
    libraryVersion,
    now,
  });

  return async (req, res) => {
    const started = performance.now();
    let responseStatus = 500;
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch (err) {
      const apiRequest = typeof req.url === 'string' && req.url.startsWith('/api/');
      const responseHeaders = { ...securityHeaders };
      if (apiRequest) responseHeaders['cache-control'] = 'no-store';
      logSafeError(console, 'warn', 'Rejected malformed Playground request path', err);
      responseStatus = 400;
      return send(res, 400, { error: 'BadRequest', message: 'Invalid request path' }, responseHeaders);
    }
    const apiRequest = url.pathname.startsWith('/api/');
    const respond = (code, body, headers = {}) => {
      responseStatus = code;
      const responseHeaders = { ...securityHeaders, ...headers };
      if (apiRequest) responseHeaders['cache-control'] = 'no-store';
      const cookies = responseHeaders['set-cookie'];
      const setCookies = Array.isArray(cookies) ? [...cookies] : cookies ? [cookies] : [];
      if (req[EXPIRE_VISITOR_COOKIE] &&
        !setCookies.some((cookie) => cookie.startsWith(`${visitorCookieName}=`))) {
        setCookies.push(expiredVisitorCookie);
      }
      if (req[EXPIRE_LEGACY_VISITOR_COOKIE] || (publicMode && hasCookie(req, VISITOR_COOKIE))) {
        if (!setCookies.includes(legacyVisitorCookie)) setCookies.push(legacyVisitorCookie);
      }
      if (setCookies.length) responseHeaders['set-cookie'] = setCookies;
      return send(res, code, body, responseHeaders);
    };

    try {
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

      if (req.method === 'GET' && url.pathname === '/metrics') {
        let active = registry.size;
        try {
          active = await sessionStore.countActive();
        } catch (err) {
          metrics?.counter('playground_metrics_scrape_errors_total');
          logSafeError(console, 'warn', 'Playground metrics session count failed', err);
        }
        metrics?.gauge('playground_sessions_active', {}, active);
        metrics?.gauge('playground_runtimes_active', {}, registry.size);
        for (const [pool, stats] of Object.entries(poolUsage())) {
          for (const [state, value] of Object.entries(stats)) {
            metrics?.gauge('playground_pool_connections', { pool, state }, value);
          }
        }
        responseStatus = 200;
        res.writeHead(200, {
          ...securityHeaders,
          'content-type': 'text/plain; version=0.0.4; charset=utf-8',
          'cache-control': 'no-store',
        });
        res.end(metrics?.render() ?? '');
        return;
      }

      const key = `${req.method} ${url.pathname}`;
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
      responseStatus = 200;
      res.writeHead(200, { ...securityHeaders, 'content-type': MIME[extname(file)] ?? 'text/plain' });
      res.end(readFileSync(file));
    } catch (err) {
      if (err instanceof DuplicateVisitorSessionCookieError) {
        markExpired(req);
        return respond(400, { error: 'InvalidSessionCookie', message: 'Multiple visitor session cookies are not allowed' });
      }
      if (err instanceof RequestBodyTooLargeError) return respond(413, errorPayload(err));
      if (err instanceof InvalidVisitorSessionCookieError) {
        return respond(401, { error: 'InvalidSessionCookie', message: 'Visitor session cookie is invalid or expired' });
      }
      if (err instanceof VisitorSessionLostError) {
        return respond(410, {
          error: 'SessionLost',
          detail: 'start-a-new-session',
          message: 'Visitor session is no longer available; start a new session',
        });
      }
      if (err instanceof SessionPlaneUnavailableError) {
        logSafeError(console, 'error', 'Visitor session store unavailable', err.cause ?? err);
        return respond(503, {
          error: 'SessionPlaneUnavailable',
          message: 'Visitor session service is temporarily unavailable; retry later',
        });
      }
      if (err instanceof NotAuthenticatedError) {
        return respond(401, { error: 'NotAuthenticated', message: 'Visitor session is not authenticated; authenticate before retrying' });
      }
      logSafeError(console, 'error', 'Playground request failed', err);
      respond(500, { error: 'InternalServerError', message: 'Request could not be completed' });
    } finally {
      metrics?.observe('playground_request_duration_seconds', {
        route: classifyRoute(req.method, url.pathname),
        method: req.method === 'GET' || req.method === 'POST' ? req.method : 'other',
        status: String(responseStatus),
      }, (performance.now() - started) / 1000);
    }
  };
}
