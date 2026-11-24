import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import test from 'node:test';
import { QueryRejectedError, ScopeViolationError } from '@abaxxlabs/agents/sql';
import { createVisitorHttpHandler } from '../src/visitor-http.mjs';
import { createVisitorSessionRegistry } from '../src/visitor-session-registry.mjs';
import { createVisitorSessionCookie } from '../src/visitor-session-cookie.mjs';
import { createVisitorSessionCleaner } from '../src/visitor-session-cleaner.mjs';
import { createPlaygroundMetrics } from '../src/playground-metrics.mjs';
import { resolveHttpBoundaryConfig } from '../src/env-file.mjs';

function fixture(options = {}) {
  const events = [];
  const runtimes = [];
  const sessions = new Map();
  const origins = new Map();
  let runtimeCount = 0;
  let admissions = 0;
  let now = options.now ?? 1_000_000;
  const absoluteTtlMs = options.absoluteTtlMs ?? 60_000;
  const inactivityTtlMs = options.inactivityTtlMs ?? 30_000;
  const maxSessions = options.maxSessions ?? 4;
  const maxNewSessions = options.maxNewSessions ?? 100;
  const rateWindowMs = options.rateWindowMs ?? 60_000;
  const sessionStore = {
    async admit({ sandboxId, originHash }) {
      const bucket = origins.get(originHash);
      if (!bucket || now - bucket.startedAt >= rateWindowMs) {
        origins.set(originHash, { startedAt: now, count: 1 });
      } else if (bucket.count >= maxNewSessions) {
        return { ok: false, reason: 'rate-limit', retryAfterMs: bucket.startedAt + rateWindowMs - now };
      } else {
        bucket.count += 1;
      }
      if (sessions.size >= maxSessions) return { ok: false, reason: 'capacity' };
      admissions += 1;
      const row = { createdAt: now, expiresAt: now + absoluteTtlMs, lastSeenAt: now, originHash };
      sessions.set(sandboxId, row);
      return { ok: true, expiresAt: row.expiresAt, lastSeenAt: now };
    },
    async resolve({ sandboxId }) {
      const row = sessions.get(sandboxId);
      if (!row) return { ok: false, reason: 'unknown' };
      if (row.expiresAt <= now) return { ok: false, reason: 'absolute-expired' };
      if (row.lastSeenAt <= now - inactivityTtlMs) return { ok: false, reason: 'inactive' };
      return { ok: true, expiresAt: row.expiresAt, lastSeenAt: row.lastSeenAt };
    },
    async touch({ sandboxId }) {
      const row = sessions.get(sandboxId);
      if (!row) return false;
      row.lastSeenAt = now;
      return true;
    },
    async release({ sandboxId }) {
      const row = sessions.get(sandboxId);
      sessions.delete(sandboxId);
      return Boolean(row);
    },
    async countActive() {
      return sessions.size;
    },
  };
  const sessionCookie = createVisitorSessionCookie({
    key: Buffer.alloc(32, 7),
    absoluteTtlMs,
    now: () => now,
  });
  const registry = createVisitorSessionRegistry({
    async createRuntime({ sandboxId }) {
      const label = `visitor_${++runtimeCount}`;
      events.push(`runtime:${label}`);
      const loggedIn = new Map();
      const scope = {
        async listAgents() { return [{ name: label }]; },
        auditLoggerInstance: {
          async export() { return [{ databaseName: label }]; },
          async verifyAuditChain() { return { ok: true }; },
        },
      };
      const runtime = {
        sandboxId,
        scope,
        simulator: {
          routes: {
            'GET /api/sim/agent': async () => [200, { databaseName: label }],
            'GET /api/sim/raw-bytes': async () => [200, { databaseName: label }],
            'POST /api/sim/config': async () => [200, { ok: true }],
            'POST /api/sim/raw': async () => [200, { ok: true }],
            'POST /api/sim/scoped': async () => [200, { ok: true }],
            'POST /api/sim/reset': async () => [200, { ok: true }],
          },
        },
        async loginSession(alias) {
          events.push(`login:${label}:${alias}`);
          const session = {
            humanDid: `did:key:${alias}`,
            scopeCeiling: {
              columns: ['*'], actions: ['read'], source: 'test', resolvedFrom: [], credentialMaxTtlMs: 1000,
            },
          };
          loggedIn.set(session.humanDid, session);
          return session;
        },
        getSession(humanDid) {
          const session = loggedIn.get(humanDid);
          if (!session) throw new Error('No visitor login');
          return session;
        },
        async close() { events.push(`close:${label}`); },
      };
      runtimes.push(runtime);
      return runtime;
    },
  });
  const boundaryConfig = options.publicOrigin !== undefined
    ? resolveHttpBoundaryConfig({
        PLAYGROUND_HTTP_MODE: 'public',
        PLAYGROUND_PUBLIC_ORIGIN: options.publicOrigin,
        PLAYGROUND_TRUSTED_PROXY_IPS: '127.0.0.1/32',
      })
    : { mode: 'local' };
  const metrics = createPlaygroundMetrics();
  const sessionCleaner = createVisitorSessionCleaner({
    registry,
    sessionStore,
    logger: { error() {} },
  });
  const handler = createVisitorHttpHandler({
    registry,
    sessionStore,
    sessionCleaner,
    sessionCookie,
    metrics,
    libraryVersion: 'test-version',
    httpBoundaryConfig: boundaryConfig,
    hostGatewayIps: null,
    publicRoot: new URL('../public/', import.meta.url).pathname,
    now: () => now,
  });
  const server = createServer(handler);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const address = server.address();
      resolve({
        server,
        runtimes,
        events,
        sessions,
        sessionStore,
        sessionCookie,
        registry,
        get admissions() { return admissions; },
        advance(ms) { now += ms; },
        baseUrl: `http://127.0.0.1:${address.port}`,
        port: address.port,
        publicOrigin: options.publicOrigin ?? null,
      });
    });
  });
}

// Bypasses fetch so callers can set socket peer and Host/Proto headers the boundary inspects.
function rawRequest(port, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = httpRequest({
      method,
      hostname: '127.0.0.1',
      port,
      path,
      headers: {
        ...(payload !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

async function request(baseUrl, path, { method = 'GET', body, cookie } = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(cookie ? { cookie } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }
  return { response, body: parsed, text };
}

function sessionCookie(response) {
  return response.headers.get('set-cookie').split(';', 1)[0];
}

test('first login creates one runtime and a valid login cookie reuses the runtime', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const first = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  assert.equal(first.response.status, 200);
  const cookie = sessionCookie(first.response);
  assert.match(cookie, /^visitorSessionId=v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(first.body).includes(cookie.split('=')[1]), false);
  assert.equal(app.runtimes.length, 1);

  const second = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'bob' }, cookie,
  });
  assert.equal(second.response.status, 200);
  assert.equal(app.runtimes.length, 1);
  assert.deepEqual(app.events.filter((event) => event.startsWith('login:')), [
    'login:visitor_1:alice', 'login:visitor_1:bob',
  ]);
});

test('separate browser cookies route requests to separate visitor runtimes', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  const first = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const second = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'bob' } });
  const firstCookie = sessionCookie(first.response);
  const secondCookie = sessionCookie(second.response);
  assert.notEqual(firstCookie, secondCookie);
  assert.equal(app.runtimes.length, 2);

  const firstAgents = await request(app.baseUrl, '/api/agents', { cookie: firstCookie });
  const secondAgents = await request(app.baseUrl, '/api/agents', { cookie: secondCookie });
  const firstAudit = await request(app.baseUrl, '/api/audit', { cookie: firstCookie });
  const secondSimulator = await request(app.baseUrl, '/api/sim/agent', { cookie: secondCookie });
  assert.equal(firstAgents.body.agents[0].name, 'visitor_1');
  assert.equal(secondAgents.body.agents[0].name, 'visitor_2');
  assert.equal(firstAudit.body.records[0].databaseName, 'visitor_1');
  assert.equal(secondSimulator.body.databaseName, 'visitor_2');
  assert.equal(app.runtimes.length, 2);
});

test('query rejections expose the audit ID without exposing scope details or changing HTTP decisions', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  const agent = 'did:key:query-agent';
  const sql = 'SELECT id FROM orders';

  for (const err of [
    new ScopeViolationError(agent, ['orders.hidden_column'], ['orders.authorized_column']),
    new QueryRejectedError(agent, 'Only SELECT is allowed'),
  ]) {
    err.details.auditId = 'rejection-audit-id';
    err.details.requestedColumns = ['orders.hidden_column'];
    err.details.authorizedColumns = ['orders.authorized_column'];
    app.runtimes[0].scope.query = async () => { throw err; };

    const result = await request(app.baseUrl, '/api/query', {
      method: 'POST', cookie, body: { agent, credential: 'test-credential', sql },
    });
    assert.equal(result.response.status, 403);
    assert.equal(result.body.ok, false);
    assert.equal(result.body.error, err.constructor.name);
    assert.equal(result.body.message, err.message);
    assert.deepEqual(result.body.inspection.evidence, {
      agent, sql, authorization: 'rejected', error: err.code, auditId: 'rejection-audit-id',
    });
    assert.ok(result.body.inspection.decisionTrace.includes('Rejection recorded'));
    assert.doesNotMatch(JSON.stringify(result.body), /requestedColumns|authorizedColumns|hidden_column|authorized_column/);
  }
});

test('invalid visitor cookies and mock identities fail without creating a runtime', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  for (const { path, options, status, error } of [
    { path: '/api/agents', options: { cookie: 'visitorSessionId=not-registered' }, status: 401, error: 'InvalidSessionCookie' },
    { path: '/api/login', options: { method: 'POST', body: { humanDid: 'unknown' } }, status: 400, error: 'ValidationError' },
  ]) {
    const result = await request(app.baseUrl, path, options);
    assert.equal(result.response.status, status);
    assert.equal(result.body.error, error);
    assert.equal(app.runtimes.length, 0);
  }
});

test('an expired session returns an explicit session-lost response and keeps the cookie for re-login', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  app.advance(31_000);

  const result = await request(app.baseUrl, '/api/agents', { cookie });
  assert.equal(result.response.status, 410);
  assert.equal(result.body.error, 'SessionLost');
  assert.equal(result.body.detail, 'start-a-new-session');
  assert.equal(result.response.headers.get('set-cookie')?.includes('Max-Age=0') ?? false, false);
  assert.equal(app.runtimes.length, 1);
  assert.ok(app.events.includes('close:visitor_1'));

  const relogin = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'alice' }, cookie,
  });
  assert.equal(relogin.response.status, 200);
  assert.equal(app.sessions.size, 1);
  assert.equal(app.runtimes.length, 2);
});

test('polling does not extend the inactivity deadline', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  app.advance(20_000);
  for (let index = 0; index < 5; index += 1) {
    assert.equal((await request(app.baseUrl, '/api/agents', { cookie })).response.status, 200);
  }
  app.advance(11_000);

  const result = await request(app.baseUrl, '/api/agents', { cookie });
  assert.equal(result.response.status, 410);
  assert.equal(result.body.error, 'SessionLost');
});

test('a tampered cookie is rejected and clears both the local and legacy paths', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  const tampered = `${cookie.slice(0, -1)}${cookie.endsWith('A') ? 'B' : 'A'}`;

  const result = await request(app.baseUrl, '/api/agents', { cookie: tampered });
  assert.equal(result.response.status, 401);
  assert.equal(result.body.error, 'InvalidSessionCookie');
  const cleared = result.response.headers.getSetCookie();
  assert.equal(cleared.length, 2);
  assert.ok(cleared.some((value) => value.includes('Path=/api')));
  assert.ok(cleared.some((value) => value.endsWith('Path=/')));
  assert.equal(app.runtimes.length, 1);
});

test('a valid cookie for an unknown sandbox returns session-lost', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  const token = app.sessionCookie.issue({ sandboxId: 'a'.repeat(43) }).token;

  const result = await request(app.baseUrl, '/api/agents', { cookie: `visitorSessionId=${token}` });
  assert.equal(result.response.status, 410);
  assert.equal(result.body.error, 'SessionLost');
  assert.equal(app.runtimes.length, 0);
});

test('login with an invalid cookie starts a new session instead of reusing an identity', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const first = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'alice' }, cookie: 'visitorSessionId=stale',
  });
  assert.equal(first.response.status, 200);
  assert.match(sessionCookie(first.response), /^visitorSessionId=v1\./);
  assert.equal(app.runtimes.length, 1);
});

test('login with two local visitor cookies starts a new session and clears the legacy path', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const result = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'alice' }, cookie: 'visitorSessionId=first; visitorSessionId=second',
  });
  assert.equal(result.response.status, 200);
  const cookies = result.response.headers.getSetCookie();
  assert.ok(cookies.some((value) => value.startsWith('visitorSessionId=v1.')));
  assert.ok(cookies.some((value) => value.includes('Max-Age=0') && value.includes('Path=/api')));
  assert.equal(app.runtimes.length, 1);
});

test('a reused cookie near expiry is reissued with a positive Max-Age', async (t) => {
  const app = await fixture({ absoluteTtlMs: 60_000, inactivityTtlMs: 120_000 });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  app.advance(59_999);

  const relogin = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'bob' }, cookie,
  });
  assert.equal(relogin.response.status, 200);
  const issued = relogin.response.headers.getSetCookie().find((value) => value.startsWith('visitorSessionId=v1.'));
  assert.match(issued, /Max-Age=1;/);
});

test('a session store failure maps to 503 without becoming a validation or cookie error', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  app.sessionStore.resolve = async () => { throw new Error('control database unavailable'); };
  const resolveFailure = await request(app.baseUrl, '/api/agents', { cookie });
  assert.equal(resolveFailure.response.status, 503);
  assert.equal(resolveFailure.body.error, 'SessionPlaneUnavailable');

  app.sessionStore.admit = async () => { throw new Error('control database unavailable'); };
  const admitFailure = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'bob' } });
  assert.equal(admitFailure.response.status, 503);
  assert.equal(admitFailure.body.error, 'SessionPlaneUnavailable');
});

test('new-session admission is rejected by origin without creating a session', async (t) => {
  const app = await fixture({ maxNewSessions: 1 });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const first = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  assert.equal(first.response.status, 200);
  const second = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'bob' } });
  assert.equal(second.response.status, 429);
  assert.equal(second.body.error, 'RateLimitExceeded');
  assert.ok(Number(second.response.headers.get('retry-after')) > 0);
  assert.equal(app.runtimes.length, 1);
  assert.equal(app.admissions, 1);
});

test('login keeps an active row when this replica has no runtime', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const first = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(first.response);
  const sandboxId = app.sessionCookie.verify(cookie.split('=')[1]).sandboxId;
  await app.registry.closeRuntime(sandboxId);
  assert.equal(app.sessions.has(sandboxId), true);

  const second = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'bob' }, cookie,
  });
  assert.equal(second.response.status, 200);
  assert.equal(app.sessions.has(sandboxId), true);
  assert.equal(app.sessions.size, 2);
  assert.equal(app.runtimes.length, 2);
});

test('login issues a cookie with the live reservation expiry', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  const verdict = app.sessionCookie.verify(cookie.split('=')[1]);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.expiresAt, app.sessions.get(verdict.sandboxId).expiresAt);
});

test('a full global cap rejects admission with 503 and creates no runtime', async (t) => {
  const app = await fixture({ maxSessions: 0 });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const result = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  assert.equal(result.response.status, 503);
  assert.equal(result.body.error, 'VisitorSessionCapacityError');
  assert.equal(app.runtimes.length, 0);
  assert.equal(app.sessions.size, 0);
});

test('metrics expose active sessions, admissions and route latency', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const result = await request(app.baseUrl, '/metrics');
  assert.equal(result.response.status, 200);
  assert.match(result.response.headers.get('content-type'), /text\/plain/);
  assert.match(result.text, /^# TYPE playground_admissions_total counter$/m);
  assert.match(result.text, /^playground_admissions_total\{origin="[0-9a-f]{12}"\} 1$/m);
  assert.match(result.text, /^playground_sessions_active 1$/m);
  assert.match(result.text, /^# TYPE playground_request_duration_seconds histogram$/m);
  assert.match(result.text, /playground_request_duration_seconds_count\{method="POST",route="login",status="200"\} 1/);
});

function publicHost(app) {
  return new URL(app.publicOrigin).host;
}

test('public mode 403s a forged Host/Proto from the same trusted peer', async (t) => {
  const app = await fixture({ publicOrigin: 'https://playground.example.com' });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const badHost = await rawRequest(app.port, '/api/status', {
    headers: { host: 'evil.example.com', 'x-forwarded-proto': 'https' },
  });
  assert.equal(badHost.status, 403);
  const badProto = await rawRequest(app.port, '/api/status', {
    headers: { host: publicHost(app), 'x-forwarded-proto': 'http' },
  });
  assert.equal(badProto.status, 403);
});
