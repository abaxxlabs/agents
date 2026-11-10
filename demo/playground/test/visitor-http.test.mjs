import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import test from 'node:test';
import { QueryRejectedError, ScopeViolationError } from '@abaxxlabs/agents/sql';
import { createVisitorHttpHandler } from '../src/visitor-http.mjs';
import { createVisitorSessionRegistry } from '../src/visitor-session-registry.mjs';
import { resolveHttpBoundaryConfig } from '../src/env-file.mjs';

function fixture(options = {}) {
  const events = [];
  const runtimes = [];
  let provisionCount = 0;
  let dropCount = 0;
  let time = 0;
  const dropGate = { shouldFail: options.failDropFor };
  const provisioner = {
    async createVisitorDatabase() {
      const number = ++provisionCount;
      events.push(`provision:${number}`);
      return {
        databaseName: `visitor_${number}`,
        appDatabaseUrl: `postgres://agents_playground_app@localhost/visitor_${number}`,
      };
    },
    async dropVisitorDatabase(databaseName) {
      dropCount += 1;
      events.push(`drop:${databaseName}`);
      if (dropGate.shouldFail?.(databaseName)) throw new Error(`drop failed for ${databaseName}`);
    },
  };
  const registry = createVisitorSessionRegistry({
    provisioner,
    maxSessions: options.maxSessions ?? 4,
    inactivityTtlMs: options.inactivityTtlMs ?? 60_000,
    now: () => time,
    async createRuntime({ databaseName }) {
      events.push(`runtime:${databaseName}`);
      const loggedIn = new Map();
      const scope = {
        async listAgents() { return [{ name: databaseName }]; },
        auditLoggerInstance: {
          async export() { return [{ databaseName }]; },
        },
      };
      const runtime = {
        databaseName,
        scope,
        simulator: { routes: { 'GET /api/sim/agent': async () => [200, { databaseName }] } },
        async loginSession(alias) {
          events.push(`login:${databaseName}:${alias}`);
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
        async close() { events.push(`close:${databaseName}`); },
      };
      runtimes.push(runtime);
      return runtime;
    },
  });
  // Resolved before construction so the handler's public-mode cookie name,
  // Secure attribute, and HSTS header are live for every request, not just
  // the per-request boundary check.
  const boundaryConfig = options.publicOrigin !== undefined
    ? resolveHttpBoundaryConfig({
        PLAYGROUND_HTTP_MODE: 'public',
        PLAYGROUND_PUBLIC_ORIGIN: options.publicOrigin,
        PLAYGROUND_TRUSTED_PROXY_IPS: '127.0.0.1/32',
      })
    : (options.httpBoundaryConfig ?? { mode: 'local' });
  const handler = createVisitorHttpHandler({
    registry,
    libraryVersion: 'test-version',
    httpBoundaryConfig: boundaryConfig,
    hostGatewayIps: null,
    publicRoot: new URL('../public/', import.meta.url).pathname,
    ...(options.sessionRateLimit ? { sessionRateLimit: options.sessionRateLimit } : {}),
  });
  const server = createServer(handler);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const address = server.address();
      resolve({
        server,
        registry,
        runtimes,
        events,
        get provisionCount() { return provisionCount; },
        get dropGate() { return dropGate; },
        advance: (milliseconds) => { time += milliseconds; },
        get dropCount() { return dropCount; },
        baseUrl: `http://127.0.0.1:${address.port}`,
        port: address.port,
        publicOrigin: options.publicOrigin ?? null,
      });
    });
  });
}

// Public-mode peers must be simulated at the socket layer, so this bypasses
// fetch (which always uses 127.0.0.1) and lets the caller set the Host header
// and other fields that the boundary policy inspects.
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
  return { response, body: await response.json() };
}

function sessionCookie(response) {
  return response.headers.get('set-cookie').split(';', 1)[0];
}

test('status stays global and never provisions a visitor database', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const { response, body } = await request(app.baseUrl, '/api/status');
  assert.equal(response.status, 200);
  assert.deepEqual(body, { status: 'ok', libraryVersion: 'test-version' });
  assert.equal(app.provisionCount, 0);
});

test('first login provisions once and a valid login cookie reuses the runtime', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const first = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  assert.equal(first.response.status, 200);
  const cookie = sessionCookie(first.response);
  assert.match(cookie, /^visitorSessionId=[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(first.body).includes(cookie.split('=')[1]), false);
  assert.equal(app.provisionCount, 1);

  const second = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'bob' }, cookie,
  });
  assert.equal(second.response.status, 200);
  assert.equal(app.provisionCount, 1);
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
  assert.equal(app.provisionCount, 2);

  const firstAgents = await request(app.baseUrl, '/api/agents', { cookie: firstCookie });
  const secondAgents = await request(app.baseUrl, '/api/agents', { cookie: secondCookie });
  const firstAudit = await request(app.baseUrl, '/api/audit', { cookie: firstCookie });
  const secondSimulator = await request(app.baseUrl, '/api/sim/agent', { cookie: secondCookie });
  assert.equal(firstAgents.body.agents[0].name, 'visitor_1');
  assert.equal(secondAgents.body.agents[0].name, 'visitor_2');
  assert.equal(firstAudit.body.records[0].databaseName, 'visitor_1');
  assert.equal(secondSimulator.body.databaseName, 'visitor_2');
  assert.equal(app.provisionCount, 2);
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

test('query rejections without a valid audit ID report an unconfirmed audit', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  const login = await request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: 'alice' } });
  const cookie = sessionCookie(login.response);
  const agent = 'did:key:query-agent';

  for (const auditId of [undefined, null, '', '   ', 42, {}, [], ['audit-id']]) {
    for (const err of [
      new ScopeViolationError(agent, ['orders.hidden_column'], ['orders.authorized_column']),
      new QueryRejectedError(agent, 'Only SELECT is allowed'),
    ]) {
      if (auditId !== undefined) err.details.auditId = auditId;
      app.runtimes[0].scope.query = async () => { throw err; };
      const result = await request(app.baseUrl, '/api/query', {
        method: 'POST', cookie,
        body: { agent, credential: 'test-credential', sql: 'SELECT id FROM orders' },
      });
      assert.equal(result.response.status, 403);
      assert.equal(result.body.message, err.message);
      assert.equal(result.body.inspection.evidence.auditId, null);
      assert.ok(!result.body.inspection.decisionTrace.includes('Rejection recorded'));
      assert.ok(result.body.inspection.decisionTrace.includes('Rejection audit not confirmed'));
    }
  }
});

test('invalid visitor cookies and mock identities fail without provisioning', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  for (const { path, options, status, error } of [
    { path: '/api/agents', options: { cookie: 'visitorSessionId=not-registered' }, status: 401, error: 'VisitorSessionNotFoundError' },
    { path: '/api/login', options: { method: 'POST', body: { humanDid: 'unknown' } }, status: 400, error: 'ValidationError' },
  ]) {
    const result = await request(app.baseUrl, path, options);
    assert.equal(result.response.status, status);
    assert.equal(result.body.error, error);
    assert.equal(app.provisionCount, 0);
  }
});

test('an invalid cookie is replaced by a new session on login after expired cleanup', async (t) => {
  const app = await fixture();
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  const order = [];
  const cleanup = app.registry.cleanupExpiredSessions.bind(app.registry);
  const create = app.registry.createSession.bind(app.registry);
  app.registry.cleanupExpiredSessions = async () => { order.push('expired-cleanup'); return cleanup(); };
  app.registry.createSession = async () => { order.push('create-session'); return create(); };

  const { response } = await request(app.baseUrl, '/api/login', {
    method: 'POST', body: { humanDid: 'alice' }, cookie: 'visitorSessionId=stale-session-id',
  });
  assert.equal(response.status, 200);
  assert.deepEqual(order, ['expired-cleanup', 'create-session']);
  assert.equal(app.provisionCount, 1);
});

function publicHost(app) {
  return new URL(app.publicOrigin).host;
}

test('public mode serves the UI to a socket peer inside a trusted CIDR', async (t) => {
  const app = await fixture({ publicOrigin: 'https://playground.example.com' });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const status = await rawRequest(app.port, '/api/status', {
    headers: { host: publicHost(app), 'x-forwarded-proto': 'https' },
  });
  assert.equal(status.status, 200);
  assert.equal(JSON.parse(status.body).libraryVersion, 'test-version');
});

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

test('public mode probes are served pre-boundary and unauthenticated requests are 403', async (t) => {
  const app = await fixture({ publicOrigin: 'https://playground.example.com' });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  // /healthz responds before the boundary check.
  const health = await rawRequest(app.port, '/healthz');
  assert.equal(health.status, 200);

  // A real socket peer (127.0.0.1) is in the configured CIDR, but without the
  // public Host header the boundary rejects the UI request.
  const noHost = await rawRequest(app.port, '/api/status');
  assert.equal(noHost.status, 403);
});

test('public mode login serves the __Host- secure session cookie and HSTS from a trusted peer', async (t) => {
  const app = await fixture({ publicOrigin: 'https://playground.example.com' });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const { status, headers } = await rawRequest(app.port, '/api/login', {
    method: 'POST',
    body: { humanDid: 'alice' },
    headers: { host: publicHost(app), origin: app.publicOrigin, 'x-forwarded-proto': 'https' },
  });
  assert.equal(status, 200);
  assert.equal(app.provisionCount, 1);

  const cookies = headers['set-cookie'];
  assert.ok(Array.isArray(cookies), 'expected a set-cookie array on public login');
  const session = cookies.find((cookie) => cookie.startsWith('__Host-visitorSessionId='));
  assert.ok(session, 'expected the __Host- prefixed public session cookie');
  assert.match(session, /;\s*Secure/);
  assert.match(session, /HttpOnly/);
  assert.ok(cookies.some((cookie) => cookie.startsWith('visitorSessionId=;')), 'expected the legacy cookie to be expired');

  assert.equal(headers['strict-transport-security'], 'max-age=31536000');
});

test('a rate-limited login rejects before cleanup retries run', async (t) => {
  const app = await fixture({ sessionRateLimit: { maxNewSessions: 2, windowMs: 60_000 }, failDropFor: () => true });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  let cleanupRuns = 0;
  const cleanup = app.registry.cleanupExpiredSessions.bind(app.registry);
  app.registry.cleanupExpiredSessions = async () => { cleanupRuns += 1; return cleanup(); };

  const login = (alias) => request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: alias } });
  await login('alice');
  await login('bob');
  app.advance(61_000);
  cleanupRuns = 0;
  const third = await login('alice');
  assert.equal(third.response.status, 429);
  assert.equal(third.body.error, 'RateLimitExceeded');
  assert.match(third.response.headers.get('retry-after'), /^\d+$/);
  assert.equal(cleanupRuns, 0);
  assert.equal(app.provisionCount, 2);
  assert.equal(app.dropCount, 0);
});

test('a failed session cleanup holds login at capacity until the next retry frees the slot', async (t) => {
  const app = await fixture({ maxSessions: 2, failDropFor: () => true });
  t.after(() => new Promise((resolve) => app.server.close(resolve)));

  const login = (alias) => request(app.baseUrl, '/api/login', { method: 'POST', body: { humanDid: alias } });
  await login('alice');
  await login('bob');
  assert.equal(app.provisionCount, 2);
  app.advance(61_000);
  const rejected = await login('alice');
  assert.equal(rejected.response.status, 503);
  assert.equal(rejected.body.error, 'VisitorSessionCapacityError');
  assert.equal(app.provisionCount, 2);
  const closesBefore = app.events.filter((event) => event.startsWith('close:')).length;
  const dropsBefore = app.dropCount;
  app.dropGate.shouldFail = () => false;
  const admitted = await login('alice');
  assert.equal(admitted.response.status, 200);
  assert.equal(app.provisionCount, 3);
  assert.match(sessionCookie(admitted.response), /^visitorSessionId=[A-Za-z0-9_-]{43}$/);
  assert.equal(app.events.filter((event) => event.startsWith('close:')).length, closesBefore);
  assert.ok(app.dropCount > dropsBefore, 'retry re-issued DROPs without re-closing runtimes');
});
