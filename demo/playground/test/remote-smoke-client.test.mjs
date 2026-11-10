import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';
import { createRemoteSmokeClient, RemoteSmokeError } from '../scripts/remote-smoke-client.mjs';

let server;
let origin;
const issuedTokens = [];

async function readRequest(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function handler(req, res) {
  const route = `${req.method} ${req.url}`;
  const send = (status, body, headers = {}) => {
    if (res.destroyed) return;
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };
  if (route === 'POST /api/login') {
    readRequest(req).then(() => {
      const token = randomUUID();
      issuedTokens.push(token);
      send(200, { humanDid: 'alice', ceiling: null }, { 'set-cookie': [
        `__Host-visitorSessionId=${token}; HttpOnly; SameSite=Lax; Path=/; Secure`,
        'visitorSessionId=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Path=/api',
      ] });
    });
    return;
  }
  if (route === 'GET /api/echo' || route === 'POST /api/echo') {
    readRequest(req).then(() => send(200, {
      method: req.method,
      origin: req.headers.origin ?? null,
      contentType: req.headers['content-type'] ?? null,
      cookie: req.headers.cookie ?? null,
    }));
    return;
  }
  if (route === 'POST /api/slow') {
    readRequest(req).then(() => setTimeout(() => send(200, { ok: true }), 300));
    return;
  }
  if (route === 'GET /api/redirect') {
    res.writeHead(302, { location: 'http://127.0.0.1:1/elsewhere' });
    res.end();
    return;
  }
  if (route === 'GET /api/logout') {
    send(200, { ok: true }, { 'set-cookie':
      '__Host-visitorSessionId=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/; Secure' });
    return;
  }
  if (route === 'POST /api/denied') {
    readRequest(req).then(() => send(403, { error: 'ScopeViolationError' }));
    return;
  }
  send(404, { error: 'NotFound' });
}

before(async () => {
  server = createServer(handler);
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolveClose) => {
  server.closeAllConnections();
  server.close(resolveClose);
}));

test('each visitor keeps an independent cookie jar', async () => {
  const { visitor } = createRemoteSmokeClient(origin);
  const first = visitor();
  const second = visitor();

  const login = await first.post('/api/login', { humanDid: 'alice' });
  assert.equal(login.status, 200);
  assert.equal(login.json.humanDid, 'alice');

  const fresh = await second.get('/api/echo');
  assert.equal(fresh.json.cookie, null, 'a fresh visitor must not send cookies');

  const firstEcho = await first.get('/api/echo');
  assert.equal(firstEcho.json.cookie, `__Host-visitorSessionId=${issuedTokens[0]}`,
    'only the public session cookie is replayed, not the legacy expiry cookie');

  await second.post('/api/login', { humanDid: 'bob' });
  const secondEcho = await second.get('/api/echo');
  assert.equal(secondEcho.json.cookie, `__Host-visitorSessionId=${issuedTokens[1]}`);
  assert.doesNotMatch(secondEcho.json.cookie, new RegExp(issuedTokens[0]),
    'visitor two must not carry visitor one session cookie');

  await first.get('/api/logout');
  const afterLogout = await first.get('/api/echo');
  assert.equal(afterLogout.json.cookie, null, 'a Max-Age=0 set-cookie must remove the session cookie');
});

test('POST sends Origin and JSON content type, GET sends no Origin, and non-2xx responses are returned', async () => {
  const { visitor } = createRemoteSmokeClient(origin);
  const current = visitor();
  const postEcho = await current.post('/api/echo', { note: 'x' });
  assert.equal(postEcho.status, 200);
  assert.equal(postEcho.json.origin, origin, 'POST must carry the exact origin');
  assert.equal(postEcho.json.contentType, 'application/json');

  const getEcho = await current.get('/api/echo');
  assert.equal(getEcho.json.origin, null, 'GET must not send Origin');

  const denied = await current.post('/api/denied', { credential: 'credential-abc', sql: 'SELECT 1' });
  assert.equal(denied.status, 403, 'denied responses are returned for assertions, not thrown');
  assert.equal(denied.json.error, 'ScopeViolationError');
});

test('timeouts, redirects, and escaped paths fail with a RemoteSmokeError that names the operation only', async () => {
  const { visitor } = createRemoteSmokeClient(origin, { timeoutMs: 100 });
  const current = visitor();
  await current.post('/api/login', { humanDid: 'alice' });
  const token = issuedTokens.at(-1);

  let timedOut;
  try {
    await current.post('/api/slow', { credential: `credential-${token}`, sql: 'SELECT 1' });
  } catch (error) {
    timedOut = error;
  }
  assert.ok(timedOut instanceof RemoteSmokeError, 'a slow request must time out');
  assert.match(timedOut.message, /^remote smoke: POST \/api\/slow failed: timed out after 100ms$/);
  assert.doesNotMatch(timedOut.message, new RegExp(token), 'the timeout error must not leak the session cookie');
  assert.doesNotMatch(timedOut.message, /credential-/, 'the timeout error must not leak request body material');

  let redirected;
  try {
    await current.get('/api/redirect');
  } catch (error) {
    redirected = error;
  }
  assert.ok(redirected instanceof RemoteSmokeError, 'a redirect must be rejected');
  assert.match(redirected.message, /^remote smoke: GET \/api\/redirect failed: attempted a redirect$/);
  assert.doesNotMatch(redirected.message, /elsewhere/, 'the redirect error must not leak the target');

  // The guard must refuse before fetch, so the mock never sees these requests.
  const escapedCases = [
    ['//other.example/steal', /path must stay within the configured origin/],
    ['api/echo', /path must start with \//],
  ];
  for (const [escaped, reason] of escapedCases) {
    let refused;
    try {
      await current.get(escaped);
    } catch (error) {
      refused = error;
    }
    assert.ok(refused instanceof RemoteSmokeError, `escaped path must be refused: ${escaped}`);
    assert.match(refused.message, reason);
  }
});
