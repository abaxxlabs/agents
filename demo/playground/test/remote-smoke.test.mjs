import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';
import { createRemoteSmokeClient } from '../scripts/remote-smoke-client.mjs';
import {
  assertAuthorizedRead,
  assertBroadCredentialAllows,
  assertIndependentResetLeavesOtherUnchanged,
  login,
  assertOutOfScopeRejected,
  assertRestrictedIdentityCeiling,
  assertVisitorIsolation,
  runRemoteSmoke,
  waitForReady,
} from '../scripts/remote-smoke.mjs';

// A faithful-in-shape mock of the deployed public Playground. It is not a
// reimplementation of the scope engine; it returns the same response shapes the
// real server produces so the smoke's own assertions are exercised.
const ORDER_COLUMNS = ['orders.instrument', 'orders.side', 'orders.quantity', 'orders.status', 'orders.price', 'orders.counterparty'];
const BOB_CEILING = ['orders.instrument', 'orders.side', 'orders.quantity', 'orders.status'];
const ENCRYPTED = new Set(['orders.price', 'orders.counterparty']);
const SEED = { instrument: 'EU-CARBON-DEC26', side: 'BUY', quantity: 750, price: 88.1, counterparty: 'Alpenwerk AG', status: 'OPEN' };
const CANONICAL_PLAINTEXT = [
  { id: 1, status: 'OPEN' }, { id: 2, status: 'OPEN' }, { id: 3, status: 'FILLED' },
  { id: 4, status: 'OPEN' }, { id: 5, status: 'OPEN' }, { id: 6, status: 'CANCELLED' },
  { id: 7, status: 'OPEN' }, { id: 8, status: 'OPEN' },
];
function canonicalSandbox() {
  return CANONICAL_PLAINTEXT.map((row) => ({ ...row }));
}

const state = { sessions: new Map() };
let readyFailuresLeft = 0;
let leakCredentialOnDenial = false;
let tamperDecryptedValue = false;
const TAMPERED_COUNTERPARTY = 'TAMPERED_SECRET_COUNTERPARTY';

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function readRequest(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function selectedColumns(sql) {
  const match = sql.match(/select\s+([\s\S]+?)\s+from\s+orders/i);
  if (!match) return [];
  return match[1].split(',').map((part) => part.trim()).filter(Boolean)
    .map((column) => `orders.${column.split('.').pop()}`);
}

// Mirror the real server: a row carries only the columns the query selected.
function projectRow(columns) {
  const row = {};
  for (const column of columns) {
    const name = column.split('.').pop();
    row[name] = SEED[name] ?? null;
  }
  if (tamperDecryptedValue) row.counterparty = TAMPERED_COUNTERPARTY;
  return row;
}

// Mirror the real server: the login response carries a did:key identity derived
// from the alias (see createMockSession), never the alias itself.
function didForAlias(alias) {
  const digest = createHash('sha256').update(`mock-human:${alias}`).digest('base64url').replace(/=/g, '');
  return `did:key:z${digest}`;
}

function sessionFrom(req) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0 && part.slice(0, separator).trim() === '__Host-visitorSessionId') {
      return state.sessions.get(part.slice(separator + 1).trim()) ?? null;
    }
  }
  return null;
}

function handler(req, res) {
  const send = (status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };
  const route = `${req.method} ${req.url}`;

  if (route === 'GET /healthz') return send(200, { status: 'ok' });
  if (route === 'GET /readyz') {
    if (readyFailuresLeft > 0) {
      readyFailuresLeft -= 1;
      return send(503, { status: 'not-ready' });
    }
    return send(200, { status: 'ready' });
  }

  if (route === 'POST /api/login') {
    readRequest(req).then((raw) => {
      const { humanDid: alias } = JSON.parse(raw || '{}');
      const token = randomUUID();
      const session = {
        humanDid: didForAlias(alias),
        alias,
        ceilingColumns: alias === 'bob' ? BOB_CEILING : ORDER_COLUMNS,
        agents: new Map(), credentials: new Map(), audit: [], sandbox: canonicalSandbox(),
      };
      state.sessions.set(token, session);
      send(200, {
        humanDid: session.humanDid,
        ceiling: {
          columns: session.ceilingColumns,
          actions: ['read'],
          source: 'oidc-groups',
          resolvedFrom: session.alias === 'bob' ? ['desk-junior'] : null,
          credentialMaxTtlMs: 14_400_000,
        },
      }, { 'set-cookie': [`__Host-visitorSessionId=${token}; HttpOnly; SameSite=Lax; Path=/; Secure`] });
    });
    return;
  }

  const session = sessionFrom(req);
  if (!session) {
    readRequest(req).then(() => send(401, { error: 'VisitorSessionNotFoundError', message: 'Visitor session cookie is missing' }));
    return;
  }

  if (route === 'POST /api/agents') {
    readRequest(req).then((raw) => {
      const { humanDid, name } = JSON.parse(raw || '{}');
      if (!humanDid || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name ?? '')) {
        return send(400, { error: 'ValidationError', message: 'invalid agent' });
      }
      const did = `did:key:${randomUUID()}`;
      session.agents.set(did, { ownerDid: humanDid, name });
      send(201, { did, name, ownerDid: humanDid, publicKey: 'ab'.repeat(32) });
    });
    return;
  }

  if (route === 'POST /api/credentials') {
    readRequest(req).then((raw) => {
      const { humanDid, agent, columns } = JSON.parse(raw || '{}');
      if (!humanDid || !agent || !Array.isArray(columns) || !columns.length ||
        !columns.every((column) => ORDER_COLUMNS.includes(column))) {
        return send(400, { error: 'ValidationError', message: 'humanDid, agent and valid orders columns[] required' });
      }
      const ceiling = session.ceilingColumns;
      const excess = columns.filter((column) => !ceiling.includes(column));
      if (excess.length) {
        const deniedBody = {
          error: 'ScopeExceedsCeilingError',
          message: `Requested scope exceeds session ceiling: ${excess.join(', ')}`,
        };
        if (leakCredentialOnDenial) deniedBody.credential = 'FAKE_CREDENTIAL_TOKEN';
        return send(403, deniedBody);
      }
      const credential = `cred-${randomUUID()}`;
      session.credentials.set(credential, { agentDid: agent, columns });
      send(201, { credential });
    });
    return;
  }

  if (route === 'POST /api/query') {
    readRequest(req).then((raw) => {
      const { agent, credential, sql } = JSON.parse(raw || '{}');
      const info = session.credentials.get(credential);
      if (!info) {
        return send(403, {
          ok: false,
          error: 'CredentialInvalidError',
          message: 'unknown credential',
          inspection: { evidence: { agent, sql, authorization: 'rejected', error: 'CREDENTIAL_INVALID' } },
        });
      }
      const selected = selectedColumns(sql);
      const inScope = selected.length > 0 && selected.every((column) => info.columns.includes(column));
      if (!inScope) {
        session.audit.push({
          id: randomUUID(), agentDid: agent, status: 'rejected',
          queryHash: sha(sql), rowCount: 0, reasonCode: 'SCOPE_VIOLATION',
        });
        return send(403, {
          ok: false,
          error: 'ScopeViolationError',
          message: 'query references columns outside the credential scope',
          inspection: {
            decisionTrace: ['Credential accepted', 'Query not executed', 'Rejection recorded'],
            evidence: { agent, sql, authorization: 'rejected', error: 'SCOPE_VIOLATION' },
          },
        });
      }
      const decrypted = selected.filter((column) => ENCRYPTED.has(column));
      const auditId = randomUUID();
      session.audit.push({ id: auditId, agentDid: agent, status: 'success', queryHash: sha(sql), rowCount: 1 });
      send(200, {
        ok: true,
        rows: [projectRow(selected)],
        metadata: { columnsDecrypted: decrypted, auditId },
        inspection: {
          decisionTrace: ['Query executed', 'Audit recorded'],
          evidence: { agent, sql, authorization: 'allowed', columnsDecrypted: decrypted, auditId },
        },
      });
    });
    return;
  }

  if (route === 'GET /api/agents') {
    return send(200, { agents: [...session.agents.entries()].map(([did, info]) => ({ did, name: info.name, ownerDid: info.ownerDid })) });
  }

  if (route === 'POST /api/sim/raw') {
    readRequest(req).then((raw) => {
      const { sql } = JSON.parse(raw || '{}');
      if (typeof sql !== 'string') return send(400, { error: 'ValidationError', message: 'sql required' });
      const update = sql.match(/^update orders_plaintext set status = '(.+)' where id = (\d+)$/i);
      if (update) {
        const row = session.sandbox.find((candidate) => candidate.id === Number(update[2]));
        if (row) row.status = update[1];
        return send(200, { ok: true, command: 'UPDATE', rowCount: row ? 1 : 0 });
      }
      const select = sql.match(/^select status from orders_plaintext where id = (\d+)$/i);
      if (select) {
        const row = session.sandbox.find((candidate) => candidate.id === Number(select[1]));
        return send(200, { ok: true, command: 'SELECT', rowsReturned: row ? 1 : 0, rows: row ? [{ status: row.status }] : [] });
      }
      send(403, { ok: false, error: 'DirectSqlRejected', message: 'unsupported sandbox statement' });
    });
    return;
  }

  if (route === 'POST /api/sim/reset') {
    readRequest(req).then(() => {
      session.sandbox = canonicalSandbox();
      send(200, { ok: true, rows: session.sandbox.length });
    });
    return;
  }

  if (route === 'GET /api/audit') return send(200, { records: session.audit.slice(-50).reverse() });

  send(404, { error: 'NotFound' });
}

let server;
let origin;
const client = () => createRemoteSmokeClient(origin, { timeoutMs: 5_000 });

before(async () => {
  server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => {
  server.closeAllConnections();
  server.close(resolve);
}));

test('readiness probe waits through early not-ready responses and fails fast with a clean message when unreachable', async () => {
  readyFailuresLeft = 2;
  await waitForReady(client(), { deadlineMs: 2_000, intervalMs: 10 });
  assert.equal(readyFailuresLeft, 0, 'waitForReady must keep polling until the origin reports ready');

  const dead = createRemoteSmokeClient('http://127.0.0.1:1', { timeoutMs: 100 });
  let failure;
  try {
    await waitForReady(dead, { deadlineMs: 500, intervalMs: 20 });
  } catch (error) {
    failure = error;
  }
  assert.ok(failure, 'an unreachable origin must fail readiness');
  assert.match(failure.message, /remote Playground not ready/, 'readiness must surface a stable, operator-facing reason');
  assert.match(failure.message, /remote smoke: GET \/healthz failed:/, 'the error must name the operation');
  assert.doesNotMatch(failure.message, /127\.0\.0\.1/, 'the readiness error must never echo the target host');
});

test('login issues a did:key identity distinct from the requested alias', async () => {
  const { session } = await login(client(), 'alice');
  assert.ok(session.humanDid.startsWith('did:key:z'), 'login must issue a did:key identity, not the alias');
  assert.notEqual(session.humanDid, 'alice', 'the issued identity must differ from the login alias');
});

test('authorized read decrypts the seed row and correlates it to a success audit record', async () => {
  const alice = await assertAuthorizedRead(client());
  assert.ok(alice.agent.did && alice.credential, 'authorized read must surface the agent and credential');
});

test('out-of-scope query is denied with no rows and audit-logged, then a broad credential allows it', async () => {
  const alice = await assertAuthorizedRead(client());
  await assertOutOfScopeRejected(alice);
  await assertBroadCredentialAllows(alice);
});

test('restricted identity cannot obtain an encrypted-column credential but can obtain an in-ceiling one', async () => {
  await assertRestrictedIdentityCeiling(client());
});

test('a denial that wrongly carries a credential keeps the token out of the failure message', async () => {
  leakCredentialOnDenial = true;
  try {
    await assertRestrictedIdentityCeiling(client());
    assert.fail('the in-ceiling credential guard must throw when a denial leaks a credential');
  } catch (error) {
    assert.match(error.message, /no credential may be issued to bob/, 'the static operation diagnostic must remain');
    assert.doesNotMatch(error.message, /FAKE_CREDENTIAL_TOKEN/, 'a leaked credential must never appear in the error');
  } finally {
    leakCredentialOnDenial = false;
  }
});

test('an unexpected decrypted value fails the seed check without being printed', async () => {
  tamperDecryptedValue = true;
  try {
    await assertAuthorizedRead(client());
    assert.fail('the seed check must throw when a decrypted value is unexpected');
  } catch (error) {
    assert.match(error.message, /counterparty must decrypt to the seed value/, 'the static diagnostic must remain');
    assert.doesNotMatch(error.message, /TAMPERED_SECRET_COUNTERPARTY/, 'a leaked decrypted value must never appear in the error');
  } finally {
    tamperDecryptedValue = false;
  }
});

test('two alice sessions are isolated: distinct cookies, own agents and own audits', async () => {
  const smoke = client();
  const alice = await assertAuthorizedRead(smoke);
  const isolation = await assertVisitorIsolation(smoke, alice);
  assert.ok(isolation.a.visitor.cookie !== isolation.b.visitor.cookie, 'the two sessions must hold distinct cookies');
});

test('resetting visitor A restores its seed while visitor B keeps its changes and can still query', async () => {
  const smoke = client();
  const alice = await assertAuthorizedRead(smoke);
  const isolation = await assertVisitorIsolation(smoke, alice);
  await assertIndependentResetLeavesOtherUnchanged(isolation);
});

test('the full remote smoke runs every scenario in order against a healthy origin', async () => {
  await runRemoteSmoke(client(), { readyDeadlineMs: 2_000, readyIntervalMs: 10 });
});
