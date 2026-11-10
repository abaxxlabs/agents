#!/usr/bin/env node
/** HTTP-only smoke for a deployed Playground origin, selected by smoke-dispatch.mjs. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { createRemoteSmokeClient } from './remote-smoke-client.mjs';

const ORDER_COLUMNS = Object.freeze([
  'orders.instrument',
  'orders.side',
  'orders.quantity',
  'orders.status',
  'orders.price',
  'orders.counterparty',
]);
const ENCRYPTED_COLUMNS = Object.freeze(['orders.counterparty', 'orders.price']);
const ALICE_COLUMNS = Object.freeze(['orders.instrument', 'orders.price', 'orders.counterparty']);
const BROAD_COLUMNS = ORDER_COLUMNS;
const BOB_CEILING = Object.freeze(['orders.instrument', 'orders.side', 'orders.quantity', 'orders.status']);

// ORDER BY instrument LIMIT 1 always selects the deterministic EU-CARBON-DEC26 row.
const SEED_ROW = Object.freeze({ instrument: 'EU-CARBON-DEC26', price: 88.1, counterparty: 'Alpenwerk AG' });
const AUTHORIZED_SQL = 'SELECT instrument, price, counterparty FROM orders ORDER BY instrument LIMIT 1';
const OUT_OF_SCOPE_SQL = 'SELECT instrument, price, counterparty, quantity FROM orders ORDER BY instrument LIMIT 1';

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function toPositiveMs(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

// Polls the readiness probes until the deployed origin is up, so a cold start
// does not fail the whole run. The probe uses a cookieless visitor: neither
// endpoint provisions a session and both are safe to repeat.
export async function waitForReady(client, { deadlineMs = 60_000, intervalMs = 1_000 } = {}) {
  const probe = client.visitor();
  const deadline = Date.now() + deadlineMs;
  let lastError;
  for (;;) {
    try {
      const health = await probe.get('/healthz');
      if (health.status === 200 && health.json?.status === 'ok') {
        const ready = await probe.get('/readyz');
        if (ready.status === 200 && ready.json?.status === 'ready') return;
        lastError = new Error(`readyz returned ${ready.status}`);
      } else {
        lastError = new Error(`healthz returned ${health.status}`);
      }
    } catch (error) {
      lastError = error;
    }
    if (Date.now() + intervalMs > deadline) {
      throw new Error(`remote Playground not ready: ${lastError?.message ?? 'unknown error'}`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

export async function login(client, humanAlias) {
  const visitor = client.visitor();
  const response = await visitor.post('/api/login', { humanDid: humanAlias });
  assert.equal(response.status, 200,
    `login as ${humanAlias} must return 200, got ${response.status}`);
  // The server issues a did:key identity, not the requested alias; every later
  // call reuses the returned did via session.humanDid.
  const issued = response.json?.humanDid;
  assert.ok(typeof issued === 'string' && issued.startsWith('did:key:z'),
    'login must issue a did:key identity');
  return { visitor, session: response.json };
}

async function createAgent(visitor, humanDid, name) {
  const response = await visitor.post('/api/agents', { humanDid, name });
  assert.equal(response.status, 201, `agent creation must return 201, got ${response.status}`);
  assert.ok(typeof response.json?.did === 'string' && response.json.did.length > 0,
    'agent creation must return a did');
  return response.json;
}

function runQuery(visitor, { agent, credential, sql }) {
  return visitor.post('/api/query', { agent, credential, sql });
}

async function createAgentWithCredential(visitor, humanDid, name) {
  const agent = await createAgent(visitor, humanDid, name);
  const issued = await visitor.post('/api/credentials', {
    humanDid,
    agent: agent.did,
    columns: [...ALICE_COLUMNS],
    expiresIn: '5m',
  });
  assert.equal(issued.status, 201, `credential issuance for ${name} must return 201, got ${issued.status}`);
  const credential = issued.json.credential;
  assert.ok(typeof credential === 'string' && credential.length > 0, `credential for ${name} must be issued`);
  return { agent, credential };
}

function sandboxRaw(visitor, sql) {
  return visitor.post('/api/sim/raw', { sql });
}

function assertSeedRow(result, label) {
  assert.equal(result.ok, true, `${label}: query must report ok`);
  assert.equal(result.rows?.length, 1, `${label}: query must return exactly one seed row`);
  // Boolean guards: a mismatched (possibly decrypted) value must never land in error.message.
  const row = result.rows[0];
  assert.ok(row.instrument === SEED_ROW.instrument, `${label}: instrument must match the deterministic seed`);
  assert.ok(Number(row.price) === SEED_ROW.price, `${label}: price must decrypt to the seed value`);
  assert.ok(row.counterparty === SEED_ROW.counterparty, `${label}: counterparty must decrypt to the seed value`);
}

// Login as Alice, create her agent, issue an in-scope credential, and prove the
// authorized read decrypts the seed row while the audit trail correlates to it.
export async function assertAuthorizedRead(client) {
  const { visitor, session } = await login(client, 'alice');
  const agent = await createAgent(visitor, session.humanDid, `remote-smoke-${Date.now()}`);
  const issued = await visitor.post('/api/credentials', {
    humanDid: session.humanDid,
    agent: agent.did,
    columns: [...ALICE_COLUMNS],
    expiresIn: '5m',
  });
  assert.equal(issued.status, 201, `alice credential issuance must return 201, got ${issued.status}`);
  const credential = issued.json.credential;
  assert.ok(typeof credential === 'string' && credential.length > 0, 'alice credential must be issued');

  const response = await runQuery(visitor, { agent: agent.did, credential, sql: AUTHORIZED_SQL });
  assert.equal(response.status, 200,
    `authorized query must return 200, got ${response.status}`);
  const result = response.json;
  assertSeedRow(result, 'authorized query');
  assert.deepEqual([...(result.metadata?.columnsDecrypted ?? [])].sort(), [...ENCRYPTED_COLUMNS].sort(),
    'exactly the encrypted in-scope columns must be decrypted');
  const auditId = result.metadata?.auditId;
  assert.ok(typeof auditId === 'string' && auditId.length > 0, 'result metadata must carry an auditId');
  assert.equal(result.inspection?.evidence?.auditId, auditId, 'inspection evidence must reference the audit record');

  const audit = await visitor.get('/api/audit');
  assert.equal(audit.status, 200, 'audit export must return 200');
  const record = audit.json.records.find((candidate) => candidate.id === auditId);
  assert.ok(record, 'audit export must contain the correlated record');
  assert.equal(record.agentDid, agent.did, 'audit record must belong to the querying agent');
  assert.equal(record.status, 'success', 'audit record must report success');
  assert.equal(record.queryHash, sha256(AUTHORIZED_SQL), 'audit record must hash the exact executed SQL');
  assert.equal(record.rowCount, 1, 'audit record must report the returned row count');

  return { visitor, session, agent, credential };
}

// The same SQL with a column outside the narrow credential is denied by the
// scope engine before execution: 403, no rows, and a rejected audit record.
export async function assertOutOfScopeRejected(alice) {
  const response = await runQuery(alice.visitor,
    { agent: alice.agent.did, credential: alice.credential, sql: OUT_OF_SCOPE_SQL });
  assert.equal(response.status, 403,
    `out-of-scope query must return 403, got ${response.status}`);
  const body = response.json;
  assert.equal(body.ok, false, 'out-of-scope query must not report ok');
  assert.equal(body.error, 'ScopeViolationError',
    'out-of-scope denial must come from the scope engine, not a generic error');
  // Guard as a boolean so a misbehaving server cannot dump rows/metadata into the failure text.
  assert.ok(body.rows === undefined, 'out-of-scope query must return no rows');
  assert.ok(body.metadata === undefined, 'out-of-scope query must return no result metadata');
  assert.equal(body.inspection?.evidence?.error, 'SCOPE_VIOLATION',
    'out-of-scope query evidence must report SCOPE_VIOLATION');
  assert.equal(body.inspection?.evidence?.authorization, 'rejected',
    'out-of-scope query evidence must report rejected');

  const audit = await alice.visitor.get('/api/audit');
  const rejection = audit.json.records.find(
    (record) => record.queryHash === sha256(OUT_OF_SCOPE_SQL) && record.status === 'rejected');
  assert.ok(rejection, 'audit must record the rejected SQL');
  assert.equal(rejection.agentDid, alice.agent.did, 'rejection record must be attributed to the querying agent');
  assert.equal(rejection.reasonCode, 'SCOPE_VIOLATION', 'rejection record must carry the scope-violation reason code');
  assert.equal(rejection.rowCount, 0, 'rejection record must report zero executed rows');
}

// Positive control: a broader credential for the same agent lets the previously
// rejected SQL execute, proving the 403 above was a scope denial not an error.
export async function assertBroadCredentialAllows(alice) {
  const issued = await alice.visitor.post('/api/credentials', {
    humanDid: alice.session.humanDid,
    agent: alice.agent.did,
    columns: [...BROAD_COLUMNS],
    expiresIn: '5m',
  });
  assert.equal(issued.status, 201, `broad credential issuance must return 201, got ${issued.status}`);
  const credential = issued.json.credential;
  assert.ok(typeof credential === 'string' && credential.length > 0, 'broad credential must be issued');

  const response = await runQuery(alice.visitor, { agent: alice.agent.did, credential, sql: OUT_OF_SCOPE_SQL });
  assert.equal(response.status, 200,
    `broad-credential query must return 200, got ${response.status}`);
  assertSeedRow(response.json, 'broad-credential query');
}

// Bob's identity ceiling (assigned server-side, as from IdP groups) excludes the
// encrypted columns: price is denied, an in-ceiling column is issued.
export async function assertRestrictedIdentityCeiling(client) {
  const { visitor, session } = await login(client, 'bob');
  assert.deepEqual(session.ceiling?.columns, [...BOB_CEILING],
    'bob session must carry the restricted demo ceiling without encrypted columns');
  const agent = await createAgent(visitor, session.humanDid, `remote-smoke-bob-${Date.now()}`);

  const denied = await visitor.post('/api/credentials', {
    humanDid: session.humanDid,
    agent: agent.did,
    columns: ['orders.instrument', 'orders.price'],
    expiresIn: '5m',
  });
  assert.equal(denied.status, 403, `ceiling violation must return 403, got ${denied.status}`);
  assert.equal(denied.json.error, 'ScopeExceedsCeilingError',
    'denial must be the identity ceiling, not ownership or session handling');
  assert.match(denied.json.message, /exceeds session ceiling/, 'denial must cite the session ceiling');
  assert.match(denied.json.message, /orders\.price/, 'denial must name the excess column');
  // assert.ok on the boolean keeps the token out of error.message if a denial ever leaks one.
  assert.ok(denied.json.credential === undefined, 'no credential may be issued to bob for encrypted columns');

  const allowed = await visitor.post('/api/credentials', {
    humanDid: session.humanDid,
    agent: agent.did,
    columns: ['orders.instrument'],
    expiresIn: '5m',
  });
  assert.equal(allowed.status, 201, `in-ceiling credential for bob must return 201, got ${allowed.status}`);
  assert.ok(typeof allowed.json.credential === 'string' && allowed.json.credential.length > 0,
    'in-ceiling credential for bob must be issued');
}

// Two independent Alice sessions: distinct cookies, and each visitor sees only
// its own agents and its own audit records. Visitor A reuses an already
// authenticated Alice session so the full smoke holds at most three concurrent
// sessions; only visitor B is a fresh login.
export async function assertVisitorIsolation(client, aliceA) {
  const a = aliceA;
  const b = await login(client, 'alice');
  assert.ok(a.visitor.cookie && b.visitor.cookie, 'each alice login must carry a session cookie');
  assert.ok(a.visitor.cookie !== b.visitor.cookie, 'two alice logins must mint distinct session cookies');

  const [flowA, flowB] = await Promise.all([
    createAgentWithCredential(a.visitor, a.session.humanDid, `iso-a-${Date.now()}`),
    createAgentWithCredential(b.visitor, b.session.humanDid, `iso-b-${Date.now()}`),
  ]);

  const agentsA = await a.visitor.get('/api/agents');
  const agentsB = await b.visitor.get('/api/agents');
  assert.equal(agentsA.status, 200, 'visitor A agent listing must return 200');
  assert.equal(agentsB.status, 200, 'visitor B agent listing must return 200');
  const didsA = agentsA.json.agents.map((entry) => entry.did);
  const didsB = agentsB.json.agents.map((entry) => entry.did);
  assert.ok(didsA.includes(flowA.agent.did), 'visitor A must list its own agent');
  assert.ok(didsB.includes(flowB.agent.did), 'visitor B must list its own agent');
  assert.ok(!didsA.includes(flowB.agent.did), 'visitor A must not list visitor B agent');
  assert.ok(!didsB.includes(flowA.agent.did), 'visitor B must not list visitor A agent');

  // One authorized query each, purely to generate a per-visitor audit record.
  const queryA = await runQuery(a.visitor, { agent: flowA.agent.did, credential: flowA.credential, sql: AUTHORIZED_SQL });
  assert.equal(queryA.status, 200, 'visitor A authorized query must return 200');
  const queryB = await runQuery(b.visitor, { agent: flowB.agent.did, credential: flowB.credential, sql: AUTHORIZED_SQL });
  assert.equal(queryB.status, 200, 'visitor B authorized query must return 200');

  const auditA = await a.visitor.get('/api/audit');
  const auditB = await b.visitor.get('/api/audit');
  assert.equal(auditA.status, 200, 'visitor A audit export must return 200');
  assert.equal(auditB.status, 200, 'visitor B audit export must return 200');
  const auditAgentsA = new Set(auditA.json.records.map((record) => record.agentDid));
  const auditAgentsB = new Set(auditB.json.records.map((record) => record.agentDid));
  assert.ok(auditAgentsA.has(flowA.agent.did), 'visitor A audit must contain its own agent record');
  assert.ok(auditAgentsB.has(flowB.agent.did), 'visitor B audit must contain its own agent record');
  assert.ok(!auditAgentsA.has(flowB.agent.did), 'visitor A audit must not contain visitor B agent');
  assert.ok(!auditAgentsB.has(flowA.agent.did), 'visitor B audit must not contain visitor A agent');

  return { a, b, flowA, flowB };
}

// Mark both sandboxes differently, reset only visitor A, and prove A recovers
// the canonical seed while B keeps its marker and can still run an authorized
// query against its own protected data.
export async function assertIndependentResetLeavesOtherUnchanged(isolation) {
  const { a, b, flowB } = isolation;
  const markerA = 'ISO-A';
  const markerB = 'ISO-B';

  const updateA = await sandboxRaw(a.visitor, `UPDATE orders_plaintext SET status = '${markerA}' WHERE id = 1`);
  assert.equal(updateA.status, 200, 'visitor A sandbox marker must return 200');
  assert.ok(updateA.json?.ok === true && updateA.json?.rowCount === 1, 'visitor A sandbox marker must touch exactly one row');
  const updateB = await sandboxRaw(b.visitor, `UPDATE orders_plaintext SET status = '${markerB}' WHERE id = 1`);
  assert.equal(updateB.status, 200, 'visitor B sandbox marker must return 200');
  assert.ok(updateB.json?.ok === true && updateB.json?.rowCount === 1, 'visitor B sandbox marker must touch exactly one row');

  // The two sandboxes now hold different data; a reset must not cross that line.
  const statusA = await sandboxRaw(a.visitor, 'SELECT status FROM orders_plaintext WHERE id = 1');
  const statusB = await sandboxRaw(b.visitor, 'SELECT status FROM orders_plaintext WHERE id = 1');
  assert.equal(statusA.json?.rows?.[0]?.status, markerA, 'visitor A sandbox must hold its own marker');
  assert.equal(statusB.json?.rows?.[0]?.status, markerB, 'visitor B sandbox must hold its own marker');

  const resetA = await a.visitor.post('/api/sim/reset');
  assert.equal(resetA.status, 200, 'visitor A sandbox reset must return 200');
  assert.ok(resetA.json?.ok === true, 'visitor A sandbox reset must report ok');
  assert.equal(resetA.json?.rows, 8, 'visitor A sandbox reset must restore the canonical eight rows');

  const afterA = await sandboxRaw(a.visitor, 'SELECT status FROM orders_plaintext WHERE id = 1');
  assert.equal(afterA.json?.rows?.[0]?.status, 'OPEN', 'visitor A reset must restore the canonical status');
  const afterB = await sandboxRaw(b.visitor, 'SELECT status FROM orders_plaintext WHERE id = 1');
  assert.equal(afterB.json?.rows?.[0]?.status, markerB, 'visitor A reset must leave visitor B sandbox unchanged');

  const queryB = await runQuery(b.visitor, { agent: flowB.agent.did, credential: flowB.credential, sql: AUTHORIZED_SQL });
  assert.equal(queryB.status, 200, 'visitor B authorized query must still return 200 after visitor A reset');
  assertSeedRow(queryB.json, 'visitor B post-reset');
}

export async function runRemoteSmoke(client, { readyDeadlineMs = 60_000, readyIntervalMs = 1_000 } = {}) {
  await waitForReady(client, { deadlineMs: readyDeadlineMs, intervalMs: readyIntervalMs });
  const alice = await assertAuthorizedRead(client);
  await assertOutOfScopeRejected(alice);
  await assertBroadCredentialAllows(alice);
  await assertRestrictedIdentityCeiling(client);
  const isolation = await assertVisitorIsolation(client, alice);
  await assertIndependentResetLeavesOtherUnchanged(isolation);
}

const TARGET_ERROR =
  'PLAYGROUND_SMOKE_BASE_URL must be a bare HTTPS origin without a path, query, or credentials';

function resolveOrigin(env) {
  const raw = env.PLAYGROUND_SMOKE_BASE_URL;
  if (raw === undefined) return { code: 2, error: 'PLAYGROUND_SMOKE_BASE_URL is required for the remote smoke' };
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { code: 2, error: TARGET_ERROR };
  }
  if (url.protocol !== 'https:' || url.username || url.password ||
    url.pathname !== '/' || url.search || url.hash) {
    return { code: 2, error: TARGET_ERROR };
  }
  return { code: 0, origin: url.origin };
}

async function main() {
  const target = resolveOrigin(process.env);
  if (target.code !== 0) {
    console.error(`remote smoke: ${target.error}`);
    return target.code;
  }
  const client = createRemoteSmokeClient(target.origin,
    { timeoutMs: toPositiveMs(process.env.PLAYGROUND_SMOKE_TIMEOUT_MS, 30_000) });
  try {
    await runRemoteSmoke(client, {
      readyDeadlineMs: toPositiveMs(process.env.PLAYGROUND_SMOKE_READY_TIMEOUT_MS, 60_000),
      readyIntervalMs: toPositiveMs(process.env.PLAYGROUND_SMOKE_READY_INTERVAL_MS, 1_000),
    });
  } catch (error) {
    console.error(error?.message ?? String(error));
    return 1;
  }
  console.log('Remote smoke passed.');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
    .then((code) => process.exit(code))
    .catch((error) => {
      console.error(error?.message ?? String(error));
      process.exit(1);
    });
}
