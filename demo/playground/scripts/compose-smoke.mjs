#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';

const projectName = `agents-playground-test-${process.pid}`;
const externalDatabaseName = `${projectName}-external-db`;
const projectNetwork = `${projectName}_default`;
const appRole = 'agents_playground_app';
const hostPort = process.env.PLAYGROUND_TEST_PORT ?? String(20_000 + (process.pid % 20_000));
const baseUrl = `http://127.0.0.1:${hostPort}`;
const commandEnv = {
  ...process.env,
  PLAYGROUND_IMAGE: `agents-playground-test:${process.pid}`,
  PLAYGROUND_PORT: hostPort,
  PLAYGROUND_NEW_SESSION_RATE_LIMIT: '10000',
  PLAYGROUND_NEW_SESSION_RATE_WINDOW_MS: '60000',
  PLAYGROUND_DATABASE_URL:
    'postgresql://postgres:postgres@postgres:5432/playground?user=postgres&password=postgres',
};
delete commandEnv.PLAYGROUND_MASTER_KEY;
let postgresContainer = 'postgres';
let visitorCookie;
let visitorDatabase;

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: new URL('..', import.meta.url),
    env: commandEnv,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error([
      `${command} ${args.join(' ')} failed with exit code ${result.status}`,
      result.stdout,
      result.stderr,
    ].filter(Boolean).join('\n'));
  }
  return result.stdout.trim();
}

function compose(args) {
  return run('docker', ['compose', '--project-name', projectName, ...args]);
}

function psql(database, sql, role = 'postgres') {
  const args = ['psql', '-U', role, '-d', database, '-Atc', sql];
  return postgresContainer === 'postgres'
    ? compose(['exec', '-T', 'postgres', ...args])
    : run('docker', ['exec', postgresContainer, ...args]);
}

function visitorDatabases() {
  const names = psql('postgres',
    "SELECT datname FROM pg_database WHERE datname ~ '^agents_playground_visitor_[0-9a-f]{32}$' ORDER BY datname");
  return names ? names.split('\n') : [];
}

function configFingerprint() {
  return compose([
    'exec', '-T', 'playground', 'node', '-e',
    "const {createHash}=require('node:crypto');const {readFileSync}=require('node:fs');process.stdout.write(createHash('sha256').update(readFileSync(process.env.PLAYGROUND_ENV_FILE)).digest('hex'))",
  ]);
}

function masterKeyFingerprint() {
  return compose([
    'exec', '-T', 'playground', 'node', '-e',
    "const {createHash}=require('node:crypto');const {readFileSync}=require('node:fs');" +
    "const key=readFileSync(process.env.PLAYGROUND_ENV_FILE,'utf8')" +
    ".match(/^AGENTS_MASTER_KEY=(.+)$/m)?.[1];" +
    "if(!/^[0-9a-f]{64}$/.test(key??''))process.exit(1);" +
    "process.stdout.write(createHash('sha256').update(key).digest('hex'))",
  ]);
}

function databaseState(database = visitorDatabase) {
  return psql(database,
    "SELECT (SELECT count(*) FROM orders), (SELECT count(*) FROM orders_plaintext), (SELECT count(*) FROM agent_keys WHERE table_name = 'orders'), (SELECT count(*) FROM agent_columns WHERE table_name = 'orders' AND is_encrypted)");
}

const SNAPSHOT_SQL = [
  'agents',
  'revoked_credentials',
  'agent_audit',
  'orders',
  'orders_plaintext',
].map((table) => `SELECT row_to_json(t) FROM ${table} t`).join('\nUNION ALL\n');

function stateSnapshot(database = visitorDatabase) {
  const rows = psql(database, SNAPSHOT_SQL);
  return rows ? rows.split('\n').sort() : [];
}

function assertStateUnchanged(before, database = visitorDatabase) {
  const after = stateSnapshot(database);
  const added = after.filter((row) => !before.includes(row));
  const removed = before.filter((row) => !after.includes(row));
  assert.deepEqual(added, [], `request added state rows:\n${added.join('\n')}`);
  assert.deepEqual(removed, [], `request removed state rows:\n${removed.join('\n')}`);
}

function tableFingerprint(table) {
  const rows = psql(visitorDatabase, `SELECT row_to_json(t)::text FROM ${table} t`);
  return rows ? rows.split('\n').sort() : [];
}

function roleState(role) {
  return psql('playground',
    `SELECT rolname || '|' || rolsuper || '|' || rolcreatedb || '|' || rolcreaterole || '|' || rolinherit || '|' || rolreplication || '|' || rolbypassrls || '|' || (SELECT count(*) FROM pg_auth_members WHERE member = pg_roles.oid) FROM pg_roles WHERE rolname = '${role}'`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function smokeFetch(path, init = {}) {
  return fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { ...init.headers, connection: 'close' },
  });
}

function visitorFetch(path, init = {}) {
  return smokeFetch(path, {
    ...init,
    headers: { ...(visitorCookie ? { cookie: visitorCookie } : {}), ...init.headers },
  });
}

function fetchWithCookie(cookie) {
  return (path, init = {}) => smokeFetch(path, {
    ...init,
    headers: { cookie, ...(init.method === 'POST' ? { 'content-type': 'application/json' } : {}), ...init.headers },
  });
}

async function createIndependentSession(humanDid) {
  const databasesBefore = visitorDatabases();
  const response = await smokeFetch('/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ humanDid }),
  });
  const session = await response.json();
  assert.ok(response.ok, `independent login (${humanDid}) returned ${response.status}: ${JSON.stringify(session)}`);
  const cookie = response.headers.get('set-cookie')?.split(';', 1)[0];
  assert.match(cookie, /^visitorSessionId=[A-Za-z0-9_-]{43}$/, `independent login (${humanDid}) must set an opaque visitor cookie`);
  const created = visitorDatabases().filter((database) => !databasesBefore.includes(database));
  assert.equal(created.length, 1, `independent login (${humanDid}) must provision exactly one visitor database`);
  return { session, cookie, database: created[0], fetchAs: fetchWithCookie(cookie) };
}

async function authorizedQuery({ fetchAs, agent, credential, label }) {
  const sql = 'SELECT instrument, price, counterparty FROM orders ORDER BY instrument LIMIT 1';
  const response = await fetchAs('/api/query', {
    method: 'POST',
    body: JSON.stringify({ agent: agent.did, credential, sql }),
  });
  const result = await response.json();
  assert.equal(response.status, 200, `${label}: authorized query must return 200, got ${response.status}: ${JSON.stringify(result)}`);
  assert.equal(result.ok, true, `${label}: authorized query must report ok`);
  assert.equal(result.rows?.length, 1, `${label}: authorized query must return exactly one seed row`);
  assert.equal(result.rows[0].instrument, 'EU-CARBON-DEC26', `${label}: first instrument must match the deterministic seed`);
  assert.equal(Number(result.rows[0].price), 88.1, `${label}: price must decrypt to the seed value`);
  assert.equal(result.rows[0].counterparty, 'Alpenwerk AG', `${label}: counterparty must decrypt to the seed value`);
  assert.deepEqual([...(result.metadata?.columnsDecrypted ?? [])].sort(), ['orders.counterparty', 'orders.price'],
    `${label}: exactly the encrypted in-scope columns must be decrypted`);
  const auditId = result.metadata?.auditId;
  assert.ok(typeof auditId === 'string' && auditId.length > 0, `${label}: result metadata must carry an auditId`);
  assert.equal(result.inspection?.evidence?.auditId, auditId, `${label}: inspection evidence must reference the audit record`);
  const auditResponse = await fetchAs('/api/audit');
  const audit = await auditResponse.json();
  assert.equal(auditResponse.status, 200, `${label}: audit export must return 200`);
  const record = audit.records.find((candidate) => candidate.id === auditId);
  assert.ok(record, `${label}: audit export must contain the correlated record ${auditId}`);
  assert.equal(record.agentDid, agent.did, `${label}: audit record must belong to the querying agent`);
  assert.equal(record.status, 'success', `${label}: audit record must report success`);
  assert.equal(record.queryHash, sha256(sql), `${label}: audit record must hash the exact executed SQL`);
  assert.equal(record.rowCount, 1, `${label}: audit record must report the returned row count`);
  return { sql, auditId };
}

async function request(path, init = {}) {
  const headers = init.method === 'POST'
    ? { 'content-type': 'application/json', ...init.headers }
    : init.headers;
  const response = await visitorFetch(path, { ...init, headers });
  const body = await response.json();
  assert.ok(response.ok, `${path} returned ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

async function login() {
  const databasesBefore = visitorDatabases();
  const response = await visitorFetch('/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ humanDid: 'alice' }),
  });
  const session = await response.json();
  assert.ok(response.ok, `/api/login returned ${response.status}: ${JSON.stringify(session)}`);
  const cookie = response.headers.get('set-cookie')?.split(';', 1)[0];
  assert.match(cookie, /^visitorSessionId=[A-Za-z0-9_-]{43}$/);
  const created = visitorDatabases().filter((database) => !databasesBefore.includes(database));
  if (cookie === visitorCookie) {
    assert.deepEqual(created, [], 'reusing a session must not provision another database');
  } else {
    assert.equal(created.length, 1, 'a new session must provision exactly one visitor database');
    visitorDatabase = created[0];
  }
  visitorCookie = cookie;
  return session;
}

async function authorizedRead() {
  const session = await login();
  const agent = await request('/api/agents', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ humanDid: session.humanDid, name: `compose-smoke-${Date.now()}` }),
  });
  const { credential } = await request('/api/credentials', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      humanDid: session.humanDid,
      agent: agent.did,
      columns: ['orders.instrument', 'orders.price', 'orders.counterparty'],
      expiresIn: '5m',
    }),
  });
  const fetchAs = (path, init = {}) => visitorFetch(path, {
    ...init,
    headers: { 'content-type': 'application/json', ...init.headers },
  });
  const { sql, auditId } = await authorizedQuery({ fetchAs, agent, credential, label: 'compose-smoke' });
  return { session, agent, credential, sql, auditId };
}

async function assertOutOfScopeQueryIsRejectedAndNotExecuted() {
  const { session, agent, credential } = await authorizedRead();
  const outOfScopeSql = 'SELECT instrument, price, counterparty, quantity FROM orders ORDER BY instrument LIMIT 1';
  const queryHash = sha256(outOfScopeSql);

  // Control: the identical SQL succeeds with a broader credential, proving it is
  // executable and returns seed data, so the 403 below cannot mask an execution failure.
  const broad = await request('/api/credentials', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      humanDid: session.humanDid,
      agent: agent.did,
      columns: ['orders.instrument', 'orders.side', 'orders.quantity', 'orders.status', 'orders.price', 'orders.counterparty'],
      expiresIn: '5m',
    }),
  });
  const control = await visitorFetch('/api/query', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ agent: agent.did, credential: broad.credential, sql: outOfScopeSql }),
  });
  const controlBody = await control.json();
  assert.equal(control.status, 200,
    `out-of-scope control: broad-credential query must return 200, got ${control.status}: ${JSON.stringify(controlBody)}`);
  assert.equal(controlBody.rows?.[0]?.instrument, 'EU-CARBON-DEC26',
    'out-of-scope control: broad-credential query must return the deterministic seed row');

  const ordersBefore = tableFingerprint('orders');
  const plaintextBefore = tableFingerprint('orders_plaintext');
  const auditCountBefore = psql(visitorDatabase, 'SELECT count(*) FROM agent_audit');

  const rejected = await visitorFetch('/api/query', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ agent: agent.did, credential, sql: outOfScopeSql }),
  });
  const body = await rejected.json();
  assert.equal(rejected.status, 403, `out-of-scope query must return 403, got ${rejected.status}: ${JSON.stringify(body)}`);
  assert.equal(body.ok, false, 'out-of-scope query must not report ok');
  assert.equal(body.error, 'ScopeViolationError', 'out-of-scope denial must come from the scope engine, not a generic error');
  assert.equal(body.rows, undefined, 'out-of-scope query must return no rows');
  assert.equal(body.metadata, undefined, 'out-of-scope query must return no result metadata');
  assert.equal(body.inspection?.evidence?.error, 'SCOPE_VIOLATION', 'out-of-scope query evidence must report SCOPE_VIOLATION');
  assert.equal(body.inspection?.evidence?.authorization, 'rejected', 'out-of-scope query evidence must report rejected');

  const audit = await (await visitorFetch('/api/audit')).json();
  const rejection = audit.records.find((record) => record.queryHash === queryHash && record.status === 'rejected');
  assert.ok(rejection, `audit must record the rejected SQL with hash ${queryHash}`);
  assert.equal(rejection.agentDid, agent.did, 'rejection record must be attributed to the querying agent');
  assert.equal(rejection.reasonCode, 'SCOPE_VIOLATION', 'rejection record must carry the scope-violation reason code');
  assert.equal(rejection.rowCount, 0, 'rejection record must report zero executed rows');

  assert.deepEqual(tableFingerprint('orders'), ordersBefore, 'rejected query must not modify protected orders');
  assert.deepEqual(tableFingerprint('orders_plaintext'), plaintextBefore, 'rejected query must not modify the comparison sandbox');
  assert.equal(psql(visitorDatabase, 'SELECT count(*) FROM agent_audit'), String(Number(auditCountBefore) + 1),
    'rejected query must add exactly one audit record');
}

async function assertRestrictedIdentityCannotObtainEncryptedColumns() {
  const bob = await createIndependentSession('bob');
  assert.deepEqual(bob.session.ceiling?.columns, ['orders.instrument', 'orders.side', 'orders.quantity', 'orders.status'],
    'bob session must carry the restricted demo ceiling without encrypted columns');

  const created = await bob.fetchAs('/api/agents', {
    method: 'POST',
    body: JSON.stringify({ humanDid: bob.session.humanDid, name: 'bob-smoke-agent' }),
  });
  const agent = await created.json();
  assert.equal(created.status, 201, `bob agent creation returned ${created.status}: ${JSON.stringify(agent)}`);

  const before = stateSnapshot(bob.database);
  const denied = await bob.fetchAs('/api/credentials', {
    method: 'POST',
    body: JSON.stringify({
      humanDid: bob.session.humanDid,
      agent: agent.did,
      columns: ['orders.instrument', 'orders.price'],
      expiresIn: '5m',
    }),
  });
  const deniedBody = await denied.json();
  assert.equal(denied.status, 403, `ceiling violation must return 403, got ${denied.status}: ${JSON.stringify(deniedBody)}`);
  assert.equal(deniedBody.error, 'ScopeExceedsCeilingError', 'denial must be the identity ceiling, not ownership or session handling');
  assert.match(deniedBody.message, /exceeds session ceiling/, 'denial must cite the session ceiling');
  assert.match(deniedBody.message, /orders\.price/, 'denial must name the excess column');
  assert.equal(deniedBody.credential, undefined, 'no credential may be issued to bob for encrypted columns');
  assertStateUnchanged(before, bob.database);

  const allowed = await bob.fetchAs('/api/credentials', {
    method: 'POST',
    body: JSON.stringify({
      humanDid: bob.session.humanDid,
      agent: agent.did,
      columns: ['orders.instrument'],
      expiresIn: '5m',
    }),
  });
  const allowedBody = await allowed.json();
  assert.equal(allowed.status, 201, `in-ceiling credential for bob must succeed, got ${allowed.status}: ${JSON.stringify(allowedBody)}`);
  assert.ok(typeof allowedBody.credential === 'string' && allowedBody.credential.length > 0,
    'in-ceiling credential for bob must be issued');
}

async function runProtectedFlow(visitor, agentName) {
  const created = await visitor.fetchAs('/api/agents', {
    method: 'POST',
    body: JSON.stringify({ humanDid: visitor.session.humanDid, name: agentName }),
  });
  const agent = await created.json();
  assert.equal(created.status, 201, `${agentName} creation returned ${created.status}: ${JSON.stringify(agent)}`);
  const issued = await visitor.fetchAs('/api/credentials', {
    method: 'POST',
    body: JSON.stringify({
      humanDid: visitor.session.humanDid,
      agent: agent.did,
      columns: ['orders.instrument', 'orders.price', 'orders.counterparty'],
      expiresIn: '5m',
    }),
  });
  const { credential } = await issued.json();
  assert.equal(issued.status, 201, `${agentName} credential issuance returned ${issued.status}`);
  assert.ok(typeof credential === 'string' && credential.length > 0, `${agentName} credential must be issued`);
  const flow = await authorizedQuery({ fetchAs: visitor.fetchAs, agent, credential, label: agentName });
  return { agent, credential, ...flow };
}

async function assertConcurrentVisitorSessionsAreIsolated() {
  const first = await createIndependentSession('alice');
  const second = await createIndependentSession('alice');
  assert.notEqual(first.cookie, second.cookie, 'each alice login must mint a distinct opaque cookie');
  assert.notEqual(first.database, second.database, 'each alice session must own a distinct database');

  const [flowFirst, flowSecond] = await Promise.all([
    runProtectedFlow(first, 'iso-first-agent'),
    runProtectedFlow(second, 'iso-second-agent'),
  ]);

  const firstAgentsResponse = await first.fetchAs('/api/agents');
  const secondAgentsResponse = await second.fetchAs('/api/agents');
  assert.equal(firstAgentsResponse.status, 200, 'visitor A agent listing must return 200');
  assert.equal(secondAgentsResponse.status, 200, 'visitor B agent listing must return 200');
  const firstAgentList = (await firstAgentsResponse.json()).agents.map((entry) => entry.did);
  const secondAgentList = (await secondAgentsResponse.json()).agents.map((entry) => entry.did);
  assert.ok(firstAgentList.includes(flowFirst.agent.did), 'visitor A must list its own agent');
  assert.ok(secondAgentList.includes(flowSecond.agent.did), 'visitor B must list its own agent');
  assert.ok(!firstAgentList.includes(flowSecond.agent.did), 'visitor A must not list visitor B agent');
  assert.ok(!secondAgentList.includes(flowFirst.agent.did), 'visitor B must not list visitor A agent');

  const firstAuditResponse = await first.fetchAs('/api/audit');
  const secondAuditResponse = await second.fetchAs('/api/audit');
  assert.equal(firstAuditResponse.status, 200, 'visitor A audit export must return 200');
  assert.equal(secondAuditResponse.status, 200, 'visitor B audit export must return 200');
  const firstAudit = (await firstAuditResponse.json()).records;
  const secondAudit = (await secondAuditResponse.json()).records;
  assert.ok(firstAudit.some((record) => record.id === flowFirst.auditId), 'visitor A audit must contain its correlated query record');
  assert.ok(secondAudit.some((record) => record.id === flowSecond.auditId), 'visitor B audit must contain its correlated query record');
  assert.equal(firstAudit.some((record) => record.agentDid === flowSecond.agent.did), false,
    'visitor A audit must not contain visitor B records');
  assert.equal(secondAudit.some((record) => record.agentDid === flowFirst.agent.did), false,
    'visitor B audit must not contain visitor A records');

  return { first, second, flowFirst, flowSecond };
}

async function assertIndependentResetLeavesOtherSessionUnchanged({ first, second, flowSecond }) {
  const update = await second.fetchAs('/api/sim/raw', {
    method: 'POST',
    body: JSON.stringify({ sql: "UPDATE orders_plaintext SET status = 'ISO-B' WHERE id = 1" }),
  });
  const updateBody = await update.json();
  assert.equal(update.status, 200, `visitor B sandbox marker write must return 200, got ${update.status}: ${JSON.stringify(updateBody)}`);
  assert.equal(updateBody.ok, true, 'visitor B sandbox marker write must succeed');
  assert.equal(updateBody.rowCount, 1, 'visitor B sandbox marker must touch exactly one row');
  assert.equal(psql(second.database, "SELECT status FROM orders_plaintext WHERE id = 1"), 'ISO-B',
    'visitor B sandbox marker must be persisted before the reset');

  const before = stateSnapshot(second.database);
  const reset = await first.fetchAs('/api/sim/reset', { method: 'POST' });
  const resetBody = await reset.json();
  assert.equal(reset.status, 200, `visitor A sandbox reset must return 200, got ${reset.status}: ${JSON.stringify(resetBody)}`);
  assert.equal(resetBody.rows, 8, 'visitor A sandbox reset must restore the canonical sandbox rows');
  assert.deepEqual(stateSnapshot(second.database), before, 'visitor A reset must leave visitor B protected, comparison, agent, and audit state unchanged');

  await authorizedQuery({ fetchAs: second.fetchAs, agent: flowSecond.agent, credential: flowSecond.credential, label: 'visitor B post-reset' });
}

async function existingValidationsStillFailClosed() {
  const { session, agent, credential } = await authorizedRead();

  const beforeBadAlias = stateSnapshot();
  const badAlias = await smokeFetch('/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ humanDid: 'mallory' }),
  });
  assert.equal(badAlias.status, 400);
  assert.match(await badAlias.text(), /humanDid must be alice or bob/);
  const noSession = await smokeFetch('/api/agents', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ humanDid: 'mallory', name: 'rejected-login-agent' }),
  });
  assert.equal(noSession.status, 401);
  assertStateUnchanged(beforeBadAlias);

  const beforeUnknownColumn = stateSnapshot();
  const unknownColumn = await visitorFetch('/api/credentials', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      humanDid: session.humanDid,
      agent: agent.did,
      columns: ['orders.id'],
    }),
  });
  assert.equal(unknownColumn.status, 400);
  const unknownColumnBody = await unknownColumn.json();
  assert.match(unknownColumnBody.message, /valid orders columns/);
  assert.equal(unknownColumnBody.credential, undefined);
  assertStateUnchanged(beforeUnknownColumn);

  const beforeWrongTable = stateSnapshot();
  const wrongTable = await visitorFetch('/api/query', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      agent: agent.did,
      credential,
      sql: 'SELECT instrument FROM orders LIMIT 1',
      table: 'other',
    }),
  });
  assert.equal(wrongTable.status, 400);
  assert.match(await wrongTable.text(), /table can only be orders/);
  assertStateUnchanged(beforeWrongTable);
}

async function assertBrowserRequestsRejected() {
  const beforeCrossOrigin = stateSnapshot();
  const crossOrigin = await visitorFetch('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://attacker.example' },
    body: JSON.stringify({ sql: 'DELETE FROM orders_plaintext' }),
  });
  assert.equal(crossOrigin.status, 403);
  assertStateUnchanged(beforeCrossOrigin);

  const beforeWrongContentType = stateSnapshot();
  const wrongContentType = await visitorFetch('/api/sim/raw', {
    method: 'POST',
    headers: { origin: baseUrl },
    body: JSON.stringify({ sql: 'DELETE FROM orders_plaintext' }),
  });
  assert.equal(wrongContentType.status, 415);
  assertStateUnchanged(beforeWrongContentType);
}

async function directSimulatorRead() {
  const result = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT COUNT(*)::int AS count FROM orders_plaintext' }),
  });
  assert.equal(result.ok, true);
  assert.equal(result.command, 'SELECT');
  assert.equal(result.rowsReturned, 1);
  assert.equal(result.rowCount, undefined);
  assert.equal(result.rows[0].count, 8);

  const qualified = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT COUNT(*)::int AS count FROM public.orders_plaintext' }),
  });
  assert.equal(qualified.ok, true);
  assert.equal(qualified.rows[0].count, 8);

  // The connection identity is a property of the naive pool, not of the SQL
  // surface: verify it directly as that role.
  const identity = psql(visitorDatabase, 'SELECT current_user', 'agents_playground_naive');
  assert.equal(identity, 'agents_playground_naive');

  async function rawRejected(sql, expected) {
    const before = stateSnapshot();
    const response = await visitorFetch('/api/sim/raw', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sql }),
    });
    assert.equal(response.status, 403, `${sql} -> ${response.status}`);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.equal(body.error, 'DirectSqlRejected');
    if (expected) assert.match(body.message, expected, sql);
    assertStateUnchanged(before);
  }

  await rawRejected('SELECT COUNT(*) FROM orders', /relation "orders" is not allowed/);
  await rawRejected('SELECT * FROM agents', /relation "agents" is not allowed/);
  await rawRejected('SELECT * FROM pg_catalog.pg_user', /relation "pg_catalog.pg_user" is not allowed/);
  await rawRejected('SELECT id FROM orders_plaintext; DELETE FROM orders_plaintext', /exactly one statement is allowed/);
  await rawRejected('SELECT pg_sleep(5) FROM orders_plaintext LIMIT 1', /function "pg_sleep" is not allowed/);
  await rawRejected("SELECT set_config('statement_timeout', '1ms', true) FROM orders_plaintext LIMIT 1", /function "set_config" is not allowed/);
  await rawRejected('SELECT pg_advisory_lock(42) FROM orders_plaintext LIMIT 1', /function "pg_advisory_lock" is not allowed/);
  await rawRejected('DROP TABLE orders_plaintext', /only SELECT, UPDATE or DELETE/);
  await rawRejected('ALTER TABLE orders_plaintext ADD COLUMN should_not_exist TEXT', /only SELECT, UPDATE or DELETE/);
  await rawRejected('CREATE TABLE evil_orders (id int)', /only SELECT, UPDATE or DELETE/);
  await rawRejected('TRUNCATE orders_plaintext', /only SELECT, UPDATE or DELETE/);
  await rawRejected('BEGIN', /only SELECT, UPDATE or DELETE/);
  await rawRejected('SET statement_timeout TO 0', /only SELECT, UPDATE or DELETE/);
  await rawRejected('WITH x AS (DELETE FROM orders_plaintext RETURNING *) SELECT * FROM x', /CTEs \(WITH clauses\) are not allowed/);
  await rawRejected('DELETE FROM orders_plaintext WHERE id = 1 RETURNING id', /RETURNING is not allowed/);
  await rawRejected('SELECT * INTO copied_orders FROM orders_plaintext', /SELECT INTO is not allowed/);
  await rawRejected('SELECT * FROM orders_plaintext FOR UPDATE', /locking clauses/);
  await rawRejected('SELECT * FROM (SELECT * FROM orders_plaintext) t', /FROM table expression "RangeSubselect"/);

  const update = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: "UPDATE orders_plaintext SET status = 'CHECKED' WHERE id = 1" }),
  });
  assert.equal(update.ok, true);
  assert.equal(update.rowCount, 1);

  const deletion = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'DELETE FROM orders_plaintext WHERE id = 1' }),
  });
  assert.equal(deletion.ok, true);
  assert.equal(deletion.rowCount, 1);
  const afterDeletion = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT COUNT(*)::int AS count FROM orders_plaintext' }),
  });
  assert.equal(afterDeletion.rows[0].count, 7);
  const reset = await request('/api/sim/reset', { method: 'POST' });
  assert.equal(reset.rows, 8);
  const afterReset = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT COUNT(*)::int AS count FROM orders_plaintext' }),
  });
  assert.equal(afterReset.rows[0].count, 8);

  const pruned = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'DELETE FROM orders_plaintext WHERE id = (SELECT min(id) FROM orders_plaintext)' }),
  });
  assert.equal(pruned.ok, true);
  assert.equal(pruned.rowCount, 1);

  const beforeOversizedReset = stateSnapshot();
  const oversizedReset = await visitorFetch('/api/sim/reset', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: 'x'.repeat(64 * 1024 + 1),
  });
  assert.equal(oversizedReset.status, 413);
  assert.match(await oversizedReset.text(), /Body exceeds the 64 KiB limit/);
  assertStateUnchanged(beforeOversizedReset);
  const resetSkipped = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT COUNT(*)::int AS count FROM orders_plaintext' }),
  });
  assert.equal(resetSkipped.rows[0].count, 7);

  const boundaryReset = await visitorFetch('/api/sim/reset', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: 'x'.repeat(64 * 1024),
  });
  assert.equal(boundaryReset.status, 200);
  assert.equal((await boundaryReset.json()).rows, 8);
}

async function assertRuntimeRoleRestricted() {
  const identity = await request('/api/sim/scoped', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT current_user AS instrument FROM orders LIMIT 1' }),
  });
  assert.equal(identity.rows[0].instrument, appRole);

  const response = await visitorFetch('/api/sim/scoped', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      sql: "SELECT pg_read_file('/etc/passwd') AS instrument FROM orders LIMIT 1",
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 500);
  assert.deepEqual(body, {
    error: 'InternalServerError',
    message: 'Request could not be completed',
  });
  assert.doesNotMatch(JSON.stringify(body), /pg_read_file|permission denied|root:x:0:0/);
}

async function timedRaw(sql) {
  const startedAt = Date.now();
  // connection: close avoids racing the server keep-alive idle timeout between
  // the long psql steps of this smoke.
  const response = await visitorFetch('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json', connection: 'close' },
    body: JSON.stringify({ sql }),
  });
  const body = await response.json();
  return { status: response.status, body, ms: Date.now() - startedAt };
}

function naiveSessionSettings() {
  return psql(visitorDatabase,
    "SELECT current_setting('statement_timeout') || '|' || current_setting('lock_timeout')", 'agents_playground_naive');
}

async function assertDirectSqlLimitsDoNotLeak() {
  assert.equal(naiveSessionSettings(), '0|0', 'pool sessions must carry no persistent timeouts');
  const fast = await timedRaw('SELECT COUNT(*)::int AS count FROM orders_plaintext');
  assert.equal(fast.body.ok, true);
  assert.ok(fast.ms < 2000, `post-timeout query must not be delayed (${fast.ms}ms)`);
}

async function assertPoolAcquisitionIsBounded() {
  const sql = 'SELECT count(*) FROM orders_plaintext a, orders_plaintext b';
  const requests = await Promise.all([timedRaw(sql), timedRaw(sql), timedRaw(sql)]);
  for (const request of requests) {
    assert.equal(request.status, 200);
    assert.equal(request.body.ok, false);
    assert.ok(request.ms < 3500, `pool-saturated request exceeded the bounded wait (${request.ms}ms)`);
  }
  await assertDirectSqlLimitsDoNotLeak();
}

async function assertStatementTimeout() {
  psql(visitorDatabase,
    "INSERT INTO orders_plaintext (instrument, side, quantity, price, counterparty, status) " +
    "SELECT 'TIMEOUT-SEED', 'BUY', 1, 1, 'x', 'OPEN' FROM generate_series(1, 1000000)");
  assert.equal(
    psql(visitorDatabase, "SELECT count(*) FROM orders_plaintext WHERE instrument = 'TIMEOUT-SEED'"),
    '1000000',
  );
  try {
    const slow = await timedRaw('SELECT count(*) FROM orders_plaintext a, orders_plaintext b');
    assert.equal(slow.body.ok, false);
    assert.equal(slow.body.error, 'TimeoutError');
    assert.equal(slow.body.kind, 'statement');
    assert.match(slow.body.message, /statement_timeout/);
    assert.ok(slow.ms >= 2000, `cancelled before the 2s statement timeout (${slow.ms}ms)`);
    assert.ok(slow.ms < 30_000, `statement timeout did not cancel the query (${slow.ms}ms)`);
    await assertDirectSqlLimitsDoNotLeak();
    await assertPoolAcquisitionIsBounded();
  } finally {
    psql(visitorDatabase, "DELETE FROM orders_plaintext WHERE instrument = 'TIMEOUT-SEED'");
  }
  assert.equal(databaseState(), '8|8|2|2');
}

async function assertLockTimeout() {
  // One implicit transaction: take the row lock with FOR UPDATE, then stay in
  // the transaction (holding it) for the duration of the pg_sleep.
  const lockerScript =
    'SELECT * FROM orders_plaintext WHERE id = 1 FOR UPDATE; ' +
    'SELECT pg_sleep(300);';
  const child = spawn(
    'docker',
    ['compose', '--project-name', projectName, 'exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', visitorDatabase, '-Atc', lockerScript],
    { cwd: new URL('..', import.meta.url), env: commandEnv, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let lockerPid = null;
  try {
    const deadline = Date.now() + 30_000;
    for (;;) {
      lockerPid = psql(visitorDatabase,
        "SELECT pid FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query LIKE '%pg_sleep(300)%' LIMIT 1");
      if (lockerPid !== '') break;
      if (Date.now() > deadline || child.exitCode !== null) {
        throw new Error(`row lock holder never appeared (exit=${child.exitCode}, stdout=${child.stdout.read()})`);
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    const before = psql(visitorDatabase, 'SELECT status FROM orders_plaintext WHERE id = 1');
    const blocked = await timedRaw("UPDATE orders_plaintext SET status = 'LOCKED' WHERE id = 1");
    assert.equal(blocked.body.ok, false);
    assert.equal(blocked.body.error, 'TimeoutError');
    assert.equal(blocked.body.kind, 'lock');
    assert.match(blocked.body.message, /lock_timeout/);
    assert.ok(blocked.ms >= 1000, `cancelled before the 1s lock timeout (${blocked.ms}ms)`);
    assert.ok(blocked.ms < 15_000, `lock timeout did not cancel the query (${blocked.ms}ms)`);
    const after = psql(visitorDatabase, 'SELECT status FROM orders_plaintext WHERE id = 1');
    assert.equal(after, before, 'the timed-out UPDATE must not have been applied');
    await assertDirectSqlLimitsDoNotLeak();
  } finally {
    if (lockerPid) {
      psql(visitorDatabase, `SELECT pg_terminate_backend(${Number(lockerPid)})`);
    }
    child.kill('SIGKILL');
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const holders = psql(visitorDatabase,
        "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query LIKE '%pg_sleep(300)%'");
      if (holders === '0') break;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

async function assertResultLimits() {
  const seed = 'ROWLIM';
  psql(visitorDatabase,
    `INSERT INTO orders_plaintext (instrument, side, quantity, price, counterparty, status) ` +
    `SELECT '${seed}', 'BUY', 1, 1, 'x', 'OPEN' FROM generate_series(1, 150)`);
  try {
    const limited = await timedRaw('SELECT id, instrument FROM orders_plaintext');
    assert.equal(limited.status, 200);
    assert.equal(limited.body.ok, true);
    assert.equal(limited.body.command, 'SELECT');
    assert.equal(limited.body.rowsReturned, 100);
    assert.equal(limited.body.rows.length, 100);
    assert.equal(limited.body.limitedBy, 'rows');
    assert.equal(limited.body.rowCount, undefined);
    assert.ok(Buffer.byteLength(JSON.stringify(limited.body, null, 2), 'utf8') <= 64 * 1024);
  } finally {
    psql(visitorDatabase, `DELETE FROM orders_plaintext WHERE instrument = '${seed}'`);
  }
  assert.equal(databaseState(), '8|8|2|2');

  psql(visitorDatabase, "UPDATE orders_plaintext SET counterparty = repeat('x', 200000) WHERE id = 1");
  try {
    const bytewise = await timedRaw('SELECT id, counterparty FROM orders_plaintext WHERE id = 1');
    assert.equal(bytewise.body.ok, true);
    assert.equal(bytewise.body.limitedBy, 'responseBytes');
    assert.equal(bytewise.body.rowsReturned, 0);
    assert.ok(Buffer.byteLength(JSON.stringify(bytewise.body, null, 2), 'utf8') <= 64 * 1024);
  } finally {
    psql(visitorDatabase, "UPDATE orders_plaintext SET counterparty = 'Meridian Energy' WHERE id = 1");
  }
  assert.equal(databaseState(), '8|8|2|2');
}

const CANONICAL_PLAINTEXT_ROWS = [
  '1|LNG-JKM-SEP26|BUY|500|12.45|Meridian Energy|OPEN',
  '2|LNG-JKM-OCT26|SELL|250|12.80|Hokuto Gas|OPEN',
  '3|NG-HH-SEP26|BUY|1000|3.215|Gulf Coast Trading|FILLED',
  '4|EU-CARBON-DEC26|BUY|750|88.10|Alpenwerk AG|OPEN',
  '5|LNG-JKM-NOV26|SELL|400|13.05|Meridian Energy|OPEN',
  '6|NG-HH-OCT26|SELL|600|3.410|Iberdrola Trading|CANCELLED',
  '7|EU-CARBON-SEP26|BUY|320|86.75|Nordvik Kraft|OPEN',
  '8|LNG-JKM-DEC26|BUY|150|13.30|Hokuto Gas|OPEN',
];

async function assertResetRestoresSandboxWithoutTouchingProtectedData() {
  const ordersBefore = tableFingerprint('orders');
  const auditBefore = tableFingerprint('agent_audit');
  assert.ok(ordersBefore.length > 0, 'orders fingerprint must capture encrypted rows');
  assert.ok(auditBefore.length > 0, 'agent_audit fingerprint must capture history rows');

  const updated = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: "UPDATE orders_plaintext SET status = 'MODIFIED' WHERE id <= 3" }),
  });
  assert.equal(updated.ok, true);
  assert.equal(updated.rowCount, 3);

  const deleted = await request('/api/sim/raw', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sql: 'DELETE FROM orders_plaintext WHERE id = 8' }),
  });
  assert.equal(deleted.ok, true);
  assert.equal(deleted.rowCount, 1);

  const reset = await request('/api/sim/reset', { method: 'POST' });
  assert.equal(reset.rows, 8);

  const canonical = psql(visitorDatabase,
    'SELECT id || \'|\' || instrument || \'|\' || side || \'|\' || quantity || \'|\' || ' +
    'price || \'|\' || counterparty || \'|\' || status FROM orders_plaintext ORDER BY id');
  assert.equal(canonical, CANONICAL_PLAINTEXT_ROWS.join('\n'));

  assert.deepEqual(tableFingerprint('orders'), ordersBefore, 'reset must not modify orders');
  assert.deepEqual(
    tableFingerprint('agent_audit'),
    auditBefore,
    'reset must not modify agent_audit',
  );
}

function assertSameNetworkRejected() {
  // A sibling container on the project network may not pass as local by
  // writing a loopback Host header; only the network-assigned source
  // address decides locality.
  const before = stateSnapshot('playground');
  const script = `
    const http = require('node:http');
    function call(path, body) {
      return new Promise((resolve, reject) => {
        const headers = { host: '127.0.0.1:3100' };
        if (body) {
          headers['content-type'] = 'application/json';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ hostname: 'playground', port: 3100, path, method: body ? 'POST' : 'GET', headers },
          (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
        req.on('error', reject);
        if (body) req.end(body); else req.end();
      });
    }
    (async () => {
      const statuses = [
        await call('/api/status'),
        await call('/index.html'),
        await call('/api/sim/raw', JSON.stringify({ sql: 'DELETE FROM orders_plaintext' })),
      ];
      process.exit(statuses.every((status) => status === 403) ? 0 : 1);
    })();
  `;
  const result = spawnSync(
    'docker',
    ['run', '--rm', '--network', projectNetwork, 'node:22-bookworm-slim', 'node', '-e', script],
    { encoding: 'utf8', timeout: 60_000 },
  );
  if (result.status !== 0) {
    throw new Error(
      `Same-network requests with a spoofed loopback Host were not rejected ` +
      `(exit ${result.status})\n${result.stdout}\n${result.stderr}`,
    );
  }
  assertStateUnchanged(before, 'playground');
}

async function waitForPlayground() {
  const deadline = Date.now() + 60_000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await smokeFetch('/api/status');
      if (response.ok) return;
      lastError = new Error(`status returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`Playground did not become ready: ${lastError?.message ?? 'unknown error'}`);
}

async function waitForExternalDatabase() {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const result = spawnSync(
      'docker',
      [
        'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground',
        '-Atc', 'SELECT 1',
      ],
      { encoding: 'utf8' },
    );
    if (result.status === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error('External PostgreSQL did not become ready');
}

function cleanUp() {
  compose(['down', '--volumes', '--remove-orphans']);
}

function cleanUpQuietly() {
  spawnSync('docker', [
    'compose', '--project-name', projectName, 'down', '--volumes', '--remove-orphans',
  ], { cwd: new URL('..', import.meta.url), env: commandEnv });
  spawnSync('docker', ['rm', '--force', externalDatabaseName]);
  spawnSync('docker', [
    'compose', '--project-name', projectName, 'down', '--volumes', '--remove-orphans',
  ], { cwd: new URL('..', import.meta.url), env: commandEnv });
  spawnSync('docker', ['network', 'rm', projectNetwork]);
  spawnSync('docker', ['image', 'rm', commandEnv.PLAYGROUND_IMAGE]);
}

try {
  cleanUp();
  const config = JSON.parse(compose(['config', '--format', 'json']));
  assert.equal(config.services.setup.depends_on.postgres.condition, 'service_healthy');
  assert.equal(
    config.services.playground.depends_on.setup.condition,
    'service_completed_successfully',
  );
  assert.equal(config.services.postgres.ports, undefined);
  assert.equal(config.services.playground.environment.PLAYGROUND_HTTP_MODE, 'local');
  assert.equal(config.services.playground.environment.PLAYGROUND_NEW_SESSION_RATE_LIMIT, '10000');
  assert.equal(config.services.playground.environment.PLAYGROUND_NEW_SESSION_RATE_WINDOW_MS, '60000');
  assert.ok(JSON.stringify(config.services.playground.healthcheck.test).includes('/healthz'));
  assert.equal(config.services.playground.ports[0].host_ip, '127.0.0.1');
  assert.equal(config.services.playground.ports[0].published, hostPort);

  compose(['up', '--build', '--detach', '--wait']);
  await waitForPlayground();

  const healthResponse = await smokeFetch('/healthz');
  assert.equal(healthResponse.status, 200);
  assert.deepEqual(await healthResponse.json(), { status: 'ok' });
  const readinessResponse = await smokeFetch('/readyz');
  assert.equal(readinessResponse.status, 200);
  assert.deepEqual(await readinessResponse.json(), { status: 'ready' });

  assert.match(compose(['port', 'playground', '3100']), new RegExp(`^127\\.0\\.0\\.1:${hostPort}$`));
  assertSameNetworkRejected();
  assert.equal(databaseState('playground'), '8|8|2|2');
  const templateBefore = stateSnapshot('playground');
  assert.ok(templateBefore.length > 0, 'template snapshot must capture demo rows');
  assert.deepEqual(visitorDatabases(), [], 'health probes, status, and static requests must not provision a visitor');
  assert.equal(roleState(appRole), `${appRole}|false|false|false|false|false|false|0`);
  assert.equal(
    roleState('agents_playground_naive'),
    'agents_playground_naive|false|false|false|false|false|false|0',
  );
  await authorizedRead();
  assert.equal(databaseState(), '8|8|2|2');
  await existingValidationsStillFailClosed();
  await assertBrowserRequestsRejected();
  await directSimulatorRead();
  await assertRuntimeRoleRestricted();
  await assertStatementTimeout();
  await assertLockTimeout();
  await assertResultLimits();
  await assertResetRestoresSandboxWithoutTouchingProtectedData();
  await assertOutOfScopeQueryIsRejectedAndNotExecuted();
  await assertRestrictedIdentityCannotObtainEncryptedColumns();
  const isolatedSessions = await assertConcurrentVisitorSessionsAreIsolated();
  await assertIndependentResetLeavesOtherSessionUnchanged(isolatedSessions);
  assert.deepEqual(stateSnapshot('playground'), templateBefore, 'visitor requests must not modify the template');
  const initialFingerprint = configFingerprint();
  const initialMasterKeyFingerprint = masterKeyFingerprint();

  psql('playground', 'DELETE FROM orders_plaintext WHERE id = (SELECT min(id) FROM orders_plaintext)');
  assert.equal(databaseState('playground'), '8|7|2|2');
  compose(['run', '--rm', 'setup']);
  assert.equal(databaseState('playground'), '8|8|2|2');

  const expiredCookie = visitorCookie;
  const staleVisitor = `agents_playground_visitor_${randomBytes(16).toString('hex')}`;
  const unmarkedVisitor = `agents_playground_visitor_${randomBytes(16).toString('hex')}`;
  psql('postgres', `CREATE DATABASE "${staleVisitor}" TEMPLATE playground`);
  psql('postgres', `CREATE DATABASE "${unmarkedVisitor}"`);
  compose(['restart', 'playground']);
  await waitForPlayground();
  assert.equal(configFingerprint(), initialFingerprint);
  assert.equal(masterKeyFingerprint(), initialMasterKeyFingerprint);
  assert.equal(databaseState('playground'), '8|8|2|2');
  assert.deepEqual(visitorDatabases(), [unmarkedVisitor], 'startup must remove owned clones but preserve unmarked databases');
  psql('postgres', `DROP DATABASE "${unmarkedVisitor}"`);
  const staleSession = await visitorFetch('/api/agents');
  assert.equal(staleSession.status, 401, 'restart must invalidate old browser cookies');
  await authorizedRead();
  assert.notEqual(visitorCookie, expiredCookie);

  const containerId = compose(['ps', '--quiet', 'playground']);
  compose(['stop', '--timeout', '15', 'playground']);
  assert.equal(run('docker', ['inspect', '--format', '{{.State.ExitCode}}', containerId]), '0');
  assert.equal(psql('postgres',
    "SELECT count(*) FROM pg_stat_activity WHERE application_name IN ('agents-playground-server', 'agents-playground-naive')"), '0');
  assert.deepEqual(visitorDatabases(), [], 'shutdown must drop visitor databases');

  cleanUp();
  compose(['up', '--detach', '--wait']);
  await waitForPlayground();
  assert.notEqual(configFingerprint(), initialFingerprint);
  assert.notEqual(masterKeyFingerprint(), initialMasterKeyFingerprint);
  assert.equal(databaseState('playground'), '8|8|2|2');
  await authorizedRead();

  cleanUp();
  commandEnv.PLAYGROUND_DATABASE_URL =
    'postgresql://postgres:postgres@missing-postgres:5432/playground';
  const failedStart = spawnSync(
    'docker',
    ['compose', '--project-name', projectName, 'up', '--detach', '--wait'],
    { cwd: new URL('..', import.meta.url), env: commandEnv, encoding: 'utf8' },
  );
  assert.notEqual(failedStart.status, 0);
  assert.equal(compose(['ps', '--status', 'running', '--services']), 'postgres');
  assert.match(compose(['logs', '--no-color', 'setup']), /missing-postgres/);
  cleanUp();

  run('docker', [
    'network', 'create',
    '--label', `com.docker.compose.project=${projectName}`,
    '--label', 'com.docker.compose.network=default',
    projectNetwork,
  ]);
  run('docker', [
    'run', '--detach', '--name', externalDatabaseName, '--network', projectNetwork,
    '--env', 'POSTGRES_DB=playground',
    '--env', 'POSTGRES_USER=postgres',
    '--env', 'POSTGRES_PASSWORD=postgres',
    'postgres:16-alpine',
  ]);
  await waitForExternalDatabase();

  run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    'CREATE TABLE orders (id INT PRIMARY KEY); INSERT INTO orders VALUES (42); ' +
    'CREATE TABLE orders_plaintext (id INT PRIMARY KEY); INSERT INTO orders_plaintext VALUES (84)',
  ]);
  const unmanagedSetup = spawnSync(
    'docker',
    ['compose', '--project-name', projectName, 'run', '--build', '--rm', '--no-deps', 'setup'],
    {
      cwd: new URL('..', import.meta.url),
      env: {
        ...commandEnv,
        PLAYGROUND_DATABASE_URL:
          `postgresql://postgres:postgres@${externalDatabaseName}:5432/playground`,
      },
      encoding: 'utf8',
    },
  );
  assert.notEqual(unmanagedSetup.status, 0);
  assert.match(
    `${unmanagedSetup.stdout}\n${unmanagedSetup.stderr}`,
    /already contains orders, orders_plaintext without the Playground marker/,
  );
  assert.equal(run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    "SELECT (SELECT count(*) FROM orders WHERE id = 42), (SELECT count(*) FROM orders_plaintext WHERE id = 84), to_regclass('public.demo_playground_metadata') IS NULL, to_regclass('public.demo_migrations') IS NULL, to_regclass('public.agents') IS NULL",
  ]), '1|1|t|t|t');
  run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    'DROP TABLE orders, orders_plaintext',
  ]);

  // An unprivileged setup user must fail early, with a clear error and
  // without creating any table, before the documented superuser path runs.
  run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    "CREATE ROLE agents_smoke_restricted LOGIN PASSWORD 'restricted'",
  ]);
  const restrictedSetup = spawnSync(
    'docker',
    ['compose', '--project-name', projectName, 'run', '--build', '--rm', '--no-deps', 'setup'],
    {
      cwd: new URL('..', import.meta.url),
      env: {
        ...commandEnv,
        PLAYGROUND_DATABASE_URL:
          `postgresql://agents_smoke_restricted:restricted@${externalDatabaseName}:5432/playground`,
      },
      encoding: 'utf8',
    },
  );
  assert.notEqual(restrictedSetup.status, 0);
  assert.match(
    `${restrictedSetup.stdout}\n${restrictedSetup.stderr}`,
    /lacks a required database privilege and no changes were made/,
  );
  assert.equal(run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('demo_playground_metadata', 'demo_migrations', 'orders', 'orders_plaintext')",
  ]), '0');
  run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    'DROP ROLE agents_smoke_restricted',
  ]);

  commandEnv.PLAYGROUND_DATABASE_URL =
    `postgresql://postgres:postgres@${externalDatabaseName}:5432/playground`;
  compose(['run', '--build', '--rm', '--no-deps', 'setup']);
  compose(['up', '--detach', '--no-deps', 'playground']);
  await waitForPlayground();
  postgresContainer = externalDatabaseName;
  assert.equal(compose(['ps', '--all', '--services']), 'playground');
  assert.equal(run('docker', [
    'exec', externalDatabaseName, 'psql', '-U', 'postgres', '-d', 'playground', '-Atc',
    'SELECT (SELECT count(*) FROM orders), (SELECT count(*) FROM orders_plaintext)',
  ]), '8|8');
  await authorizedRead();
  assert.equal(databaseState(), '8|8|2|2');

  console.log('Compose startup, restart, decryption, shutdown, reset, and external database passed.');
} finally {
  cleanUpQuietly();
}
