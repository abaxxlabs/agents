import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { AgentScope } from '@abaxxlabs/agents/sql';
import { createVisitorRuntime, NotAuthenticatedError } from '../src/visitor-runtime.mjs';

const masterKeyHex = 'ab'.repeat(32);
const userCeilings = {
  alice: undefined,
  bob: { columns: ['orders.instrument'], actions: ['read'], source: 'oidc-groups', resolvedFrom: ['desk-junior'] },
};

function runtimeOptions(databaseName) {
  return {
    databaseName,
    appDatabaseUrl: `postgresql://agents_playground_app:app-password@localhost/${databaseName}`,
    masterKeyHex,
    naiveDbPassword: 'naive-password',
    userCeilings,
    readBody: () => ({}),
    rejected: () => {},
    hostGatewayIps: null,
  };
}

function mockResources(t, { scopeError, simulatorError, scopeCloseError } = {}) {
  const pools = [];
  const scopes = [];
  const keys = [];
  const events = [];
  t.mock.method(pg, 'Pool', function FakePool(options) {
    const url = new URL(options.connectionString);
    const database = url.pathname.slice(1);
    const pool = {
      options,
      database,
      role: url.username,
      endCount: 0,
      on() { return this; },
      async end() {
        this.endCount++;
        events.push(`${database}:${this.role}.end`);
      },
    };
    pools.push(pool);
    return pool;
  });
  t.mock.method(AgentScope, 'create', async (config, { masterKey, pool }) => {
    keys.push(masterKey);
    if (scopeError) throw scopeError;
    const database = new URL(config.database.connectionString).pathname.slice(1);
    const scope = {
      pool,
      closed: false,
      async close() {
        events.push(`${database}:scope.close`);
        this.closed = true;
        masterKey.fill(0);
        if (scopeCloseError) throw scopeCloseError;
      },
      async authenticate({ mockHumanDid, scopeCeiling }) {
        if (mockHumanDid === 'demo-operator' && simulatorError) throw simulatorError;
        return {
          humanDid: `did:key:${mockHumanDid}`,
          scopeCeiling,
          async issueCredential() {
            const payload = { exp: Math.floor(Date.now() / 1000) + 3600, jti: 'test-jti' };
            return `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
          },
        };
      },
      async listAgents() { return []; },
      async createAgentIdentity() { return { did: `did:key:sim-${database}`, name: 'sim-agent' }; },
    };
    scopes.push(scope);
    return scope;
  });
  return { pools, scopes, keys, events };
}

test('runtimes isolate mock sessions, scopes, simulators, pools, and key Buffers', async (t) => {
  const { pools, scopes, keys, events } = mockResources(t);
  const first = await createVisitorRuntime(runtimeOptions('visitor_a'));
  const second = await createVisitorRuntime(runtimeOptions('visitor_b'));
  try {
    assert.deepEqual(Object.keys(first).sort(), ['databaseName', 'scope', 'simulator', 'loginSession', 'getSession', 'close'].sort());
    assert.notEqual(first.scope, second.scope);
    assert.notEqual(first.simulator.routes, second.simulator.routes);
    assert.equal(scopes[0].pool, pools[0]);
    assert.equal(scopes[1].pool, pools[2]);
    assert.deepEqual(pools.map(({ database, role }) => [database, role]), [
      ['visitor_a', 'agents_playground_app'], ['visitor_a', 'agents_playground_naive'],
      ['visitor_b', 'agents_playground_app'], ['visitor_b', 'agents_playground_naive'],
    ]);
    assert.notEqual(keys[0], keys[1]);
    assert.equal(keys[0].toString('hex'), masterKeyHex);
    assert.equal(keys[1].toString('hex'), masterKeyHex);

    const aliceA = await first.loginSession('alice');
    assert.throws(() => second.getSession(aliceA.humanDid), NotAuthenticatedError);
    const aliceB = await second.loginSession('alice');
    assert.equal(first.getSession(aliceA.humanDid), aliceA);
    assert.equal(second.getSession(aliceB.humanDid), aliceB);
    assert.notEqual(aliceA, aliceB);
    assert.equal(aliceA.humanDid, aliceB.humanDid);
    assert.equal((await second.loginSession('bob')).scopeCeiling, userCeilings.bob);
    await assert.rejects(first.loginSession('unknown'), /Unknown mock identity/);
    assert.deepEqual(events, []);

    const [statusA, statusB] = await Promise.all([
      first.simulator.routes['GET /api/sim/agent'](),
      second.simulator.routes['GET /api/sim/agent'](),
    ]);
    assert.notEqual(statusA[1].agentDid, statusB[1].agentDid);

    await Promise.all([first.close(), first.close()]);
    assert.deepEqual(events, [
      'visitor_a:scope.close',
      'visitor_a:agents_playground_naive.end',
      'visitor_a:agents_playground_app.end',
    ]);
    assert.equal(keys[0].every((byte) => byte === 0), true);
    assert.equal(keys[1].toString('hex'), masterKeyHex);
    assert.equal(pools[2].endCount, 0);
    assert.equal(pools[3].endCount, 0);
    assert.equal(second.getSession(aliceB.humanDid), aliceB);
    assert.equal((await second.simulator.routes['GET /api/sim/agent']())[1].agentDid, statusB[1].agentDid);

    await second.close();
    assert.deepEqual(events.slice(3), [
      'visitor_b:scope.close',
      'visitor_b:agents_playground_naive.end',
      'visitor_b:agents_playground_app.end',
    ]);
  } finally {
    await Promise.allSettled([first.close(), second.close()]);
  }
});

test('scope initialization failure closes the app pool and clears its key Buffer', async (t) => {
  const originalError = new Error('scope failed');
  const { pools, keys, events } = mockResources(t, { scopeError: originalError });

  await assert.rejects(createVisitorRuntime(runtimeOptions('visitor_a')), (err) => err === originalError);
  assert.equal(pools.length, 1);
  assert.equal(pools[0].endCount, 1);
  assert.deepEqual(events, ['visitor_a:agents_playground_app.end']);
  assert.equal(keys[0].every((byte) => byte === 0), true);
});

test('simulator initialization failure closes its pool, the scope, and the app pool', async (t) => {
  const originalError = new Error('simulator failed');
  const { pools, scopes, keys, events } = mockResources(t, { simulatorError: originalError });

  await assert.rejects(createVisitorRuntime(runtimeOptions('visitor_a')), (err) => err === originalError);
  assert.deepEqual(events, [
    'visitor_a:agents_playground_naive.end',
    'visitor_a:scope.close',
    'visitor_a:agents_playground_app.end',
  ]);
  assert.equal(scopes[0].closed, true);
  assert.deepEqual(pools.map((pool) => pool.endCount), [1, 1]);
  assert.equal(keys[0].every((byte) => byte === 0), true);
});

test('an initialization error survives cleanup failure while remaining resources close', async (t) => {
  const originalError = new Error('simulator failed');
  const closeError = new Error('scope cleanup failed');
  const logs = [];
  t.mock.method(console, 'error', (...args) => logs.push(args));
  const { pools, events } = mockResources(t, { simulatorError: originalError, scopeCloseError: closeError });

  await assert.rejects(createVisitorRuntime(runtimeOptions('visitor_a')), (err) => err === originalError);
  assert.deepEqual(events, [
    'visitor_a:agents_playground_naive.end',
    'visitor_a:scope.close',
    'visitor_a:agents_playground_app.end',
  ]);
  assert.deepEqual(pools.map((pool) => pool.endCount), [1, 1]);
  assert.equal(logs.length, 1);
  assert.deepEqual(logs[0][1], { type: 'AggregateError' });
  assert.doesNotMatch(JSON.stringify(logs), /scope cleanup failed/);
});
