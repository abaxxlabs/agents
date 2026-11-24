import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentScope } from '@abaxxlabs/agents/sql';
import { createVisitorRuntime, NotAuthenticatedError } from '../src/visitor-runtime.mjs';

const masterKeyHex = 'ab'.repeat(32);
const masterKeyBuffer = Buffer.from(masterKeyHex, 'hex');
const userCeilings = {
  alice: undefined,
  bob: { columns: ['orders.instrument'], actions: ['read'], source: 'oidc-groups', resolvedFrom: ['desk-junior'] },
};

const sharedFixture = {
  sharedDatabaseUrl: 'postgresql://agents_playground_app@localhost/playground_shared',
  pool: { application_name: 'agents-playground-shared', endCount: 0 },
};

const directSqlPool = {
  application_name: 'agents-playground-direct',
  endCount: 0,
  async connect() { throw new Error('direct SQL is not exercised'); },
};

function runtimeOptions() {
  return {
    masterKeyBuffer,
    sharedFixture,
    directSqlPool,
    userCeilings,
    readBody: async () => ({ sql: 'SELECT id FROM orders' }),
    rejected: () => {},
  };
}

function mockResources(t, { scopeError, simulatorError } = {}) {
  const scopes = [];
  const events = [];
  t.mock.method(AgentScope, 'create', async (config, injections) => {
    if (scopeError) throw scopeError;
    events.push('scope.create');
    const scopeId = scopes.length + 1;
    const scope = {
      pool: injections.pool,
      storage: injections.storage,
      closed: false,
      async close() {
        events.push('scope.close');
        this.closed = true;
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
      async createAgentIdentity() { return { did: `did:key:sim-agent-${scopeId}`, name: 'sim-agent' }; },
      queryCalls: [],
      async query(args) {
        scope.queryCalls.push(args);
        return { rows: [{ id: 1 }], rowCount: 1, metadata: {} };
      },
    };
    scopes.push({ scope, config, injections });
    return scope;
  });
  return { scopes, events };
}

test('runtimes share the process pools while isolating SDK scopes and storage', async (t) => {
  const { scopes, events } = mockResources(t);
  const first = await createVisitorRuntime(runtimeOptions());
  const second = await createVisitorRuntime(runtimeOptions());
  const storageCloses = [];
  for (const { injections } of scopes) {
    const storage = injections.storage;
    const originalClose = storage.close.bind(storage);
    storage.close = async () => {
      storageCloses.push(storage);
      return originalClose();
    };
  }
  try {
    assert.deepEqual(Object.keys(first).sort(), ['scope', 'simulator', 'loginSession', 'getSession', 'close'].sort());
    assert.equal(first.scope, scopes[0].scope);
    assert.notEqual(first.scope, second.scope);
    assert.notEqual(first.simulator.routes, second.simulator.routes);

    assert.equal(scopes[0].injections.pool, sharedFixture.pool);
    assert.equal(scopes[1].injections.pool, sharedFixture.pool);
    assert.notEqual(scopes[0].injections.storage, scopes[1].injections.storage);
    assert.equal(scopes[0].injections.masterKey, masterKeyBuffer);
    assert.equal(new URL(scopes[0].config.database.connectionString).pathname, '/playground_shared');

    const aliceA = await first.loginSession('alice');
    assert.throws(() => second.getSession(aliceA.humanDid), NotAuthenticatedError);
    const aliceB = await second.loginSession('alice');
    assert.equal(first.getSession(aliceA.humanDid), aliceA);
    assert.equal(second.getSession(aliceB.humanDid), aliceB);
    assert.notEqual(aliceA, aliceB);
    assert.equal((await second.loginSession('bob')).scopeCeiling, userCeilings.bob);
    await assert.rejects(first.loginSession('unknown'), /Unknown mock identity/);
    assert.deepEqual(events, ['scope.create', 'scope.create']);

    const [statusA, statusB] = await Promise.all([
      first.simulator.routes['GET /api/sim/agent'](),
      second.simulator.routes['GET /api/sim/agent'](),
    ]);
    assert.notEqual(statusA[1].agentDid, statusB[1].agentDid);

    const [scopedCode, scopedBody] = await first.simulator.routes['POST /api/sim/scoped']({});
    assert.equal(scopedCode, 200);
    assert.deepEqual(scopedBody.rows, [{ id: 1 }]);
    assert.deepEqual(scopes[0].scope.queryCalls.map(({ table }) => table), ['orders']);
    assert.deepEqual(scopes[1].scope.queryCalls, []);

    await Promise.all([first.close(), first.close()]);
    assert.deepEqual(events.slice(2), ['scope.close']);
    assert.equal(storageCloses.length, 1);
    assert.equal(second.getSession(aliceB.humanDid), aliceB);

    await second.close();
    assert.deepEqual(events.slice(3), ['scope.close']);
    assert.equal(storageCloses.length, 2);
  } finally {
    await Promise.allSettled([first.close(), second.close()]);
  }
});

test('a failed runtime close can be retried and a successful close is memoized', async (t) => {
  const { scopes } = mockResources(t);
  const runtime = await createVisitorRuntime(runtimeOptions());
  const scope = scopes[0].scope;
  let attempts = 0;
  scope.close = async () => {
    attempts += 1;
    if (attempts === 1) throw new Error('scope close failed');
  };

  await assert.rejects(runtime.close(), AggregateError);
  await runtime.close();
  await runtime.close();
  assert.equal(attempts, 2);
});

test('concurrent runtime close calls share one attempt and stay retryable', async (t) => {
  const { scopes } = mockResources(t);
  const runtime = await createVisitorRuntime(runtimeOptions());
  const scope = scopes[0].scope;
  let attempts = 0;
  scope.close = async () => {
    attempts += 1;
    if (attempts === 1) throw new Error('scope close failed');
  };

  const results = await Promise.allSettled([runtime.close(), runtime.close()]);
  assert.equal(attempts, 1);
  assert.ok(results.every((result) => result.status === 'rejected'));

  await runtime.close();
  assert.equal(attempts, 2);
  await runtime.close();
  assert.equal(attempts, 2);
});

test('initialization failure releases the scoped runtime and leaves shared pools untouched', async (t) => {
  for (const [failure, expectedEvents, expectedScopes] of [
    ['scopeError', [], 0],
    ['simulatorError', ['scope.create', 'scope.close'], 1],
  ]) {
    const originalError = new Error('initialization failed');
    const { scopes, events } = mockResources(t, { [failure]: originalError });

    await assert.rejects(createVisitorRuntime(runtimeOptions()), (err) => err === originalError);
    assert.deepEqual(events, expectedEvents);
    assert.equal(scopes.length, expectedScopes);
    assert.ok(scopes.every(({ scope }) => scope.closed));
  }
});
