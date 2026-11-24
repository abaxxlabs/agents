import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import {
  createScopedSdkRuntime,
  createSharedFixtureRuntime,
} from '../src/shared-fixture-adapter.mjs';

const SHARED_URL = 'postgresql://agents_playground_app@localhost/playground_shared';
const MASTER_KEY = Buffer.alloc(32, 7);
const sharedFixture = { sharedDatabaseUrl: SHARED_URL, pool: { application_name: 'agents-playground-shared' } };

test('shared fixture runtime opens one bounded pool, probes it, and closes once', async (t) => {
  const events = [];
  let endCount = 0;
  let captured;
  t.mock.method(pg, 'Pool', function FakePool(options) {
    captured = options;
    return {
      options,
      on() { return this; },
      async query(sql) { events.push(sql); return { rows: [] }; },
      async end() { endCount += 1; events.push('end'); },
    };
  });

  const runtime = await createSharedFixtureRuntime({ sharedDatabaseUrl: SHARED_URL, poolMax: 4 });
  assert.equal(captured.connectionString, SHARED_URL);
  assert.equal(captured.application_name, 'agents-playground-shared');
  assert.equal(captured.max, 4);
  assert.equal(captured.connectionTimeoutMillis, 5_000);
  assert.equal(captured.statement_timeout, 5_000);
  assert.deepEqual(events, ['SELECT 1']);
  assert.equal(runtime.sharedDatabaseUrl, SHARED_URL);

  await Promise.all([runtime.close(), runtime.close()]);
  assert.equal(endCount, 1);
});

test('shared fixture runtime closes the pool when the boot probe fails', async (t) => {
  const bootError = new Error('unreachable');
  let endCount = 0;
  t.mock.method(pg, 'Pool', function FakePool() {
    return {
      on() { return this; },
      async query() { throw bootError; },
      async end() { endCount += 1; },
    };
  });

  await assert.rejects(
    createSharedFixtureRuntime({ sharedDatabaseUrl: SHARED_URL }),
    (err) => err === bootError,
  );
  assert.equal(endCount, 1);
});

function scopedFixture({ failInitialize, failScope, failScopeClose = () => false, failStorageClose } = {}) {
  const scopeCloseFails = typeof failScopeClose === 'function' ? failScopeClose : () => failScopeClose;
  const events = [];
  const captured = {};
  const createStorage = (options) => {
    captured.sessionMacKey = options.sessionMacKey;
    if (failInitialize) {
      return {
        async initialize() { throw new Error('storage initialize failed'); },
        async close() { events.push('storage.close'); },
      };
    }
    return {
      async initialize() { events.push('storage.initialize'); },
      async close() {
        events.push('storage.close');
        if (failStorageClose) throw new Error('storage close failed');
      },
    };
  };
  const createScope = async (config, injections) => {
    captured.config = config;
    captured.injections = injections;
    events.push('scope.create');
    if (failScope) throw new Error('scope create failed');
    return {
      async close() {
        events.push('scope.close');
        if (scopeCloseFails()) throw new Error('scope close failed');
      },
    };
  };
  return { events, captured, createStorage, createScope };
}

test('scoped runtime builds the scope on the shared pool and closes storage after it', async () => {
  const { events, captured, createStorage, createScope } = scopedFixture();
  const runtime = await createScopedSdkRuntime({
    sharedFixture,
    masterKeyBuffer: MASTER_KEY,
    createStorage,
    createScope,
  });

  assert.equal(captured.config.database.connectionString, SHARED_URL);
  assert.equal(captured.injections.pool, sharedFixture.pool);
  assert.equal(captured.injections.masterKey, MASTER_KEY);
  assert.ok(captured.injections.storage);
  assert.deepEqual(events, ['storage.initialize', 'scope.create']);
  assert.notEqual(runtime.scope, undefined);

  await runtime.close();
  assert.deepEqual(events.slice(2), ['scope.close', 'storage.close']);
  assert.equal(captured.sessionMacKey.every((byte) => byte === 0), true);
  assert.equal(MASTER_KEY.toString('hex'), '07'.repeat(32));

  await runtime.close();
  assert.deepEqual(events.slice(2), ['scope.close', 'storage.close']);
});

test('scoped runtime rejects and closes storage when initialization fails', async () => {
  const { events, captured, createStorage, createScope } = scopedFixture({ failInitialize: true });
  await assert.rejects(
    createScopedSdkRuntime({ sharedFixture, masterKeyBuffer: MASTER_KEY, createStorage, createScope }),
    /storage initialize failed/,
  );
  assert.deepEqual(events, ['storage.close']);
  assert.equal(captured.config, undefined);
  assert.equal(captured.sessionMacKey.every((byte) => byte === 0), true);
});

test('scoped runtime rejects, closes storage, and never closes a missing scope when scope creation fails', async () => {
  const { events, captured, createStorage, createScope } = scopedFixture({ failScope: true });
  await assert.rejects(
    createScopedSdkRuntime({ sharedFixture, masterKeyBuffer: MASTER_KEY, createStorage, createScope }),
    /scope create failed/,
  );
  assert.deepEqual(events, ['storage.initialize', 'scope.create', 'storage.close']);
  assert.equal(captured.sessionMacKey.every((byte) => byte === 0), true);
});

test('scoped runtime aggregates close failures and still zeroizes the session MAC key', async () => {
  const { events, captured, createStorage, createScope } = scopedFixture({
    failScopeClose: true,
    failStorageClose: true,
  });
  const runtime = await createScopedSdkRuntime({
    sharedFixture,
    masterKeyBuffer: MASTER_KEY,
    createStorage,
    createScope,
  });

  await assert.rejects(
    runtime.close(),
    (err) => err instanceof AggregateError && err.errors.length === 2,
  );
  assert.deepEqual(events, ['storage.initialize', 'scope.create', 'scope.close', 'storage.close']);
  assert.equal(captured.sessionMacKey.every((byte) => byte === 0), true);

  await assert.rejects(runtime.close(), (err) => err instanceof AggregateError);
  assert.equal(events.filter((event) => event === 'scope.close').length, 2);
  assert.equal(events.filter((event) => event === 'storage.close').length, 2);
  assert.equal(captured.sessionMacKey.every((byte) => byte === 0), true);
});

test('scoped runtime retries a failed close and memoizes the successful attempt', async () => {
  let failures = 1;
  const { events, captured, createStorage, createScope } = scopedFixture({
    failScopeClose: () => failures-- > 0,
  });
  const runtime = await createScopedSdkRuntime({
    sharedFixture,
    masterKeyBuffer: MASTER_KEY,
    createStorage,
    createScope,
  });

  await assert.rejects(runtime.close(), (err) => err instanceof AggregateError);
  assert.equal(captured.sessionMacKey.every((byte) => byte === 0), true);

  await runtime.close();
  assert.deepEqual(events.slice(2), ['scope.close', 'storage.close', 'scope.close', 'storage.close']);

  await runtime.close();
  assert.equal(events.filter((event) => event === 'scope.close').length, 2);
});

test('closing a real AgentScope leaves the caller master key intact', async () => {
  const pool = { query: async () => ({ rows: [] }) };
  const masterKeyBuffer = Buffer.alloc(32, 7);
  const runtime = await createScopedSdkRuntime({
    sharedFixture: { sharedDatabaseUrl: SHARED_URL, pool },
    masterKeyBuffer,
  });

  await runtime.close();
  assert.equal(masterKeyBuffer.toString('hex'), '07'.repeat(32));
});
