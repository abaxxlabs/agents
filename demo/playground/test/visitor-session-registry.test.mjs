import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createVisitorSessionRegistry,
  VisitorRegistryClosingError,
  VisitorSessionCapacityError,
  VisitorSessionCleanupError,
  VisitorSessionNotFoundError,
  VisitorSessionUnavailableError,
} from '../src/visitor-session-registry.mjs';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function registryFixture({
  createDatabase,
  createRuntime,
  dropDatabase,
  generateSessionId,
  maxSessions = 10,
  inactivityTtlMs = 1_000,
  now,
} = {}) {
  const events = [];
  let nextDatabase = 0;
  const provisioner = {
    async createVisitorDatabase() {
      events.push('provision');
      if (createDatabase) return createDatabase();
      const databaseName = `visitor_${++nextDatabase}`;
      return { databaseName, appDatabaseUrl: `postgres://app/${databaseName}` };
    },
    async dropVisitorDatabase(databaseName) {
      events.push(`drop:${databaseName}`);
      return dropDatabase?.(databaseName);
    },
  };
  const runtimeFactory = async (options) => {
    events.push(`runtime:${options.databaseName}`);
    if (createRuntime) return createRuntime(options);
    return { databaseName: options.databaseName, async close() { events.push(`close:${options.databaseName}`); } };
  };
  return {
    registry: createVisitorSessionRegistry({
      provisioner, createRuntime: runtimeFactory, generateSessionId, maxSessions, inactivityTtlMs, now,
    }),
    events,
  };
}

test('requires positive safe session limits and a clock function', () => {
  const provisioner = { createVisitorDatabase() {}, dropVisitorDatabase() {} };
  assert.throws(() => createVisitorSessionRegistry({ provisioner, inactivityTtlMs: 1 }), RangeError);
  for (const option of ['maxSessions', 'inactivityTtlMs']) {
    for (const value of [undefined, 0, -1, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => createVisitorSessionRegistry({
        provisioner, maxSessions: 1, inactivityTtlMs: 1, [option]: value,
      }), RangeError);
    }
  }
  assert.throws(() => createVisitorSessionRegistry({
    provisioner, maxSessions: 1, inactivityTtlMs: 1, now: 1,
  }), TypeError);
});

test('cleanup retains a younger session and expires sessions at or beyond the TTL', async () => {
  let time = 0;
  const { registry, events } = registryFixture({ inactivityTtlMs: 100, now: () => time });
  const first = await registry.createSession();
  time = 99;
  await registry.cleanupExpiredSessions();
  assert.equal(registry.getSession(first.sessionId), first.runtime);
  assert.deepEqual(events, ['provision', 'runtime:visitor_1']);

  time = 100;
  await registry.cleanupExpiredSessions();
  assert.throws(() => registry.getSession(first.sessionId), VisitorSessionNotFoundError);

  const second = await registry.createSession();
  time = 201;
  await registry.cleanupExpiredSessions();
  assert.throws(() => registry.getSession(second.sessionId), VisitorSessionNotFoundError);
  assert.deepEqual(events.slice(2), [
    'close:visitor_1', 'drop:visitor_1', 'provision', 'runtime:visitor_2', 'close:visitor_2', 'drop:visitor_2',
  ]);
});

test('touching a session extends its inactivity lifetime', async () => {
  let time = 0;
  const { registry, events } = registryFixture({ inactivityTtlMs: 100, now: () => time });
  const { sessionId, runtime } = await registry.createSession();
  time = 99;
  const { lastActivity } = registry.touchSession(sessionId);
  assert.equal(lastActivity.getTime(), 99);
  time = 198;
  await registry.cleanupExpiredSessions();
  assert.equal(registry.getSession(sessionId), runtime);
  assert.equal(events.includes('close:visitor_1'), false);
});

test('expired cleanup closes before DROP and frees capacity only after successful DROP', async () => {
  let time = 0;
  const dropping = deferred();
  const { registry, events } = registryFixture({
    maxSessions: 1, inactivityTtlMs: 100, now: () => time, dropDatabase: () => dropping.promise,
  });
  const { sessionId } = await registry.createSession();
  time = 100;
  const cleanup = registry.cleanupExpiredSessions();
  await Promise.resolve();
  assert.deepEqual(events.slice(2), ['close:visitor_1', 'drop:visitor_1']);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  dropping.resolve();
  await cleanup;
  assert.throws(() => registry.getSession(sessionId), VisitorSessionNotFoundError);
  await registry.createSession();
});

test('expired cleanup retries a failed DROP on a later pass and frees capacity without closing again', async () => {
  let time = 0;
  let failDrop = true;
  const dropError = new Error('drop failed');
  const { registry, events } = registryFixture({
    maxSessions: 1, inactivityTtlMs: 100, now: () => time, dropDatabase: () => { if (failDrop) throw dropError; },
  });
  const { sessionId } = await registry.createSession();
  time = 100;
  await assert.rejects(registry.cleanupExpiredSessions(), (err) => err instanceof AggregateError && err.message.includes(sessionId));
  assert.throws(() => registry.getSession(sessionId), VisitorSessionUnavailableError);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  failDrop = false;
  await registry.cleanupExpiredSessions();
  assert.throws(() => registry.getSession(sessionId), VisitorSessionNotFoundError);
  await registry.createSession();
  assert.deepEqual(events.slice(2), [
    'close:visitor_1', 'drop:visitor_1', 'drop:visitor_1', 'provision', 'runtime:visitor_2',
  ]);
});

test('expired cleanup skips sessions already deleting or cleanup_failed', async () => {
  let time = 0;
  const dropping = deferred();
  const { registry, events } = registryFixture({
    inactivityTtlMs: 100, now: () => time, dropDatabase: () => dropping.promise,
  });
  const { sessionId } = await registry.createSession();
  time = 100;
  const deletion = registry.deleteSession(sessionId);
  await registry.cleanupExpiredSessions();
  assert.deepEqual(events.slice(2), ['close:visitor_1', 'drop:visitor_1']);
  dropping.resolve();
  await deletion;
});

test('expired cleanup cleans eligible sessions while failed DROPs stay counted until they succeed', async () => {
  let time = 0;
  const dropError = new Error('drop failed');
  let dropSucceedsFor = (databaseName) => databaseName === 'visitor_2';
  const { registry, events } = registryFixture({
    maxSessions: 2, inactivityTtlMs: 100, now: () => time,
    dropDatabase: (databaseName) => { if (!dropSucceedsFor(databaseName)) throw dropError; },
  });
  const failed = await registry.createSession();
  const other = await registry.createSession();
  time = 100;
  await assert.rejects(registry.cleanupExpiredSessions(), (err) => err instanceof AggregateError && err.errors.length === 1
    && err.message.includes(failed.sessionId) && !err.message.includes(other.sessionId));
  assert.throws(() => registry.getSession(failed.sessionId), VisitorSessionUnavailableError);
  assert.throws(() => registry.getSession(other.sessionId), VisitorSessionNotFoundError);
  const admitted = await registry.createSession();
  time = 200;
  await assert.rejects(registry.cleanupExpiredSessions(), (err) => err instanceof AggregateError && err.errors.length === 2);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  dropSucceedsFor = () => true;
  await registry.cleanupExpiredSessions();
  assert.throws(() => registry.getSession(failed.sessionId), VisitorSessionNotFoundError);
  assert.throws(() => registry.getSession(admitted.sessionId), VisitorSessionNotFoundError);
  await registry.createSession();
  const counts = (event) => events.filter((stored) => stored === event).length;
  assert.equal(counts('close:visitor_1'), 1);
  assert.equal(counts('close:visitor_2'), 1);
  assert.equal(counts('close:visitor_3'), 1);
  assert.equal(counts('drop:visitor_1'), 3);
  assert.equal(counts('drop:visitor_2'), 1);
  assert.equal(counts('drop:visitor_3'), 2);
  assert.equal(counts('provision'), 4);
  assert.equal(counts('runtime:visitor_4'), 1);
});

test('concurrent cleanup passes and deletions share a single drop retry for a failed session', async () => {
  let time = 0;
  const dropError = new Error('drop failed');
  const retryDrop = deferred();
  let drops = 0;
  const { registry } = registryFixture({
    maxSessions: 1, inactivityTtlMs: 100, now: () => time,
    dropDatabase: () => {
      drops += 1;
      if (drops === 1) throw dropError;
      return retryDrop.promise;
    },
  });
  const { sessionId } = await registry.createSession();
  time = 100;
  await assert.rejects(registry.cleanupExpiredSessions(), (err) => err instanceof AggregateError
    && err.errors[0] instanceof VisitorSessionCleanupError && err.errors[0].dropError === dropError);
  const cleanup = registry.cleanupExpiredSessions();
  const explicit = registry.deleteSession(sessionId);
  assert.equal(drops, 2);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  const concurrentPass = registry.cleanupExpiredSessions();
  assert.equal(drops, 2);
  retryDrop.resolve();
  await Promise.all([cleanup, explicit, concurrentPass]);
  assert.throws(() => registry.getSession(sessionId), VisitorSessionNotFoundError);
});

test('expired cleanup processes every session and reports failures after waiting', async () => {
  let time = 0;
  const secondDrop = deferred();
  const firstDropError = new Error('first drop failed');
  const { registry, events } = registryFixture({
    inactivityTtlMs: 100,
    now: () => time,
    dropDatabase: (databaseName) => {
      if (databaseName === 'visitor_1') throw firstDropError;
      return secondDrop.promise;
    },
  });
  const first = await registry.createSession();
  await registry.createSession();
  time = 100;
  const cleanup = registry.cleanupExpiredSessions();
  await Promise.resolve();
  assert.deepEqual([...events.slice(4)].sort(), [
    'close:visitor_1', 'close:visitor_2', 'drop:visitor_1', 'drop:visitor_2',
  ]);
  secondDrop.resolve();
  await assert.rejects(cleanup, (err) => err instanceof AggregateError && err.message.includes(first.sessionId));
});

test('touch before cleanup refreshes the session, while cleanup first makes touch unavailable', async () => {
  let time = 0;
  const drop = deferred();
  const { registry } = registryFixture({
    inactivityTtlMs: 100, now: () => time, dropDatabase: () => drop.promise,
  });
  const first = await registry.createSession();
  time = 100;
  registry.touchSession(first.sessionId);
  await registry.cleanupExpiredSessions();
  assert.equal(registry.getSession(first.sessionId), first.runtime);

  time = 200;
  const cleanup = registry.cleanupExpiredSessions();
  assert.throws(() => registry.touchSession(first.sessionId), VisitorSessionUnavailableError);
  drop.resolve();
  await cleanup;
});

test('reserves capacity before provisioning concurrent creations', async () => {
  const databases = [deferred(), deferred()];
  let next = 0;
  const { registry, events } = registryFixture({ maxSessions: 2, createDatabase: () => databases[next++].promise });
  const first = registry.createSession();
  const second = registry.createSession();
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  assert.equal(next, 2);
  assert.deepEqual(events, ['provision', 'provision']);

  databases[0].resolve({ databaseName: 'visitor_1', appDatabaseUrl: 'postgres://app/visitor_1' });
  databases[1].resolve({ databaseName: 'visitor_2', appDatabaseUrl: 'postgres://app/visitor_2' });
  const [one, two] = await Promise.all([first, second]);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  assert.equal(next, 2);
  await registry.deleteSession(one.sessionId);
  assert.equal(registry.getSession(two.sessionId), two.runtime);
});

test('retains capacity while deleting and releases it only after DROP completes', async () => {
  const dropping = deferred();
  const { registry, events } = registryFixture({ maxSessions: 1, dropDatabase: () => dropping.promise });
  const { sessionId } = await registry.createSession();
  const deletion = registry.deleteSession(sessionId);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  assert.equal(events.filter((event) => event === 'provision').length, 1);
  dropping.resolve();
  await deletion;
  await registry.createSession();
  assert.equal(events.filter((event) => event === 'provision').length, 2);
});

test('failed DROP retains capacity and an unavailable session until a drop-only retry succeeds', async () => {
  let failDrop = true;
  const dropError = new Error('drop failed');
  const { registry, events } = registryFixture({
    maxSessions: 1,
    dropDatabase: () => { if (failDrop) throw dropError; },
  });
  const { sessionId } = await registry.createSession();
  await assert.rejects(registry.deleteSession(sessionId), (err) => err instanceof VisitorSessionCleanupError && err.dropError === dropError);
  assert.throws(() => registry.getSession(sessionId), VisitorSessionUnavailableError);
  assert.throws(() => registry.touchSession(sessionId), VisitorSessionUnavailableError);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  await assert.rejects(registry.deleteSession(sessionId), VisitorSessionCleanupError);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  assert.equal(events.filter((event) => event === 'provision').length, 1);
  assert.equal(events.filter((event) => event === 'close:visitor_1').length, 1);
  failDrop = false;
  await registry.deleteSession(sessionId);
  assert.deepEqual(events.slice(2), [
    'close:visitor_1', 'drop:visitor_1', 'drop:visitor_1', 'drop:visitor_1',
  ]);
  assert.throws(() => registry.getSession(sessionId), VisitorSessionNotFoundError);
  await registry.createSession();
  assert.equal(events.filter((event) => event === 'provision').length, 2);
});

test('a failed provision or compensated runtime initialization releases capacity', async () => {
  const provisionFailure = new Error('provision failed');
  let failProvision = true;
  const provision = registryFixture({ maxSessions: 1, createDatabase: () => {
    if (failProvision) throw provisionFailure;
    return { databaseName: 'visitor_1' };
  } });
  await assert.rejects(provision.registry.createSession(), (err) => err === provisionFailure);
  failProvision = false;
  await provision.registry.createSession();

  const runtimeFailure = new Error('runtime failed');
  let failRuntime = true;
  const runtime = registryFixture({ maxSessions: 1, createRuntime: ({ databaseName }) => {
    if (failRuntime) throw runtimeFailure;
    return { databaseName, async close() {} };
  } });
  await assert.rejects(runtime.registry.createSession(), (err) => err === runtimeFailure);
  failRuntime = false;
  await runtime.registry.createSession();
});

test('failed creation compensation retains capacity until a drop-only retry succeeds', async (t) => {
  const runtimeFailure = new Error('runtime failed');
  const dropFailure = new Error('drop failed');
  let failDrop = true;
  const ids = ['failed-creation', 'new-session'];
  const { registry, events } = registryFixture({
    maxSessions: 1,
    generateSessionId: () => ids.shift(),
    createRuntime: () => { throw runtimeFailure; },
    dropDatabase: () => { if (failDrop) throw dropFailure; },
  });
  const logs = [];
  t.mock.method(console, 'error', (...args) => logs.push(args));
  await assert.rejects(registry.createSession(), (err) => err === runtimeFailure);
  assert.equal(runtimeFailure.cleanupSessionId, 'failed-creation');
  assert.equal(runtimeFailure.cleanupError, dropFailure);
  assert.deepEqual(logs[0][1], { type: 'Error' });
  assert.doesNotMatch(JSON.stringify(logs), /drop failed/);
  assert.throws(() => registry.getSession('failed-creation'), VisitorSessionUnavailableError);
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  failDrop = false;
  await registry.deleteSession('failed-creation');
  assert.deepEqual(events, ['provision', 'runtime:visitor_1', 'drop:visitor_1', 'drop:visitor_1']);
  await assert.rejects(registry.createSession(), (err) => err === runtimeFailure);
});

test('retains capacity and database name when provisioner reports failed partial cleanup', async () => {
  const provisionFailure = Object.assign(new Error('grant failed'), {
    orphanedDatabaseName: 'visitor_partial', cleanupError: new Error('drop failed'),
  });
  let failProvision = true;
  const ids = ['failed-provision', 'next-session'];
  const { registry, events } = registryFixture({
    maxSessions: 1,
    generateSessionId: () => ids.shift(),
    createDatabase: () => { if (failProvision) throw provisionFailure; return { databaseName: 'visitor_next' }; },
  });
  await assert.rejects(registry.createSession(), (err) => err === provisionFailure);
  assert.equal(provisionFailure.cleanupSessionId, 'failed-provision');
  await assert.rejects(registry.createSession(), VisitorSessionCapacityError);
  await registry.deleteSession('failed-provision');
  failProvision = false;
  await registry.createSession();
  assert.deepEqual(events, ['provision', 'drop:visitor_partial', 'provision', 'runtime:visitor_next']);
});

test('shutdown retains a failed compensating drop as cleanup_failed', async () => {
  const database = deferred();
  const dropFailure = new Error('drop failed');
  const ids = ['pending-session'];
  const { registry, events } = registryFixture({
    maxSessions: 1,
    generateSessionId: () => ids.shift(),
    createDatabase: () => database.promise,
    dropDatabase: () => { throw dropFailure; },
  });
  const creation = registry.createSession();
  const shutdown = registry.closeAll();
  database.resolve({ databaseName: 'visitor_pending' });
  await assert.rejects(creation, (err) => err instanceof VisitorSessionCleanupError && err.dropError === dropFailure);
  await assert.rejects(shutdown, AggregateError);
  assert.throws(() => registry.getSession('pending-session'), VisitorSessionUnavailableError);
  assert.equal(events.filter((event) => event === 'close:visitor_pending').length, 1);
});

test('creates a database before its runtime and returns opaque distinct session IDs', async () => {
  const { registry, events } = registryFixture();
  const first = await registry.createSession();
  const second = await registry.createSession();

  assert.match(first.sessionId, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.sessionId, second.sessionId);
  assert.notEqual(first.runtime, second.runtime);
  assert.deepEqual(events, ['provision', 'runtime:visitor_1', 'provision', 'runtime:visitor_2']);
});

test('regenerates an ID collision rather than overwriting a session', async () => {
  const ids = ['collision', 'collision', 'unique'];
  const { registry } = registryFixture({ generateSessionId: () => ids.shift() });
  const first = await registry.createSession();
  const second = await registry.createSession();
  assert.equal(first.sessionId, 'collision');
  assert.equal(second.sessionId, 'unique');
  assert.notEqual(registry.getSession(first.sessionId), registry.getSession(second.sessionId));
});

test('drops a provisioned database when runtime creation fails', async () => {
  const runtimeError = new Error('runtime failed');
  const { registry, events } = registryFixture({ createRuntime: () => { throw runtimeError; } });
  await assert.rejects(registry.createSession(), (err) => err === runtimeError);
  assert.deepEqual(events, ['provision', 'runtime:visitor_1', 'drop:visitor_1']);
});

test('gets and touches only active sessions', async () => {
  const { registry } = registryFixture();
  const { sessionId, runtime } = await registry.createSession();
  assert.equal(registry.getSession(sessionId), runtime);
  const { lastActivity } = registry.touchSession(sessionId);
  assert.ok(lastActivity instanceof Date);
  assert.throws(() => registry.getSession('missing'), VisitorSessionNotFoundError);
  assert.throws(() => registry.touchSession('missing'), VisitorSessionNotFoundError);

  const deletion = registry.deleteSession(sessionId);
  assert.throws(() => registry.getSession(sessionId), VisitorSessionUnavailableError);
  assert.throws(() => registry.touchSession(sessionId), VisitorSessionUnavailableError);
  await deletion;
});

test('concurrent deletion shares close and drop, in that order', async () => {
  const { registry, events } = registryFixture();
  const { sessionId } = await registry.createSession();
  const first = registry.deleteSession(sessionId);
  const second = registry.deleteSession(sessionId);
  assert.equal(first, second);
  await first;
  assert.deepEqual(events.slice(2), ['close:visitor_1', 'drop:visitor_1']);
});

test('closing failure still drops the database, removes the session, and frees capacity', async () => {
  const closeError = new Error('close failed');
  const { registry, events } = registryFixture({
    maxSessions: 1,
    createRuntime: async ({ databaseName }) => ({ databaseName, async close() { events.push(`close:${databaseName}`); throw closeError; } }),
  });
  const { sessionId } = await registry.createSession();
  await assert.rejects(registry.deleteSession(sessionId), (err) => err instanceof VisitorSessionCleanupError && err.closeError === closeError && !err.dropError);
  assert.deepEqual(events.slice(2), ['close:visitor_1', 'drop:visitor_1']);
  assert.throws(() => registry.getSession(sessionId), VisitorSessionNotFoundError);
  await registry.createSession();
  assert.equal(events.filter((event) => event === 'provision').length, 2);
});

test('closeAll shares shutdown, waits for pending creation, and compensates it', async () => {
  const database = deferred();
  const { registry, events } = registryFixture({ createDatabase: () => database.promise });
  const creation = registry.createSession();
  const shutdown = registry.closeAll();
  assert.equal(registry.closeAll(), shutdown);
  await assert.rejects(registry.createSession(), VisitorRegistryClosingError);
  database.resolve({ databaseName: 'visitor_pending', appDatabaseUrl: 'postgres://app/visitor_pending' });
  await assert.rejects(creation, VisitorRegistryClosingError);
  await shutdown;
  assert.deepEqual(events, ['provision', 'runtime:visitor_pending', 'close:visitor_pending', 'drop:visitor_pending']);
});

test('closeAll retries cleanup_failed sessions and waits for all cleanup attempts', async () => {
  let failDrop = true;
  const { registry } = registryFixture({ dropDatabase: () => { if (failDrop) throw new Error('drop failed'); } });
  const { sessionId } = await registry.createSession();
  await assert.rejects(registry.deleteSession(sessionId), VisitorSessionCleanupError);
  failDrop = false;
  await registry.closeAll();
  assert.throws(() => registry.getSession(sessionId), VisitorSessionNotFoundError);
});

test('closeAll attempts every session before reporting cleanup failures', async () => {
  const { registry, events } = registryFixture({
    dropDatabase: (databaseName) => {
      if (databaseName === 'visitor_1') throw new Error('drop failed');
    },
  });
  const first = await registry.createSession();
  const second = await registry.createSession();

  await assert.rejects(registry.closeAll(), AggregateError);
  const cleanupEvents = events.slice(4);
  assert.deepEqual([...cleanupEvents].sort(), [
    'close:visitor_1', 'close:visitor_2', 'drop:visitor_1', 'drop:visitor_2',
  ]);
  assert.ok(cleanupEvents.indexOf('close:visitor_1') < cleanupEvents.indexOf('drop:visitor_1'));
  assert.ok(cleanupEvents.indexOf('close:visitor_2') < cleanupEvents.indexOf('drop:visitor_2'));
  assert.throws(() => registry.getSession(first.sessionId), VisitorSessionUnavailableError);
  assert.throws(() => registry.getSession(second.sessionId), VisitorSessionNotFoundError);
});
