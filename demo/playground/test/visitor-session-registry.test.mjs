import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createVisitorSessionRegistry,
  VisitorSessionNotFoundError,
} from '../src/visitor-session-registry.mjs';

function registryFixture({ createRuntime, now } = {}) {
  const events = [];
  const runtimeFactory = async (options) => {
    events.push(`runtime:${options.sandboxId}`);
    if (createRuntime) return createRuntime(options);
    return { sandboxId: options.sandboxId, async close() { events.push(`close:${options.sandboxId}`); } };
  };
  return {
    registry: createVisitorSessionRegistry({ createRuntime: runtimeFactory, now }),
    events,
  };
}

test('creates a runtime for each sandbox and resolves them locally', async () => {
  const { registry, events } = registryFixture();
  const first = await registry.createRuntime('sandbox_one');
  const second = await registry.createRuntime('sandbox_two');

  assert.equal(registry.getRuntime('sandbox_one'), first);
  assert.equal(registry.getRuntime('sandbox_two'), second);
  assert.equal(registry.hasRuntime('sandbox_two'), true);
  assert.equal(registry.size, 2);
  assert.deepEqual(events, ['runtime:sandbox_one', 'runtime:sandbox_two']);
});

test('runtime initialization failure leaves no local state', async () => {
  const runtimeError = new Error('runtime failed');
  const { registry, events } = registryFixture({
    createRuntime: () => { throw runtimeError; },
  });

  await assert.rejects(registry.createRuntime('sandbox_failed'), (err) => err === runtimeError);
  assert.equal(registry.hasRuntime('sandbox_failed'), false);
  assert.deepEqual(events, ['runtime:sandbox_failed']);
});

test('closing a runtime removes only local state', async () => {
  const { registry, events } = registryFixture();
  const runtime = await registry.createRuntime('sandbox_one');

  assert.equal(await registry.closeRuntime('sandbox_one'), true);
  assert.equal(registry.hasRuntime('sandbox_one'), false);
  assert.throws(() => registry.getRuntime('sandbox_one'), VisitorSessionNotFoundError);
  assert.equal(await registry.closeRuntime('sandbox_one'), null);
  assert.deepEqual(events, ['runtime:sandbox_one', 'close:sandbox_one']);
  assert.equal(runtime.sandboxId, 'sandbox_one');
});

test('a failed close keeps the runtime for a later retry', async () => {
  let time = 1_000_000;
  let fail = true;
  const { registry } = registryFixture({
    now: () => time,
    createRuntime: ({ sandboxId }) => ({
      sandboxId,
      async close() {
        if (fail) {
          fail = false;
          throw new Error('close failed');
        }
      },
    }),
  });
  await registry.createRuntime('sandbox_one');

  time += 1_000;
  const firstSweep = await registry.expireLocal({ absoluteTtlMs: 1, inactivityTtlMs: 1 });
  assert.equal(firstSweep.failures.length, 1);
  assert.equal(registry.hasRuntime('sandbox_one'), true);

  const secondSweep = await registry.expireLocal({ absoluteTtlMs: 1, inactivityTtlMs: 1 });
  assert.deepEqual(secondSweep.expired, [{ sandboxId: 'sandbox_one' }]);
  assert.deepEqual(secondSweep.failures, []);
  assert.equal(registry.hasRuntime('sandbox_one'), false);
});

test('local runtimes expire on absolute or inactivity TTL independently of polling', async () => {
  let time = 1_000_000;
  const { registry, events } = registryFixture({ now: () => time });
  await registry.createRuntime('sandbox_one');
  await registry.createRuntime('sandbox_two');

  time = 1_000_100;
  assert.equal(registry.touchRuntime('sandbox_two'), true);
  assert.equal(registry.touchRuntime('sandbox_missing'), false);

  time = 1_000_201;
  const firstSweep = await registry.expireLocal({ absoluteTtlMs: 10_000, inactivityTtlMs: 150 });
  assert.deepEqual(firstSweep.expired, [
    { sandboxId: 'sandbox_one' },
  ]);
  assert.deepEqual(firstSweep.failures, []);
  assert.equal(registry.hasRuntime('sandbox_one'), false);
  assert.equal(registry.hasRuntime('sandbox_two'), true);

  time = 1_001_000;
  const secondSweep = await registry.expireLocal({ absoluteTtlMs: 1_000, inactivityTtlMs: 150 });
  assert.deepEqual(secondSweep.expired, [
    { sandboxId: 'sandbox_two' },
  ]);
  assert.deepEqual(secondSweep.failures, []);
  assert.equal(registry.size, 0);
  assert.deepEqual(events, [
    'runtime:sandbox_one',
    'runtime:sandbox_two',
    'close:sandbox_one',
    'close:sandbox_two',
  ]);
});

test('closeAll closes local runtimes once and rejects new creations', async () => {
  const { registry, events } = registryFixture();
  await registry.createRuntime('sandbox_one');
  await registry.createRuntime('sandbox_two');

  const shutdown = registry.closeAll();
  assert.equal(registry.closeAll(), shutdown);
  await assert.rejects(registry.createRuntime('sandbox_three'), /closing/);
  assert.deepEqual(await shutdown, {
    closedSandboxIds: ['sandbox_one', 'sandbox_two'],
    failures: [],
  });

  assert.equal(registry.size, 0);
  assert.deepEqual(events, [
    'runtime:sandbox_one',
    'runtime:sandbox_two',
    'close:sandbox_one',
    'close:sandbox_two',
  ]);
});

test('closeAll reports only closed sandboxes and aggregates close failures', async () => {
  const { registry, events } = registryFixture({
    createRuntime: ({ sandboxId }) => ({
      sandboxId,
      async close() {
        events.push(`close:${sandboxId}`);
        if (sandboxId === 'sandbox_one') throw new Error('close failed');
      },
    }),
  });
  await registry.createRuntime('sandbox_one');
  await registry.createRuntime('sandbox_two');

  const result = await registry.closeAll();
  assert.deepEqual(result.closedSandboxIds, ['sandbox_two']);
  assert.equal(result.failures.length, 1);
  assert.deepEqual(events, [
    'runtime:sandbox_one',
    'runtime:sandbox_two',
    'close:sandbox_one',
    'close:sandbox_two',
  ]);
  assert.equal(registry.size, 0);
});

test('creation that finishes during shutdown closes its runtime', async () => {
  let releaseRuntime;
  let runtimeStarted;
  const started = new Promise((resolve) => { runtimeStarted = resolve; });
  const blocked = new Promise((resolve) => { releaseRuntime = resolve; });
  const { registry, events } = registryFixture({
    createRuntime: async ({ sandboxId }) => {
      runtimeStarted();
      await blocked;
      return { sandboxId, async close() { events.push(`close:${sandboxId}`); } };
    },
  });

  const creation = registry.createRuntime('sandbox_race');
  await started;
  const shutdown = registry.closeAll();
  releaseRuntime();

  await assert.rejects(creation, /closing/);
  assert.deepEqual(await shutdown, { closedSandboxIds: [], failures: [] });
  assert.deepEqual(events, [
    'runtime:sandbox_race', 'close:sandbox_race',
  ]);
  assert.equal(registry.size, 0);
});
