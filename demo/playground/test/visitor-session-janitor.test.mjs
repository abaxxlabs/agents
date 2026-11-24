import assert from 'node:assert/strict';
import test from 'node:test';
import { createVisitorSessionJanitor } from '../src/visitor-session-janitor.mjs';
import { createPlaygroundMetrics } from '../src/playground-metrics.mjs';

function janitorFixture({
  store,
  metrics = createPlaygroundMetrics(),
  onExpired = async () => {},
  onSweep = async () => {},
} = {}) {
  return createVisitorSessionJanitor({
    store,
    onExpired,
    onSweep,
    intervalMs: 1_000_000,
    batchSize: 10,
    maxAttempts: 3,
    retryDelayMs: 1,
    sleep: async () => {},
    logger: { error() {} },
    metrics,
  });
}

test('runOnce expires sessions, cleans origin windows and records reasons', async () => {
  const calls = [];
  const expired = [
    { sandboxId: 'absolute', reason: 'absolute' },
    { sandboxId: 'inactive', reason: 'inactivity' },
  ];
  const store = {
    async claimExpired({ limit }) { calls.push(['claim', limit]); return expired; },
    async cleanupRateWindows() { calls.push(['windows']); },
  };
  const onExpired = [];
  const metrics = createPlaygroundMetrics();
  const janitor = janitorFixture({ store, metrics, onExpired: async (entry) => onExpired.push(entry) });

  assert.equal(await janitor.runOnce(), 2);
  assert.deepEqual(calls, [['claim', 10], ['windows']]);
  assert.deepEqual(onExpired, expired);
  const text = metrics.render();
  assert.match(text, /playground_sessions_expired_total\{reason="absolute"\} 1/);
  assert.match(text, /playground_sessions_expired_total\{reason="inactivity"\} 1/);
});

test('a failed sweep retries a bounded number of times before giving up', async () => {
  let attempts = 0;
  const store = {
    async claimExpired() {
      attempts += 1;
      if (attempts < 3) throw new Error('database unavailable');
      return [];
    },
    async cleanupRateWindows() {},
  };
  const janitor = janitorFixture({ store });

  assert.equal(await janitor.runOnce(), 0);
  assert.equal(attempts, 3);
});

test('a control database failure still runs the rate window and local runtime sweeps', async () => {
  let cleanups = 0;
  let sweeps = 0;
  const store = {
    async claimExpired() { throw new Error('database unavailable'); },
    async cleanupRateWindows() { cleanups += 1; },
  };
  const janitor = janitorFixture({ store, onSweep: async () => { sweeps += 1; } });

  assert.equal(await janitor.runOnce(), 0);
  assert.equal(cleanups, 1);
  assert.equal(sweeps, 1);
});

test('one failed cleanup does not stop the remaining expired sessions', async () => {
  const cleaned = [];
  const store = {
    async claimExpired() {
      return [
        { sandboxId: 'broken', reason: 'absolute' },
        { sandboxId: 'healthy', reason: 'inactivity' },
      ];
    },
    async cleanupRateWindows() {},
  };
  const janitor = janitorFixture({
    store,
    onExpired: async ({ sandboxId }) => {
      if (sandboxId === 'broken') throw new Error('close failed');
      cleaned.push(sandboxId);
    },
  });

  assert.equal(await janitor.runOnce(), 2);
  assert.deepEqual(cleaned, ['healthy']);
});

test('runOnce runs the local runtime sweep even when no shared row expires', async () => {
  let sweeps = 0;
  const store = {
    async claimExpired() { return []; },
    async cleanupRateWindows() {},
  };
  const janitor = janitorFixture({ store, onSweep: async () => { sweeps += 1; } });

  assert.equal(await janitor.runOnce(), 0);
  assert.equal(sweeps, 1);
});

test('stop clears the pending timer without a sweep', async () => {
  let claims = 0;
  const store = {
    async claimExpired() { claims += 1; return []; },
    async cleanupRateWindows() {},
  };
  const janitor = janitorFixture({ store });
  janitor.start();
  await janitor.stop();
  assert.equal(claims, 0);
});
