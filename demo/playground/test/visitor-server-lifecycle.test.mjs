import assert from 'node:assert/strict';
import test from 'node:test';
import { shutdownVisitorServer } from '../src/visitor-server-lifecycle.mjs';

test('shutdown stops acceptance, releases closed session rows, then closes pools and the key', async () => {
  const events = [];
  const released = [];
  await shutdownVisitorServer({
    server: { close(callback) { events.push('server.close'); callback(); } },
    janitor: { async stop() { events.push('janitor.stop'); } },
    registry: {
      async closeAll() {
        events.push('registry.closeAll');
        return { closedSandboxIds: ['sandbox_one', 'sandbox_two'], failures: [] };
      },
    },
    sessionStore: {
      async releaseMany({ sandboxIds }) {
        released.push(...sandboxIds);
        events.push('sessionStore.releaseMany');
        return sandboxIds.length;
      },
    },
    directSqlPool: { async end() { events.push('directSqlPool.end'); } },
    controlPool: { async end() { events.push('controlPool.end'); } },
    sessionCookie: { close() { events.push('sessionCookie.close'); } },
  });
  assert.deepEqual(events, [
    'janitor.stop',
    'server.close',
    'registry.closeAll',
    'sessionStore.releaseMany',
    'directSqlPool.end',
    'controlPool.end',
    'sessionCookie.close',
  ]);
  assert.deepEqual(released, ['sandbox_one', 'sandbox_two']);
});

test('shutdown aggregates row release and runtime close failures', async () => {
  await assert.rejects(shutdownVisitorServer({
    server: { close(callback) { callback(); } },
    registry: {
      async closeAll() {
        return { closedSandboxIds: ['sandbox_one'], failures: [new Error('close failed')] };
      },
    },
    sessionStore: { async releaseMany() { throw new Error('release failed'); } },
    controlPool: { async end() {} },
  }), AggregateError);
});
