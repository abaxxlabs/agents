import assert from 'node:assert/strict';
import test from 'node:test';
import { shutdownVisitorServer } from '../src/visitor-server-lifecycle.mjs';

test('shutdown stops HTTP acceptance, closes all visitor sessions, then closes admin pool', async () => {
  const events = [];
  await shutdownVisitorServer({
    server: { close(callback) { events.push('server.close'); callback(); } },
    registry: { async closeAll() { events.push('registry.closeAll'); } },
    adminPool: { async end() { events.push('adminPool.end'); } },
  });
  assert.deepEqual(events, ['server.close', 'registry.closeAll', 'adminPool.end']);
});
