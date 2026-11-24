import assert from 'node:assert/strict';
import test from 'node:test';
import { createVisitorSessionCleaner } from '../src/visitor-session-cleaner.mjs';

function cleanerFixture() {
  const events = [];
  const registry = {
    async closeRuntime(sandboxId) {
      events.push(`close:${sandboxId}`);
      return true;
    },
  };
  const sessionStore = {
    async release({ sandboxId }) {
      events.push(`release:${sandboxId}`);
      return true;
    },
  };
  return {
    cleaner: createVisitorSessionCleaner({
      registry,
      sessionStore,
      logger: { error() {} },
    }),
    events,
  };
}

test('release drops the row and closes the runtime', async () => {
  const { cleaner, events } = cleanerFixture();
  await cleaner.release('sandbox_one');

  assert.deepEqual(events, [
    'release:sandbox_one',
    'close:sandbox_one',
  ]);
});

test('dispose closes the runtime without releasing the row', async () => {
  const { cleaner, events } = cleanerFixture();
  await cleaner.dispose({ sandboxId: 'sandbox_one' });

  assert.deepEqual(events, [
    'close:sandbox_one',
  ]);
});
