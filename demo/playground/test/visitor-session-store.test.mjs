import assert from 'node:assert/strict';
import test from 'node:test';
import { loadModule, parseSync } from 'libpg-query';
import {
  createVisitorSessionStore,
  VISITOR_SESSION_SCHEMA_SQL,
} from '../src/visitor-session-store.mjs';

const NOW = 1_000_000;

function fakePool({ query = async () => ({ rows: [] }), client = async () => ({ rows: [] }) } = {}) {
  const events = [];
  return {
    events,
    async query(sql, params) {
      events.push({ sql, params });
      return query(sql, params);
    },
    async connect() {
      return {
        async query(sql, params) {
          events.push({ sql, params });
          return client(sql, params);
        },
        release() {
          events.push({ release: true });
        },
      };
    },
  };
}

function storeFixture(options = {}) {
  const pool = fakePool(options);
  const store = createVisitorSessionStore({
    pool,
    now: () => NOW,
    absoluteTtlMs: 60_000,
    inactivityTtlMs: 30_000,
    maxSessions: 2,
    rateLimit: { maxNewSessions: 10, windowMs: 60_000 },
  });
  return { store, pool };
}

test('every emitted statement parses as PostgreSQL and cleanupRateWindows returns the deleted count', async () => {
  await loadModule();
  assert.doesNotThrow(() => parseSync(VISITOR_SESSION_SCHEMA_SQL), 'schema must parse as PostgreSQL');
  const { store, pool } = storeFixture({
    query: async (sql) => {
      if (/SELECT count\(\*\)/.test(sql)) return { rows: [{ active: 0 }], rowCount: 0 };
      if (/DELETE FROM playground_sandbox_session WHERE sandbox_id = \$1/.test(sql)) return { rows: [], rowCount: 0 };
      if (/DELETE FROM playground_sandbox_session WHERE sandbox_id = ANY/.test(sql)) return { rows: [], rowCount: 2 };
      if (/DELETE FROM playground_new_session_window/.test(sql)) return { rows: [], rowCount: 3 };
      return { rows: [], rowCount: 1 };
    },
    client: async (sql) => {
      if (/SELECT count\(\*\)/.test(sql)) return { rows: [{ active: 0 }] };
      return { rows: [] };
    },
  });

  await store.admit({ sandboxId: 'sandbox', originHash: 'origin' });
  await store.resolve({ sandboxId: 'sandbox' });
  await store.touch({ sandboxId: 'sandbox' });
  await store.release({ sandboxId: 'sandbox' });
  await store.claimExpired({ limit: 1 });
  assert.equal(await store.cleanupRateWindows(), 3);
  assert.equal(await store.releaseMany({ sandboxIds: ['sandbox'] }), 2);
  await store.countActive();

  const statements = pool.events.map(({ sql }) => sql).filter(Boolean);
  assert.ok(statements.some((sql) => /DELETE FROM playground_new_session_window w/.test(sql)));
  for (const sql of statements) {
    assert.doesNotThrow(() => parseSync(sql), `statement must parse: ${sql}`);
  }
});

test('cleanupRateWindows drains every stale batch in a single tick', async () => {
  let stale = 2_500;
  const deletes = [];
  const { store } = storeFixture({
    query: async (sql, params) => {
      if (/DELETE FROM playground_new_session_window/.test(sql)) {
        deletes.push(params);
        const removed = Math.min(stale, params[1]);
        stale -= removed;
        return { rows: [], rowCount: removed };
      }
      return { rows: [], rowCount: 0 };
    },
  });

  assert.equal(await store.cleanupRateWindows({ limit: 1_000 }), 2_500);
  assert.equal(deletes.length, 3);
  assert.equal(stale, 0);
});

test('cleanupRateWindows never deletes a restarted origin window', async () => {
  const { store, pool } = storeFixture({ query: async () => ({ rows: [], rowCount: 0 }) });
  await store.cleanupRateWindows();

  const [query] = pool.events;
  assert.match(query.sql, /AND w\.window_start <= \$1/);
  assert.deepEqual(query.params, [new Date(NOW - 60_000), 1_000]);
});

test('releaseMany deletes only the supplied sandbox rows', async () => {
  const { store, pool } = storeFixture({
    query: async () => ({ rowCount: 2 }),
  });

  assert.equal(await store.releaseMany({ sandboxIds: ['sandbox_a', 'sandbox_b'] }), 2);
  const [query] = pool.events;
  assert.match(query.sql, /WHERE sandbox_id = ANY\(\$1::text\[\]\)/);
  assert.deepEqual(query.params, [['sandbox_a', 'sandbox_b']]);
  assert.equal(await store.releaseMany({ sandboxIds: [] }), 0);
  assert.equal(pool.events.length, 1);
  await assert.rejects(store.releaseMany({ sandboxIds: [''] }), TypeError);
});

test('admission rejects capacity atomically without inserting a session', async () => {
  const { store, pool } = storeFixture({
    client: async (sql) => {
      if (/SELECT window_start/.test(sql)) return { rows: [] };
      if (/SELECT count\(\*\)/.test(sql)) return { rows: [{ active: 2 }] };
      return { rows: [] };
    },
  });

  assert.deepEqual(await store.admit({ sandboxId: 'sandbox', originHash: 'origin' }), {
    ok: false,
    reason: 'capacity',
  });
  const sqls = pool.events.map(({ sql }) => sql);
  assert.ok(sqls.includes('BEGIN'));
  assert.ok(sqls.includes('ROLLBACK'));
  assert.ok(sqls.includes('COMMIT') === false);
  assert.ok(!sqls.some((sql) => /INSERT INTO playground_sandbox_session/.test(sql)));
  assert.ok(sqls.some((sql) => /pg_advisory_xact_lock/.test(sql)));
});

test('admission rejects a second new session in the same origin window', async () => {
  const { store, pool } = storeFixture({
    client: async (sql) => {
      if (/SELECT window_start/.test(sql)) {
        return { rows: [{ window_start: new Date(NOW - 1_000), attempts: 10 }] };
      }
      return { rows: [] };
    },
  });

  assert.deepEqual(await store.admit({ sandboxId: 'sandbox', originHash: 'origin' }), {
    ok: false,
    reason: 'rate-limit',
    retryAfterMs: 59_000,
  });
  assert.ok(pool.events.some(({ sql }) => sql === 'ROLLBACK'));
});

test('admission inserts the session and commits after reserving capacity', async () => {
  const { store, pool } = storeFixture({
    client: async (sql) => {
      if (/SELECT window_start/.test(sql)) return { rows: [] };
      if (/SELECT count\(\*\)/.test(sql)) return { rows: [{ active: 1 }] };
      return { rows: [] };
    },
  });

  const result = await store.admit({ sandboxId: 'sandbox', originHash: 'origin' });
  assert.deepEqual(result, { ok: true, expiresAt: NOW + 60_000, lastSeenAt: NOW });
  const sqls = pool.events.map(({ sql }) => sql);
  assert.ok(sqls.includes('COMMIT'));
  assert.ok(sqls.some((sql) => /INSERT INTO playground_sandbox_session/.test(sql)));
  assert.ok(pool.events.at(-1).release);
});

test('resolves active, expired, inactive and unknown sessions', async () => {
  let row;
  const { store } = storeFixture({
    query: async () => ({ rows: row ? [row] : [] }),
  });

  assert.deepEqual(await store.resolve({ sandboxId: 'missing' }), { ok: false, reason: 'unknown' });

  row = {
    sandbox_id: 'expired',
    created_at: new Date(NOW - 120_000),
    expires_at: new Date(NOW - 1),
    last_seen_at: new Date(NOW - 1_000),
  };
  assert.deepEqual(await store.resolve({ sandboxId: 'expired' }), { ok: false, reason: 'absolute-expired' });

  row = {
    sandbox_id: 'inactive',
    created_at: new Date(NOW - 120_000),
    expires_at: new Date(NOW + 60_000),
    last_seen_at: new Date(NOW - 30_001),
  };
  assert.deepEqual(await store.resolve({ sandboxId: 'inactive' }), { ok: false, reason: 'inactive' });

  row = {
    sandbox_id: 'active',
    created_at: new Date(NOW - 10_000),
    expires_at: new Date(NOW + 60_000),
    last_seen_at: new Date(NOW - 1_000),
  };
  assert.deepEqual(await store.resolve({ sandboxId: 'active' }), {
    ok: true,
    expiresAt: NOW + 60_000,
    lastSeenAt: NOW - 1_000,
  });
});

test('touch renews a live session and reports a missing or expired one', async () => {
  let rowCount = 1;
  const { store, pool } = storeFixture({
    query: async () => ({ rowCount }),
  });

  assert.equal(await store.touch({ sandboxId: 'sandbox' }), true);
  const [query] = pool.events;
  assert.deepEqual(query.params, [
    'sandbox',
    new Date(NOW),
    new Date(NOW - 30_000),
  ]);

  rowCount = 0;
  assert.equal(await store.touch({ sandboxId: 'sandbox' }), false);
});

test('claimExpired maps deleted sessions to their expiry reason', async () => {
  const { store } = storeFixture({
    query: async () => ({
      rows: [
        { sandbox_id: 'absolute', reason: 'absolute' },
        { sandbox_id: 'inactive', reason: 'inactivity' },
      ],
    }),
  });

  assert.deepEqual(await store.claimExpired({ limit: 10 }), [
    { sandboxId: 'absolute', reason: 'absolute' },
    { sandboxId: 'inactive', reason: 'inactivity' },
  ]);
});

test('release reports whether a row was removed and countActive aggregates', async () => {
  let rowCount = 1;
  let active = 3;
  const { store } = storeFixture({
    query: async (sql) => {
      if (/DELETE FROM playground_sandbox_session/.test(sql)) return { rowCount };
      if (/SELECT count\(\*\)/.test(sql)) return { rows: [{ active }] };
      return { rowCount: 1 };
    },
  });

  assert.equal(await store.release({ sandboxId: 'sandbox' }), true);
  rowCount = 0;
  assert.equal(await store.release({ sandboxId: 'sandbox' }), false);
  assert.equal(await store.countActive(), active);
  active = 0;
  assert.equal(await store.countActive(), 0);
});
