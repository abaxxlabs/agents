import assert from 'node:assert/strict';
import test from 'node:test';
import {
  resolveControlDatabaseUrl,
  resolveControlPoolMax,
  resolveDirectSqlPoolMax,
  resolveSessionConfig,
  resolveSessionCookieKey,
  resolveSharedFixtureDatabaseUrl,
  resolveSharedPoolMax,
  withoutEnvironmentEntry,
} from '../src/env-file.mjs';

const runtime = 'postgresql://agents_playground_app@localhost/playground';
const valid = 'postgresql://agents_playground_app@localhost/playground_shared';

function resolve(shared) {
  return resolveSharedFixtureDatabaseUrl({
    PLAYGROUND_RUNTIME_DATABASE_URL: runtime,
    PLAYGROUND_SHARED_DATABASE_URL: shared,
  });
}

test('shared fixture URL must decode to the derived database name', () => {
  assert.equal(resolve(valid), valid);
  assert.equal(
    resolve('postgresql://agents_playground_app@localhost/%70layground_shared'),
    'postgresql://agents_playground_app@localhost/%70layground_shared',
  );

  for (const [shared, code] of [
    [undefined, 'PLAYGROUND_SHARED_DATABASE_URL_MISSING'],
    ['not-a-url', 'PLAYGROUND_SHARED_DATABASE_URL_INVALID'],
    ['postgresql://agents_playground_app@localhost/%70layground', 'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID'],
    ['postgresql://agents_playground_app@localhost/other_shared', 'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID'],
    ['postgresql://agents_playground_app@otherhost/playground_shared', 'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID'],
    ['postgresql://agents_playground_app@localhost/', 'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID'],
    ['postgresql://postgres@localhost/playground_shared', 'PLAYGROUND_SHARED_DATABASE_URL_ROLE_INVALID'],
    ['postgresql://agents_playground_app@localhost/playground', 'PLAYGROUND_SHARED_DATABASE_URL_NAME_INVALID'],
  ]) {
    assert.throws(() => resolve(shared), (err) => err.code === code, `expected ${code} for ${String(shared)}`);
  }

  assert.throws(
    () => resolveSharedFixtureDatabaseUrl({
      PLAYGROUND_SHARED_DATABASE_URL: valid,
    }),
    (err) => err.code === 'PLAYGROUND_RUNTIME_DATABASE_URL_INVALID',
  );
});

test('shared pool max defaults to 10 and rejects invalid sizes', () => {
  assert.equal(resolveSharedPoolMax({}), 10);
  assert.equal(resolveSharedPoolMax({ PLAYGROUND_SHARED_POOL_MAX: '20' }), 20);
  for (const value of ['0', '-1', '1.5', 'abc', '']) {
    assert.throws(
      () => resolveSharedPoolMax({ PLAYGROUND_SHARED_POOL_MAX: value }),
      (err) => err.code === 'PLAYGROUND_SHARED_POOL_MAX_INVALID',
      `expected an error for ${value}`,
    );
  }
});

test('session settings default to the documented absolute and inactivity TTLs', () => {
  assert.deepEqual(resolveSessionConfig({}), {
    absoluteTtlMs: 4 * 60 * 60 * 1000,
    inactivityTtlMs: 60 * 60 * 1000,
    maxSessions: 10,
    janitor: {
      intervalMs: 30_000,
      batchSize: 100,
      maxAttempts: 3,
      retryDelayMs: 250,
    },
  });
  assert.equal(
    resolveSessionConfig({ PLAYGROUND_VISITOR_INACTIVITY_TTL_MS: '30000' }).inactivityTtlMs,
    30_000,
  );
  assert.equal(resolveDirectSqlPoolMax({}), 2);
  assert.equal(resolveControlPoolMax({}), 4);
});

test('session settings reject inconsistent or malformed values', () => {
  for (const [env, code] of [
    [{ PLAYGROUND_SESSION_ABSOLUTE_TTL_MS: '0' }, 'PLAYGROUND_SESSION_ABSOLUTE_TTL_MS_INVALID'],
    [{ PLAYGROUND_SESSION_INACTIVITY_TTL_MS: 'abc' }, 'PLAYGROUND_SESSION_INACTIVITY_TTL_MS_INVALID'],
    [{ PLAYGROUND_MAX_VISITOR_SESSIONS: '1.5' }, 'PLAYGROUND_MAX_VISITOR_SESSIONS_INVALID'],
    [{ PLAYGROUND_SESSION_JANITOR_INTERVAL_MS: '-1' }, 'PLAYGROUND_SESSION_JANITOR_INTERVAL_MS_INVALID'],
    [{ PLAYGROUND_SESSION_JANITOR_BATCH_SIZE: '0' }, 'PLAYGROUND_SESSION_JANITOR_BATCH_SIZE_INVALID'],
    [{ PLAYGROUND_SESSION_JANITOR_MAX_ATTEMPTS: 'x' }, 'PLAYGROUND_SESSION_JANITOR_MAX_ATTEMPTS_INVALID'],
    [{ PLAYGROUND_SESSION_JANITOR_RETRY_DELAY_MS: '0' }, 'PLAYGROUND_SESSION_JANITOR_RETRY_DELAY_MS_INVALID'],
    [{ PLAYGROUND_SESSION_ABSOLUTE_TTL_MS: '1000', PLAYGROUND_SESSION_INACTIVITY_TTL_MS: '2000' }, 'PLAYGROUND_SESSION_TTLS_INCONSISTENT'],
  ]) {
    assert.throws(() => resolveSessionConfig(env), (err) => err.code === code, `expected ${code}`);
  }

  assert.throws(
    () => resolveDirectSqlPoolMax({ PLAYGROUND_DIRECT_SQL_POOL_MAX: '0' }),
    (err) => err.code === 'PLAYGROUND_DIRECT_SQL_POOL_MAX_INVALID',
  );
  assert.throws(
    () => resolveControlPoolMax({ PLAYGROUND_CONTROL_POOL_MAX: 'x' }),
    (err) => err.code === 'PLAYGROUND_CONTROL_POOL_MAX_INVALID',
  );
});

test('the control database URL keeps the restricted runtime credentials', () => {
  assert.equal(
    resolveControlDatabaseUrl('playground', 'postgresql://agents_playground_app:secret@localhost:5432/playground'),
    'postgresql://agents_playground_app:secret@localhost:5432/playground_control',
  );
  assert.throws(
    () => resolveControlDatabaseUrl('x'.repeat(56), 'postgresql://agents_playground_app@localhost/playground'),
    (err) => err.code === 'PLAYGROUND_CONTROL_DATABASE_NAME_INVALID',
  );
  assert.throws(
    () => resolveControlDatabaseUrl('playground', 'not-a-url'),
    (err) => err.code === 'PLAYGROUND_CONTROL_DATABASE_URL_INVALID',
  );
});

test('the control database URL requires the restricted runtime role', () => {
  assert.throws(
    () => resolveControlDatabaseUrl('playground', 'postgresql://postgres:postgres@localhost/playground'),
    (err) => err.code === 'PLAYGROUND_RUNTIME_DATABASE_URL_ROLE_INVALID',
  );
  assert.throws(
    () => resolveControlDatabaseUrl('playground', 'postgresql://agents_playground_app@localhost/playground?user=postgres'),
    (err) => err.code === 'PLAYGROUND_RUNTIME_DATABASE_URL_ROLE_INVALID',
  );
});

test('removing a stale entry leaves the rest of the env file intact', () => {
  const contents =
    'AGENTS_MASTER_KEY=abc\n' +
    'PLAYGROUND_ADMIN_DATABASE_URL=postgresql://postgres:secret@localhost/playground\n' +
    'PLAYGROUND_PORT=3100\n';
  assert.equal(
    withoutEnvironmentEntry(contents, 'PLAYGROUND_ADMIN_DATABASE_URL'),
    'AGENTS_MASTER_KEY=abc\nPLAYGROUND_PORT=3100\n',
  );
  assert.equal(withoutEnvironmentEntry('A=1\n', 'MISSING'), 'A=1\n');
});

test('the cookie key is shared through the master key unless explicitly configured', () => {
  const masterKey = Buffer.from('ab'.repeat(32), 'hex');
  const derived = resolveSessionCookieKey({}, masterKey);
  assert.equal(derived.length, 32);
  assert.notDeepEqual(derived, masterKey);
  assert.deepEqual(resolveSessionCookieKey({}, masterKey), derived);

  const configured = resolveSessionCookieKey({ PLAYGROUND_SESSION_COOKIE_KEY: 'cd'.repeat(32) }, masterKey);
  assert.deepEqual(configured, Buffer.from('cd'.repeat(32), 'hex'));
  assert.throws(
    () => resolveSessionCookieKey({ PLAYGROUND_SESSION_COOKIE_KEY: 'not-hex' }, masterKey),
    (err) => err.code === 'PLAYGROUND_SESSION_COOKIE_KEY_INVALID',
  );
});
