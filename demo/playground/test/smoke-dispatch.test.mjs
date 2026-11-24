import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { resolveSmokeTarget } from '../scripts/smoke-dispatch.mjs';

const testDir = dirname(fileURLToPath(import.meta.url));
const playgroundRoot = resolve(testDir, '..');
const ORIGIN = 'https://playground.example.com';

function runDispatcher(env, extraEnv = {}) {
  const childEnv = { ...process.env, ...extraEnv, ...env };
  // An ambient value must not steer the mode under test; tests set it explicitly.
  if (!('PLAYGROUND_SMOKE_BASE_URL' in env) && !('PLAYGROUND_SMOKE_BASE_URL' in extraEnv)) {
    delete childEnv.PLAYGROUND_SMOKE_BASE_URL;
  }
  return spawnSync(
    process.execPath,
    [join(playgroundRoot, 'scripts', 'smoke-dispatch.mjs')],
    { env: childEnv, encoding: 'utf8', timeout: 60_000 },
  );
}

test('dispatcher selects and starts the local Compose smoke when the target is unset', () => {
  assert.deepEqual(resolveSmokeTarget({}), { mode: 'local', script: 'compose-smoke.mjs' });
  assert.deepEqual(
    resolveSmokeTarget({ PLAYGROUND_PORT: '3110', PLAYGROUND_DATABASE_URL: 'postgres://x' }),
    { mode: 'local', script: 'compose-smoke.mjs' },
  );
  // An empty PATH makes the first docker call fail, proving local selection.
  const result = runDispatcher({}, { PATH: '/nonexistent' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /docker compose --project-name agents-playground-test-/);
  assert.doesNotMatch(result.stderr, /remote smoke/);
});

test('dispatcher routes a bare HTTPS origin to the remote module and propagates its exit code', () => {
  assert.deepEqual(resolveSmokeTarget({ PLAYGROUND_SMOKE_BASE_URL: ORIGIN }), {
    mode: 'remote',
    script: 'remote-smoke.mjs',
    baseUrl: ORIGIN,
  });
  assert.equal(
    resolveSmokeTarget({ PLAYGROUND_SMOKE_BASE_URL: 'https://playground.example.com:8443' }).baseUrl,
    'https://playground.example.com:8443',
    'a non-default HTTPS port is part of the deployed origin',
  );
  const result = runDispatcher({
    PLAYGROUND_SMOKE_BASE_URL: ORIGIN,
    PLAYGROUND_SMOKE_TIMEOUT_MS: '300',
    PLAYGROUND_SMOKE_READY_TIMEOUT_MS: '400',
  });
  assert.equal(result.status, 1, 'an unreachable deployed origin must fail the remote smoke');
  assert.match(result.stderr, /remote Playground not ready/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /docker|psql|playground\.example\.com/);
});

const INVALID_TARGETS = [
  ['', 'empty string'],
  ['   ', 'whitespace only'],
  ['not a url', 'malformed url'],
  ['http://playground.example.com', 'plain http scheme'],
  ['postgres://playground.example.com/playground', 'non-web scheme'],
  ['https://playground.example.com/smoke', 'path'],
  ['https://playground.example.com?probe=1', 'query'],
  ['https://playground.example.com#readyz', 'fragment'],
  ['https://user:token@playground.example.com', 'credentials'],
];

test('dispatcher rejects invalid targets without starting any smoke', () => {
  for (const [value, label] of INVALID_TARGETS) {
    assert.throws(
      () => resolveSmokeTarget({ PLAYGROUND_SMOKE_BASE_URL: value }),
      /PLAYGROUND_SMOKE_BASE_URL must be a bare HTTPS origin/,
      label,
    );
  }
  const result = runDispatcher({ PLAYGROUND_SMOKE_BASE_URL: 'http://playground.example.com' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /smoke selector: PLAYGROUND_SMOKE_BASE_URL must be a bare HTTPS origin/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /docker|remote smoke|psql/);
});
