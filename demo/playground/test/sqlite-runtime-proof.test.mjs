import assert from 'node:assert/strict';
import test from 'node:test';
import { execute, poll } from '../scripts/sqlite-runtime-proof/commands.mjs';
import { PREFIX, parseRecords, requireResult } from '../scripts/sqlite-runtime-proof/report.mjs';
import { provenanceMatches } from '../scripts/sqlite-runtime-proof/evidence.mjs';

const encoded = (value) => `${PREFIX}${JSON.stringify(value)}\n`;
const result = (status = 'PASS') => ({ type: 'result', status, checks: [{ name: 'real-operation', status }] });

test('native load failure, timeout, malformed or missing evidence cannot pass', () => {
  assert.throws(() => requireResult('native module could not load', 1));
  assert.throws(() => requireResult(encoded({ type: 'sample' }), 0));
  assert.throws(() => requireResult(encoded({ type: 'result', status: 'PASS', checks: [] }), 0));
  assert.throws(() => requireResult(encoded(result()) + encoded(result()), 0));
  assert.throws(() => parseRecords(`${PREFIX}{malformed\n`));
  assert.equal(requireResult(encoded(result()), -1).status, 'FAIL');
  assert.equal(requireResult(encoded(result('FAIL')), 0).status, 'FAIL');
  assert.equal(requireResult(encoded({ ...result(), checks: [{ name: 'cleanup', status: 'FAIL' }] }), 0).status, 'FAIL');
  assert.equal(requireResult(`diagnostic\n${encoded(result())}`, 0).status, 'FAIL');
});

test('an existing image must prove the expected Node, non-root user, driver and lock', () => {
  const expected = { sdkVersion: 'sdk-test', sqliteVersion: 'driver-test', lockSha256: 'lock-test' };
  const runtime = { node: 'v22.1.0', platform: 'linux', uid: 1000, sdk: { version: 'sdk-test' },
    betterSqlite3: { version: 'driver-test', probe: 'PASS', sqliteVersion: 'sqlite-test' },
    imagePackageLock: { sha256: 'lock-test' } };
  assert.equal(provenanceMatches(runtime, expected), true);
  for (const changed of [{ node: 'v24.1.0' }, { uid: 0 }, { sdk: { version: 'stale' } },
    { betterSqlite3: { ...runtime.betterSqlite3, probe: 'FAIL' } }, { imagePackageLock: { sha256: 'stale' } }]) {
    assert.equal(provenanceMatches({ ...runtime, ...changed }, expected), false);
  }
});

test('commands terminate on deadline or abort and do not mistake a signal for success', async () => {
  const timeout = await execute(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeout: 50 });
  assert.equal(timeout.code, -1);
  assert.equal(timeout.timedOut, true);
  const controller = new AbortController();
  const pending = execute(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { signal: controller.signal });
  setTimeout(() => controller.abort(), 50);
  assert.equal((await pending).code, -1);
  const attempts = [];
  const polled = await poll(async () => attempts.push(true), (count) => count === 3, { interval: 1 });
  assert.equal(polled.value, 3);
  await assert.rejects(poll(async () => false, Boolean, { timeout: 1, interval: 1 }), /deadline-exceeded/);
  const aborted = new AbortController();
  const waiting = poll(async () => { aborted.abort(); return false; }, Boolean, { timeout: 60_000, signal: aborted.signal });
  await assert.rejects(waiting, /interrupted/);
});
