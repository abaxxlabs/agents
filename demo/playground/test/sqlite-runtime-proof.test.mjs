import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { parseOptions } from '../scripts/sqlite-runtime-proof.mjs';
import { execute, poll } from '../scripts/sqlite-runtime-proof/commands.mjs';
import { PREFIX, parseRecords, requireResult, finalizeReport, writeReport } from '../scripts/sqlite-runtime-proof/report.mjs';
import { provenanceMatches } from '../scripts/sqlite-runtime-proof/evidence.mjs';
import { fileURLToPath } from 'node:url';

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

test('an old worker cannot pass with a single cleanup check instead of scenario evidence', () => {
  const incomplete = { type: 'result', action: 'restart', status: 'PASS',
    checks: [{ name: 'worker-master-buffer-overwritten', status: 'PASS' }] };
  const checked = requireResult(encoded(incomplete), 0, { action: 'run', cycles: 200, warmup: 20 });
  assert.equal(checked.status, 'FAIL');
  const failures = checked.checks.at(-1).failures;
  assert.ok(failures.includes('worker-protocol-or-action'));
  assert.ok(failures.includes('image-runtime-provenance'));
  assert.ok(failures.includes('completed-workload'));
  assert.ok(failures.includes('resource-samples'));
  assert.ok(failures.includes('missing:A-full-audit-chain'));
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

test('a missing crash/restart, cleanup failure or interruption prevents approval', () => {
  const complete = () => ({ phases: Object.fromEntries(['fixture', 'run', 'kill', 'restart', 'postgres', 'cleanup']
    .map((name) => [name, { status: 'PASS' }])) });
  assert.equal(finalizeReport(complete()).status, 'PASS');
  for (const phase of ['fixture', 'run', 'kill', 'restart', 'postgres', 'cleanup']) {
    const report = complete();
    delete report.phases[phase];
    assert.equal(finalizeReport(report).status, 'FAIL');
  }
  const cleanup = complete();
  cleanup.phases.cleanup.status = 'FAIL';
  assert.equal(finalizeReport(cleanup).status, 'FAIL');
  const interrupted = { ...complete(), failure: { stage: 'interrupted' } };
  assert.equal(finalizeReport(interrupted).status, 'FAIL');
  assert.match(interrupted.recommendation, /Do not approve/);
});

test('report retains incomplete evidence and is readable without raw worker logs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sqlite-proof-report-'));
  try {
    const report = finalizeReport({ startedAt: new Date().toISOString(), command: 'npm run proof:sqlite-runtime',
      environment: { image: 'sha256:example' }, phases: { fixture: { status: 'FAIL' }, cleanup: { status: 'PASS' } } });
    await writeReport(directory, report);
    assert.equal(JSON.parse(await readFile(join(directory, 'report.json'), 'utf8')).status, 'FAIL');
    const markdown = await readFile(join(directory, 'report.md'), 'utf8');
    assert.match(markdown, /NOT_PROVEN/);
    assert.match(markdown, /Do not approve/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('options bound the workload and reject accidental unknown arguments', () => {
  assert.deepEqual(parseOptions([]), { cycles: 200, warmup: 20 });
  assert.deepEqual(parseOptions(['--cycles', '5', '--warmup', '0']), { cycles: 5, warmup: 0 });
  for (const args of [['--cycles', '0'], ['--cycles', '10001'], ['--warmup', '-1'], ['--cycles'],
    ['--unexpected', '1'], ['--image', 'image;command']]) assert.throws(() => parseOptions(args));
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

test('SIGTERM after daemon-side network creation still removes that network and reports interruption', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sqlite-proof-interruption-'));
  try {
    const docker = `#!${process.execPath}\nimport {writeFileSync,unlinkSync} from 'node:fs';
const args=process.argv.slice(2);
if(args[0]==='version') console.log('test');
else if(args[0]==='image') console.log(JSON.stringify([{Id:'test',Config:{User:'node'}}]));
else if(args[0]==='network'&&args[1]==='create') {
  writeFileSync(process.env.FAKE_NETWORK,'created');
  process.kill(process.ppid,'SIGTERM');
  setInterval(()=>{},1000);
} else if(args[0]==='network'&&args[1]==='rm') unlinkSync(process.env.FAKE_NETWORK);
else process.exitCode=1;
`;
    await writeFile(join(directory, 'docker'), docker, { mode: 0o700 });
    const network = join(directory, 'network');
    const output = join(directory, 'results');
    const script = fileURLToPath(new URL('../scripts/sqlite-runtime-proof.mjs', import.meta.url));
    const execution = await execute(process.execPath, [script, '--image', 'proof-test', '--output', output], {
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, FAKE_NETWORK: network }, timeout: 10_000,
    });
    assert.equal(execution.code, 1);
    const report = JSON.parse(await readFile(join(output, 'report.json'), 'utf8'));
    assert.equal(report.status, 'FAIL');
    assert.equal(report.failure.stage, 'interrupted');
    assert.equal(report.phases.cleanup.status, 'PASS');
    assert.equal(report.phases.cleanup.network, true);
    await assert.rejects(readFile(network), { code: 'ENOENT' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
