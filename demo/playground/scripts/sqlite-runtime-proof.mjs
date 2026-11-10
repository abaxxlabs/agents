#!/usr/bin/env node
import { randomBytes, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execute, poll, CommandFailure } from './sqlite-runtime-proof/commands.mjs';
import { parseRecords, requireResult, finalizeReport, writeReport } from './sqlite-runtime-proof/report.mjs';
import { readyMatches } from './sqlite-runtime-proof/evidence.mjs';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const playground = join(root, 'demo/playground');
const worker = 'scripts/sqlite-runtime-proof/worker.mjs';
const database = 'runtime_proof';

export function parseOptions(args) {
  const options = { cycles: 200, warmup: 20 };
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!['--cycles', '--warmup', '--output', '--image'].includes(flag) || !value) throw new Error('Invalid proof arguments');
    if (flag === '--cycles' || flag === '--warmup') {
      const minimum = flag === '--cycles' ? 1 : 0;
      if (!/^\d{1,5}$/.test(value) || Number(value) < minimum || Number(value) > 10_000) throw new Error('Invalid cycle count');
      options[flag.slice(2)] = Number(value);
    } else if (flag === '--image') {
      if (!/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$/.test(value)) throw new Error('Invalid image reference');
      options.image = value;
    } else options.output = resolve(value);
  }
  return options;
}

export async function runProof(options) {
  const suffix = `${process.pid}-${randomBytes(4).toString('hex')}`;
  const name = `agents-sqlite-proof-${suffix}`;
  const image = options.image ?? `agents-playground-sqlite-proof:${suffix}`;
  const pgImage = 'postgres:16-bookworm';
  const output = options.output ?? join(playground, 'test-results/sqlite-runtime-proof', suffix);
  const containers = new Set();
  const report = { startedAt: new Date().toISOString(), phases: {}, environment: {},
    command: `npm run proof:sqlite-runtime -- --cycles ${options.cycles} --warmup ${options.warmup}${options.image ? ` --image ${options.image}` : ''}` };
  const secret = () => randomBytes(32).toString('hex');
  const adminPassword = secret();
  const queryPassword = secret();
  const rawPassword = secret();
  const env = { ...process.env, POSTGRES_PASSWORD: adminPassword,
    PROOF_ADMIN_DATABASE_URL: `postgresql://postgres:${adminPassword}@postgres:5432/${database}`,
    PROOF_DATABASE_URL: `postgresql://proof_query:${queryPassword}@postgres:5432/${database}`,
    PROOF_RAW_DATABASE_URL: `postgresql://proof_raw:${rawPassword}@postgres:5432/${database}`,
    PROOF_MASTER_KEY: secret(), PROOF_QUERY_PASSWORD: queryPassword, PROOF_RAW_PASSWORD: rawPassword,
    PROOF_CYCLES: String(options.cycles), PROOF_WARMUP: String(options.warmup) };
  let networkAttempted = false;
  let cleaning = false;
  let stage = 'docker-preflight';
  const signalController = new AbortController();
  const docker = (args, extra = {}) => execute('docker', args, { cwd: root, env,
    signal: cleaning ? undefined : signalController.signal, timeout: cleaning ? 15_000 : 120_000, ...extra });
  const required = async (args, extra = {}) => {
    const result = await docker(args, extra);
    if (result.code !== 0) throw new CommandFailure(stage, result.timedOut ? 'TIMEOUT' : result.code);
    return result.stdout.trim();
  };
  const psql = (sql) => required(['exec', `${name}-postgres`, 'psql', '-X', '-U', 'postgres', '-d', database, '-Atqc', sql]);
  const pgActivity = async () => Number(await psql(`SELECT count(*) FROM pg_stat_activity WHERE datname = '${database}'
    AND application_name IN ('sqlite-runtime-proof-query', 'sqlite-runtime-proof-raw')`));
  const state = async () => JSON.parse(await psql(`SELECT json_build_object(
    'orders', (SELECT count(*) FROM orders),
    'fingerprint', (SELECT md5(string_agg(row_to_json(t)::text, '' ORDER BY id)) FROM orders t),
    'agents', (SELECT count(*) FROM agents), 'audit', (SELECT count(*) FROM agent_audit),
    'revocations', (SELECT count(*) FROM revoked_credentials), 'sessions', (SELECT count(*) FROM sessions),
    'context', (SELECT count(*) FROM agent_context))`));
  const workerArgs = (container, action, detached = false) => [
    'run', ...(detached ? ['--detach'] : []), '--name', container, '--network', name,
    '--memory=512m', '--cpus=1', '--pids-limit=128', '--ulimit', 'nofile=1024:1024',
    ...['PROOF_DATABASE_URL', 'PROOF_RAW_DATABASE_URL', 'PROOF_MASTER_KEY', 'PROOF_CYCLES', 'PROOF_WARMUP',
      ...(action === 'restart' ? ['PROOF_PREVIOUS_AGENTS'] : [])].flatMap((key) => ['--env', key]),
    image, 'node', worker, action,
  ];
  const interrupted = () => signalController.abort();
  const wait = (operation, accept, extra = {}) => poll(operation, accept, { signal: signalController.signal, ...extra });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, interrupted);
  try {
    await required(['version', '--format', '{{.Server.Version}}']);
    const revision = await execute('git', ['rev-parse', 'HEAD'], { cwd: root });
    const dirty = await execute('git', ['status', '--porcelain'], { cwd: root });
    report.environment = { sourceRevision: revision.stdout.trim(), workingTree: dirty.stdout ? 'dirty' : 'clean',
      hostNode: process.version, cycles: options.cycles, warmup: options.warmup,
      runtimeLimits: { memoryBytes: 536870912, cpus: 1, pids: 128, fileDescriptors: 1024 },
      build: options.image ? 'explicitly selected existing image; caller must rebuild after source changes' : 'canonical Playground Dockerfile',
      lockSha256: createHash('sha256').update(await readFile(join(playground, 'package-lock.json'))).digest('hex') };
    const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
    const contract = { cycles: options.cycles, warmup: options.warmup, sdkVersion: manifest.version,
      sqliteVersion: manifest.peerDependencies['better-sqlite3'], lockSha256: report.environment.lockSha256 };
    stage = 'image-build';
    if (!options.image) {
      console.log('Building the actual Playground image...');
      await required(['build', '--file', 'demo/playground/Dockerfile', '--tag', image, '.'], { inherit: true, timeout: 900_000 });
    }
    const [built] = JSON.parse(await required(['image', 'inspect', image]));
    report.environment.image = { reference: image, id: built.Id, repoDigests: built.RepoDigests,
      architecture: built.Architecture, os: built.Os, user: built.Config.User };
    stage = 'isolated-postgres';
    networkAttempted = true;
    await required(['network', 'create', '--internal', name]);
    containers.add(`${name}-postgres`);
    await required(['run', '--detach', '--name', `${name}-postgres`, '--network', name, '--network-alias', 'postgres',
      '--env', 'POSTGRES_PASSWORD', '--env', `POSTGRES_DB=${database}`, '--memory=512m', '--cpus=1', '--pids-limit=256', pgImage]);
    await wait(() => docker(['exec', `${name}-postgres`, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', database]),
      (result) => result.code === 0, { timeout: 60_000 });
    const [pg] = JSON.parse(await required(['image', 'inspect', pgImage]));
    report.environment.postgres = { image: pgImage, id: pg.Id, repoDigests: pg.RepoDigests,
      version: await psql('SHOW server_version') };
    stage = 'fixture';
    const fixtureContainer = `${name}-fixture`;
    containers.add(fixtureContainer);
    const fixture = await docker(['run', '--name', fixtureContainer, '--network', name,
      ...['PROOF_ADMIN_DATABASE_URL', 'PROOF_MASTER_KEY', 'PROOF_QUERY_PASSWORD', 'PROOF_RAW_PASSWORD'].flatMap((key) => ['--env', key]),
      image, 'node', 'scripts/sqlite-runtime-proof/fixture.mjs']);
    report.phases.fixture = parseRecords(fixture.stdout).find((record) => record.type === 'fixture') ?? { status: 'FAIL' };
    if (fixture.code !== 0 || report.phases.fixture.status !== 'PASS') throw new CommandFailure(stage, fixture.code);
    const before = await state();
    stage = 'run';
    console.log(`Running real SDK checks and ${options.cycles} measured cycles (${options.warmup} warmup)...`);
    const runContainer = `${name}-run`;
    containers.add(runContainer);
    const run = await docker(workerArgs(runContainer, 'run'), { timeout: 600_000 });
    report.phases.run = requireResult(run.stdout, run.code, { ...contract, action: 'run' });
    if (report.phases.run.status !== 'PASS') throw new CommandFailure(stage, run.code);
    stage = 'hold';
    const holdContainer = `${name}-hold`;
    containers.add(holdContainer);
    await required(workerArgs(holdContainer, 'hold', true));
    const ready = await wait(async () => {
      const result = await docker(['logs', holdContainer]);
      return parseRecords(result.stdout).find((record) => record.type === 'ready' || record.type === 'result');
    }, (record) => !!record, { timeout: 60_000 });
    if (!readyMatches(ready.value, contract)) throw new CommandFailure('hold-evidence-contract');
    stage = 'kill';
    const connectionsBefore = await pgActivity();
    if (connectionsBefore < 2) throw new CommandFailure('kill-missing-live-connections');
    await required(['kill', '--signal', 'KILL', holdContainer]);
    const exit = await wait(async () => JSON.parse(await required(['inspect', '--format', '{{json .State}}', holdContainer])),
      (value) => value.Running === false);
    if (exit.value.ExitCode !== 137 || exit.value.OOMKilled) throw new CommandFailure('unexpected-worker-exit');
    const disconnected = await wait(pgActivity, (count) => count === 0);
    report.phases.kill = { status: 'PASS', signal: 'SIGKILL', exitCode: exit.value.ExitCode, oomKilled: false,
      connectionsBefore, connectionsAfter: disconnected.value, disconnectMs: disconnected.elapsedMs, ready: ready.value };
    stage = 'restart';
    console.log('Worker death observed; verifying empty SQLite state after restart...');
    env.PROOF_PREVIOUS_AGENTS = JSON.stringify(ready.value.agents);
    const restartContainer = `${name}-restart`;
    containers.add(restartContainer);
    const restart = await docker(workerArgs(restartContainer, 'restart'));
    report.phases.restart = requireResult(restart.stdout, restart.code, { ...contract, action: 'restart' });
    if (report.phases.restart.status !== 'PASS') throw new CommandFailure(stage, restart.code);
    stage = 'postgres-state';
    const after = await state();
    const unchanged = JSON.stringify(before) === JSON.stringify(after)
      && ['agents', 'audit', 'revocations', 'sessions', 'context'].every((key) => after[key] === 0);
    report.phases.postgres = { status: unchanged ? 'PASS' : 'FAIL', before, after };
    if (!unchanged) throw new CommandFailure(stage);
    if (signalController.signal.aborted) throw new CommandFailure('interrupted');
  } catch (error) {
    report.failure = { stage: error.stage ?? stage, code: error instanceof CommandFailure ? error.code : 'REDACTED' };
    report.phases[stage] ??= { status: 'FAIL' };
  } finally {
    cleaning = true;
    let cleaned = true;
    for (const container of [...containers].reverse()) {
      const removed = await docker(['container', 'rm', '--force', '--volumes', container]);
      if (removed.code !== 0) {
        const exists = await docker(['container', 'ls', '--all', '--filter', `name=${container}`, '--format', '{{.Names}}']);
        if (exists.code !== 0 || exists.stdout.trim().split('\n').includes(container)) cleaned = false;
      }
    }
    if (networkAttempted && (await docker(['network', 'rm', name])).code !== 0) {
      const exists = await docker(['network', 'ls', '--filter', `name=${name}`, '--format', '{{.Name}}']);
      if (exists.code !== 0 || exists.stdout.trim().split('\n').includes(name)) cleaned = false;
    }
    report.phases.cleanup = { status: cleaned ? 'PASS' : 'FAIL', containers: containers.size, network: networkAttempted };
    for (const key of Object.keys(env)) if (key.startsWith('PROOF_') || key === 'POSTGRES_PASSWORD') delete env[key];
    if (signalController.signal.aborted) report.failure = { stage: 'interrupted', code: 'CANCELLED' };
    finalizeReport(report);
    await writeReport(output, report);
    if (signalController.signal.aborted && !report.failure) {
      report.failure = { stage: 'interrupted', code: 'CANCELLED' };
      finalizeReport(report);
      await writeReport(output, report);
    }
    for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, interrupted);
  }
  console.log(`SQLite runtime proof: ${report.status}. Report: ${join(output, 'report.md')}`);
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const report = await runProof(parseOptions(process.argv.slice(2)));
    if (report.status !== 'PASS') process.exitCode = 1;
  } catch {
    console.error('SQLite runtime proof could not start or write its report. Check arguments, Docker and output permissions.');
    process.exitCode = 1;
  }
}
