#!/usr/bin/env node
// Host orchestrator for the two-worker routing/fencing proof.
// It owns the container lifecycle only: build the canonical Playground image,
// bring up a private --internal docker network with a fresh postgres, run the
// fixture (canonical migrations + session catalog), serve two bounded workers
// (the real 887 SDK runtime + fenced executor), and run the scenario driver
// (HTTP + psql faults + a host-mounted docker CLI for the catalog-down fault).
// The driver emits exactly one WORKER_ROUTING_FENCING_PROOF result record; the
// host combines it with the workers' clean-shutdown records into a go/no-go
// report citing the merged 887 and 888 prerequisite reports.
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, readdir } from 'node:fs/promises';
import { realpathSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execute, poll, CommandFailure } from './sqlite-runtime-proof/commands.mjs';
import { parseRecords, requireResult, finalizeReport, writeReport } from './worker-routing-fencing-proof/report.mjs';
import { workerEvidenceFailures } from './worker-routing-fencing-proof/evidence.mjs';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const playground = join(root, 'demo/playground');
const scriptDirectory = fileURLToPath(new URL('./worker-routing-fencing-proof', import.meta.url));
const containerScript = '/app/demo/playground/scripts/worker-routing-fencing-proof';
const database = 'routing_proof';
const dockerSocket = '/var/run/docker.sock';
const dockerSocketReal = realpathSync(dockerSocket);
const dockerSocketUid = statSync(dockerSocketReal).uid;

export function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!['--image', '--output'].includes(flag) || !value) throw new Error('Invalid proof arguments');
    if (flag === '--image' && !/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$/.test(value)) {
      throw new Error('Invalid image reference');
    }
    if (flag === '--output') options.output = resolve(value);
    else options.image = value;
  }
  return options;
}

export async function runProof(options) {
  const suffix = `${process.pid}-${randomBytes(4).toString('hex')}`;
  const name = `agents-wrfp-${suffix}`;
  const image = options.image ?? `agents-playground-wrfp:${suffix}`;
  const pgImage = 'postgres:16-bookworm';
  const output = options.output ?? join(playground, 'test-results/worker-routing-fencing-proof', suffix);
  const containers = new Set();
  const secret = () => randomBytes(32).toString('hex');
  const adminPassword = secret();
  const queryPassword = secret();
  const rawPassword = secret();
  const controlPassword = secret();
  const env = { ...process.env, POSTGRES_PASSWORD: adminPassword,
    ROUTING_ADMIN_URL: `postgresql://postgres:${adminPassword}@postgres:5432/${database}`,
    ROUTING_QUERY_URL: `postgresql://proof_query:${queryPassword}@postgres:5432/${database}`,
    ROUTING_RAW_URL: `postgresql://proof_raw:${rawPassword}@postgres:5432/${database}`,
    ROUTING_CONTROL_URL: `postgresql://proof_control:${controlPassword}@postgres:5432/${database}`,
    ROUTING_QUERY_PASSWORD: queryPassword, ROUTING_RAW_PASSWORD: rawPassword,
    ROUTING_CONTROL_PASSWORD: controlPassword,
    ROUTING_MASTER_KEY: secret(), ROUTING_SECRET_A: secret(), ROUTING_SECRET_B: secret(),
    ROUTING_CONTROL_SECRET: secret(), ROUTING_LEASE_MS: '30000',
    ROUTING_DRAIN_GRACE_MS: '20000', ROUTING_PG_CONTAINER: `${name}-postgres`,
    ROUTING_ALLOWED_ORIGINS: 'https://playground.example,http://localhost:3100',
    WORKER_PORT: '8080' };
  const report = { protocol: 1, status: 'FAIL', startedAt: new Date().toISOString(), phases: {},
    environment: {},
    command: `npm run proof:worker-routing-fencing${options.image ? ` -- --image ${options.image}` : ''}` };
  let networkAttempted = false;
  let stage = 'docker-preflight';
  const controller = new AbortController();
  const docker = (args, extra = {}) => execute('docker', args, { cwd: root, env,
    signal: controller.signal, timeout: 120_000, ...extra });
  const required = async (args, extra = {}) => {
    const result = await docker(args, extra);
    if (result.code !== 0) throw new CommandFailure(stage, result.timedOut ? 'TIMEOUT' : result.code);
    return result.stdout.trim();
  };
  const workerEnvKeys = ['ROUTING_ADMIN_URL', 'ROUTING_QUERY_URL', 'ROUTING_RAW_URL', 'ROUTING_CONTROL_URL',
    'ROUTING_MASTER_KEY', 'ROUTING_SECRET_A', 'ROUTING_SECRET_B', 'ROUTING_CONTROL_SECRET',
    'ROUTING_LEASE_MS', 'ROUTING_DRAIN_GRACE_MS', 'ROUTING_ALLOWED_ORIGINS', 'WORKER_PORT'];
  const driverEnvKeys = [...workerEnvKeys, 'ROUTING_PG_CONTAINER'];

  const workerArgs = (workerId) => [
    'run', '--detach', '--name', `${name}-${workerId}`, '--network', name, '--network-alias', workerId,
    '--memory=512m', '--cpus=1', '--pids-limit=128',
    ...workerEnvKeys.flatMap((key) => ['--env', key]),
    '--env', `WORKER_ID=${workerId}`,
    image, 'node', `${containerScript}/worker.mjs`,
  ];

  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  try {
    await required(['version', '--format', '{{.Server.Version}}']);
    const revision = await execute('git', ['rev-parse', 'HEAD'], { cwd: root });
    const dirty = await execute('git', ['status', '--porcelain'], { cwd: root });
    const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
    report.environment = {
      sourceRevision: revision.stdout.trim(), workingTree: dirty.stdout ? 'dirty' : 'clean',
      hostNode: process.version, docker: await required(['version', '--format', '{{.Server.Version}}']),
      sdkVersion: manifest.version,
      build: options.image ? 'explicitly selected existing image' : 'canonical Playground Dockerfile',
      lockSha256: createHash('sha256').update(await readFile(join(playground, 'package-lock.json'))).digest('hex'),
    };
    stage = 'image-build';
    if (!options.image) {
      console.log('Building the canonical Playground image...');
      await required(['build', '--file', 'demo/playground/Dockerfile', '--tag', image, '.'], { inherit: true, timeout: 900_000 });
    }
    stage = 'image-provenance';
    const [built] = JSON.parse(await required(['image', 'inspect', image]));
    report.environment.image = { reference: image, id: built.Id, repoDigests: built.RepoDigests,
      architecture: built.Architecture, os: built.Os, user: built.Config.User };
    report.environment.modules = {};
    for (const file of (await readdir(scriptDirectory)).filter((file) => file.endsWith('.mjs') || file.endsWith('.sql')).sort()) {
      report.environment.modules[file] = createHash('sha256').update(await readFile(join(scriptDirectory, file))).digest('hex');
    }
    // W4: the image must carry exactly the modules and prerequisite reports
    // the host just hashed. A stale image would otherwise prove the old code
    // while the report cites the new one.
    const prerequisiteReports = ['reports/sqlite-runtime-proof.md', 'reports/sandbox-isolation-proof.json'];
    report.environment.prerequisiteReports = {};
    for (const file of prerequisiteReports) {
      report.environment.prerequisiteReports[file] = createHash('sha256').update(await readFile(join(playground, file))).digest('hex');
    }
    const imageFiles = [
      ...Object.keys(report.environment.modules).map((file) => `${containerScript}/${file}`),
      ...prerequisiteReports.map((file) => join('/app/demo/playground', file)),
    ];
    const imageHashes = {};
    for (const line of (await required(['run', '--rm', '--entrypoint', 'sha256sum', image, ...imageFiles])).split('\n')) {
      const [hash, rawPath] = line.trim().split(/\s+/);
      if (hash && rawPath) imageHashes[rawPath] = hash;
    }
    const mismatches = [];
    for (const [file, hash] of Object.entries(report.environment.modules)) {
      if (imageHashes[`${containerScript}/${file}`] !== hash) mismatches.push(file);
    }
    for (const file of prerequisiteReports) {
      if (imageHashes[join('/app/demo/playground', file)] !== report.environment.prerequisiteReports[file]) mismatches.push(file);
    }
    if (mismatches.length) throw new CommandFailure('image-provenance', `image-module-mismatch:${mismatches.join(',')}`);

    stage = 'private-postgres';
    networkAttempted = true;
    await required(['network', 'create', '--internal', name]);
    containers.add(`${name}-postgres`);
    await required(['run', '--detach', '--name', `${name}-postgres`, '--network', name, '--network-alias', 'postgres',
      '--env', 'POSTGRES_PASSWORD', '--env', `POSTGRES_DB=${database}`, '--memory=512m', '--cpus=1', pgImage]);
    await poll(() => docker(['exec', `${name}-postgres`, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', database]),
      (result) => result.code === 0, { timeout: 60_000, signal: controller.signal });
    const [pg] = JSON.parse(await required(['image', 'inspect', pgImage]));
    report.environment.postgres = { image: pgImage, id: pg.Id, repoDigests: pg.RepoDigests,
      version: await required(['exec', `${name}-postgres`, 'psql', '-X', '-U', 'postgres', '-d', database, '-Atqc', 'SHOW server_version']) };

    stage = 'fixture';
    containers.add(`${name}-fixture`);
    const fixture = await docker(['run', '--name', `${name}-fixture`, '--network', name,
      ...['ROUTING_ADMIN_URL', 'ROUTING_MASTER_KEY', 'ROUTING_QUERY_PASSWORD', 'ROUTING_RAW_PASSWORD',
        'ROUTING_CONTROL_PASSWORD'].flatMap((key) => ['--env', key]),
      image, 'node', `${containerScript}/fixture.mjs`], { timeout: 300_000 });
    report.phases.fixture = parseRecords(fixture.stdout).find((record) => record.type === 'fixture') ?? { status: 'FAIL' };
    if (fixture.code !== 0 || report.phases.fixture.status !== 'PASS') throw new CommandFailure(stage, fixture.code);

    stage = 'workers';
    containers.add(`${name}-worker-a`);
    containers.add(`${name}-worker-b`);
    await required(workerArgs('worker-a'), { timeout: 60_000 });
    await required(workerArgs('worker-b'), { timeout: 60_000 });

    stage = 'driver';
    containers.add(`${name}-driver`);
    const driver = await docker([
      'run', '--name', `${name}-driver`, '--network', name, '--memory=512m', '--cpus=1', '--pids-limit=128',
      '--user', `${dockerSocketUid}`,
      ...driverEnvKeys.flatMap((key) => ['--env', key]),
      '--mount', `type=bind,src=${dockerSocketReal},dst=${dockerSocket}`,
      image, 'node', `${containerScript}/scenarios.mjs`,
    ], { timeout: 600_000 });
    report.driver = requireResult(driver.stdout, driver.code);
    report.phases.driver = { status: report.driver.status, checks: report.driver.checks,
      acceptance: report.driver.acceptance, workloadAuth: report.driver.workloadAuth,
      combinedGate: report.driver.acceptance?.combinedGate, driver: report.driver };
    if (report.driver.status !== 'PASS') throw new CommandFailure(stage, driver.code);

    if (controller.signal.aborted) throw new CommandFailure('interrupted');
    report.status = 'PASS';
  } catch (error) {
    report.failure = { stage: error.stage ?? stage, code: error instanceof CommandFailure ? error.code : 'EVIDENCE_FAILED',
      message: error?.message };
    report.phases[stage] ??= { status: 'FAIL' };
    if (stage === 'driver') {
      const base = report.driver
        ? { status: report.driver.status, checks: report.driver.checks, acceptance: report.driver.acceptance,
            workloadAuth: report.driver.workloadAuth, combinedGate: report.driver.acceptance?.combinedGate, driver: report.driver }
        : {};
      const driverLogs = await docker(['logs', `${name}-driver`], { timeout: 30_000 }).catch(() => ({ stdout: '', stderr: '' }));
      report.phases.driver = { ...base, status: 'FAIL', logs: driverLogs.stdout, stderr: driverLogs.stderr };
    }
  } finally {
    // Graceful worker shutdown: SIGTERM triggers each worker's cleanup and a
    // result record (provenance + runtime/pool disposal). The host applies the
    // fail-closed worker-evidence contract to each result: a worker that
    // self-reports PASS but with wrong provenance, empty checks, or a dirty
    // cleanup is flipped to FAIL.
    for (const workerId of ['worker-a', 'worker-b']) {
      const container = `${name}-${workerId}`;
      if (!containers.has(container)) continue;
      await docker(['stop', '--timeout', '15', container], { timeout: 30_000 }).catch(() => ({ code: 1 }));
      const logs = await docker(['logs', container], { timeout: 30_000 }).catch(() => ({ stdout: '', code: 1 }));
      const result = parseRecords(logs.stdout).find((record) => record.type === 'result');
      const tail = (s) => (s ?? '').split('\n').slice(-25).join('\n');
      const evidenceFailures = workerEvidenceFailures(result);
      if (evidenceFailures.length) report.status = 'FAIL';
      report.phases[workerId] = {
        status: evidenceFailures.length ? 'FAIL' : (result?.status ?? 'FAIL'),
        cleanup: result?.cleanup?.status ?? 'FAIL',
        poolErrors: result?.poolError ?? null,
        evidenceFailures,
        runtimeProvenance: result?.runtime ? { node: result.runtime.node, platform: result.runtime.platform,
          architecture: result.runtime.architecture, uid: result.runtime.uid,
          sqliteDriver: result.runtime.sqliteDriver } : null,
        logs: tail(logs.stdout),
      };
    }
    // Tear down, recording every failure: a container the proof could not
    // remove, or a network it could not delete, is a dirty environment and
    // fails the cleanup phase (W5).
    const teardownFailures = [];
    for (const container of [...containers].reverse()) {
      const removed = await docker(['container', 'rm', '--force', '--volumes', container], { timeout: 30_000 }).catch(() => ({ code: 1 }));
      if (removed.code === 0) continue;
      const exists = await docker(['container', 'ls', '--all', '--filter', `name=^/${container}$`, '--format', '{{.Names}}'], { timeout: 15_000 }).catch(() => ({ code: 1 }));
      if (exists.code === 0 && exists.stdout.trim()) teardownFailures.push({ resource: container, reason: 'still-exists' });
    }
    if (networkAttempted) {
      const networkRemoved = await docker(['network', 'rm', name], { timeout: 30_000 }).catch(() => ({ code: 1 }));
      if (networkRemoved.code !== 0) teardownFailures.push({ resource: `network:${name}`, reason: 'network-rm-failed' });
    }
    const workerPhases = ['worker-a', 'worker-b'].every((w) => report.phases[w]?.cleanup === 'PASS');
    report.phases.cleanup = { status: (workerPhases && teardownFailures.length === 0) ? 'PASS' : 'FAIL',
      workers: workerPhases, teardownFailures };
    for (const key of Object.keys(env)) if (key.startsWith('ROUTING_') || key === 'POSTGRES_PASSWORD') delete env[key];
    finalizeReport(report);
    await mkdir(output, { recursive: true });
    await writeReport(output, report);
    if (controller.signal.aborted && !report.failure) report.failure = { stage: 'interrupted', code: 'CANCELLED' };
    for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, () => controller.abort());
  }
  console.log(`Worker routing/fencing proof: ${report.status}. Report: ${join(output, 'report.json')}`);
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const report = await runProof(parseOptions(process.argv.slice(2)));
    if (report.status !== 'PASS') process.exitCode = 1;
  } catch {
    console.error('Worker routing/fencing proof could not start. Check arguments, Docker and output permissions.');
    process.exitCode = 1;
  }
}
