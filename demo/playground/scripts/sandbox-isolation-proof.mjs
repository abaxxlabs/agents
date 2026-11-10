#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execute, poll } from './sqlite-runtime-proof/commands.mjs';

const playground = fileURLToPath(new URL('..', import.meta.url));
const root = fileURLToPath(new URL('../../..', import.meta.url));
const proofDirectory = join(playground, 'scripts/sandbox-isolation-proof');
const containerDirectory = '/app/demo/playground/scripts/sandbox-isolation-proof';
const prefix = 'SANDBOX_ISOLATION_PROOF ';

export function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const [flag, value] = args.slice(index, index + 2);
    if (!['--image', '--output'].includes(flag) || !value || options[flag.slice(2)]) throw new Error('Invalid arguments');
    options[flag.slice(2)] = flag === '--output' ? resolve(value) : value;
  }
  if (options.image !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$/.test(options.image)) {
    throw new Error('--image must select a canonical Playground image containing the SQLite runtime proof');
  }
  return options;
}

function command(args, options) {
  return execute('docker', args, { cwd: root, ...options });
}

function record(stdout) {
  const matches = stdout.split('\n').filter((line) => line.startsWith(prefix));
  assert.equal(matches.length, 1, 'Exactly one proof result is required');
  return JSON.parse(matches[0].slice(prefix.length));
}

function markdown(report) {
  const rows = report.worker?.checks ?? [];
  return `# Sandbox isolation evidence\n\n**${report.status}**\n\n` +
    `Image: \`${report.environment?.image?.id ?? 'unavailable'}\`\n\n` +
    `The image supplies the native SQLite runtime proof. This runner mounts its own hashed SQL isolation modules read-only; it does not alter public serving or imply lifecycle, fencing or capacity acceptance.\n\n` +
    `## Checks\n\n| Check | Result |\n|---|---|\n` + rows.map((row) => `| ${row.name} | ${row.status} |`).join('\n') +
    `\n\n## Transaction and privilege contract\n\n` +
    `Visitor SQL uses non-owner, non-BYPASSRLS role-specific pools. Context is signed by a separate control role and bound to sandbox, backend PID, transaction ID and login role. Every checkout begins a transaction, installs transaction-local context/timeouts and commits or rolls back before release. Failed rollback discards the connection. SQL policy rejection, SDK credential rejection and PostgreSQL grants/RLS are distinct evidence layers.\n\n` +
    `Reset is a control-only sandbox-scoped DELETE/reseed. Raw bytes read through the same sandbox-bound raw executor. The control role is trusted and never exposed to visitor SQL. Ordinary PostgreSQL system metadata is not claimed hidden. Lease/generation fencing and concurrent reset/cleanup exclusion must compose inside these transactions; they are not implemented here.\n\n` +
    `Full SQL matrix, physical connection events, source hashes, cleanup and any failure are in report.json. Cleanup: ${report.cleanup?.status ?? 'FAIL'}.\n`;
}

export async function runProof(options) {
  const suffix = `${process.pid}-${randomBytes(4).toString('hex')}`;
  const name = `agents-sandbox-proof-${suffix}`;
  const imageReference = options.image ?? `agents-playground-sandbox-proof:${suffix}`;
  const output = options.output ?? join(playground, 'test-results/sandbox-isolation-proof', suffix);
  const report = { protocol: 1, status: 'FAIL', startedAt: new Date().toISOString(),
    command: ['npm', 'run', 'proof:sandbox-isolation', ...(options.image ? ['--', '--image', options.image] : [])], environment: {} };
  const containers = [];
  let networkAttempted = false;
  let stage = 'source-provenance';
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  const secret = () => randomBytes(32).toString('hex');
  const adminPassword = secret();
  const queryPassword = secret();
  const rawPassword = secret();
  const controlPassword = secret();
  const env = { ...process.env, POSTGRES_PASSWORD: adminPassword,
    ISOLATION_ADMIN_URL: `postgresql://postgres:${adminPassword}@postgres:5432/sandbox_proof`,
    ISOLATION_QUERY_URL: `postgresql://proof_query:${queryPassword}@postgres:5432/sandbox_proof`,
    ISOLATION_RAW_URL: `postgresql://proof_raw:${rawPassword}@postgres:5432/sandbox_proof`,
    ISOLATION_CONTROL_URL: `postgresql://proof_control:${controlPassword}@postgres:5432/sandbox_proof`,
    ISOLATION_QUERY_PASSWORD: queryPassword, ISOLATION_RAW_PASSWORD: rawPassword,
    ISOLATION_CONTROL_PASSWORD: controlPassword, ISOLATION_MASTER_KEY: secret() };
  const docker = (args, extra = {}) => command(args, { env, signal: controller.signal, ...extra });
  const required = async (args, extra = {}) => {
    const result = await docker(args, extra);
    if (result.code !== 0) throw new Error(result.timedOut ? 'COMMAND_TIMEOUT' : 'COMMAND_FAILED');
    return result.stdout.trim();
  };
  const runContainer = async (label, keys, script) => {
    const container = `${name}-${label}`;
    containers.push(container);
    return docker(['run', '--name', container, '--network', name, '--memory=512m', '--cpus=1', '--pids-limit=128',
      '--mount', `type=bind,src=${proofDirectory},dst=${containerDirectory},readonly`,
      ...keys.flatMap((key) => ['--env', key]), report.environment.image.id,
      'node', `${containerDirectory}/${script}`], { timeout: 180_000 });
  };
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, interrupt);
  try {
    const source = await execute('git', ['rev-parse', 'HEAD'], { cwd: root, signal: controller.signal });
    const dirty = await execute('git', ['status', '--porcelain'], { cwd: root, signal: controller.signal });
    if (source.code !== 0 || dirty.code !== 0) throw new Error('COMMAND_FAILED');
    report.environment.sourceRevision = source.stdout.trim();
    report.environment.workingTree = dirty.stdout.trim() ? 'dirty' : 'clean';
    report.environment.hostNode = process.version;
    report.environment.build = options.image ? 'Explicit existing image; image sources may differ from this checkout'
      : 'Canonical Playground Dockerfile built from the current checkout';
    report.environment.lockSha256 = createHash('sha256').update(await readFile(join(playground, 'package-lock.json'))).digest('hex');
    stage = 'image-build';
    if (!options.image) {
      console.log('Building the canonical Playground image...');
      await required(['build', '--file', 'demo/playground/Dockerfile', '--tag', imageReference, '.'],
        { inherit: true, timeout: 900_000 });
    }
    stage = 'image-provenance';
    const [image] = JSON.parse(await required(['image', 'inspect', imageReference]));
    assert.equal(image.Config.User, 'node');
    report.environment.image = { reference: imageReference, id: image.Id, digests: image.RepoDigests,
      architecture: image.Architecture, os: image.Os, user: image.Config.User };
    report.environment.modules = {};
    report.environment.hostRunnerSha256 = createHash('sha256').update(await readFile(fileURLToPath(import.meta.url))).digest('hex');
    report.environment.hostCommandModuleSha256 = createHash('sha256').update(await readFile(new URL('./sqlite-runtime-proof/commands.mjs', import.meta.url))).digest('hex');
    for (const file of (await readdir(proofDirectory)).filter((file) => file.endsWith('.mjs')).sort()) {
      report.environment.modules[file] = createHash('sha256').update(await readFile(join(proofDirectory, file))).digest('hex');
    }
    stage = 'private-postgres';
    networkAttempted = true;
    await required(['network', 'create', '--internal', name]);
    const postgres = `${name}-postgres`;
    containers.push(postgres);
    await required(['run', '--detach', '--name', postgres, '--network', name, '--network-alias', 'postgres',
      '--env', 'POSTGRES_PASSWORD', '--env', 'POSTGRES_DB=sandbox_proof', '--memory=512m', '--cpus=1',
      'postgres:16-bookworm']);
    await poll(() => docker(['exec', postgres, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'sandbox_proof']),
      (result) => result.code === 0, { timeout: 60_000, signal: controller.signal });
    const [databaseImage] = JSON.parse(await required(['image', 'inspect', 'postgres:16-bookworm']));
    report.environment.postgres = { id: databaseImage.Id, digests: databaseImage.RepoDigests,
      version: await required(['exec', postgres, 'psql', '-X', '-U', 'postgres', '-d', 'sandbox_proof', '-Atqc', 'SHOW server_version']) };
    stage = 'fixture';
    const fixture = await runContainer('fixture', ['ISOLATION_ADMIN_URL', 'ISOLATION_MASTER_KEY',
      'ISOLATION_QUERY_PASSWORD', 'ISOLATION_RAW_PASSWORD', 'ISOLATION_CONTROL_PASSWORD'], 'fixture.mjs');
    report.fixture = record(fixture.stdout);
    assert.equal(fixture.code, 0);
    assert.equal(report.fixture.status, 'PASS');
    stage = 'worker';
    const worker = await runContainer('worker', ['ISOLATION_QUERY_URL', 'ISOLATION_RAW_URL',
      'ISOLATION_CONTROL_URL', 'ISOLATION_MASTER_KEY'], 'worker.mjs');
    report.worker = record(worker.stdout);
    assert.equal(worker.code, 0);
    assert.equal(report.worker.protocol, 1);
    assert.equal(report.worker.status, 'PASS');
    assert.ok(report.worker.checks?.length > 0 && report.worker.checks.every((check) => check.status === 'PASS'));
    for (const key of ['privateOperations', 'hostileSql', 'physicalReuse', 'rowPolicies', 'protectedBehavior']) {
      assert.equal(report.worker.evidence?.acceptance?.[key], true);
    }
    assert.ok(report.worker.evidence.matrix.length > 0);
    assert.ok(report.worker.events.length > 0);
    assert.ok(report.worker.cleanup?.length === 5 && report.worker.cleanup.every((item) => item.status === 'PASS'));
    if (controller.signal.aborted) throw new Error('CANCELLED');
    report.status = 'PASS';
  } catch (error) {
    const code = stage === 'private-postgres' && error?.stage === 'deadline-exceeded'
      ? 'POSTGRES_READY_TIMEOUT' : error?.message;
    report.failure = { stage, code: ['COMMAND_TIMEOUT', 'COMMAND_FAILED', 'POSTGRES_READY_TIMEOUT', 'CANCELLED'].includes(code)
      ? code : 'EVIDENCE_FAILED' };
  } finally {
    const cleanup = [];
    for (const container of containers.reverse()) {
      const result = await command(['container', 'rm', '--force', '--volumes', container], { env, timeout: 30_000 }).catch(() => ({ code: 1 }));
      const remaining = await command(['container', 'ls', '--all', '--filter', `name=^/${container}$`, '--format', '{{.Names}}'], { env, timeout: 15_000 }).catch(() => ({ code: 1 }));
      cleanup.push({ resource: container, status: remaining.code === 0 && !remaining.stdout.trim() ? 'PASS' : 'FAIL', removeExit: result.code });
    }
    if (networkAttempted) {
      await command(['network', 'rm', name], { env, timeout: 30_000 }).catch(() => ({ code: 1 }));
      const remaining = await command(['network', 'ls', '--filter', `name=^${name}$`, '--format', '{{.Name}}'], { env, timeout: 15_000 }).catch(() => ({ code: 1 }));
      cleanup.push({ resource: name, status: remaining.code === 0 && !remaining.stdout.trim() ? 'PASS' : 'FAIL' });
    }
    report.cleanup = { status: cleanup.every((item) => item.status === 'PASS') ? 'PASS' : 'FAIL', resources: cleanup };
    if (report.cleanup.status !== 'PASS' || controller.signal.aborted) report.status = 'FAIL';
    if (controller.signal.aborted) report.failure = { stage: 'interrupted', code: 'CANCELLED' };
    for (const key of Object.keys(env)) if (key.startsWith('ISOLATION_') || key === 'POSTGRES_PASSWORD') delete env[key];
    report.finishedAt = new Date().toISOString();
    await mkdir(output, { recursive: true });
    await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
    await writeFile(join(output, 'report.md'), markdown(report));
    for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, interrupt);
  }
  console.log(`Sandbox isolation proof: ${report.status}. Report: ${join(output, 'report.json')}`);
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const report = await runProof(parseOptions(process.argv.slice(2)));
    if (report.status !== 'PASS') process.exitCode = 1;
  } catch {
    console.error('Sandbox isolation proof could not start. Check arguments, Docker and output permissions.');
    process.exitCode = 1;
  }
}
