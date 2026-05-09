#!/usr/bin/env node
// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Release gate: runs install, typecheck, lint, tests, build, pack, and
 * publish dry-run in sequence. Validates npm cache ownership first.
 */

import { spawn } from 'node:child_process';
import { mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  formatNpmCacheFailure,
  resolveNpmCachePath,
  validateNpmCache,
} from './check-npm-cache.mjs';

export const LINT_MAX_WARNINGS = '387';
export const RELEASE_GATE_COMMAND_STEPS = [
  {
    label: 'Install dependencies from bun.lock',
    command: 'bun',
    args: ['install', '--frozen-lockfile'],
  },
  { label: 'Type-check source', command: 'npm', args: ['run', 'typecheck'] },
  { label: 'Check public API snapshot', command: 'npm', args: ['run', 'check:public-api'] },
  {
    label: 'Lint source',
    command: 'npm',
    args: ['run', 'lint', '--', `--max-warnings=${LINT_MAX_WARNINGS}`],
  },
  { label: 'Run tests', command: 'npm', args: ['test'] },
  { label: 'Clean dist', command: 'npm', args: ['run', 'clean'] },
  { label: 'Build package', command: 'npm', args: ['run', 'build'] },
  {
    label: 'Assert package metadata artifacts',
    command: 'npm',
    args: ['run', 'assert:package-artifacts'],
  },
  {
    label: 'Audit package artifact guardrails',
    command: 'npm',
    args: ['run', 'audit:package-files'],
  },
  {
    label: 'Verify npm pack dry-run',
    command: 'npm',
    args: ['pack', '--dry-run', '--ignore-scripts'],
  },
  {
    label: 'Verify npm publish dry-run',
    command: 'npm',
    args: ['publish', '--dry-run', '--ignore-scripts'],
  },
];

class CommandFailure extends Error {
  constructor(command, args, code) {
    super(`${command} ${args.join(' ')} exited with status ${code}`);
    this.name = 'CommandFailure';
  }
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? process.cwd(),
      env: { ...process.env, ...options.env },
      stdio: 'inherit',
    });

    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new CommandFailure(command, args, code));
    });
  });
}

function runCommandCapture(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? process.cwd(),
      env: { ...process.env, ...options.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new CommandFailure(command, args, code));
      }
    });
  });
}

async function runStep(label, fn) {
  console.log(`\n==> ${label}`);
  return await fn();
}

export function formatDirtyTreeFailure(statusOutput) {
  const dirtyLines = statusOutput
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(0, 50);

  return [
    'ERROR: release gate requires a clean working tree before it installs, builds, or packs.',
    'Commit, stash, or remove these changes, then rerun `npm run release:gate`:',
    ...dirtyLines.map((line) => `  ${line}`),
  ].join('\n');
}

async function assertCleanWorkingTree() {
  const { stdout } = await runCommandCapture('git', ['status', '--porcelain=v1']);
  if (stdout.trim().length === 0) {
    console.log('Working tree clean.');
    return;
  }

  console.error(formatDirtyTreeFailure(stdout));
  throw new Error('working tree is dirty');
}

async function assertBunLockfile() {
  const lockfile = path.resolve(process.cwd(), 'bun.lock');
  try {
    const lockStats = await stat(lockfile);
    if (!lockStats.isFile()) throw new Error('not a file');
  } catch {
    throw new Error(
      `Expected root bun.lock at ${lockfile}; release verification uses \`bun install --frozen-lockfile\`, not \`npm ci\`.`,
    );
  }

  console.log(`Using Bun frozen lockfile: ${lockfile}`);
}

async function checkNpmCache() {
  const cachePath = await resolveNpmCachePath();
  const result = await validateNpmCache(cachePath);
  if (!result.ok) {
    console.error(formatNpmCacheFailure(result));
    throw new Error('npm cache validation failed');
  }
  console.log(`npm cache OK: ${result.cachePath}`);
}

async function smokeInstallTarball() {
  const packDir = await mkdtemp(path.join(os.tmpdir(), 'agents-release-pack-'));
  const consumerDir = await mkdtemp(path.join(os.tmpdir(), 'agents-release-consumer-'));
  const keepSmokeDirs = process.env.AGENTS_RELEASE_KEEP_SMOKE === '1';
  const smokeScript = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'smoke-installed-package.mjs');
  let tarball;

  try {
    await runCommand('npm', ['pack', '--ignore-scripts', '--pack-destination', packDir]);

    const tarballs = (await readdir(packDir)).filter((entry) => entry.endsWith('.tgz'));
    if (tarballs.length !== 1) {
      throw new Error(`Expected exactly one packed tarball in ${packDir}, found ${tarballs.length}.`);
    }
    tarball = path.join(packDir, tarballs[0]);

    await runCommand('npm', ['init', '-y', '--silent'], { cwd: consumerDir });
    await runCommand(
      'npm',
      [
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--package-lock=false',
        tarball,
        'pg@8.20.0',
        'libpg-query@17.7.3',
      ],
      { cwd: consumerDir },
    );

    await runCommand('node', [smokeScript, '@abaxxlabs/agents'], { cwd: consumerDir });
    return tarball;
  } finally {
    if (!keepSmokeDirs) {
      await rm(consumerDir, { recursive: true, force: true });
      if (!tarball) {
        await rm(packDir, { recursive: true, force: true });
      }
    } else {
      console.log(`Kept smoke directories: ${packDir} ${consumerDir}`);
    }
  }
}

async function smokeInstallMcpWithoutManualPeers(tarball) {
  const consumerDir = await mkdtemp(path.join(os.tmpdir(), 'agents-release-consumer-no-peers-'));
  const keepSmokeDirs = process.env.AGENTS_RELEASE_KEEP_SMOKE === '1';
  const smokeScript = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'smoke-installed-package.mjs');

  try {
    await runCommand('npm', ['init', '-y', '--silent'], { cwd: consumerDir });
    await runCommand(
      'npm',
      [
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--package-lock=false',
        tarball,
      ],
      { cwd: consumerDir },
    );
    await runCommand(
      'node',
      [
        smokeScript,
        '@abaxxlabs/agents',
        '--only',
        '@abaxxlabs/agents/mcp',
        '--skip-bin',
      ],
      { cwd: consumerDir },
    );

    console.log('MCP subpath smoke test passed without manually installed peer dependencies');

    await assertVendoredIdSdkMcpServerLoads(consumerDir);
  } finally {
    if (!keepSmokeDirs) {
      await rm(consumerDir, { recursive: true, force: true });
    } else {
      console.log(`Kept no-peer smoke directory: ${consumerDir}`);
    }
  }
}

/**
 * Spawns the vendored id-sdk-mcp server from the smoke consumer's node_modules
 * and confirms it stays alive long enough to bind stdio.
 *
 * Catches regressions where a future vendor sync drops a transitive dependency
 * from the root package.json: in that case `node server.mjs` exits within
 * milliseconds with `ERR_MODULE_NOT_FOUND` and we surface the captured stderr.
 * If the server is still running after the grace window it has cleared its
 * imports — we kill it and pass. The optional deps `level` and
 * `@mattrglobal/bbs-signatures` are still required here because npm installs
 * them by default; only platforms where their native build fails skip them.
 */
async function assertVendoredIdSdkMcpServerLoads(consumerDir) {
  const resolveScript = `
    import { resolveVendoredIdSdkMcpServerPath } from '@abaxxlabs/agents/id-sdk-mcp';
    process.stdout.write(resolveVendoredIdSdkMcpServerPath());
  `;
  const { stdout: serverPath } = await runCommandCapture(
    process.execPath,
    ['--input-type=module', '--eval', resolveScript],
    { cwd: consumerDir },
  );

  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [serverPath.trim()], {
      cwd: consumerDir,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    const graceMs = 4000;
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolvePromise();
    }, graceMs);

    child.on('error', (err) => {
      clearTimeout(timer);
      rejectPromise(err);
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (signal === 'SIGKILL') {
        resolvePromise();
        return;
      }
      rejectPromise(
        new Error(
          `id-sdk-mcp server exited early (code=${code}, signal=${signal}). ` +
            'Likely cause: a transitive dependency listed in vendor/id-sdk-mcp/server.mjs ' +
            'is no longer declared on the root package.json. ' +
            `Captured stderr:\n${stderr.trim() || '(none)'}`,
        ),
      );
    });
  });

  console.log('Vendored id-sdk-mcp server starts cleanly with no manually installed deps');
}

export async function runReleaseGate() {
  await runStep('Verify clean working tree', assertCleanWorkingTree);
  await runStep('Verify Bun lockfile contract', assertBunLockfile);
  await runStep('Validate npm cache ownership', checkNpmCache);
  for (const step of RELEASE_GATE_COMMAND_STEPS) {
    await runStep(step.label, () => runCommand(step.command, step.args));
  }
  const tarball = await runStep('Smoke install packed tarball', smokeInstallTarball);
  await runStep('Smoke import MCP without manual peers', () => smokeInstallMcpWithoutManualPeers(tarball));
  console.log(`\nRelease gate passed. Generated tarball: ${tarball}`);
  return { tarball };
}

const isMain = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;

if (isMain) {
  runReleaseGate().catch((error) => {
    if (error.message !== 'npm cache validation failed') {
      console.error(error.message);
    }
    process.exitCode = 1;
  });
}
