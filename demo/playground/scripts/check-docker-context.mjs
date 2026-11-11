#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const dockerfile = 'demo/playground/Dockerfile';
const included = [
  'control.txt',
  'package.json',
  'bun.lock',
  'tsconfig.json',
  'tsconfig.cjs.json',
  'src/index.ts',
  'src/nested/source.ts',
  'scripts/gen-cjs-shim.mjs',
  'migrations/001_context.sql',
  'vendor/fixture/sdk/index.mjs',
  'vendor/fixture/LICENSE',
  'demo/playground/package.json',
  'demo/playground/package-lock.json',
  'demo/playground/src/server.mjs',
  'demo/playground/scripts/setup-db.mjs',
  'demo/playground/styles/tailwind.css',
  'demo/playground/public/index.html',
  'demo/playground/public/app.js',
];
const excluded = ['', 'demo/playground/', 'demo/playground/nested/'].flatMap((prefix) => [
  '.env',
  '.env.local',
  '.env.production',
  'node_modules/context-probe.txt',
  '.git/context-probe.txt',
  '.claude/context-probe.txt',
  '.Codex/context-probe.txt',
  '.codex/context-probe.txt',
  '.gstack/context-probe.txt',
  '.scratch/context-probe.txt',
  '.cache/context-probe.txt',
  '.DS_Store',
  'dist/context-probe.txt',
  'coverage/context-probe.txt',
  'data/context-probe.txt',
  'logs/context-probe.txt',
  'archive/context-probe.txt',
  'archives/context-probe.txt',
  'playwright-report/context-probe.txt',
  'test-results/context-probe.txt',
  'context-probe.log',
  'context-probe.tgz',
  'context-probe.zip',
  'context-probe.tar',
  'context-probe.tar.gz',
  'context-probe.bak',
  'context-probe.tmp',
].map((file) => `${prefix}${file}`));
excluded.push('demo/playground/public/styles.css', 'nested-worktree/.git', 'demo/other-demo/context-probe.txt');
const marker = 'docker-context-fixture\n';

function docker(args, cwd, failure) {
  const result = spawnSync('docker', args, {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = result.error?.message || result.stderr?.trim() || result.stdout?.trim();
    throw new Error(`${failure}${detail ? `\n${detail}` : ''}`);
  }
}

async function checkContext() {
  const rules = await readFile(new URL('../Dockerfile.dockerignore', import.meta.url), 'utf8');
  docker(['version', '--format', '{{.Server.Version}}'], undefined,
    'Docker Engine is unavailable. Start Docker and rerun npm run test:docker-context.');
  docker(['buildx', 'version'], undefined,
    'Docker Buildx is required. Install it and rerun npm run test:docker-context.');

  const temporary = await mkdtemp(join(tmpdir(), 'playground-docker-context-'));
  try {
    const fixture = join(temporary, 'fixture');
    const output = join(temporary, 'output');
    for (const file of [...included, ...excluded]) {
      const path = join(fixture, file);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, marker);
    }
    await writeFile(join(fixture, dockerfile), 'FROM scratch\nCOPY . /context\n');
    await writeFile(join(fixture, `${dockerfile}.dockerignore`), rules);
    await writeFile(join(fixture, '.dockerignore'), [
      ...included,
      ...excluded.map((file) => `!${file}`),
      '',
    ].join('\n'));

    docker([
      'buildx', 'build',
      '--file', dockerfile,
      '--network=none',
      '--no-cache',
      '--progress=plain',
      '--output', `type=local,dest=${output}`,
      '.',
    ], fixture, 'Docker context export failed. Check that the active Buildx builder is available.');

    for (const file of included) {
      assert.equal(await readFile(join(output, 'context', file), 'utf8'), marker,
        `Required build input was not retained: ${file}`);
    }
    for (const file of excluded) {
      await assert.rejects(lstat(join(output, 'context', file)), { code: 'ENOENT' },
        `Excluded marker reached the Docker context: ${file}`);
    }
    console.log(`[playground] Docker context passed: ${included.length} build inputs retained, ` +
      `${excluded.length} residue markers excluded, Dockerfile ignore precedence confirmed.`);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

checkContext().catch((error) => {
  console.error(`[playground] ${error.message}`);
  process.exitCode = 1;
});
