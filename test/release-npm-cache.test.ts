import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { resolveNpmCachePath, runCli, validateNpmCache } from '../scripts/check-npm-cache.mjs';

let tmpRoot: string;

beforeEach(async () => {
  tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'npm-cache-guard-test-'));
});

afterEach(async () => {
  await rm(tmpRoot, { recursive: true, force: true });
});

describe('release npm cache guard', () => {
  it('creates and validates a missing user-owned npm cache directory', async () => {
    const cachePath = path.join(tmpRoot, 'cache');

    const result = await validateNpmCache(cachePath);

    expect(result).toMatchObject({ ok: true, cachePath });
    await expect(stat(cachePath)).resolves.toMatchObject({ uid: process.getuid?.() });
  });

  it('uses npm_config_cache without shelling out to npm config', async () => {
    const cachePath = path.join(tmpRoot, 'env-cache');

    await expect(resolveNpmCachePath({ npm_config_cache: cachePath })).resolves.toBe(cachePath);
  });

  it('returns a clear CLI failure when the configured cache path is not a directory', async () => {
    const cachePath = path.join(tmpRoot, 'cache-file');
    await writeFile(cachePath, 'not a directory');
    const stderr: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((message: string) => {
      stderr.push(message);
    });

    try {
      await expect(runCli(['--cache', cachePath])).resolves.toBe(1);
    } finally {
      errSpy.mockRestore();
    }

    expect(stderr.join('\n')).toContain('not a directory');
    expect(stderr.join('\n')).toContain('sudo chown -R');
  });
});
