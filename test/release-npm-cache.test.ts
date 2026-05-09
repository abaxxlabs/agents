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
 * Release npm cache guard tests.
 *
 * The release gate depends on npm's configured cache being either the
 * maintainer's user-owned cache or a CI-provided runner-owned cache. These
 * tests exercise the guard directly so ownership and permission regressions
 * fail before packaging checks fall back to npm's less actionable cache error.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  formatNpmCacheFailure,
  resolveNpmCachePath,
  runCli,
  validateNpmCache,
} from '../scripts/check-npm-cache.mjs';

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

  it.runIf(typeof process.getuid === 'function')(
    'reports an actionable ownership repair when the cache owner is wrong',
    async () => {
      const cachePath = path.join(tmpRoot, 'cache');
      await mkdir(path.join(cachePath, '_cacache'), { recursive: true });

      const currentUid = process.getuid();
      const wrongUid = currentUid === 0 ? 1 : currentUid + 1;
      const result = await validateNpmCache(cachePath, {
        expectedUid: wrongUid,
        expectedGid: process.getgid?.(),
      });

      expect(result).toMatchObject({ ok: false, code: 'ownership', cachePath });
      const message = formatNpmCacheFailure(result);
      expect(message).toContain('before release verification');
      expect(message).toContain('First non-owned entry:');
      expect(message).toContain('sudo chown -R');
      expect(message).toContain(cachePath);
      expect(message).toContain('CI should set npm_config_cache');
    },
  );

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
