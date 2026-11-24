import { describe, it, expect } from 'vitest';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getVersion } from '#mcp/server.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'version-resolution');
const stub = join(fixturesDir, 'stub-package.json');
const emptyVersion = join(fixturesDir, 'empty-version-package.json');
const missing = join(fixturesDir, 'does-not-exist.json');

describe('getVersion', () => {
  it('returns "0.0.0" when no candidate yields a usable version', () => {
    expect(getVersion([stub, emptyVersion, missing])).toBe('0.0.0');
  });

  it('regression: dist/cjs/package.json stub does not poison version resolution', () => {
    const distCjsStub = stub;
    const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    expect(getVersion([distCjsStub, repoRoot])).not.toBe('0.0.0');
    expect(getVersion([distCjsStub, repoRoot])).not.toBe(undefined);
  });
});
