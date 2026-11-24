import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const FORBIDDEN_EXPORTS = [
  './mcp/rest-bridge',
  './mcp/rest-bridge.js',
  './dist/mcp/rest-bridge.js',
];

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(resolve(ROOT, path), 'utf8')) as T;
}

describe('historical REST bridge public surface policy', () => {
  it('does not define a supported package export for the REST bridge', () => {
    const pkg = readJson<{ exports?: Record<string, unknown> }>('package.json');
    const exportKeys = Object.keys(pkg.exports ?? {});

    expect(exportKeys).toContain('./mcp');
    for (const forbiddenExport of FORBIDDEN_EXPORTS) {
      expect(exportKeys).not.toContain(forbiddenExport);
    }
  });
});
