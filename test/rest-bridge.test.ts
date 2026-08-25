import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const REST_BRIDGE_SOURCE = 'src/mcp/rest-bridge.ts';
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

  it('keeps the historical bridge source out of ESM and CJS build inputs', () => {
    const esmConfig = readJson<{ exclude?: string[] }>('tsconfig.json');
    const cjsConfig = readJson<{ exclude?: string[] }>('tsconfig.cjs.json');

    expect(esmConfig.exclude).toContain(REST_BRIDGE_SOURCE);
    expect(cjsConfig.exclude).toContain(REST_BRIDGE_SOURCE);
  });

  it('documents the bridge as source-only reference material', () => {
    const source = readFileSync(resolve(ROOT, REST_BRIDGE_SOURCE), 'utf8');

    expect(source).toContain('source-only reference material');
    expect(source).toContain('intentionally excluded from');
    expect(source).toContain('has no package.json export path');
  });

  it('registers tools through the non-deprecated registerTool API only', () => {
    const source = readFileSync(resolve(ROOT, REST_BRIDGE_SOURCE), 'utf8');

    expect(source).not.toMatch(/\.tool\(/);
    expect(source).not.toMatch(/\.resource\(/);
    expect(source.match(/server\.registerTool\(/g)).toHaveLength(13);
  });
});
