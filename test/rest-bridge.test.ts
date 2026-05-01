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
    const decisions = readFileSync(resolve(ROOT, 'docs/DECISIONS.md'), 'utf8');

    expect(source).toContain('source-only reference material');
    expect(source).toContain('intentionally excluded from');
    expect(source).toContain('has no package.json export path');
    expect(decisions).toContain('Package output policy');
    expect(decisions).toContain('The supported MCP import path remains `@abaxxlabs/agents/mcp`.');
  });
});
