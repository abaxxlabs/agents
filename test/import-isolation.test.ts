import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';

const SRC = resolve(import.meta.dirname, '..', 'src');

function collectImportGraph(entryFile: string): Set<string> {
  const visited = new Set<string>();
  const queue = [resolve(entryFile)];

  while (queue.length > 0) {
    const file = queue.pop()!;
    if (visited.has(file)) continue;
    visited.add(file);

    let content: string;
    try {
      content = readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    // Match import/export ... from '...' but skip type-only imports
    // (import type / export type) since they emit nothing at runtime.
    const importRegex = /(?:import|export)\s+(?!type\s).*?from\s+['"]([^'"]+)['"]/g;
    let match;
    while ((match = importRegex.exec(content)) !== null) {
      const specifier = match[1];
      if (!specifier.startsWith('.')) continue;

      const resolved = specifier.replace(/\.js$/, '.ts');
      const abs = resolve(dirname(file), resolved);
      if (!visited.has(abs)) queue.push(abs);

      const indexPath = resolve(dirname(file), resolved.replace(/\.ts$/, ''), 'index.ts');
      if (!visited.has(indexPath)) queue.push(indexPath);
    }
  }

  return visited;
}

function graphImportsPackage(entryFile: string, packageName: string): boolean {
  const visited = collectImportGraph(entryFile);
  for (const file of visited) {
    let content: string;
    try {
      content = readFileSync(file, 'utf-8');
    } catch {
      continue;
    }
    const regex = new RegExp(`(?:import|export)\\s+.*?from\\s+['"]${packageName}['"]`);
    if (regex.test(content)) return true;
  }
  return false;
}

describe('Import isolation (agents/sql split acceptance criterion)', () => {
  it('main entry does not transitively import pg', () => {
    expect(graphImportsPackage(resolve(SRC, 'index.ts'), 'pg')).toBe(false);
  });

  it('main entry does not transitively import libpg-query', () => {
    expect(graphImportsPackage(resolve(SRC, 'index.ts'), 'libpg-query')).toBe(false);
  });

  it('sql entry does import pg', () => {
    expect(graphImportsPackage(resolve(SRC, 'sql', 'index.ts'), 'pg')).toBe(true);
  });

  it('sql entry does import libpg-query', () => {
    expect(graphImportsPackage(resolve(SRC, 'sql', 'scope-engine.ts'), 'libpg-query')).toBe(true);
  });

  it('main entry graph does not include sql/ files', () => {
    const graph = collectImportGraph(resolve(SRC, 'index.ts'));
    const sqlFiles = [...graph].filter((f) => f.includes('/sql/'));
    expect(sqlFiles).toEqual([]);
  });

  it('mcp entry does not eagerly import pg or libpg-query', () => {
    expect(graphImportsPackage(resolve(SRC, 'mcp', 'index.ts'), 'pg')).toBe(false);
    expect(graphImportsPackage(resolve(SRC, 'mcp', 'index.ts'), 'libpg-query')).toBe(false);
  });

  it('mcp entry graph does not eagerly include sql/ files', () => {
    const graph = collectImportGraph(resolve(SRC, 'mcp', 'index.ts'));
    const sqlFiles = [...graph].filter((f) => f.includes('/sql/'));
    expect(sqlFiles).toEqual([]);
  });
});
