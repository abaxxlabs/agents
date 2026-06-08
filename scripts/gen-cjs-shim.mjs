#!/usr/bin/env node
/**
 * Generates dist/cjs/package.json with a CJS-relative imports map derived from the
 * root package.json#imports field. Without this, Node.js stops at the dist/cjs/
 * package boundary and cannot resolve #-prefixed specifiers at runtime.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

const cjsImports = {};
for (const [key, value] of Object.entries(pkg.imports ?? {})) {
  const defaultPath = typeof value === 'string' ? value : value.default;
  cjsImports[key] = defaultPath.replace(/^\.\/dist\//, './');
}

const outDir = resolve(root, 'dist/cjs');
mkdirSync(outDir, { recursive: true });
writeFileSync(
  resolve(outDir, 'package.json'),
  JSON.stringify({ type: 'commonjs', imports: cjsImports }, null, 2) + '\n',
);
