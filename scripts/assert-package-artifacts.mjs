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
 * Asserts that every artifact path named in package.json metadata
 * (main, module, types, exports, bin) exists on disk after a clean build.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const args = process.argv.slice(2);
const FORBIDDEN_PACKAGE_ARTIFACTS = [
  './dist/mcp/rest-bridge.js',
  './dist/mcp/rest-bridge.js.map',
  './dist/mcp/rest-bridge.d.ts',
  './dist/mcp/rest-bridge.d.ts.map',
  './dist/cjs/mcp/rest-bridge.js',
  './dist/cjs/mcp/rest-bridge.js.map',
];

if (args.includes('--help') || args.includes('-h')) {
  console.log('Usage: node scripts/assert-package-artifacts.mjs [package.json]');
  process.exit(0);
}

const packageJsonPath = resolve(process.cwd(), args[0] ?? 'package.json');
const packageRoot = dirname(packageJsonPath);

function readPackageJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    console.error(`[package-artifacts] Failed to read ${path}: ${formatError(err)}`);
    process.exit(1);
  }
}

function formatError(err) {
  return err instanceof Error ? err.message : String(err);
}

function pathSegment(base, key) {
  return /^[A-Za-z_$][\w$]*$/.test(key)
    ? `${base}.${key}`
    : `${base}[${JSON.stringify(key)}]`;
}

function addPackagePath(checks, metadataPath, packagePath) {
  if (typeof packagePath !== 'string' || packagePath.length === 0) return;

  checks.push({
    metadataPath,
    packagePath,
    filePath: resolve(packageRoot, packagePath),
  });
}

function walkExports(checks, value, metadataPath) {
  if (typeof value === 'string') {
    addPackagePath(checks, metadataPath, value);
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      walkExports(checks, item, `${metadataPath}[${index}]`);
    });
    return;
  }

  if (!value || typeof value !== 'object') return;

  for (const [key, nested] of Object.entries(value)) {
    walkExports(checks, nested, pathSegment(metadataPath, key));
  }
}

function collectMetadataPaths(pkg) {
  const checks = [];

  addPackagePath(checks, 'main', pkg.main);
  addPackagePath(checks, 'module', pkg.module);
  addPackagePath(checks, 'types', pkg.types);

  if (pkg.exports !== undefined) {
    walkExports(checks, pkg.exports, 'exports');
  }

  if (typeof pkg.bin === 'string') {
    addPackagePath(checks, 'bin', pkg.bin);
  } else if (pkg.bin && typeof pkg.bin === 'object') {
    for (const [name, target] of Object.entries(pkg.bin)) {
      addPackagePath(checks, pathSegment('bin', name), target);
    }
  }

  return checks;
}

function isExistingFile(path) {
  try {
    return existsSync(path) && statSync(path).isFile();
  } catch {
    return false;
  }
}

const pkg = readPackageJson(packageJsonPath);
const checks = collectMetadataPaths(pkg);
const missing = checks.filter((check) => !isExistingFile(check.filePath));
const forbidden = FORBIDDEN_PACKAGE_ARTIFACTS
  .map((packagePath) => ({
    packagePath,
    filePath: resolve(packageRoot, packagePath),
  }))
  .filter((check) => isExistingFile(check.filePath));

if (missing.length > 0) {
  console.error(
    `[package-artifacts] ${missing.length} package metadata path(s) point at missing files:`,
  );

  for (const check of missing) {
    console.error(`- ${check.metadataPath}: ${check.packagePath} -> ${check.filePath}`);
  }

  process.exit(1);
}

if (forbidden.length > 0) {
  console.error(
    '[package-artifacts] Historical REST bridge artifact(s) must not be emitted or packed:',
  );

  for (const check of forbidden) {
    console.error(`- ${check.packagePath} -> ${check.filePath}`);
  }

  process.exit(1);
}

console.log(
  `[package-artifacts] OK: ${checks.length} package metadata path(s) exist; historical REST bridge artifacts absent.`,
);
