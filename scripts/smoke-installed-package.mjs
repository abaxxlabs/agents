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
 * Smoke-tests a packed and installed package from a consumer project directory.
 * Requires and imports every exported subpath, runs each bin with --help.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, resolve } from 'node:path';

function parseArgs(argv) {
  const args = [...argv];
  let packageName = '@abaxxlabs/agents';
  const only = [];
  let skipBin = false;
  let packageNameSet = false;

  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--only') {
      const specifier = args.shift();
      if (!specifier) fail('--only requires a package specifier');
      only.push(specifier);
    } else if (arg === '--skip-bin') {
      skipBin = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log(
        'Usage: node scripts/smoke-installed-package.mjs [packageName] [--only <specifier>] [--skip-bin]',
      );
      process.exit(0);
    } else if (!packageNameSet) {
      packageName = arg;
      packageNameSet = true;
    } else {
      fail(`Unknown argument: ${arg}`);
    }
  }

  return { packageName, only, skipBin };
}

const args = parseArgs(process.argv.slice(2));
const packageName = args.packageName;
const requireFromConsumer = createRequire(resolve(process.cwd(), 'package.json'));
const REQUIRED_PUBLIC_SUBPATHS = ['.', './sql', './mcp', './storage', './sqlite', './bootstrap'];

function findInstalledPackageRoot(name) {
  let entryPath;
  try {
    entryPath = requireFromConsumer.resolve(name);
  } catch (err) {
    fail(`Unable to resolve ${name}: ${formatError(err)}`);
  }

  let dir = dirname(entryPath);

  while (dir !== dirname(dir)) {
    const candidate = resolve(dir, 'package.json');
    if (existsSync(candidate)) {
      const pkg = readJson(candidate);
      if (pkg.name === name) return dir;
    }
    dir = dirname(dir);
  }

  fail(`Unable to find package.json for ${name} from ${entryPath}`);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    fail(`Unable to read ${path}: ${formatError(err)}`);
  }
}

function formatError(err) {
  return err instanceof Error ? err.message : String(err);
}

function formatChildError(err) {
  if (err && typeof err === 'object' && 'stderr' in err && err.stderr) {
    const stderr = Buffer.isBuffer(err.stderr)
      ? err.stderr.toString('utf8').trim()
      : String(err.stderr).trim();

    if (stderr) return stderr;
  }

  return formatError(err);
}

function fail(message) {
  console.error(`[package-smoke] ${message}`);
  process.exit(1);
}

function exportSpecifiers(pkg) {
  if (!pkg.exports) return [pkg.name];
  if (typeof pkg.exports === 'string') return [pkg.name];

  return Object.keys(pkg.exports)
    .filter((key) => key === '.' || key.startsWith('./'))
    .sort((a, b) => {
      if (a === '.') return -1;
      if (b === '.') return 1;
      return a.localeCompare(b);
    })
    .map((key) => (key === '.' ? pkg.name : `${pkg.name}/${key.slice(2)}`));
}

function assertRequiredPublicSubpaths(pkg) {
  if (!pkg.exports || typeof pkg.exports !== 'object' || Array.isArray(pkg.exports)) {
    fail('package exports must be an object containing the public subpath map');
  }

  const missing = REQUIRED_PUBLIC_SUBPATHS.filter((subpath) => !(subpath in pkg.exports));
  if (missing.length > 0) {
    fail(`package exports are missing required public subpath(s): ${missing.join(', ')}`);
  }
}

function normalizeBin(pkg) {
  if (!pkg.bin) return {};

  if (typeof pkg.bin === 'string') {
    return { [basename(pkg.name)]: pkg.bin };
  }

  return pkg.bin;
}

function assertFile(path, label) {
  try {
    if (!existsSync(path) || !statSync(path).isFile()) {
      fail(`${label} is missing: ${path}`);
    }
  } catch (err) {
    fail(`${label} is not readable at ${path}: ${formatError(err)}`);
  }
}

const packageRoot = findInstalledPackageRoot(packageName);
const pkg = readJson(resolve(packageRoot, 'package.json'));
assertRequiredPublicSubpaths(pkg);
const discoveredSpecifiers = exportSpecifiers(pkg);
const specifiers = args.only.length > 0 ? args.only : discoveredSpecifiers;

for (const specifier of specifiers) {
  if (!specifier.startsWith(`${packageName}/`) && specifier !== packageName) {
    fail(`--only specifier must belong to ${packageName}: ${specifier}`);
  }
}

for (const specifier of specifiers) {
  try {
    requireFromConsumer(specifier);
  } catch (err) {
    fail(`require failed for ${specifier}: ${formatError(err)}`);
  }

  console.log(`[package-smoke] require OK: ${specifier}`);
}

for (const specifier of specifiers) {
  try {
    execFileSync(
      process.execPath,
      ['--input-type=module', '--eval', `await import(${JSON.stringify(specifier)});`],
      {
        cwd: process.cwd(),
        env: { ...process.env, NODE_ENV: 'test' },
        stdio: 'pipe',
      },
    );
  } catch (err) {
    fail(`import failed for ${specifier}: ${formatChildError(err)}`);
  }

  console.log(`[package-smoke] import OK: ${specifier}`);
}

const binEntries = args.skipBin ? {} : normalizeBin(pkg);

if (!args.skipBin && !Object.hasOwn(binEntries, 'agents')) {
  console.log('[package-smoke] bin.agents absent; CLI contract has no agents bin metadata.');
}

for (const [name, target] of Object.entries(binEntries)) {
  const targetPath = resolve(packageRoot, target);
  const binPath = resolve(process.cwd(), 'node_modules', '.bin', name);

  assertFile(targetPath, `bin target ${name}`);
  assertFile(binPath, `npm bin link ${name}`);

  try {
    execFileSync(binPath, ['--help'], {
      env: { ...process.env, NODE_ENV: 'test' },
      stdio: 'pipe',
    });
  } catch (err) {
    fail(`bin ${name} --help failed: ${formatChildError(err)}`);
  }

  console.log(`[package-smoke] bin OK: ${name}`);
}

console.log(
  `[package-smoke] OK: ${specifiers.length} export(s), ${Object.keys(binEntries).length} bin(s).`,
);
