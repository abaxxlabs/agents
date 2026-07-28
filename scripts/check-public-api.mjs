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
 * Snapshot gate for the six supported package subpaths. Fails if any public
 * export is added or removed without explicitly updating the snapshot.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);

let ts;
try {
  ts = require('typescript');
} catch {
  console.error(
    '[public-api] Unable to load the "typescript" package. Run the repository install step first.',
  );
  process.exit(1);
}

const ROOT_DIR = process.cwd();
const DEFAULT_SNAPSHOT = 'api/public-api.v0.11.3.snapshot.json';
const PUBLIC_ENTRIES = {
  '.': 'src/index.ts',
  './sql': 'src/sql/index.ts',
  './mcp': 'src/mcp/index.ts',
  './storage': 'src/storage/index.ts',
  './sqlite': 'src/storage/sqlite/index.ts',
  './bootstrap': 'src/bootstrap/index.ts',
};

function usage() {
  return `
Usage:
  node scripts/check-public-api.mjs [--update] [--snapshot <path>]

Examples:
  npm run check:public-api
  npm run update:public-api
`.trim();
}

function parseArgs(argv) {
  const args = [...argv];
  let update = false;
  let snapshot = DEFAULT_SNAPSHOT;

  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--update') {
      update = true;
    } else if (arg === '--snapshot') {
      snapshot = args.shift();
      if (!snapshot) throw new Error('--snapshot requires a path');
    } else if (arg === '--help' || arg === '-h') {
      return { help: true };
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return { update, snapshot };
}

function loadPackageJson() {
  return JSON.parse(readFileSync(path.resolve(ROOT_DIR, 'package.json'), 'utf8'));
}

function loadProgram() {
  const configPath = ts.findConfigFile(ROOT_DIR, ts.sys.fileExists, 'tsconfig.json');
  if (!configPath) throw new Error('Unable to find tsconfig.json');

  const configFile = ts.readConfigFile(configPath, ts.sys.readFile);
  if (configFile.error) {
    throw new Error(ts.flattenDiagnosticMessageText(configFile.error.messageText, '\n'));
  }

  const parsed = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    path.dirname(configPath),
  );

  if (parsed.errors.length > 0) {
    throw new Error(
      parsed.errors
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'))
        .join('\n'),
    );
  }

  return ts.createProgram(parsed.fileNames, parsed.options);
}

function classifyExport(symbol, checker) {
  const target =
    symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
  const flags = target.getFlags();
  const hasValue = Boolean(flags & ts.SymbolFlags.Value);
  const hasType = Boolean(flags & ts.SymbolFlags.Type);

  if (hasValue && hasType) return 'type+value';
  if (hasValue) return 'value';
  if (hasType) return 'type';
  if (flags & ts.SymbolFlags.Namespace) return 'namespace';
  return 'unknown';
}

function collectExports(program) {
  const checker = program.getTypeChecker();
  const entries = {};

  for (const [subpath, relativeFile] of Object.entries(PUBLIC_ENTRIES)) {
    const absoluteFile = path.resolve(ROOT_DIR, relativeFile);
    const sourceFile = program.getSourceFile(absoluteFile);
    if (!sourceFile) {
      throw new Error(`Public entry source file is missing from the TypeScript program: ${relativeFile}`);
    }

    const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
    if (!moduleSymbol) {
      throw new Error(`Public entry source file has no module symbol: ${relativeFile}`);
    }

    entries[subpath] = checker
      .getExportsOfModule(moduleSymbol)
      .filter((symbol) => symbol.getName() !== 'default')
      .map((symbol) => ({
        name: symbol.getName(),
        kind: classifyExport(symbol, checker),
      }))
      .sort((a, b) => a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind));
  }

  return entries;
}

function buildSnapshot() {
  const pkg = loadPackageJson();
  const program = loadProgram();

  return {
    schemaVersion: 1,
    packageName: pkg.name,
    publicSubpaths: Object.keys(PUBLIC_ENTRIES),
    entries: collectExports(program),
  };
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function entryKey(item) {
  return `${item.name}:${item.kind}`;
}

function summarizeEntryDiff(expected = [], actual = []) {
  const expectedKeys = new Set(expected.map(entryKey));
  const actualKeys = new Set(actual.map(entryKey));
  const expectedByName = new Map(expected.map((item) => [item.name, item.kind]));
  const actualByName = new Map(actual.map((item) => [item.name, item.kind]));
  const lines = [];

  for (const item of actual) {
    if (expectedKeys.has(entryKey(item))) continue;
    const previousKind = expectedByName.get(item.name);
    lines.push(
      previousKind
        ? `  ~ ${item.name}: ${previousKind} -> ${item.kind}`
        : `  + ${item.name}: ${item.kind}`,
    );
  }

  for (const item of expected) {
    if (actualKeys.has(entryKey(item))) continue;
    if (actualByName.has(item.name)) continue;
    lines.push(`  - ${item.name}: ${item.kind}`);
  }

  return lines;
}

function summarizeSnapshotDiff(expected, actual) {
  const lines = [];

  if (expected.packageName !== actual.packageName) {
    lines.push(`packageName: ${expected.packageName} -> ${actual.packageName}`);
  }

  const subpaths = new Set([
    ...Object.keys(expected.entries ?? {}),
    ...Object.keys(actual.entries ?? {}),
  ]);

  for (const subpath of [...subpaths].sort()) {
    const entryLines = summarizeEntryDiff(expected.entries?.[subpath], actual.entries?.[subpath]);
    if (entryLines.length > 0) {
      lines.push(`${subpath}:`);
      lines.push(...entryLines);
    }
  }

  return lines;
}

function runCli(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return 0;
  }

  const snapshotPath = path.resolve(ROOT_DIR, args.snapshot);
  const actual = buildSnapshot();
  const actualJson = stableJson(actual);

  if (args.update) {
    writeFileSync(snapshotPath, actualJson);
    console.log(`[public-api] Updated ${path.relative(ROOT_DIR, snapshotPath)}`);
    return 0;
  }

  if (!existsSync(snapshotPath)) {
    console.error(
      `[public-api] Snapshot is missing: ${path.relative(ROOT_DIR, snapshotPath)}. ` +
        'Run npm run update:public-api and review the result.',
    );
    return 1;
  }

  const expected = JSON.parse(readFileSync(snapshotPath, 'utf8'));

  // Strip packageVersion from legacy snapshots to prevent version-bump drift
  delete expected.packageVersion;

  const expectedJson = stableJson(expected);
  if (expectedJson === actualJson) {
    const exportCount = Object.values(actual.entries).reduce((sum, entry) => sum + entry.length, 0);
    console.log(
      `[public-api] OK: ${exportCount} exported name(s) across ${Object.keys(actual.entries).length} subpath(s).`,
    );
    return 0;
  }

  console.error(
    `[public-api] Public API snapshot drift detected in ${path.relative(ROOT_DIR, snapshotPath)}.`,
  );
  for (const line of summarizeSnapshotDiff(expected, actual)) {
    console.error(line);
  }
  console.error('Run npm run update:public-api only after reviewing the public contract change.');
  return 1;
}

try {
  process.exitCode = runCli(process.argv.slice(2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  console.error(usage());
  process.exitCode = 1;
}
