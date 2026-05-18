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

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const SCAN_DIRS = ['src/', 'test/', 'scripts/', 'packages/server/src/', 'packages/create-agents/src/', 'packages/create-agents/template/src/'];

const BLOCKED_PATTERNS = [
  { label: 'ABXAGNTS-', pattern: /ABXAGNTS-/i },
  { label: 'Pre-Session', pattern: /Pre-Session/i },
  { label: 'Post-Session', pattern: /Post-Session/i },
  { label: 'pre-v0.', pattern: /pre-v0\./i },
  { label: 'post-v0.', pattern: /post-v0\./i },
];

const ALLOWLIST = [
  {
    file: 'scripts/audit-public-artifacts.mjs',
    reason: 'Declares the blocked-term patterns it enforces.',
  },
  {
    file: 'scripts/audit-source-blocked-terms.mjs',
    reason: 'Declares the blocked-term patterns it enforces.',
  },
  {
    file: 'test/public-artifact-audit.test.ts',
    reason: 'Test fixtures deliberately contain blocked terms to verify the audit.',
  },
  {
    file: 'scripts/public-sync.py',
    reason: 'Sanitization script that declares the regex rules it scrubs.',
  },
];

function allowlisted(filePath) {
  const normalized = filePath.replace(/\\/g, '/');
  return ALLOWLIST.some((entry) => normalized === entry.file);
}

function getTrackedFiles(rootDir) {
  const output = execFileSync('git', ['ls-files', '--', ...SCAN_DIRS], {
    cwd: rootDir,
    encoding: 'utf8',
  });
  return output.split('\n').filter(Boolean);
}

export function scanFiles(files, rootDir) {
  const violations = [];

  for (const filePath of files) {
    if (allowlisted(filePath)) continue;

    const abs = path.resolve(rootDir, filePath);
    let contents;
    try {
      contents = readFileSync(abs, 'utf8');
    } catch {
      continue;
    }

    const lines = contents.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      for (const { label, pattern } of BLOCKED_PATTERNS) {
        if (pattern.test(lines[i])) {
          violations.push({ file: filePath, line: i + 1, term: label });
        }
      }
    }
  }

  return violations;
}

export function run(rootDir = process.cwd()) {
  const files = getTrackedFiles(rootDir);
  const violations = scanFiles(files, rootDir);

  if (violations.length === 0) {
    console.log(`Source blocked-term audit passed: ${files.length} files scanned.`);
    return 0;
  }

  console.error('Source blocked-term audit FAILED:');
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}  blocked term "${v.term}"`);
  }
  console.error(`\n${violations.length} violation(s) in ${files.length} files.`);
  return 1;
}

const isMain = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;

if (isMain) {
  process.exitCode = run();
}
