import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  evaluatePublicRepoPath,
  firstMatchingGlob,
  loadPublicRepoPolicy,
} from './assert-package-artifacts.mjs';

export const APPROVED_LICENSE_SHA256 =
  'b3e495811207541c726aff7069914ec67a2d4c36093eea94d919b9d803557dd2';

export function readRepositoryFileContents(repositoryRoot, pathFilters = []) {
  const trackedPaths = execFileSync('git', ['ls-files', '-z', '--', ...pathFilters], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
    .split('\0')
    .filter(Boolean);
  return new Map(
    trackedPaths.map((filePath) => [filePath, readFileSync(resolve(repositoryRoot, filePath))]),
  );
}

export const APPROVED_SOURCE_HEADER = [
  '// Copyright 2026 Abaxx Technologies',
  '//',
  '// Licensed under the Apache License, Version 2.0 (the "License");',
  '// you may not use this file except in compliance with the License.',
  '// You may obtain a copy of the License at',
  '//',
  '//     https://www.apache.org/licenses/LICENSE-2.0',
  '//',
  '// Unless required by applicable law or agreed to in writing, software',
  '// distributed under the License is distributed on an "AS IS" BASIS,',
  '// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.',
  '// See the License for the specific language governing permissions and',
  '// limitations under the License.',
].join('\n');

const SOURCE_EXTENSIONS = ['.js', '.ts', '.cjs', '.cts', '.mjs', '.mts', '.jsx', '.tsx'];
const DISTRIBUTED_SOURCE_DIRECTORIES = ['src/'];
const GENERATED_SOURCE_DIRECTORIES = ['dist/'];
const NON_DISTRIBUTED_SOURCE_DIRECTORIES = ['demo/', 'test/', 'scripts/', '.github/'];
const PROTECTED_DIRECTORIES = ['vendor/'];
const PROTECTED_NOTICE_NAMES = [
  'license',
  'licence',
  'copying',
  'copyright',
  'notice',
  'attribution',
  'attributions',
  'thirdparty',
  'third-party',
  'third_party',
];

function isProtectedLicensePath(filePath) {
  const normalizedPath = filePath.toLowerCase();
  if (PROTECTED_DIRECTORIES.some((directory) => normalizedPath.startsWith(directory))) return true;
  const segments = normalizedPath.split('/');
  return segments.some((segment, index) =>
    PROTECTED_NOTICE_NAMES.some(
      (name) =>
        (index === segments.length - 1 && segment === name) ||
        ['.', '_', '-'].some((separator) => segment.startsWith(`${name}${separator}`)),
    ),
  );
}

export function selectOriginalLicenseFiles(sourceFiles, { isNpmPackage = false } = {}) {
  const packageFilePatterns = isNpmPackage
    ? JSON.parse(sourceFiles.get('package.json').toString('utf8')).files
    : [];
  const matchesPackagePath = (filePath, rule) =>
    filePath === rule || filePath.startsWith(`${rule}/`) || firstMatchingGlob(filePath, [rule]);
  return new Map(
    [...sourceFiles].filter(([filePath]) => {
      if (!isProtectedLicensePath(filePath)) return false;
      if (!isNpmPackage || filePath === 'LICENSE') return true;
      // npm never includes .gitignore files in tarballs.
      if (filePath.split('/').at(-1) === '.gitignore') return false;
      return (
        packageFilePatterns.some(
          (rule) => !rule.startsWith('!') && matchesPackagePath(filePath, rule),
        ) &&
        !packageFilePatterns.some(
          (rule) => rule.startsWith('!') && matchesPackagePath(filePath, rule.slice(1)),
        )
      );
    }),
  );
}

/**
 * Validates headers, LICENSE, and preservation of third-party notices.
 * @param {Map<string, Buffer>} artifactFiles
 * @param {{isNpmPackage?: boolean, originalLicenseFiles?: Map<string, Buffer>, sourceDirectories?: string[]}} options
 * @returns {Array<{path: string, reason: string}>}
 */
export function auditArtifactLicenses(
  artifactFiles,
  {
    isNpmPackage = false,
    originalLicenseFiles = new Map(),
    sourceDirectories = DISTRIBUTED_SOURCE_DIRECTORIES,
  } = {},
) {
  const violations = [];
  const license = artifactFiles.get('LICENSE');
  if (!license) {
    violations.push({ path: 'LICENSE', reason: 'missing approved root LICENSE' });
  } else if (createHash('sha256').update(license).digest('hex') !== APPROVED_LICENSE_SHA256) {
    violations.push({
      path: 'LICENSE',
      reason: 'root LICENSE differs from the approved complete text and notice',
    });
  }

  const protectedPaths = new Set(originalLicenseFiles.keys());
  for (const [path, contents] of artifactFiles) {
    if (path !== 'LICENSE' && isProtectedLicensePath(path)) protectedPaths.add(path);
    if (!SOURCE_EXTENSIONS.some((extension) => path.endsWith(extension))) continue;

    const text = contents.toString('utf8').replace(/\r\n/g, '\n');
    const withoutShebang = text.replace(/^#![^\n]*(?:\n|$)/, '');
    const headerAtStart =
      withoutShebang === APPROVED_SOURCE_HEADER ||
      withoutShebang.startsWith(`${APPROVED_SOURCE_HEADER}\n`);

    if (sourceDirectories.some((directory) => path.startsWith(directory)) && !headerAtStart) {
      violations.push({
        path,
        reason: 'missing approved source header at line 1 or immediately after shebang',
      });
    } else if (
      isNpmPackage &&
      GENERATED_SOURCE_DIRECTORIES.some((directory) => path.startsWith(directory)) &&
      !/\.d\.[cm]?ts$/.test(path)
    ) {
      // Compiler prologues can precede preserved source comments in generated output.
      if (!`\n${text}\n`.includes(`\n${APPROVED_SOURCE_HEADER}\n`)) {
        violations.push({ path, reason: 'missing approved header in generated package source' });
      }
    }

    if (NON_DISTRIBUTED_SOURCE_DIRECTORIES.some((directory) => path.startsWith(directory))) {
      // Only the comment preamble is a file header, not strings defining fixtures later in the file.
      const preamble = /^(?:\s+|\/\/[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)*/.exec(withoutShebang)[0];
      if (`\n${preamble}\n`.includes(`\n${APPROVED_SOURCE_HEADER}\n`)) {
        violations.push({
          path,
          reason: 'non-distributed source must not carry the repeated first-party header',
        });
      }
    }
  }

  for (const path of protectedPaths) {
    if (path === 'LICENSE') continue;
    const originalContents = originalLicenseFiles.get(path);
    const contents = artifactFiles.get(path);
    if (!originalContents) {
      violations.push({
        path,
        reason: 'vendor or third-party notice file has no trusted baseline',
      });
    } else if (!contents) {
      violations.push({
        path,
        reason: 'missing vendor or third-party notice file from trusted baseline',
      });
    } else if (!contents.equals(originalContents)) {
      violations.push({
        path,
        reason: 'vendor or third-party notice file differs from trusted baseline',
      });
    }
  }
  return violations;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const options = {};
    while (args.length) {
      const flag = args.shift();
      const value = args.shift();
      if (!['--root', '--baseline-root', '--policy'].includes(flag) || !value) {
        throw new Error('Invalid license audit arguments');
      }
      options[flag] = value;
    }
    if (!options['--root'] || !options['--baseline-root']) {
      throw new Error('License audit requires --root and --baseline-root');
    }
    const policy = options['--policy']
      ? loadPublicRepoPolicy(resolve(options['--policy']))
      : undefined;
    const artifactRoot = resolve(options['--root']);
    const sourceRoot = resolve(options['--baseline-root']);
    const artifactFiles = readRepositoryFileContents(artifactRoot);
    const sourceFiles = new Map(
      [...readRepositoryFileContents(sourceRoot)].filter(
        ([filePath]) =>
          !policy ||
          artifactRoot === sourceRoot ||
          evaluatePublicRepoPath(filePath, policy).allowed,
      ),
    );
    const violations = auditArtifactLicenses(artifactFiles, {
      originalLicenseFiles: selectOriginalLicenseFiles(sourceFiles),
      sourceDirectories: policy?.licenseSourceDirectories,
    });
    for (const { path, reason } of violations) console.error(`${JSON.stringify(path)}: ${reason}`);
    process.exitCode = violations.length ? 1 : 0;
    if (!violations.length)
      console.log(`License audit passed: ${artifactFiles.size} repository files`);
  } catch {
    console.error('License audit failed: invalid input or unreadable file.');
    process.exitCode = 1;
  }
}
