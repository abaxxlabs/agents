#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  scanArtifactContentForViolations,
  scanReleaseContentForViolations,
} from './audit-artifact-content.mjs';
import { corporateEmployeeNames, normalizePrivateUrlPrefixes } from './audit-sensitive-values.mjs';
import { evaluatePublicRepoPath, loadPublicRepoPolicy } from './assert-package-artifacts.mjs';

const PUBLIC_SOURCE_SCAN_PATHS = ['CHANGELOG.md', 'src', 'test', 'scripts'];

function getTrackedSourceFiles(rootDir, policy) {
  const args = policy ? ['ls-files'] : ['ls-files', '--', ...PUBLIC_SOURCE_SCAN_PATHS];
  const output = execFileSync('git', args, {
    cwd: rootDir,
    encoding: 'utf8',
  });
  return output
    .split('\n')
    .filter(Boolean)
    .filter((filePath) => existsSync(path.resolve(rootDir, filePath)))
    .filter((filePath) => !policy || evaluatePublicRepoPath(filePath, policy).allowed);
}

export function scanFiles(files, rootDir, options = {}) {
  const violations = [];
  for (const filePath of files) {
    let contents;
    try {
      contents = readFileSync(path.resolve(rootDir, filePath), 'utf8');
    } catch {
      violations.push({ path: filePath, reason: 'could not read source file' });
      continue;
    }
    violations.push(...scanArtifactContentForViolations(contents, filePath, options));
  }
  return violations;
}

function printViolations(violations) {
  for (const violation of violations) {
    const reason = violation.reason;
    const artifactPath = violation.path;
    const location =
      violation.line === undefined ? artifactPath : `${artifactPath}:${violation.line}`;
    console.error(`  ${location}  ${reason}`);
  }
}

export function run(rootDir = process.cwd(), options = {}) {
  const files = getTrackedSourceFiles(rootDir, options.policy);
  const violations = scanFiles(files, rootDir, options);
  if (violations.length === 0) {
    console.log(`Source blocked-term audit passed: ${files.length} files scanned.`);
    return 0;
  }

  console.error('Source blocked-term audit FAILED:');
  printViolations(violations);
  console.error(`\n${violations.length} violation(s) in ${files.length} files.`);
  return 1;
}

// Semantic-release runs this after changelog generation and before package, commit, tag, or publication.
export function prepare(pluginConfig, context) {
  const rootDir = context.cwd ?? process.cwd();
  const policy = pluginConfig.policyPath
    ? loadPublicRepoPolicy(path.resolve(rootDir, pluginConfig.policyPath))
    : undefined;
  const blockedUrls = normalizePrivateUrlPrefixes([
    ...(pluginConfig.privateUrlPrefixes ?? []),
    context.options?.repositoryUrl,
  ]);
  let contents;
  try {
    contents = readFileSync(path.resolve(rootDir, 'CHANGELOG.md'), 'utf8');
  } catch {
    throw new Error('Release changelog audit failed: could not read CHANGELOG.md');
  }
  const violations = scanReleaseContentForViolations(contents, 'CHANGELOG.md', {
    blockedContentTerms: policy?.blockedTerms,
    employeeNames: corporateEmployeeNames(rootDir, pluginConfig.corporateEmailSuffix),
    privateUrlPrefixes: blockedUrls,
    ticketPrefixes: policy?.ticketPrefixes,
  });
  if (violations.length > 0) {
    printViolations(violations);
    throw new Error('Release changelog audit failed');
  }
  console.log('Release changelog audit passed.');
}

const isMain = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;

function parseArgs(argv) {
  const args = [...argv];
  let policyPath;
  let rootDir = process.cwd();
  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--policy') {
      policyPath = args.shift();
      if (!policyPath) throw new Error('--policy requires a JSON policy path');
    } else if (arg === '--root') {
      const root = args.shift();
      if (!root) throw new Error('--root requires a repository path');
      rootDir = path.resolve(process.cwd(), root);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return { policyPath, rootDir };
}

function environmentLines(name) {
  return (process.env[name] ?? '')
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
}

if (isMain) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const privatePolicyPath = path.join(args.rootDir, 'scripts/public-repo-policy.internal.json');
    const policyPath = args.policyPath
      ? path.resolve(process.cwd(), args.policyPath)
      : existsSync(privatePolicyPath)
        ? privatePolicyPath
        : undefined;
    const policy = policyPath ? loadPublicRepoPolicy(policyPath) : undefined;
    process.exitCode = run(args.rootDir, {
      employeeNames: [
        ...new Set([
          ...corporateEmployeeNames(args.rootDir, process.env.ABAXXLABS_CORPORATE_EMAIL_SUFFIX),
          ...environmentLines('ABAXXLABS_EMPLOYEE_NAMES'),
        ]),
      ],
      privateUrlPrefixes: normalizePrivateUrlPrefixes(
        environmentLines('ABAXXLABS_PRIVATE_URL_PREFIXES'),
      ),
      blockedContentTerms: policy?.blockedTerms,
      ticketPrefixes: policy?.ticketPrefixes,
      policy,
    });
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
