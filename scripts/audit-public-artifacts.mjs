#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { artifactFileStatus, scanFileForContentViolations } from './audit-artifact-content.mjs';
import {
  evaluatePublicRepoPath,
  firstMatchingGlob,
  loadPublicRepoPolicy,
  normalizeArtifactPath,
  normalizeArtifactPaths,
  parsePublicRepoPolicy,
} from './assert-package-artifacts.mjs';
import { corporateEmployeeNames, normalizePrivateUrlPrefixes } from './audit-sensitive-values.mjs';
import {
  auditArtifactLicenses,
  selectOriginalLicenseFiles,
  readRepositoryFileContents,
} from './audit-artifact-license.mjs';

export { evaluatePublicRepoPath, loadPublicRepoPolicy, parsePublicRepoPolicy };

const ROOT_DIR = process.cwd();
const PUBLIC_REPO_LIST_ENV = 'ABAXXLABS_PUBLIC_REPO_CANDIDATE_LIST';
const PUBLIC_REPO_ROOT_ENV = 'ABAXXLABS_PUBLIC_REPO_ROOT';
const PRIVATE_URL_PREFIXES_ENV = 'ABAXXLABS_PRIVATE_URL_PREFIXES';
const CORPORATE_EMAIL_SUFFIX_ENV = 'ABAXXLABS_CORPORATE_EMAIL_SUFFIX';
const EMPLOYEE_NAMES_ENV = 'ABAXXLABS_EMPLOYEE_NAMES';

const PACKAGE_ALLOWED_PATHS = [
  'package.json',
  'README.md',
  'LICENSE',
  'dist/**',
  'vendor/id-sdk-mcp/**',
];

const PACKAGE_CREDENTIAL_FORBIDDEN_PATHS = [
  '**/.env',
  '**/.env.*',
  '**/.agent-scope-master-key',
  '**/agent-scope.config.json',
  '**/client_secret.json',
  '**/credentials.json',
  '**/id_ed25519',
  '**/id_rsa',
  '**/service-account.json',
  '**/service_account.json',
  '**/*.key',
  '**/*.p12',
  '**/*.pfx',
  '**/*.pem',
];

function auditFiles(paths, pathRules, options = {}) {
  const rootDir = options.rootDir ?? ROOT_DIR;
  const scanContents = options.scanContents ?? true;
  const requireExistingFiles = options.requireExistingFiles ?? false;
  const scanBlockedTerms = options.scanBlockedTerms ?? true;
  const { paths: normalizedPaths, violations } = normalizeArtifactPaths(paths);

  for (const artifactPath of normalizedPaths) {
    const forbiddenGlob = pathRules.evaluatePath
      ? pathRules.evaluatePath(artifactPath).matchedRule
      : firstMatchingGlob(artifactPath, pathRules.forbiddenPaths ?? []);
    if (forbiddenGlob) {
      violations.push({ path: artifactPath, reason: `forbidden path (${forbiddenGlob})` });
      continue;
    }

    if (pathRules.allowedPaths && !firstMatchingGlob(artifactPath, pathRules.allowedPaths)) {
      violations.push({ path: artifactPath, reason: 'not in artifact allowlist' });
      continue;
    }

    let fileStatus;
    if (requireExistingFiles) {
      fileStatus = artifactFileStatus(artifactPath, rootDir);
      if (!fileStatus.exists) {
        violations.push({
          path: artifactPath,
          reason: 'candidate file does not exist under audit root',
        });
        continue;
      }
      if (!fileStatus.isFile) {
        violations.push({ path: artifactPath, reason: 'candidate path is not a regular file' });
        continue;
      }
    }

    if (scanContents) {
      violations.push(
        ...scanFileForContentViolations(artifactPath, rootDir, {
          blockedContentTerms: options.blockedContentTerms,
          scanBlockedTerms,
          employeeNames: options.employeeNames,
          fileStatus,
          privateUrlPrefixes: options.privateUrlPrefixes,
          ticketPrefixes: options.ticketPrefixes,
          publishedPaths: options.validatePublishedLinks ? new Set(normalizedPaths) : undefined,
        }),
      );
    }
  }

  return {
    ok: violations.length === 0,
    fileCount: normalizedPaths.length,
    violations,
  };
}

export function auditPackageFiles(paths, options = {}) {
  return auditFiles(
    paths,
    {
      allowedPaths: PACKAGE_ALLOWED_PATHS,
      forbiddenPaths: PACKAGE_CREDENTIAL_FORBIDDEN_PATHS,
    },
    options,
  );
}

export function auditPublicRepoFiles(paths, options = {}) {
  const policy = options.policy;
  return auditFiles(
    paths,
    policy ? { evaluatePath: (artifactPath) => evaluatePublicRepoPath(artifactPath, policy) } : {},
    {
      ...options,
      blockedContentTerms: policy?.blockedTerms ?? options.blockedContentTerms,
      ticketPrefixes: policy?.ticketPrefixes ?? options.ticketPrefixes,
      validatePublishedLinks: true,
    },
  );
}

function defaultPublicRepoCandidatePaths(rootDir = ROOT_DIR) {
  const output = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    {
      cwd: rootDir,
      encoding: 'utf8',
    },
  );
  return output
    .split('\0')
    .filter(Boolean)
    .map((filePath) => normalizeArtifactPath(filePath).path)
    .filter(Boolean);
}

function environmentLines(name) {
  return (process.env[name] ?? '')
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
}

export function readPublicRepoList(filePath) {
  const contents =
    filePath === '-'
      ? readFileSync(0, 'utf8')
      : readFileSync(path.resolve(ROOT_DIR, filePath), 'utf8');
  return contents
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

export function npmPackDryRunFiles(rootDir = ROOT_DIR) {
  const npmCache =
    process.env.PUBLIC_ARTIFACT_NPM_CACHE ??
    process.env.npm_config_cache ??
    process.env.NPM_CONFIG_CACHE ??
    path.join(tmpdir(), 'abaxxlabs-agents-npm-cache');
  const npmLogs =
    process.env.PUBLIC_ARTIFACT_NPM_LOGS ??
    process.env.npm_config_logs_dir ??
    process.env.NPM_CONFIG_LOGS_DIR ??
    path.join(tmpdir(), 'abaxxlabs-agents-npm-logs');
  const output = execFileSync(
    'npm',
    [
      'pack',
      '--dry-run',
      '--json',
      '--ignore-scripts',
      `--cache=${npmCache}`,
      `--logs-dir=${npmLogs}`,
    ],
    {
      cwd: rootDir,
      encoding: 'utf8',
    },
  );
  const jsonStart = output.indexOf('[');
  if (jsonStart === -1) {
    throw new Error('npm pack --dry-run --json did not return JSON output');
  }
  const packResult = JSON.parse(output.slice(jsonStart));
  return packResult.flatMap((entry) => entry.files.map((file) => file.path));
}

function printResult(name, result) {
  if (result.ok) {
    console.log(`${name} audit passed: ${result.fileCount} files`);
    return;
  }

  console.error(`${name} audit failed:`);
  for (const violation of result.violations) {
    const location = violation.line ? `${violation.path}:${violation.line}` : violation.path;
    console.error(`- ${location}: ${violation.reason}`);
  }
}

function usage() {
  return `
Usage:
  node scripts/audit-public-artifacts.mjs [package|public-repo] [--public-root <path>] [--public-list <path|-|git>]
  node scripts/audit-public-artifacts.mjs policy-evaluate --policy <path>

  policy-evaluate  Read a JSON path array from stdin and write policy decisions as JSON.

Environment:
  ${PUBLIC_REPO_ROOT_ENV}=<assembled public repo root>
  ${PUBLIC_REPO_LIST_ENV}=<path|-|git>
  ${CORPORATE_EMAIL_SUFFIX_ENV}=<corporate email suffix used to derive employee names>
  ${EMPLOYEE_NAMES_ENV}=<newline-separated employee names>
  ${PRIVATE_URL_PREFIXES_ENV}=<newline-separated private URL prefixes>

Examples:
  npm run audit:package-files
  npm run audit:public-repo -- --public-root ../abaxxlabs-agents-public --public-list git
  npm run audit:public-repo -- --public-root ../abaxxlabs-agents-public --public-list ./public-repo-files.txt
  printf "README.md\\n.claude/settings.json\\n" | npm run audit:public-repo -- --public-root ../abaxxlabs-agents-public --public-list -
`.trim();
}

function parseArgs(argv) {
  const args = [...argv];
  const command = args[0] && !args[0].startsWith('-') ? args.shift() : 'package';
  let publicList = process.env[PUBLIC_REPO_LIST_ENV] ?? 'git';
  let publicRoot = process.env[PUBLIC_REPO_ROOT_ENV];
  let policyPath;

  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--public-list') {
      publicList = args.shift();
      if (!publicList) throw new Error('--public-list requires a path, "-", or "git"');
    } else if (arg === '--public-root') {
      publicRoot = args.shift();
      if (!publicRoot) {
        throw new Error('--public-root requires the assembled public repository root path');
      }
    } else if (arg === '--policy') {
      policyPath = args.shift();
      if (!policyPath) throw new Error('--policy requires a JSON policy path');
    } else if (arg === '--help' || arg === '-h') {
      return { help: true };
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!['package', 'public-repo', 'policy-evaluate'].includes(command)) {
    throw new Error(`Unknown audit command: ${command}`);
  }
  if (policyPath && command === 'package') {
    throw new Error('--policy is only supported by public-repo and policy-evaluate');
  }
  if (command === 'policy-evaluate' && !policyPath) {
    throw new Error('policy-evaluate requires --policy <path>');
  }
  return { command, publicList, publicRoot, policyPath };
}

function evaluatePolicyInput(policyPath) {
  const policy = loadPublicRepoPolicy(path.resolve(ROOT_DIR, policyPath));
  let paths;
  try {
    paths = JSON.parse(readFileSync(0, 'utf8'));
  } catch (error) {
    throw new Error(
      `policy evaluator input must be JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!Array.isArray(paths) || paths.some((filePath) => typeof filePath !== 'string')) {
    throw new Error('policy evaluator input must be an array of path strings');
  }
  return paths.map((filePath) => evaluatePublicRepoPath(filePath, policy));
}

function publicRepoAuditInput(args) {
  if (!args.publicRoot) {
    throw new Error(
      `public-repo audit requires --public-root <assembled public repository root> or ${PUBLIC_REPO_ROOT_ENV}`,
    );
  }
  if (args.publicList === 'default') {
    throw new Error(
      '--public-list default is no longer supported; use --public-list git with --public-root <assembled public repository root>',
    );
  }

  const rootDir = path.resolve(ROOT_DIR, args.publicRoot);
  if (rootDir === path.resolve(ROOT_DIR)) {
    throw new Error('Refusing to use the internal repository root as the public-repo audit target');
  }
  const paths =
    args.publicList === 'git'
      ? defaultPublicRepoCandidatePaths(rootDir)
      : readPublicRepoList(args.publicList);
  return { rootDir, paths };
}

function runCli(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return 0;
  }
  if (args.command === 'policy-evaluate') {
    console.log(JSON.stringify(evaluatePolicyInput(args.policyPath)));
    return 0;
  }

  const results = [];
  const sensitiveOptions = {
    employeeNames: [
      ...new Set([
        ...corporateEmployeeNames(ROOT_DIR, process.env[CORPORATE_EMAIL_SUFFIX_ENV]),
        ...environmentLines(EMPLOYEE_NAMES_ENV),
      ]),
    ],
    privateUrlPrefixes: normalizePrivateUrlPrefixes(environmentLines(PRIVATE_URL_PREFIXES_ENV)),
  };
  if (args.command === 'package') {
    const paths = npmPackDryRunFiles();
    const result = auditPackageFiles(paths, { ...sensitiveOptions, requireExistingFiles: true });
    const packageFileContents = new Map(
      paths.map((filePath) => [filePath, readFileSync(path.resolve(ROOT_DIR, filePath))]),
    );
    const sourceFiles = readRepositoryFileContents(ROOT_DIR, ['LICENSE', 'vendor']);
    sourceFiles.set('package.json', readFileSync(path.resolve(ROOT_DIR, 'package.json')));
    result.violations.push(
      ...auditArtifactLicenses(packageFileContents, {
        isNpmPackage: true,
        originalLicenseFiles: selectOriginalLicenseFiles(sourceFiles, { isNpmPackage: true }),
      }),
    );
    result.ok = result.violations.length === 0;
    results.push(['Package artifact', result]);
  }
  if (args.command === 'public-repo') {
    const publicRepoInput = publicRepoAuditInput(args);
    const policy = args.policyPath
      ? loadPublicRepoPolicy(path.resolve(ROOT_DIR, args.policyPath))
      : undefined;
    results.push([
      'Public repo artifact',
      auditPublicRepoFiles(publicRepoInput.paths, {
        rootDir: publicRepoInput.rootDir,
        requireExistingFiles: true,
        ...sensitiveOptions,
        policy,
      }),
    ]);
  }

  for (const [name, result] of results) printResult(name, result);
  return results.every(([, result]) => result.ok) ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    process.exitCode = runCli(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    console.error(usage());
    process.exitCode = 1;
  }
}
