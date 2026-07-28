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
import { existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const ROOT_DIR = process.cwd();
const PUBLIC_REPO_LIST_ENV = 'ABAXXLABS_PUBLIC_REPO_CANDIDATE_LIST';
const PUBLIC_REPO_ROOT_ENV = 'ABAXXLABS_PUBLIC_REPO_ROOT';
const PUBLIC_REPO_POLICY = JSON.parse(
  readFileSync(new URL('./public-repo-policy.json', import.meta.url), 'utf8'),
);

const PACKAGE_ALLOWED_PATHS = [
  'package.json',
  'README.md',
  'LICENSE',
  'dist/**',
  'vendor/id-sdk-mcp/**',
];

export const PUBLIC_REPO_ALLOWED_PATHS = PUBLIC_REPO_POLICY.publicAllowedPaths;
const PUBLIC_REPO_FORBIDDEN_PATHS = PUBLIC_REPO_POLICY.publicForbiddenPaths;

const SECRET_CONTENT_PATTERNS = [
  {
    name: 'private key block',
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    name: 'encrypted private key block',
    pattern: new RegExp('-----BEGIN ENCRYPTED ' + 'PRIVATE KEY-----'),
  },
  {
    name: 'PGP private key block',
    pattern: new RegExp('-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----'),
  },
  {
    name: 'SSH2 encrypted private key block',
    pattern: new RegExp('---- BEGIN SSH2 ENCRYPTED ' + 'PRIVATE KEY ----'),
  },
  {
    name: 'AWS access key id',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    name: 'AWS temporary access key id',
    pattern: /\bASIA[0-9A-Z]{16}\b/,
  },
  {
    name: 'GCP service account key metadata',
    pattern: /"private_key_id"\s*:\s*"[A-Za-z0-9_-]{16,}"/,
  },
  {
    name: 'GitHub token',
    pattern: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,})\b/,
  },
  {
    name: 'OpenAI API key',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/,
  },
  {
    name: 'Anthropic API key',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/,
  },
  {
    name: 'Slack token',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
  },
];

const MAX_SECRET_SCAN_BYTES = 1024 * 1024;

const BLOCKED_RELEASE_TERMS = [
  {
    category: 'ticket/process history',
    term: 'ABXAGNTS',
    pattern: /\bABXAGNTS(?:-\d+)?\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'PR #',
    pattern: /\bPR\s+#\d+\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'pre-landing',
    pattern: /\bpre[- ]landing\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'adversarial review',
    pattern: /\badversarial review\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'agent workflow',
    pattern: /\bagent workflow\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'handoff',
    pattern: /\bhandoff\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'Session',
    pattern: /\b(?:post-)?Sessions?\s*[- ]\s*\d+\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'Phase',
    pattern: /\bPhase\s*[- ]\s*\d+\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'hackathon',
    pattern: /\bhackathon\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'post-hackathon',
    pattern: /\bpost[- ]hackathon\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'commercial',
    pattern: /\bcommercial\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'paid',
    pattern: /\bpaid\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'upgrade path',
    pattern: /\bupgrade path\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'open-core',
    pattern: /\bopen[- ]core\b/i,
  },
  {
    category: 'person-specific presenter context',
    term: 'Ian',
    pattern: /\bIan\b/,
  },
];

const BLOCKED_RELEASE_TERM_ALLOWLIST = [
  {
    path: 'scripts/audit-public-artifacts.mjs',
    linePattern: String.raw`^\s*(?:category|term|pattern|linePattern):`,
    reason: 'The release audit source must declare the exact blocked terms it enforces.',
  },
  {
    path: 'scripts/public-repo-policy.json',
    linePattern: String.raw`^\s*"(?:demo/hackathon|docs/abxagnts-)`,
    reason: 'The public repository policy must declare forbidden internal-only path globs.',
  },
  {
    path: 'LICENSE',
    linePattern: String.raw`other commercial damages or losses`,
    reason:
      'Standard Apache License 2.0 section 8 boilerplate ("damages or losses"); not project-authored positioning.',
  },
];

const TEXT_EXTENSIONS = new Set([
  '',
  '.cjs',
  '.css',
  '.env',
  '.html',
  '.js',
  '.json',
  '.lock',
  '.md',
  '.mjs',
  '.sh',
  '.sql',
  '.toml',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);

function globToRegExp(glob) {
  let source = '^';
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i];
    const next = glob[i + 1];

    if (char === '*' && next === '*') {
      const after = glob[i + 2];
      if (after === '/') {
        source += '(?:.*\\/)?';
        i += 2;
      } else {
        source += '.*';
        i += 1;
      }
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
    }
  }
  source += '$';
  return new RegExp(source);
}

const globCache = new Map();

function matchesGlob(filePath, glob) {
  let regexp = globCache.get(glob);
  if (!regexp) {
    regexp = globToRegExp(glob);
    globCache.set(glob, regexp);
  }
  return regexp.test(filePath);
}

function firstMatchingGlob(filePath, globs) {
  return globs.find((glob) => matchesGlob(filePath, glob));
}

function normalizeArtifactPath(value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) {
    return { path: '', error: 'empty artifact path' };
  }

  const slashPath = trimmed.replace(/\\/g, '/').replace(/^\.\//, '');
  if (path.posix.isAbsolute(slashPath)) {
    return { path: slashPath, error: 'artifact paths must be relative' };
  }

  const normalized = path.posix.normalize(slashPath);
  if (normalized === '.' || normalized.startsWith('../') || normalized === '..') {
    return { path: normalized, error: 'artifact path escapes the artifact root' };
  }

  return { path: normalized };
}

function normalizeArtifactPaths(paths) {
  const normalized = [];
  const violations = [];
  const seen = new Set();

  for (const input of paths) {
    const result = normalizeArtifactPath(input);
    if (result.error) {
      violations.push({ path: result.path || String(input ?? ''), reason: result.error });
      continue;
    }
    if (!seen.has(result.path)) {
      seen.add(result.path);
      normalized.push(result.path);
    }
  }

  return { paths: normalized, violations };
}

function artifactFileStatus(artifactPath, rootDir) {
  const absolutePath = path.resolve(rootDir, artifactPath);
  if (
    !absolutePath.startsWith(path.resolve(rootDir) + path.sep) &&
    absolutePath !== path.resolve(rootDir)
  ) {
    return { withinRoot: false };
  }
  if (!existsSync(absolutePath)) {
    return { withinRoot: true, exists: false };
  }
  const stat = statSync(absolutePath);
  return { withinRoot: true, exists: true, isFile: stat.isFile(), size: stat.size };
}

function contentScanStatus(artifactPath, rootDir) {
  const fileStatus = artifactFileStatus(artifactPath, rootDir);
  if (!fileStatus.withinRoot || !fileStatus.exists || !fileStatus.isFile) {
    return { scan: false };
  }
  if (!TEXT_EXTENSIONS.has(path.extname(artifactPath))) {
    return { scan: false };
  }
  if (fileStatus.size > MAX_SECRET_SCAN_BYTES) {
    return {
      scan: false,
      violation: {
        path: artifactPath,
        reason: `exceeds text content scan size limit (${MAX_SECRET_SCAN_BYTES} bytes)`,
      },
    };
  }
  return { scan: true };
}

function validateBlockedTermAllowlistEntry(entry, index) {
  if (!entry || typeof entry !== 'object') {
    throw new Error(`blocked release term allowlist entry ${index + 1} must be an object`);
  }
  if (typeof entry.path !== 'string' || entry.path.trim().length === 0) {
    throw new Error(`blocked release term allowlist entry ${index + 1} must include a file path`);
  }
  if (entry.path.includes('*')) {
    throw new Error(
      `blocked release term allowlist entry ${index + 1} must be file-specific, not a glob`,
    );
  }
  if (path.posix.isAbsolute(entry.path) || entry.path.startsWith('../') || entry.path === '..') {
    throw new Error(
      `blocked release term allowlist entry ${index + 1} path must be relative to the audit root`,
    );
  }
  if (typeof entry.reason !== 'string' || entry.reason.trim().length < 12) {
    throw new Error(
      `blocked release term allowlist entry ${index + 1} must include a narrow reason`,
    );
  }
  if (
    (typeof entry.term !== 'string' || entry.term.trim().length === 0) &&
    (typeof entry.linePattern !== 'string' || entry.linePattern.trim().length === 0)
  ) {
    throw new Error(
      `blocked release term allowlist entry ${index + 1} must include a term or linePattern constraint`,
    );
  }
  if (entry.linePattern) {
    try {
      new RegExp(entry.linePattern);
    } catch (error) {
      throw new Error(
        `blocked release term allowlist entry ${index + 1} has an invalid linePattern: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}

function normalizeBlockedTermAllowlist(allowlist) {
  if (!Array.isArray(allowlist)) {
    throw new Error('blocked release term allowlist must be an array');
  }
  return allowlist.map((entry, index) => {
    validateBlockedTermAllowlistEntry(entry, index);
    const normalizedPath = normalizeArtifactPath(entry.path);
    if (normalizedPath.error) {
      throw new Error(
        `blocked release term allowlist entry ${index + 1} has an invalid path: ${normalizedPath.error}`,
      );
    }
    return {
      path: normalizedPath.path,
      term: entry.term?.trim(),
      reason: entry.reason.trim(),
      linePattern: entry.linePattern ? new RegExp(entry.linePattern) : undefined,
    };
  });
}

function isBlockedTermAllowlisted(allowlist, artifactPath, line, term) {
  return allowlist.some((entry) => {
    if (entry.path !== artifactPath) return false;
    if (entry.term && entry.term !== term) return false;
    if (entry.linePattern && !entry.linePattern.test(line)) return false;
    return true;
  });
}

function databaseCredentialViolations(contents, artifactPath) {
  const violations = [];
  const urlPattern = /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[^\s"'`<>]+/gi;
  const localHosts = new Set(['localhost', '127.0.0.1', '::1', 'h', 'host', 'example.com']);

  for (const match of contents.matchAll(urlPattern)) {
    try {
      const url = new URL(match[0]);
      if (!url.username || !url.password || localHosts.has(url.hostname.toLowerCase())) {
        continue;
      }
      violations.push({
        path: artifactPath,
        reason: 'contains high-confidence secret pattern: database URL with embedded password',
      });
      break;
    } catch {
      // Ignore malformed example URLs; path allowlists still apply.
    }
  }

  return violations;
}

function secretContentViolations(contents, artifactPath) {
  const patternViolations = SECRET_CONTENT_PATTERNS.filter(({ pattern }) =>
    pattern.test(contents),
  ).map(({ name }) => ({
    path: artifactPath,
    reason: `contains high-confidence secret pattern: ${name}`,
  }));
  return [...patternViolations, ...databaseCredentialViolations(contents, artifactPath)];
}

function blockedReleaseTermViolations(contents, artifactPath, allowlist) {
  const violations = [];
  const lines = contents.split(/\r?\n/);

  lines.forEach((line, index) => {
    for (const term of BLOCKED_RELEASE_TERMS) {
      if (!term.pattern.test(line)) continue;
      if (isBlockedTermAllowlisted(allowlist, artifactPath, line, term.term)) continue;
      violations.push({
        path: artifactPath,
        line: index + 1,
        term: term.term,
        reason: `contains blocked release term "${term.term}" (${term.category})`,
      });
    }
  });

  return violations;
}

function scanFileForContentViolations(artifactPath, rootDir, options = {}) {
  const status = contentScanStatus(artifactPath, rootDir);
  if (status.violation) {
    return [status.violation];
  }
  if (!status.scan) {
    return [];
  }

  const absolutePath = path.resolve(rootDir, artifactPath);
  const contents = readFileSync(absolutePath, 'utf8');
  return [
    ...secretContentViolations(contents, artifactPath),
    ...(options.scanBlockedTerms === false
      ? []
      : blockedReleaseTermViolations(contents, artifactPath, options.blockedTermAllowlist)),
  ];
}

function auditFiles(paths, policy, options = {}) {
  const rootDir = options.rootDir ?? ROOT_DIR;
  const scanContents = options.scanContents ?? true;
  const requireExistingFiles = options.requireExistingFiles ?? false;
  const scanBlockedTerms = options.scanBlockedTerms ?? true;
  const blockedTermAllowlist = normalizeBlockedTermAllowlist(
    options.blockedTermAllowlist ?? BLOCKED_RELEASE_TERM_ALLOWLIST,
  );
  const { paths: normalizedPaths, violations } = normalizeArtifactPaths(paths);
  const allForbiddenGlobs = policy.forbidden ?? [];

  for (const artifactPath of normalizedPaths) {
    const forbiddenGlob = firstMatchingGlob(artifactPath, allForbiddenGlobs);
    if (forbiddenGlob) {
      violations.push({ path: artifactPath, reason: `forbidden path (${forbiddenGlob})` });
      continue;
    }

    const allowedGlob = firstMatchingGlob(artifactPath, policy.allowed);
    if (!allowedGlob) {
      violations.push({ path: artifactPath, reason: 'not in artifact allowlist' });
      continue;
    }

    if (requireExistingFiles) {
      const fileStatus = artifactFileStatus(artifactPath, rootDir);
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
          blockedTermAllowlist,
          scanBlockedTerms,
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
      allowed: PACKAGE_ALLOWED_PATHS,
      forbidden: [],
    },
    options,
  );
}

export function auditPublicRepoFiles(paths, options = {}) {
  return auditFiles(
    paths,
    {
      allowed: PUBLIC_REPO_ALLOWED_PATHS,
      forbidden: PUBLIC_REPO_FORBIDDEN_PATHS,
    },
    options,
  );
}

export function defaultPublicRepoCandidatePaths(rootDir = ROOT_DIR) {
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
      env: {
        ...process.env,
        NPM_CONFIG_CACHE: npmCache,
        NPM_CONFIG_LOGS_DIR: npmLogs,
        npm_config_cache: npmCache,
        npm_config_logs_dir: npmLogs,
      },
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
  node scripts/audit-public-artifacts.mjs [all|package|public-repo] [--public-root <path>] [--public-list <path|-|git>] [--security-only]

  --security-only  Enforce path and secret checks without editorial release-term checks.

Environment:
  ${PUBLIC_REPO_ROOT_ENV}=<assembled public repo root>
  ${PUBLIC_REPO_LIST_ENV}=<path|-|git>

Examples:
  npm run audit:package-files
  npm run audit:public-repo -- --public-root ../abaxxlabs-agents-public --public-list git
  npm run audit:public-repo -- --public-root ../abaxxlabs-agents-public --public-list ./public-repo-files.txt
  printf "README.md\\n.claude/settings.json\\n" | npm run audit:public-repo -- --public-root ../abaxxlabs-agents-public --public-list -
`.trim();
}

function parseArgs(argv) {
  const args = [...argv];
  const command = args[0] && !args[0].startsWith('-') ? args.shift() : 'all';
  let publicList = process.env[PUBLIC_REPO_LIST_ENV] ?? 'git';
  let publicRoot = process.env[PUBLIC_REPO_ROOT_ENV];
  let securityOnly = false;

  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--public-list') {
      publicList = args.shift();
      if (!publicList) {
        throw new Error('--public-list requires a path, "-", or "git"');
      }
    } else if (arg === '--public-root') {
      publicRoot = args.shift();
      if (!publicRoot) {
        throw new Error('--public-root requires the assembled public repository root path');
      }
    } else if (arg === '--security-only') {
      securityOnly = true;
    } else if (arg === '--help' || arg === '-h') {
      return { help: true };
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!['all', 'package', 'public-repo'].includes(command)) {
    throw new Error(`Unknown audit command: ${command}`);
  }

  return { command, publicList, publicRoot, securityOnly };
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
  const results = [];
  if (args.command === 'all' || args.command === 'package') {
    const packageFiles = npmPackDryRunFiles();
    results.push(['Package artifact', auditPackageFiles(packageFiles)]);
  }

  if (args.command === 'all' || args.command === 'public-repo') {
    const publicRepoInput = publicRepoAuditInput(args);
    results.push([
      'Public repo artifact',
      auditPublicRepoFiles(publicRepoInput.paths, {
        rootDir: publicRepoInput.rootDir,
        requireExistingFiles: true,
        scanBlockedTerms: !args.securityOnly,
      }),
    ]);
  }

  for (const [name, result] of results) {
    printResult(name, result);
  }

  return results.every(([, result]) => result.ok) ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exitCode = runCli(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    console.error(usage());
    process.exitCode = 1;
  }
}
